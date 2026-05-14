"""FastAPI 앱 — 이벤트 수신 + buffer 관리 + orchestrator 호출 + 관리자 대시보드"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import asyncio

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..config import settings
from ..executor.runner import TerraformRunner
from ..logging_setup import setup_logging
from ..orchestrator.pipeline import Pipeline
from .approval_store import ApprovalStore
from .buffer import BufferManager, RoleBuffer
from .event_parser import extract_event_info

setup_logging(settings.log_level)
logger = logging.getLogger(__name__)
settings.ensure_dirs()


# ── 의존성 초기화 ──────────────────────────────────────────────────────────────

runner = TerraformRunner(
    state_bucket=settings.tf_state_bucket,
    state_region=settings.tf_state_region,
    lock_table=settings.tf_state_lock_table,
    plugin_cache_dir=settings.tf_plugin_cache_dir,
)
approval_store = ApprovalStore(base_dir=settings.approval_report_dir)
pipeline = Pipeline(
    output_base=settings.output_base_dir,
    work_base=settings.work_base_dir,
    runner=runner,
    approval_store=approval_store,
)
buffer_manager = BufferManager(
    debounce_seconds=settings.debounce_seconds,
    on_process=pipeline.process_buffer,
)

app = FastAPI(title='IAM Pipeline Codegen Server')


# CORS — 정적 SPA가 다른 origin에서 서빙될 때 필요.
_cors_origins = [
    o.strip() for o in (settings.dashboard_cors_origins or '').split(',') if o.strip()
]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=['GET', 'POST', 'OPTIONS'],
        allow_headers=['X-API-Key', 'Content-Type'],
        allow_credentials=False,
    )


@app.on_event('startup')
async def _recover_pending_approvals() -> None:
    # 이전 프로세스에서 await 중이던 승인은 in-memory Future가 사라졌으므로
    # 디스크에서 failed(server_restart)로 정리. 동일 요청이 재발생하면 새 흐름으로 진행.
    approval_store.recover_pending_on_startup()


def _require_api_key(x_api_key: Optional[str]) -> None:
    if x_api_key != settings.secret_api_key:
        raise HTTPException(status_code=401, detail='Unauthorized')


def save_payload(data: dict) -> str:
    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')
    fname = f'event_{ts}.json'
    fpath = settings.payload_dir / fname
    fpath.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
    return fname


@app.post('/webhook')
async def webhook(
    request: Request,
    x_api_key: Optional[str] = Header(None),
):
    _require_api_key(x_api_key)
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='Invalid JSON')

    saved = save_payload(data)

    try:
        info = extract_event_info(data)
    except ValueError as e:
        logger.warning(f'Event ignored: {e}')
        return {'status': 'skipped', 'reason': str(e), 'file': saved}

    await buffer_manager.upsert_event(info)

    return {
        'status': 'accepted',
        'event_name': info.get('event_name'),
        'action': info.get('action'),
        'account_id': info['account_id'],
        'role_name': info['role_name'],
        'policy_arn': info.get('policy_arn'),
        'file': saved,
    }


@app.get('/health')
async def health():
    return {
        'status': 'ok',
        'pending_buffers': len(buffer_manager.snapshot()),
        'buffers': buffer_manager.snapshot(),
    }


@app.get('/buffers/{account_id}/{role_name}')
async def buffer_detail(account_id: str, role_name: str):
    buf = buffer_manager.get(account_id, role_name)
    if buf is None:
        raise HTTPException(status_code=404, detail='No active buffer')
    return {
        'account_id': buf.account_id,
        'role_name': buf.role_name,
        'requester_iic_user': buf.requester_iic_user,
        'policies': sorted(buf.policy_arns),
        'first_event_at': buf.first_event_at.isoformat() if buf.first_event_at else None,
        'last_event_at': buf.last_event_at.isoformat() if buf.last_event_at else None,
    }


# ── 관리자 대시보드 API ────────────────────────────────────────────────────────

_SUMMARY_FIELDS = (
    'request_id', 'account_id', 'role_name', 'action', 'requester_iic_user',
    'policy_arns', 'first_event_at', 'last_event_at', 'created_at', 'status',
)


def _summarize(record: dict) -> dict:
    return {k: record.get(k) for k in _SUMMARY_FIELDS}


class DecisionPayload(BaseModel):
    decision: str = Field(..., pattern='^(approve|deny)$')
    reviewer: str = Field(..., min_length=1, max_length=200)
    comment: str = Field(default='', max_length=2000)


@app.get('/approvals')
async def list_approvals(x_api_key: Optional[str] = Header(None)):
    _require_api_key(x_api_key)
    return [_summarize(r) for r in approval_store.list_all()]


@app.get('/approvals/{request_id}')
async def get_approval(request_id: str, x_api_key: Optional[str] = Header(None)):
    _require_api_key(x_api_key)
    rec = approval_store.get(request_id)
    if rec is None:
        raise HTTPException(status_code=404, detail='Approval not found')
    return rec


@app.get('/approvals/stream')
async def stream_approvals(
    request: Request,
    x_api_key: Optional[str] = Header(None),
    api_key: Optional[str] = Query(None),
):
    # EventSource는 커스텀 헤더를 못 보내므로 쿼리스트링 api_key도 허용.
    key = x_api_key or api_key
    _require_api_key(key)

    queue = approval_store.subscribe()

    async def event_gen():
        # 연결 직후 초기 스냅샷을 보내 클라이언트가 첫 GET을 생략할 수 있게 한다.
        yield 'retry: 5000\n\n'
        yield f'event: snapshot\ndata: {json.dumps([_summarize(r) for r in approval_store.list_all()])}\n\n'
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    # heartbeat (comment line) — 프록시/브라우저 idle 차단 방지
                    yield ': keep-alive\n\n'
                    continue
                yield f'event: change\ndata: {json.dumps(ev)}\n\n'
        finally:
            approval_store.unsubscribe(queue)

    return StreamingResponse(
        event_gen(),
        media_type='text/event-stream',
        headers={
            'Cache-Control': 'no-cache, no-transform',
            'X-Accel-Buffering': 'no',  # nginx 앞단 두는 경우 버퍼링 비활성
        },
    )


@app.post('/approvals/{request_id}/decision')
async def decide_approval(
    request_id: str,
    payload: DecisionPayload,
    x_api_key: Optional[str] = Header(None),
):
    _require_api_key(x_api_key)
    rec = approval_store.decide(
        request_id=request_id,
        approve=(payload.decision == 'approve'),
        reviewer=payload.reviewer,
        comment=payload.comment,
    )
    if rec is None:
        raise HTTPException(status_code=404, detail='Approval not found')
    return rec


# ── 정적 SPA 마운트 (옵션) ────────────────────────────────────────────────────
# resource-dashboard의 `npm run build` 산출물(dist/)을 dashboard_static_dir로 지정하면
# 동일 서버에서 SPA를 서빙. 비활성 시 별도 nginx/CDN에서 서빙해도 동작.

_static_dir = settings.dashboard_static_dir
if str(_static_dir) and _static_dir.exists() and _static_dir.is_dir():
    app.mount(
        '/',
        StaticFiles(directory=str(_static_dir), html=True),
        name='dashboard',
    )
    logger.info(f'Dashboard SPA served from {_static_dir}')


def main():
    """CLI 엔트리포인트 — pyproject.toml의 [project.scripts]에서 참조"""
    import uvicorn
    uvicorn.run(
        'iam_pipeline.codegen.server:app',
        host='0.0.0.0',
        port=8000,
        log_config=None,
    )
