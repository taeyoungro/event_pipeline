"""FastAPI 앱 — 이벤트 수신 + buffer 관리 + orchestrator 호출"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request

from ..config import settings
from ..executor.runner import TerraformRunner
from ..logging_setup import setup_logging
from ..orchestrator.pipeline import Pipeline
from .buffer import BufferManager, RoleBuffer
from .event_parser import extract_event_info

setup_logging(settings.log_level)
logger = logging.getLogger(__name__)
settings.ensure_dirs()

# 의존성 초기화
runner = TerraformRunner(
    state_bucket=settings.tf_state_bucket,
    state_region=settings.tf_state_region,
    lock_table=settings.tf_state_lock_table,
    plugin_cache_dir=settings.tf_plugin_cache_dir,
)
pipeline = Pipeline(
    output_base=settings.output_base_dir,
    work_base=settings.work_base_dir,
    runner=runner,
)
buffer_manager = BufferManager(
    debounce_seconds=settings.debounce_seconds,
    on_process=pipeline.process_buffer,   # ← 핵심 연결점
)

app = FastAPI(title='IAM Pipeline Codegen Server')


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
    if x_api_key != settings.secret_api_key:
        raise HTTPException(status_code=401, detail='Unauthorized')
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
        'account_id': info['account_id'],
        'role_name': info['role_name'],
        'policy_arn': info['policy_arn'],
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


def main():
    """CLI 엔트리포인트 — pyproject.toml의 [project.scripts]에서 참조"""
    import uvicorn
    uvicorn.run(
        'iam_pipeline.codegen.server:app',
        host='0.0.0.0',
        port=8000,
        log_config=None,
    )
