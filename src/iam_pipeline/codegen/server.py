"""FastAPI 앱 — 이벤트 수신 + Trust Policy 사전 검증 + buffer 관리 + orchestrator 호출"""
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request

from ..config import settings
from ..executor.runner import TerraformRunner
from ..logging_setup import setup_logging
from ..orchestrator.pipeline import Pipeline
from .buffer import BufferManager, RoleBuffer
from .event_parser import extract_event_info
from .policy_fetcher import PolicyFetcher
from .policy_utils import is_service_role

setup_logging(settings.log_level)
logger = logging.getLogger(__name__)
settings.ensure_dirs()


# ── Trust Policy 캐시 ─────────────────────────────────────────────────────────

class _TrustPolicyCache:
    """
    Role의 Trust Policy 검증 결과를 TTL로 캐시.

    STS AssumeRole 호출 횟수를 최소화하면서 웹훅 핸들러에서
    서비스 Role을 버퍼 추가 전에 사전 필터링한다.

    - 캐시 히트: 이전 결과 즉시 반환 (API 호출 없음)
    - 캐시 미스: cross-account IAM 호출 후 결과 저장
    - fail-open: 조회 실패 시 True 반환 (버퍼 추가 허용) + WARNING 로그
    """

    def __init__(self, ttl_seconds: int = 300):
        self._ttl = ttl_seconds
        # (account_id, role_name) → (is_user_role: bool, expires_at: float)
        self._cache: dict[tuple[str, str], tuple[bool, float]] = {}

    def is_user_role(self, account_id: str, role_name: str) -> bool:
        """
        Trust Policy에 AWS/Federated Principal이 존재하면 True.
        Service Principal만 있으면 False (버퍼 추가 차단 대상).
        """
        key = (account_id, role_name)
        now = time.monotonic()

        cached = self._cache.get(key)
        if cached is not None:
            result, expires_at = cached
            if now < expires_at:
                logger.debug(f'Trust policy cache hit: {role_name} → {"user" if result else "service"}')
                return result

        fetcher = PolicyFetcher(
            audit_role_name=settings.audit_role_name,
            session_name=settings.assume_role_session_name,
            duration_seconds=settings.assume_role_duration_seconds,
        )
        try:
            trust = fetcher.get_trust_policy(account_id, role_name)
            result = not is_service_role(trust)
            label = 'user' if result else 'service'
            logger.info(
                f'Trust policy checked: {account_id}/{role_name} → {label} role '
                f'(cached {self._ttl}s)'
            )
        except RuntimeError as e:
            logger.warning(
                f'Trust policy fetch failed for {role_name} — '
                f'fail-open, proceeding to buffer: {e}'
            )
            result = True  # fail-open: 확인 불가 시 버퍼 허용
        finally:
            fetcher.close()

        self._cache[key] = (result, now + self._ttl)
        return result

    def invalidate(self, account_id: str, role_name: str) -> None:
        """DeleteRole 처리 후 캐시 항목 무효화."""
        self._cache.pop((account_id, role_name), None)


trust_policy_cache = _TrustPolicyCache(ttl_seconds=300)

# ── 의존성 초기화 ──────────────────────────────────────────────────────────────

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
    on_process=pipeline.process_buffer,
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

    # 1. 이벤트 파싱 (예약 Role 등 이름 기반 필터 포함)
    try:
        info = extract_event_info(data)
    except ValueError as e:
        logger.warning(f'Event ignored: {e}')
        return {'status': 'skipped', 'reason': str(e), 'file': saved}

    # 2. Trust Policy 사전 검증 — 버퍼 추가 전에 서비스 Role 차단
    #    DeleteRole은 Role이 이미 삭제되었으므로 Trust Policy 조회 불가 → 검증 생략
    if info['action'] != 'DELETE':
        if not trust_policy_cache.is_user_role(info['account_id'], info['role_name']):
            reason = (
                f"Service role (Trust Policy has no AWS/Federated principal): "
                f"{info['role_name']}"
            )
            logger.info(f'Skipped before buffer: {reason}')
            return {'status': 'skipped', 'reason': reason, 'file': saved}
    else:
        # DeleteRole: 처리 후 캐시 무효화
        trust_policy_cache.invalidate(info['account_id'], info['role_name'])

    # 3. 버퍼에 추가
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


def main():
    """CLI 엔트리포인트 — pyproject.toml의 [project.scripts]에서 참조"""
    import uvicorn
    uvicorn.run(
        'iam_pipeline.codegen.server:app',
        host='0.0.0.0',
        port=8000,
        log_config=None,
    )
