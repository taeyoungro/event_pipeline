"""디스크 기반 관리자 승인 저장소.

설계 원칙:
- 단일 진실원(SoT): ``settings.approval_report_dir`` 아래의 ``<request_id>.json``.
- 메모리에는 대기 중 코루틴을 깨우기 위한 ``asyncio.Future`` 만 유지.
- 서버 재기동 시 in-memory Future는 사라지므로, 기동 훅에서 ``pending`` 으로 남은
  레코드를 ``failed`` (server_restart) 로 일괄 정리한다 (재처리는 다음 동일 webhook 시).

레코드 스키마 (``<request_id>.json``):
    {
      "request_id": str,
      "account_id": str,
      "role_name": str,
      "action": "ATTACH" | "REFRESH" | "DELETE",
      "requester_iic_user": str | null,
      "target_accounts": list[str],
      "policy_arns": list[str],
      "policy_details": { arn: { is_necessary, confidence, reason } },
      "approval_report": str,
      "plan_tail": str,
      "first_event_at": str | null,
      "last_event_at": str | null,
      "created_at": str,
      "status": "pending" | "approved" | "denied" | "applying" | "applied" | "failed",
      "decided_at": str | null,
      "reviewer": str | null,
      "comment": str | null,
      "error": str | null
    }
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


_VALID_STATUSES = {
    'pending', 'approved', 'denied', 'applying', 'applied', 'failed',
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApprovalStore:
    """디스크 JSON + asyncio.Future 기반 승인 큐."""

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._futures: dict[str, asyncio.Future[bool]] = {}
        self._lock = asyncio.Lock()

    # ── 파일 IO ────────────────────────────────────────────────────────────

    def _path(self, request_id: str) -> Path:
        # request_id는 build_request_id에서 생성되며 영숫자/하이픈/언더스코어만 포함.
        if '/' in request_id or '..' in request_id:
            raise ValueError(f'invalid request_id: {request_id!r}')
        return self.base_dir / f'{request_id}.json'

    def _read(self, request_id: str) -> Optional[dict[str, Any]]:
        p = self._path(request_id)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f'approval record unreadable {p}: {e}')
            return None

    def _write(self, record: dict[str, Any]) -> None:
        p = self._path(record['request_id'])
        tmp = p.with_suffix('.json.tmp')
        tmp.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
        tmp.replace(p)

    # ── 등록 / 조회 ────────────────────────────────────────────────────────

    def register(self, record: dict[str, Any]) -> asyncio.Future[bool]:
        """pending 레코드를 디스크에 기록하고 Future를 반환."""
        record.setdefault('created_at', _now_iso())
        record['status'] = 'pending'
        record.setdefault('decided_at', None)
        record.setdefault('reviewer', None)
        record.setdefault('comment', None)
        record.setdefault('error', None)
        self._write(record)
        loop = asyncio.get_event_loop()
        fut: asyncio.Future[bool] = loop.create_future()
        self._futures[record['request_id']] = fut
        logger.info(f'[{record["request_id"]}] approval registered as pending')
        return fut

    def get(self, request_id: str) -> Optional[dict[str, Any]]:
        return self._read(request_id)

    def list_all(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for p in sorted(self.base_dir.glob('*.json')):
            try:
                records.append(json.loads(p.read_text(encoding='utf-8')))
            except (OSError, json.JSONDecodeError):
                continue
        # 최신순 (created_at 또는 last_event_at).
        records.sort(
            key=lambda r: r.get('created_at') or r.get('last_event_at') or '',
            reverse=True,
        )
        return records

    # ── 상태 전이 ──────────────────────────────────────────────────────────

    def update_status(
        self,
        request_id: str,
        status: str,
        **extra: Any,
    ) -> Optional[dict[str, Any]]:
        if status not in _VALID_STATUSES:
            raise ValueError(f'invalid status: {status!r}')
        rec = self._read(request_id)
        if rec is None:
            return None
        rec['status'] = status
        rec.update(extra)
        self._write(rec)
        return rec

    def decide(
        self,
        request_id: str,
        approve: bool,
        reviewer: str,
        comment: str = '',
    ) -> Optional[dict[str, Any]]:
        """대시보드에서 승인/거부 호출 시 진입점.

        - 디스크 상태를 approved/denied로 갱신
        - 대기 중인 Future가 있으면 set_result로 깨움 (idempotent)
        """
        rec = self._read(request_id)
        if rec is None:
            return None
        if rec.get('status') != 'pending':
            # 이미 처리된 요청: 멱등 응답 (현재 레코드 그대로 반환)
            logger.warning(
                f'[{request_id}] decide called but status={rec.get("status")} '
                '(idempotent no-op)'
            )
            return rec
        rec['status'] = 'approved' if approve else 'denied'
        rec['decided_at'] = _now_iso()
        rec['reviewer'] = reviewer
        rec['comment'] = comment
        self._write(rec)

        fut = self._futures.pop(request_id, None)
        if fut is not None and not fut.done():
            fut.set_result(approve)
        else:
            logger.warning(
                f'[{request_id}] decision recorded but no awaiting future '
                '(server may have restarted — apply will not run)'
            )
        return rec

    async def wait_for_decision(
        self,
        request_id: str,
        timeout_seconds: float,
    ) -> bool:
        """Pipeline 코루틴이 호출. Future가 set_result로 깨어나면 그 값을 반환."""
        fut = self._futures.get(request_id)
        if fut is None:
            # register 없이 wait — 호출 순서 오류.
            logger.error(f'[{request_id}] wait_for_decision: no registered future')
            return False
        try:
            return await asyncio.wait_for(fut, timeout=timeout_seconds)
        except asyncio.TimeoutError:
            logger.warning(f'[{request_id}] approval timed out after {timeout_seconds}s')
            self.update_status(request_id, 'failed', error='approval_timeout')
            self._futures.pop(request_id, None)
            return False

    # ── 기동 시 복구 ───────────────────────────────────────────────────────

    def recover_pending_on_startup(self) -> int:
        """이전 프로세스에서 pending이었던 레코드를 failed(server_restart)로 정리.

        in-memory Future가 사라졌으므로 그 코루틴은 영구 블록되지 않도록
        프로세스 시작 전 디스크에서만 정리한다. 동일 webhook이 재전송되면
        새 request_id로 다시 흐름이 시작된다.
        """
        count = 0
        for p in self.base_dir.glob('*.json'):
            try:
                rec = json.loads(p.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError):
                continue
            if rec.get('status') == 'pending':
                rec['status'] = 'failed'
                rec['error'] = 'server_restart_before_decision'
                rec['decided_at'] = _now_iso()
                p.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding='utf-8')
                count += 1
        if count:
            logger.info(f'recovered {count} stale pending approval(s) as failed')
        return count
