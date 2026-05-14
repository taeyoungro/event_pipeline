"""리소스(PS) 변경 이벤트 로그.

apply_plan / destroy 가 실제로 성공한 후 호출되어 디스크에 이벤트 레코드를 쌓는다.
관리자 승인 큐(``approval_store``)와는 별개의 디렉터리에 저장한다.

스키마 (``<event_id>.json``):
    {
      "event_id": str,                 # "<request_id>-<applied|destroyed>"
      "request_id": str,
      "account_id": str,
      "role_name": str,
      "ps_name": str | null,
      "action": "ATTACH" | "REFRESH" | "DELETE",
      "outcome": "applied" | "destroyed",
      "policy_arns": list[str],        # DELETE는 빈 리스트
      "target_accounts": list[str],
      "requester_iic_user": str | null,
      "reviewer": str | null,          # 승인자 (REFRESH/DELETE는 null 가능)
      "applied_at": str (ISO8601)
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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ResourceStore:
    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    def _path(self, event_id: str) -> Path:
        if '/' in event_id or '..' in event_id:
            raise ValueError(f'invalid event_id: {event_id!r}')
        return self.base_dir / f'{event_id}.json'

    # ── SSE pub/sub ────────────────────────────────────────────────────────

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=64)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(q)

    def _broadcast(self, event: dict[str, Any]) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning('resource SSE subscriber queue full — dropping event')

    # ── 이벤트 기록 ────────────────────────────────────────────────────────

    def record(
        self,
        *,
        request_id: str,
        account_id: str,
        role_name: str,
        action: str,
        outcome: str,
        policy_arns: Optional[list[str]] = None,
        target_accounts: Optional[list[str]] = None,
        requester_iic_user: Optional[str] = None,
        reviewer: Optional[str] = None,
        ps_name: Optional[str] = None,
    ) -> dict[str, Any]:
        event_id = f'{request_id}-{outcome}'
        record = {
            'event_id': event_id,
            'request_id': request_id,
            'account_id': account_id,
            'role_name': role_name,
            'ps_name': ps_name,
            'action': action,
            'outcome': outcome,
            'policy_arns': sorted(policy_arns or []),
            'target_accounts': list(target_accounts or []),
            'requester_iic_user': requester_iic_user,
            'reviewer': reviewer,
            'applied_at': _now_iso(),
        }
        p = self._path(event_id)
        tmp = p.with_suffix('.json.tmp')
        tmp.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
        tmp.replace(p)
        logger.info(
            f'[{request_id}] resource event recorded: {action}/{outcome} '
            f'role={role_name} account={account_id}'
        )
        self._broadcast({'type': 'created', 'event_id': event_id})
        return record

    # ── 조회 ───────────────────────────────────────────────────────────────

    def get(self, event_id: str) -> Optional[dict[str, Any]]:
        p = self._path(event_id)
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f'resource record unreadable {p}: {e}')
            return None

    def list_all(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for p in sorted(self.base_dir.glob('*.json')):
            try:
                records.append(json.loads(p.read_text(encoding='utf-8')))
            except (OSError, json.JSONDecodeError):
                continue
        records.sort(key=lambda r: r.get('applied_at') or '', reverse=True)
        return records
