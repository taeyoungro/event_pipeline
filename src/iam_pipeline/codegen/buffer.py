"""Role별 debounce buffer 관리"""
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from .policy_utils import policy_arn_to_name

logger = logging.getLogger(__name__)


@dataclass
class RoleBuffer:
    account_id: str
    role_name: str
    policy_arns: set = field(default_factory=set)
    requester_iic_user: Optional[str] = None
    target_account_id: Optional[str] = None
    timer_task: Optional[asyncio.Task] = None
    first_event_at: Optional[datetime] = None
    last_event_at: Optional[datetime] = None


# 콜백 타입: process_role 같은 처리 함수
ProcessCallback = Callable[[RoleBuffer], Awaitable[None]]


class BufferManager:
    """Role별 buffer + debounce 타이머 관리"""

    def __init__(self, debounce_seconds: int, on_process: ProcessCallback):
        self._buffers: dict[tuple[str, str], RoleBuffer] = {}
        self._lock = asyncio.Lock()
        self._debounce_seconds = debounce_seconds
        self._on_process = on_process

    async def upsert_event(self, info: dict) -> None:
        key = (info['account_id'], info['role_name'])

        async with self._lock:
            buf = self._buffers.get(key)
            now = datetime.now(timezone.utc)

            if buf is None:
                buf = RoleBuffer(
                    account_id=info['account_id'],
                    role_name=info['role_name'],
                    requester_iic_user=info['iic_user'],
                    target_account_id=info['account_id'],
                    first_event_at=now,
                )
                self._buffers[key] = buf
                logger.info(
                    f"New buffer: account={info['account_id']}, "
                    f"role={info['role_name']}, requester={info['iic_user']}"
                )
            else:
                if buf.timer_task and not buf.timer_task.done():
                    buf.timer_task.cancel()

            buf.policy_arns.add(info['policy_arn'])
            buf.last_event_at = now

            buf.timer_task = asyncio.create_task(
                self._wait_then_process(key)
            )

            logger.info(
                f"Event added: ({info['account_id']}, {info['role_name']}) "
                f"+ {policy_arn_to_name(info['policy_arn'])} "
                f"(total: {len(buf.policy_arns)})"
            )

    async def _wait_then_process(self, key: tuple[str, str]) -> None:
        try:
            await asyncio.sleep(self._debounce_seconds)
        except asyncio.CancelledError:
            logger.debug(f"Timer cancelled: {key}")
            raise

        async with self._lock:
            buf = self._buffers.pop(key, None)

        if buf is None:
            logger.warning(f"Buffer disappeared: {key}")
            return

        try:
            await self._on_process(buf)
        except Exception as e:
            logger.error(
                f"Processing failed for {key}: {type(e).__name__}: {e}",
                exc_info=True
            )

    def snapshot(self) -> list[dict]:
        return [
            {
                'account_id': k[0],
                'role_name': k[1],
                'policy_count': len(v.policy_arns),
                'first_event_at': v.first_event_at.isoformat() if v.first_event_at else None,
            }
            for k, v in self._buffers.items()
        ]

    def get(self, account_id: str, role_name: str) -> Optional[RoleBuffer]:
        return self._buffers.get((account_id, role_name))
