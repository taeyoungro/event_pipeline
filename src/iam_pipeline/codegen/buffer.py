"""Role별 debounce buffer 관리

BufferAction:
  ATTACH  — AttachRolePolicy 이벤트 누적 → PS 생성/갱신
  REFRESH — DetachRolePolicy 수신 → IAM에서 현재 상태를 새로 읽어 PS 갱신
  DELETE  — DeleteRole 수신 → PS 파괴 (terraform destroy)

액션 우선순위: ATTACH < REFRESH < DELETE (절대 다운그레이드 없음)

DeleteRole/DetachRolePolicy 레이스 처리:
  - DeleteRole 수신 시 _pending_deletes에 TTL과 함께 기록한다.
  - 이후 동일 Role의 DetachRolePolicy(REFRESH)가 도착하면 _pending_deletes를 확인하여
    DeleteRole 흐름의 일부임을 인식하고 해당 이벤트를 무시한다.
  - 모든 이벤트는 동일 debounce_seconds를 사용하므로, DeleteRole이 먼저 수신된 경우에도
    debounce 윈도우 내에서 도착하는 DetachRolePolicy가 기존 DELETE 버퍼에 흡수된다.
"""
import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Awaitable, Callable, Optional

from .policy_utils import policy_arn_to_name

logger = logging.getLogger(__name__)

# DeleteRole 수신 후 DetachRolePolicy를 무시할 시간.
# debounce_seconds보다 충분히 길게 설정하여 debounce 만료 후 늦게 도착하는
# DetachRolePolicy도 차단한다.
_PENDING_DELETE_TTL = 30.0


class BufferAction(Enum):
    ATTACH  = 'ATTACH'
    REFRESH = 'REFRESH'
    DELETE  = 'DELETE'


_ACTION_PRIORITY: dict[BufferAction, int] = {
    BufferAction.ATTACH:  0,
    BufferAction.REFRESH: 1,
    BufferAction.DELETE:  2,
}


@dataclass
class RoleBuffer:
    account_id: str
    role_name: str
    action: BufferAction = BufferAction.ATTACH
    policy_arns: set = field(default_factory=set)
    requester_iic_user: Optional[str] = None
    target_account_id: Optional[str] = None
    timer_task: Optional[asyncio.Task] = None
    first_event_at: Optional[datetime] = None
    last_event_at: Optional[datetime] = None


ProcessCallback = Callable[[RoleBuffer], Awaitable[None]]


class BufferManager:
    """Role별 buffer + debounce 타이머 관리"""

    def __init__(self, debounce_seconds: int, on_process: ProcessCallback):
        self._buffers: dict[tuple[str, str], RoleBuffer] = {}
        self._lock = asyncio.Lock()
        self._debounce_seconds = debounce_seconds
        self._on_process = on_process
        # (account_id, role_name) → pending delete 만료 시각 (monotonic)
        self._pending_deletes: dict[tuple[str, str], float] = {}

    async def upsert_event(self, info: dict) -> None:
        key = (info['account_id'], info['role_name'])
        new_action = BufferAction(info.get('action', 'ATTACH'))

        async with self._lock:
            now = datetime.now(timezone.utc)
            now_mono = time.monotonic()

            # REFRESH(DetachRolePolicy): pending delete가 있으면 Role 삭제 흐름의
            # 일부이므로 이벤트를 무시한다.
            if new_action == BufferAction.REFRESH:
                expiry = self._pending_deletes.get(key)
                if expiry is not None and now_mono < expiry:
                    logger.info(
                        f"REFRESH ignored — DeleteRole already pending: "
                        f"({info['account_id']}, {info['role_name']})"
                    )
                    return

            # DELETE 수신: 이후 도착하는 REFRESH 차단을 위해 pending delete 기록
            if new_action == BufferAction.DELETE:
                self._pending_deletes[key] = now_mono + _PENDING_DELETE_TTL
                logger.debug(
                    f"Pending delete recorded: {key} (TTL={_PENDING_DELETE_TTL}s)"
                )

            buf = self._buffers.get(key)

            if buf is None:
                buf = RoleBuffer(
                    account_id=info['account_id'],
                    role_name=info['role_name'],
                    action=new_action,
                    requester_iic_user=info.get('iic_user'),
                    target_account_id=info['account_id'],
                    first_event_at=now,
                )
                self._buffers[key] = buf
                logger.info(
                    f"New buffer: account={info['account_id']}, "
                    f"role={info['role_name']}, action={new_action.value}, "
                    f"requester={info.get('iic_user')}"
                )
            else:
                if buf.timer_task and not buf.timer_task.done():
                    buf.timer_task.cancel()
                # 액션 우선순위: 절대 다운그레이드 없음
                if _ACTION_PRIORITY[new_action] > _ACTION_PRIORITY[buf.action]:
                    logger.info(
                        f"Buffer action upgraded: {buf.action.value} → {new_action.value} "
                        f"for ({info['account_id']}, {info['role_name']})"
                    )
                    buf.action = new_action

            # ATTACH 이벤트만 policy_arns 누적 (버퍼 상태 조회용 — 실제 TF 생성은 IAM 현재 상태 기준)
            if new_action == BufferAction.ATTACH and 'policy_arn' in info:
                buf.policy_arns.add(info['policy_arn'])

            buf.last_event_at = now

            buf.timer_task = asyncio.create_task(
                self._wait_then_process(key, self._debounce_seconds)
            )

            _extra = ''
            if 'policy_arn' in info:
                _extra = f" + {policy_arn_to_name(info['policy_arn'])}"
            logger.info(
                f"Event added: ({info['account_id']}, {info['role_name']}) "
                f"action={buf.action.value}{_extra} "
                f"(policies buffered: {len(buf.policy_arns)})"
            )

    async def _wait_then_process(
        self, key: tuple[str, str], debounce: float
    ) -> None:
        try:
            await asyncio.sleep(debounce)
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
                exc_info=True,
            )

    def snapshot(self) -> list[dict]:
        return [
            {
                'account_id': k[0],
                'role_name': k[1],
                'action': v.action.value,
                'policy_count': len(v.policy_arns),
                'first_event_at': v.first_event_at.isoformat() if v.first_event_at else None,
            }
            for k, v in self._buffers.items()
        ]

    def get(self, account_id: str, role_name: str) -> Optional[RoleBuffer]:
        return self._buffers.get((account_id, role_name))
