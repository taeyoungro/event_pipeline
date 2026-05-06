"""codegen 처리 완료 → executor 호출 흐름

Phase 1.3/1.4/1.5: BufferAction에 따라 ATTACH/REFRESH/DELETE 분기
Phase 2.2/2.3/2.5: iic-target-accounts 태그 파싱 → 다중 계정 Assignment
Phase 4.1/4.2/4.3: Trust Policy 분석 (서비스 Role 감지, 위험 패턴 차단)
Phase 5.1: 처리 실패 분류 (FailureCategory enum)
"""
import logging
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from ..codegen.buffer import BufferAction, RoleBuffer
from ..codegen.policy_fetcher import PolicyFetcher
from ..codegen.tf_writer import write_destroy_workspace, write_workspace
from ..config import settings
from ..executor.runner import TerraformRunner
from ..executor.workspace import cleanup_work_dir, prepare_work_dir

logger = logging.getLogger(__name__)

_ACCOUNT_ID_RE = re.compile(r'^\d{12}$')


# ── Phase 5.1: 실패 분류 ────────────────────────────────────────────────────

class FailureCategory(Enum):
    SERVICE_ROLE            = 'service_role'
    DANGEROUS_TRUST_POLICY  = 'dangerous_trust_policy'
    INSUFFICIENT_PERMISSIONS = 'insufficient_permissions'
    POLICY_SIZE_EXCEEDED    = 'policy_size_exceeded'
    TERRAFORM_FAILED        = 'terraform_failed'
    UNKNOWN                 = 'unknown'


def classify_failure(exc: Exception) -> FailureCategory:
    msg = str(exc).lower()
    if 'assumerole failed' in msg or 'access denied' in msg:
        return FailureCategory.INSUFFICIENT_PERMISSIONS
    if 'inline policy size' in msg or 'exceeds limit' in msg:
        return FailureCategory.POLICY_SIZE_EXCEEDED
    if 'terraform' in msg and 'failed' in msg:
        return FailureCategory.TERRAFORM_FAILED
    if 'dangerous trust policy' in msg:
        return FailureCategory.DANGEROUS_TRUST_POLICY
    return FailureCategory.UNKNOWN


# ── Phase 4.3: Trust Policy 분석 ─────────────────────────────────────────────

def is_service_role(trust_policy: dict) -> bool:
    """
    Trust Policy에 AWS/Federated Principal이 전혀 없으면 서비스 전용 Role.
    서비스 Role에는 IIC Permission Set을 생성하지 않는다.
    """
    statements = trust_policy.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        principal = stmt.get('Principal', {})
        if isinstance(principal, str):
            return False
        if isinstance(principal, dict):
            if 'AWS' in principal or 'Federated' in principal:
                return False
    return True


def has_dangerous_trust(trust_policy: dict) -> bool:
    """
    Phase 4.2: Wildcard(*) Principal이 포함된 위험한 Trust Policy 감지.
    """
    statements = trust_policy.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        principal = stmt.get('Principal', {})
        if principal == '*':
            return True
        if isinstance(principal, dict):
            for v in principal.values():
                if v == '*':
                    return True
                if isinstance(v, list) and '*' in v:
                    return True
    return False


# ── Phase 2.2/2.5: 태그 기반 대상 계정 파싱 ─────────────────────────────────

def parse_target_accounts(
    tags: dict[str, str],
    source_account_id: str,
    tag_key: str,
) -> list[str]:
    """
    iic-target-accounts 태그 값(콤마 구분 12자리 계정 ID)을 파싱.
    태그 누락 또는 유효 계정 없으면 이벤트 발생 계정만 반환 (Phase 2.5 fallback).
    """
    tag_value = tags.get(tag_key, '').strip()
    if not tag_value:
        return [source_account_id]

    valid: list[str] = []
    for raw in tag_value.split(','):
        acct = raw.strip()
        if _ACCOUNT_ID_RE.match(acct):
            valid.append(acct)
        else:
            logger.warning(
                f'iic-target-accounts 태그에 유효하지 않은 계정 ID: "{acct}" (무시)'
            )

    if not valid:
        logger.warning(
            f'iic-target-accounts 태그에 유효한 계정이 없어 '
            f'이벤트 발생 계정({source_account_id})으로 fallback'
        )
        return [source_account_id]

    return valid


# ── 파이프라인 ────────────────────────────────────────────────────────────────

class Pipeline:
    """코드 생성 → 실행 통합 파이프라인"""

    def __init__(
        self,
        output_base: Path,
        work_base: Path,
        runner: TerraformRunner,
    ):
        self.output_base = output_base
        self.work_base = work_base
        self.runner = runner

    def _build_request_id(self, buf: RoleBuffer) -> str:
        ts = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        return f'role-{buf.account_id}-{buf.role_name}-{ts}'

    def _state_key(self, buf: RoleBuffer) -> str:
        return f'aws/role-{buf.account_id}-{buf.role_name}.tfstate'

    async def process_buffer(self, buf: RoleBuffer) -> None:
        request_id = self._build_request_id(buf)
        logger.info(
            f'[{request_id}] === Pipeline started '
            f'(action={buf.action.value}, role={buf.role_name}) ==='
        )

        fetcher = PolicyFetcher(
            audit_role_name=settings.audit_role_name,
            session_name=settings.assume_role_session_name,
            duration_seconds=settings.assume_role_duration_seconds,
        )

        try:
            if buf.action == BufferAction.DELETE:
                await self._process_delete(buf, request_id)
                return

            await self._process_upsert(buf, fetcher, request_id)

        except Exception as e:
            category = classify_failure(e)
            logger.error(
                f'[{request_id}] === Pipeline failed '
                f'[{category.value}]: {type(e).__name__}: {e} ===',
                exc_info=(category == FailureCategory.UNKNOWN),
            )
        finally:
            fetcher.close()

    async def _process_upsert(
        self,
        buf: RoleBuffer,
        fetcher: PolicyFetcher,
        request_id: str,
    ) -> None:
        """ATTACH / REFRESH → PS 생성·갱신"""

        # Phase 1.3/1.5: REFRESH 모드 — IAM에서 현재 상태 읽어오기
        if buf.action == BufferAction.REFRESH:
            logger.info(
                f'[{request_id}] REFRESH: fetching current role state from IAM'
            )
            current_policies = fetcher.get_attached_policies(
                buf.account_id, buf.role_name
            )
            buf.policy_arns = set(current_policies)

        # Phase 4.1: Trust Policy 조회
        try:
            trust_policy = fetcher.get_trust_policy(buf.account_id, buf.role_name)
        except RuntimeError as e:
            logger.warning(
                f'[{request_id}] Trust policy fetch failed (proceeding without): {e}'
            )
            trust_policy = {}

        # Phase 4.3: 서비스 Role 감지 → 스킵
        if is_service_role(trust_policy):
            logger.info(
                f'[{request_id}] Skipping service role '
                f'(no AWS/Federated principal): {buf.role_name}'
            )
            return

        # Phase 4.2: 위험한 Trust Policy 차단
        if settings.block_wildcard_trust and has_dangerous_trust(trust_policy):
            raise RuntimeError(
                f'Dangerous trust policy detected for role {buf.role_name} '
                f'(wildcard principal). '
                'Set block_wildcard_trust=false to override.'
            )

        # Phase 1.5: Role 인라인 정책 조회 (PutRolePolicy / REFRESH)
        try:
            role_inline_policies = fetcher.get_inline_policies(
                buf.account_id, buf.role_name
            )
        except RuntimeError as e:
            logger.warning(
                f'[{request_id}] Inline policy fetch failed (proceeding without): {e}'
            )
            role_inline_policies = {}

        # Phase 2.2: 태그에서 대상 계정 파싱
        tags = fetcher.get_role_tags(buf.account_id, buf.role_name)
        target_account_ids = parse_target_accounts(
            tags,
            source_account_id=buf.account_id,
            tag_key=settings.iic_target_accounts_tag,
        )
        logger.info(
            f'[{request_id}] Target accounts: {target_account_ids}'
        )

        # Codegen: TF 워크스페이스 생성
        source_dir = write_workspace(
            buf=buf,
            output_base=self.output_base,
            fetcher=fetcher,
            inline_max_chars=settings.inline_policy_max_chars,
            target_account_ids=target_account_ids,
            role_inline_policies=role_inline_policies,
            skip_assignment=False,
        )
        logger.info(f'[{request_id}] Workspace written: {source_dir}')

        # Executor: 임시 작업 디렉터리로 복사 후 실행
        work_dir = prepare_work_dir(source_dir, self.work_base, request_id)
        try:
            self.runner.execute(
                work_dir=work_dir,
                state_key=self._state_key(buf),
                request_id=request_id,
            )
            logger.info(f'[{request_id}] === Pipeline succeeded ===')
        except Exception:
            raise
        finally:
            cleanup_work_dir(work_dir, request_id)

    async def _process_delete(
        self,
        buf: RoleBuffer,
        request_id: str,
    ) -> None:
        """Phase 1.4: DeleteRole → terraform destroy"""
        logger.info(
            f'[{request_id}] DELETE: destroying Permission Set '
            f'for role {buf.role_name}'
        )
        source_dir = write_destroy_workspace(buf, self.output_base)
        work_dir = prepare_work_dir(source_dir, self.work_base, request_id)
        try:
            self.runner.destroy(
                work_dir=work_dir,
                state_key=self._state_key(buf),
                request_id=request_id,
            )
            logger.info(f'[{request_id}] === Pipeline destroy succeeded ===')
        except Exception as e:
            logger.error(
                f'[{request_id}] === Pipeline destroy failed: '
                f'{type(e).__name__}: {e} ===',
                exc_info=True,
            )
        finally:
            cleanup_work_dir(work_dir, request_id)
