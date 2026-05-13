"""codegen 처리 완료 → executor 호출 흐름

Phase 1.3/1.4: BufferAction에 따라 ATTACH/REFRESH/DELETE 분기
Phase 2.2/2.3/2.5: iic-target-accounts 태그 파싱 → 다중 계정 Assignment
Phase 4.1/4.2/4.3: Trust Policy 분석 (서비스 Role 감지, 위험 패턴 차단)
Phase 5.1: 처리 실패 분류 (FailureCategory enum)
"""
import asyncio
import logging
import re
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from ..bedrock.rag_validator import BedrockRAGValidator
from ..codegen.buffer import BufferAction, RoleBuffer
from ..codegen.policy_fetcher import PolicyFetcher
from ..codegen.policy_utils import has_dangerous_trust, is_service_role
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
        self.rag_validator = (
            BedrockRAGValidator(
                knowledge_base_id=settings.bedrock_knowledge_base_id,
                model_id=settings.bedrock_model_id,
                region=settings.bedrock_region,
            )
            if settings.bedrock_enable_rag_validation
            and settings.bedrock_knowledge_base_id
            else None
        )

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

        # 액션과 무관하게 항상 IAM 현재 상태로 policy_arns 교체.
        # 버퍼 누적값은 현재 debounce 윈도우 내 이벤트만 포함하므로,
        # 이전 윈도우에서 부착된 Policy가 누락 → Inline Policy 삭제로 이어지는 문제를 방지.
        logger.info(
            f'[{request_id}] Fetching current attached policies from IAM '
            f'(action={buf.action.value})'
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
        # trust_policy가 비어있으면(조회 실패) 검사 생략 — 빈 dict를 서비스 Role로 오판하지 않도록
        if trust_policy and is_service_role(trust_policy):
            logger.info(
                f'[{request_id}] Skipping service role '
                f'(no AWS/Federated principal): {buf.role_name}'
            )
            return

        # Phase 4.2: 위험한 Trust Policy 차단
        if trust_policy and settings.block_wildcard_trust and has_dangerous_trust(trust_policy):
            raise RuntimeError(
                f'Dangerous trust policy detected for role {buf.role_name} '
                f'(wildcard principal). '
                'Set block_wildcard_trust=false to override.'
            )

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

        # IIC 사용자 검증 — ARN 기반 판단 (AWSReservedSSO_ 역할 세션이 아니면 None)
        if not buf.requester_iic_user:
            logger.error(
                f'[{request_id}] === Pipeline skipped: '
                f'IIC user not identified (not an AWSReservedSSO_ session) ==='
            )
            return

        # Codegen: TF 워크스페이스 생성
        source_dir = write_workspace(
            buf=buf,
            output_base=self.output_base,
            fetcher=fetcher,
            inline_max_chars=settings.inline_policy_max_chars,
            target_account_ids=target_account_ids,
        )
        logger.info(f'[{request_id}] Workspace written: {source_dir}')

        # Executor: 임시 작업 디렉터리로 복사
        work_dir = prepare_work_dir(source_dir, self.work_base, request_id)
        try:
            # Phase 5.2: Terraform Plan 생성 후 RAG 검증
            logger.info(
                f'[{request_id}] Executing terraform plan for validation'
            )
            plan_output = self.runner.plan_and_read(
                work_dir=work_dir,
                state_key=self._state_key(buf),
                request_id=request_id,
            )

            if self.rag_validator:
                logger.info(
                    f'[{request_id}] Validating least-privilege with Bedrock RAG '
                    f'(user={buf.requester_iic_user}, account={buf.account_id})'
                )
                try:
                    validation_result = await self.rag_validator.validate_least_privilege(
                        account_id=buf.account_id,
                        role_name=buf.role_name,
                        iic_user=buf.requester_iic_user,
                        policy_arns=buf.policy_arns,
                        target_account_ids=target_account_ids,
                        terraform_plan=plan_output,
                    )

                    if not validation_result["approved"]:
                        reason = validation_result["reason"]
                        logger.error(
                            f'[{request_id}] RAG validation failed: {reason}'
                        )
                        if validation_result["requires_approval"]:
                            await self._request_admin_approval(
                                buf, request_id, reason, validation_result
                            )
                        raise RuntimeError(
                            f'Least-privilege validation failed: {reason}'
                        )

                    logger.info(
                        f'[{request_id}] RAG validation succeeded: '
                        f'{validation_result["reason"]}'
                    )
                except RuntimeError as e:
                    logger.error(
                        f'[{request_id}] RAG validation error: {e}'
                    )
                    raise

            # 관리자 최종 승인 게이트:
            # RAG 검증 통과 후, terraform plan 결과(실제 변경 내역)와 함께
            # 관리자가 Y/N으로 최종 승인해야 apply가 실행된다.
            approved = await self._prompt_admin_approval(
                buf=buf,
                target_account_ids=target_account_ids,
                plan_output=plan_output,
                request_id=request_id,
            )
            if not approved:
                logger.warning(
                    f'[{request_id}] === Pipeline aborted by admin '
                    f'(role={buf.role_name}, account={buf.account_id}) ==='
                )
                return

            # 검증 통과 시 apply 실행
            logger.info(f'[{request_id}] Applying terraform plan')
            self.runner.apply_plan(
                work_dir=work_dir,
                request_id=request_id,
            )
            logger.info(f'[{request_id}] === Pipeline succeeded ===')
        except Exception:
            raise
        finally:
            cleanup_work_dir(work_dir, request_id)

    async def _prompt_admin_approval(
        self,
        buf: RoleBuffer,
        target_account_ids: list[str],
        plan_output: str,
        request_id: str,
    ) -> bool:
        """터미널에서 관리자에게 최종 승인(Y/N)을 받아 apply 여부를 결정한다.

        - 표시 정보: 요청자, 소스 계정, 대상 계정, Role, 정책 ARN 목록, terraform plan 요약
        - 'Y' 또는 'y'만 승인으로 간주, 그 외 입력 및 EOF/비대화형 stdin은 거부로 처리한다.
        - input()은 블로킹이므로 asyncio.to_thread로 실행해 이벤트 루프를 점유하지 않는다.
        """
        plan_tail = plan_output[-3000:] if len(plan_output) > 3000 else plan_output

        banner = (
            '\n' + '=' * 70 + '\n'
            f'[ADMIN APPROVAL REQUIRED] request_id={request_id}\n'
            + '=' * 70 + '\n'
            f'  Requester (IIC user) : {buf.requester_iic_user}\n'
            f'  Source account       : {buf.account_id}\n'
            f'  Target accounts      : {", ".join(target_account_ids)}\n'
            f'  IAM Role             : {buf.role_name}\n'
            f'  Action               : {buf.action.value}\n'
            f'  Policy ARNs ({len(buf.policy_arns)}):\n'
            + ''.join(f'    - {arn}\n' for arn in sorted(buf.policy_arns))
            + '-' * 70 + '\n'
            '  Terraform plan (tail):\n'
            f'{plan_tail}\n'
            + '=' * 70 + '\n'
            'Apply this plan and create/update the IIC PermissionSet? [y/N]: '
        )

        logger.info(f'[{request_id}] Waiting for admin approval (terminal)')

        if not sys.stdin or not sys.stdin.isatty():
            logger.error(
                f'[{request_id}] Admin approval required but stdin is not a TTY — denying'
            )
            return False

        def _ask() -> str:
            try:
                return input(banner)
            except EOFError:
                return ''

        answer = (await asyncio.to_thread(_ask)).strip().lower()
        approved = answer == 'y'
        logger.info(
            f'[{request_id}] Admin approval result: '
            f'{"APPROVED" if approved else "DENIED"} (input={answer!r})'
        )
        return approved

    def _state_exists(self, buf: RoleBuffer, request_id: str) -> bool:
        """
        S3 Terraform state 파일 존재 여부로 파이프라인 관리 대상 확인 (1회 API 호출).
        API 오류 시 fail-open(True)으로 처리하여 terraform destroy를 시도한다.
        """
        state_key = self._state_key(buf)
        try:
            s3 = boto3.client('s3', region_name=settings.tf_state_region)
            s3.head_object(Bucket=settings.tf_state_bucket, Key=state_key)
            logger.info(f'[{request_id}] State file found: {state_key}')
            return True
        except ClientError as e:
            code = e.response['Error']['Code']
            if code in ('404', 'NoSuchKey'):
                logger.info(
                    f'[{request_id}] State file not found: {state_key}'
                )
                return False
            logger.warning(
                f'[{request_id}] State file check failed (fail-open): {e}'
            )
            return True

    async def _process_delete(
        self,
        buf: RoleBuffer,
        request_id: str,
    ) -> None:
        """Phase 1.4: DeleteRole → S3 state 파일 확인 후 terraform destroy"""
        state_key = self._state_key(buf)
        logger.info(
            f'[{request_id}] DELETE: checking state file for '
            f'role={buf.role_name} → key={state_key}'
        )

        if not self._state_exists(buf, request_id):
            logger.info(
                f'[{request_id}] === Pipeline skipped '
                f'(no state file: {state_key}) ==='
            )
            return

        logger.info(
            f'[{request_id}] DELETE: destroying PermissionSet for role {buf.role_name}'
        )
        source_dir = write_destroy_workspace(buf, self.output_base)
        work_dir = prepare_work_dir(source_dir, self.work_base, request_id)
        try:
            self.runner.destroy(
                work_dir=work_dir,
                state_key=state_key,
                request_id=request_id,
            )
            logger.info(f'[{request_id}] === Pipeline destroy succeeded ===')
            self._delete_state_file(state_key, request_id)
        except Exception as e:
            logger.error(
                f'[{request_id}] === Pipeline destroy failed: '
                f'{type(e).__name__}: {e} ===',
                exc_info=True,
            )
        finally:
            cleanup_work_dir(work_dir, request_id)

    def _delete_state_file(self, state_key: str, request_id: str) -> None:
        """terraform destroy 성공 후 S3 state 파일 제거."""
        try:
            s3 = boto3.client('s3', region_name=settings.tf_state_region)
            s3.delete_object(Bucket=settings.tf_state_bucket, Key=state_key)
            logger.info(f'[{request_id}] State file deleted: {state_key}')
        except ClientError as e:
            logger.warning(
                f'[{request_id}] State file deletion failed (non-critical): {e}'
            )
