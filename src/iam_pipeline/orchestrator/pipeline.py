"""codegen 처리 완료 → executor 호출 흐름

Phase 1.3/1.4: BufferAction에 따라 ATTACH/REFRESH/DELETE 분기
Phase 2.2/2.3/2.5: iic-target-accounts 태그 파싱 → 다중 계정 Assignment
Phase 4.1/4.2/4.3: Trust Policy 분석 (서비스 Role 감지, 위험 패턴 차단)
Phase 5.1: 처리 실패 분류 (FailureCategory enum)
"""
import asyncio
import json
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
from ..codegen.policy_utils import has_dangerous_trust, is_aws_managed_policy, is_service_role
from ..codegen.tf_writer import write_destroy_workspace, write_workspace
from ..config import settings
from ..executor.runner import TerraformRunner
from ..executor.workspace import cleanup_work_dir, prepare_work_dir

logger = logging.getLogger(__name__)

_ACCOUNT_ID_RE = re.compile(r'^\d{12}$')


# ── 관리자 승인 리포트 헬퍼 ──────────────────────────────────────────────────

def _classify_policy_type(arn: str) -> str:
    """ARN으로부터 AWS Managed / Customer Managed / Inline 구분."""
    # arn:aws:iam::aws:policy/...        → AWS Managed
    # arn:aws:iam::<12-digit acct>:policy/... → Customer Managed
    if ':iam::aws:policy/' in arn:
        return 'AWS Managed'
    if re.search(r':iam::\d{12}:policy/', arn):
        return 'Customer Managed'
    return 'Unknown'


def _policy_name(arn: str) -> str:
    return arn.rsplit('/', 1)[-1] if '/' in arn else arn


_account_name_cache: dict[str, str] = {}


def _lookup_account_name(account_id: str) -> str:
    """Organizations DescribeAccount으로 계정 이름 조회. 실패/권한 부족 시 빈 문자열."""
    if account_id in _account_name_cache:
        return _account_name_cache[account_id]
    name = ''
    try:
        org = boto3.client('organizations')
        name = org.describe_account(AccountId=account_id)['Account'].get('Name', '')
    except ClientError as e:
        logger.warning(
            f'Organizations DescribeAccount({account_id}) failed: '
            f'{e.response["Error"].get("Code")}'
        )
    except Exception as e:
        logger.warning(f'Account name lookup failed for {account_id}: {e}')
    _account_name_cache[account_id] = name
    return name


def build_approval_report(
    iic_user: str,
    target_account_ids: list[str],
    policy_details: dict[str, dict],
) -> str:
    """관리자에게 보여줄 텍스트 리포트 생성.

    형식:
      요청자: <IIC user>
      대상 계정: <id1> / <name1>; <id2> / <name2>
      요청 권한1: <AWS Managed|Customer Managed>/<권한이름>/<필요 사유>
      요청 권한2: ...
    """
    lines: list[str] = []
    lines.append(f'요청자: {iic_user or "(unknown)"}')

    target_parts = []
    for acct in target_account_ids:
        name = _lookup_account_name(acct) or 'Unknown'
        target_parts.append(f'{acct} / {name}')
    lines.append(f'대상 계정: {"; ".join(target_parts) if target_parts else "(none)"}')

    for i, arn in enumerate(sorted(policy_details.keys()), start=1):
        info = policy_details[arn] or {}
        ptype = _classify_policy_type(arn)
        pname = _policy_name(arn)
        reason = (info.get('reason') or '').strip().replace('\n', ' ')
        lines.append(f'요청 권한{i}: {ptype}/{pname}/{reason}')

    return '\n'.join(lines) + '\n'


def save_approval_report(
    report: str,
    policy_details: dict[str, dict],
    dest_dir: Path,
    request_id: str,
) -> Path:
    """관리자용 리포트(.txt)와 구조화 데이터(.json)를 dest_dir에 저장."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    txt_path = dest_dir / f'{request_id}.txt'
    json_path = dest_dir / f'{request_id}.json'
    txt_path.write_text(report, encoding='utf-8')
    json_path.write_text(
        json.dumps(policy_details, ensure_ascii=False, indent=2),
        encoding='utf-8',
    )
    return txt_path


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
                account_id=settings.aws_account_id,
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

            # DetachRolePolicy(REFRESH): 파이프라인이 관리하는 Role인지 먼저 확인.
            # Role 삭제 시 AWS는 DetachRolePolicy → DeleteRole 순으로 이벤트를 발행하므로
            # REFRESH 이벤트가 먼저 처리될 수 있음. state 파일이 없으면 비관리 Role이므로 skip.
            if buf.action == BufferAction.REFRESH and not self._state_exists(buf, request_id):
                logger.info(
                    f'[{request_id}] REFRESH: state file not found for role={buf.role_name}'
                    ' — not managed by this pipeline, skipping.'
                )
                return

            # AttachRolePolicy(ATTACH): RAG + 관리자 승인 게이트 적용
            # DetachRolePolicy(REFRESH): 요청자 소유권 검증만, RAG/승인 생략
            skip_validation = (buf.action == BufferAction.REFRESH)
            await self._process_upsert(
                buf, fetcher, request_id, skip_validation=skip_validation
            )

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
        skip_validation: bool = False,
    ) -> None:
        """ATTACH / REFRESH → PS 생성·갱신

        skip_validation=True (REFRESH/DetachRolePolicy):
          RAG 검증과 관리자 승인 게이트를 생략하고, 대신 요청자가 해당
          PermissionSet에 실제로 assign된 USER인지만 확인 후 apply 실행.
        """

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

            if skip_validation:
                # REFRESH(DetachRolePolicy): 요청자 소유권만 확인하고 바로 apply.
                if not self._verify_requester_owns_ps(buf, request_id):
                    logger.error(
                        f'[{request_id}] === Pipeline aborted: requester '
                        f'{buf.requester_iic_user!r} is not assigned to PS '
                        f'(account={buf.account_id}, role={buf.role_name}) ==='
                    )
                    return
                logger.info(
                    f'[{request_id}] REFRESH path: ownership verified, '
                    f'skipping RAG validation and admin approval'
                )
            else:
                policy_details: dict[str, dict] = {}
                is_new_ps = not self._state_exists(buf, request_id)

                if is_new_ps:
                    # 신규 PS: 모든 Policy에 대해 RAG 최소권한 검증 수행
                    if self.rag_validator:
                        logger.info(
                            f'[{request_id}] New PS — validating least-privilege with Bedrock RAG '
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
                                self._handle_rag_rejection(
                                    validation_result,
                                    amp_arns={a for a in buf.policy_arns if is_aws_managed_policy(a)},
                                    request_id=request_id,
                                )

                            policy_details = validation_result.get("policies_validated", {})
                            logger.info(
                                f'[{request_id}] RAG validation result: '
                                f'{validation_result["reason"]}'
                            )
                        except RuntimeError as e:
                            logger.error(
                                f'[{request_id}] RAG validation error: {e}'
                            )
                            raise

                    # RAG 검증기가 없거나 응답에 정책 상세가 빠진 경우의 fallback
                    for arn in buf.policy_arns:
                        policy_details.setdefault(
                            arn,
                            {"is_necessary": True, "confidence": "n/a", "reason": "(RAG analysis unavailable)"},
                        )
                else:
                    # 기존 PS: AMP/CMP를 각각 diff하여 신규 추가분만 RAG 검증.
                    # AMP diff: IIC SSO list_managed_policies_in_permission_set
                    # CMP diff: output_base의 metadata.json (이전 apply 시 기록)
                    existing_amp_arns = await asyncio.to_thread(
                        self._get_ps_policy_arns, buf, request_id
                    )
                    existing_cmp_arns = self._get_previous_cmp_arns(buf)

                    new_amp_arns = {
                        a for a in buf.policy_arns if is_aws_managed_policy(a)
                    } - existing_amp_arns
                    new_cmp_arns = {
                        a for a in buf.policy_arns if not is_aws_managed_policy(a)
                    } - existing_cmp_arns
                    new_arns = new_amp_arns | new_cmp_arns

                    if new_arns and self.rag_validator:
                        # 신규 CMP는 문서 내용을 가져와 RAG에 함께 전달
                        new_cmp_docs: dict[str, dict] = {}
                        for arn in new_cmp_arns:
                            try:
                                doc = await asyncio.to_thread(
                                    fetcher.get_customer_policy_document,
                                    buf.account_id, arn,
                                )
                                new_cmp_docs[arn] = doc
                            except RuntimeError as e:
                                logger.warning(
                                    f'[{request_id}] CMP document fetch failed for '
                                    f'{arn}: {e} — will be treated as necessary'
                                )

                        logger.info(
                            f'[{request_id}] Existing PS — RAG validating '
                            f'{len(new_amp_arns)} new AMP(s), '
                            f'{len(new_cmp_arns)} new CMP(s)'
                        )
                        try:
                            validation_result = await self.rag_validator.validate_least_privilege(
                                account_id=buf.account_id,
                                role_name=buf.role_name,
                                iic_user=buf.requester_iic_user,
                                policy_arns=new_amp_arns,
                                inline_policy_docs=new_cmp_docs or None,
                                target_account_ids=target_account_ids,
                                terraform_plan=plan_output,
                            )
                            if not validation_result["approved"]:
                                self._handle_rag_rejection(
                                    validation_result,
                                    amp_arns=new_amp_arns,
                                    request_id=request_id,
                                )

                            policy_details = validation_result.get("policies_validated", {})
                            logger.info(
                                f'[{request_id}] RAG validation result: '
                                f'{validation_result["reason"]}'
                            )
                        except RuntimeError as e:
                            logger.error(
                                f'[{request_id}] RAG validation error: {e}'
                            )
                            raise
                    elif not new_arns:
                        logger.info(
                            f'[{request_id}] Existing PS — no new policies detected, skipping RAG'
                        )
                    else:
                        logger.info(
                            f'[{request_id}] Existing PS — RAG validator not configured, skipping RAG'
                        )

                    # 승인 리포트: 기존 Policy는 "(previously approved)", 신규는 RAG 결과 또는 fallback
                    for arn in buf.policy_arns:
                        if arn not in new_arns:
                            policy_details.setdefault(arn, {
                                "is_necessary": True,
                                "confidence": "n/a",
                                "reason": "(existing policy — previously approved)",
                            })
                        else:
                            policy_details.setdefault(arn, {
                                "is_necessary": True,
                                "confidence": "n/a",
                                "reason": "(new policy — RAG analysis unavailable)",
                            })

                # 관리자 승인 리포트: 사람이 읽기 좋은 텍스트 + 구조화 JSON 저장
                approval_report = build_approval_report(
                    iic_user=buf.requester_iic_user or '',
                    target_account_ids=target_account_ids,
                    policy_details=policy_details,
                )
                try:
                    saved_path = save_approval_report(
                        report=approval_report,
                        policy_details=policy_details,
                        dest_dir=settings.approval_report_dir,
                        request_id=request_id,
                    )
                    logger.info(f'[{request_id}] Approval report saved: {saved_path}')
                except OSError as e:
                    logger.warning(f'[{request_id}] Approval report save failed: {e}')

                # 관리자 최종 승인 게이트:
                # RAG 검증 통과 후, terraform plan 결과(실제 변경 내역)와 함께
                # 관리자가 Y/N으로 최종 승인해야 apply가 실행된다.
                approved = await self._prompt_admin_approval(
                    buf=buf,
                    target_account_ids=target_account_ids,
                    plan_output=plan_output,
                    request_id=request_id,
                    approval_report=approval_report,
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

    def _handle_rag_rejection(
        self,
        validation_result: dict,
        amp_arns: set[str],
        request_id: str,
    ) -> None:
        """RAG 거부 결과를 AMP/CMP 별로 처리.

        AMP가 confidence=high로 거부된 경우만 RuntimeError로 하드 거부.
        그 외(CMP 거부, low/n/a confidence, RAG 응답 파싱 실패 등)는 경고 로그만 남기고
        반환 → 호출부에서 관리자 승인 단계로 진행.
        """
        policies_validated = validation_result.get("policies_validated", {})
        amp_failures = [
            arn for arn, d in policies_validated.items()
            if (
                not d.get("is_necessary", True)
                and str(d.get("confidence", "")).lower() == "high"
                and arn in amp_arns
            )
        ]
        reason = validation_result["reason"]

        if amp_failures:
            logger.error(
                f'[{request_id}] RAG rejected AMP(s) with high confidence '
                f'{amp_failures}: {reason}'
            )
            raise RuntimeError(f'Least-privilege validation failed: {reason}')

        # CMP 거부 / 낮은 확신도 / 파싱 실패는 모두 관리자 승인으로 위임
        logger.warning(
            f'[{request_id}] RAG rejection delegated to admin approval '
            f'(no high-confidence AMP failures): {reason}'
        )

    async def _prompt_admin_approval(
        self,
        buf: RoleBuffer,
        target_account_ids: list[str],
        plan_output: str,
        request_id: str,
        approval_report: str = '',
    ) -> bool:
        """터미널에서 관리자에게 최종 승인(Y/N)을 받아 apply 여부를 결정한다.

        - 표시 정보: 요청자, 소스 계정, 대상 계정, Role, 정책 ARN 목록, terraform plan 요약
        - 'Y' 또는 'y'만 승인으로 간주, 그 외 입력 및 EOF/비대화형 stdin은 거부로 처리한다.
        - /dev/tty를 직접 열어 stdin이 닫혀있거나 uvicorn/systemd가 점유한 경우에도
          제어 터미널과 통신한다. /dev/tty가 없으면 거부.
        """
        plan_tail = plan_output[-3000:] if len(plan_output) > 3000 else plan_output

        banner = (
            '\n' + '=' * 70 + '\n'
            f'[ADMIN APPROVAL REQUIRED] request_id={request_id}\n'
            + '=' * 70 + '\n'
            + (approval_report + '-' * 70 + '\n' if approval_report else '')
            + f'  IAM Role             : {buf.role_name}\n'
            f'  Action               : {buf.action.value}\n'
            + '-' * 70 + '\n'
            '  Terraform plan (tail):\n'
            f'{plan_tail}\n'
            + '=' * 70 + '\n'
            'Apply this plan and create/update the IIC PermissionSet? [y/N]: '
        )

        logger.info(f'[{request_id}] Waiting for admin approval (/dev/tty)')

        def _ask() -> str:
            # /dev/tty는 stdin/stdout과 무관하게 제어 터미널에 직접 연결된다.
            # 'r+' text mode는 seekable 요구로 OSError가 나므로 읽기/쓰기 핸들을 분리.
            try:
                tty_out = open('/dev/tty', 'w')
                tty_in = open('/dev/tty', 'r')
            except OSError as e:
                logger.error(
                    f'[{request_id}] /dev/tty unavailable ({e}) — denying approval'
                )
                return ''
            try:
                tty_out.write(banner)
                tty_out.flush()
                return tty_in.readline()  # EOF 시 '' 반환
            finally:
                tty_in.close()
                tty_out.close()

        answer = (await asyncio.to_thread(_ask)).strip().lower()
        approved = answer == 'y'
        logger.info(
            f'[{request_id}] Admin approval result: '
            f'{"APPROVED" if approved else "DENIED"} (input={answer!r})'
        )
        return approved

    def _verify_requester_owns_ps(self, buf: RoleBuffer, request_id: str) -> bool:
        """buf.requester_iic_user가 해당 Role의 PermissionSet에 USER로 assign되어
        있는지 IIC SSO + Identity Store API로 확인한다.

        - PS 이름은 codegen과 동일하게 make_ps_name(account_id, role_name)으로 도출.
        - PS가 존재하지 않으면 False (관리 대상 아님).
        - 요청자가 비어 있으면 False.
        """
        from ..codegen.tf_writer import make_ps_name

        if not buf.requester_iic_user:
            logger.error(f'[{request_id}] Requester IIC user not identified')
            return False

        ps_name = make_ps_name(buf.account_id, buf.role_name)
        region = settings.aws_region

        try:
            sso = boto3.client('sso-admin', region_name=region)
            idstore = boto3.client('identitystore', region_name=region)

            instances = sso.list_instances().get('Instances', [])
            if not instances:
                logger.error(f'[{request_id}] No IIC instance found in {region}')
                return False
            instance_arn = instances[0]['InstanceArn']
            identity_store_id = instances[0]['IdentityStoreId']

            ps_arn: Optional[str] = None
            paginator = sso.get_paginator('list_permission_sets')
            for page in paginator.paginate(InstanceArn=instance_arn):
                for arn in page.get('PermissionSets', []):
                    desc = sso.describe_permission_set(
                        InstanceArn=instance_arn, PermissionSetArn=arn,
                    )
                    if desc['PermissionSet'].get('Name') == ps_name:
                        ps_arn = arn
                        break
                if ps_arn:
                    break

            if not ps_arn:
                logger.warning(
                    f'[{request_id}] PermissionSet {ps_name!r} not found in IIC'
                )
                return False

            assigned_accounts: list[str] = []
            p = sso.get_paginator('list_accounts_for_provisioned_permission_set')
            for page in p.paginate(
                InstanceArn=instance_arn, PermissionSetArn=ps_arn,
            ):
                assigned_accounts.extend(page.get('AccountIds', []))

            user_principal_ids: set[str] = set()
            for acct in assigned_accounts:
                p = sso.get_paginator('list_account_assignments')
                for page in p.paginate(
                    InstanceArn=instance_arn,
                    AccountId=acct,
                    PermissionSetArn=ps_arn,
                ):
                    for asg in page.get('AccountAssignments', []):
                        if asg.get('PrincipalType') == 'USER':
                            user_principal_ids.add(asg['PrincipalId'])

            for uid in user_principal_ids:
                try:
                    u = idstore.describe_user(
                        IdentityStoreId=identity_store_id, UserId=uid,
                    )
                    if u.get('UserName') == buf.requester_iic_user:
                        logger.info(
                            f'[{request_id}] Requester {buf.requester_iic_user!r} '
                            f'confirmed as USER assigned to PS {ps_name!r}'
                        )
                        return True
                except ClientError as e:
                    logger.warning(
                        f'[{request_id}] DescribeUser({uid}) failed: '
                        f'{e.response["Error"].get("Code")}'
                    )

            logger.warning(
                f'[{request_id}] Requester {buf.requester_iic_user!r} is not '
                f'among USER assignments of PS {ps_name!r} '
                f'(checked {len(user_principal_ids)} users across '
                f'{len(assigned_accounts)} accounts)'
            )
            return False

        except ClientError as e:
            logger.error(
                f'[{request_id}] IIC ownership check failed: '
                f'{e.response["Error"].get("Code")}: {e}'
            )
            return False
        except Exception as e:
            logger.error(
                f'[{request_id}] IIC ownership check unexpected error: '
                f'{type(e).__name__}: {e}',
                exc_info=True,
            )
            return False

    def _get_previous_cmp_arns(self, buf: RoleBuffer) -> set[str]:
        """이전 terraform apply 시 처리된 CMP ARN 목록을 metadata.json에서 반환.

        metadata.json은 write_workspace()가 output_base에 기록하며 apply 간 유지된다.
        파일이 없거나 파싱 실패 시 빈 set 반환 → 호출부에서 전체 CMP를 신규로 간주.
        """
        meta_path = self.output_base / buf.account_id / buf.role_name / 'metadata.json'
        try:
            meta = json.loads(meta_path.read_text(encoding='utf-8'))
            return set(meta.get('customer_managed_policies', []))
        except (FileNotFoundError, json.JSONDecodeError):
            return set()

    def _get_ps_policy_arns(self, buf: RoleBuffer, request_id: str) -> set[str]:
        """IIC SSO에서 기존 PS에 현재 연결된 Managed Policy ARN 목록을 반환.

        PS 또는 API 조회 실패 시 빈 set 반환 → 호출부에서 전체 policy_arns를 신규로 간주.
        """
        from ..codegen.tf_writer import make_ps_name

        ps_name = make_ps_name(buf.account_id, buf.role_name)
        region = settings.aws_region

        try:
            sso = boto3.client('sso-admin', region_name=region)

            instances = sso.list_instances().get('Instances', [])
            if not instances:
                logger.warning(
                    f'[{request_id}] No IIC instance found — treating all policies as new'
                )
                return set()
            instance_arn = instances[0]['InstanceArn']

            ps_arn: Optional[str] = None
            paginator = sso.get_paginator('list_permission_sets')
            for page in paginator.paginate(InstanceArn=instance_arn):
                for arn in page.get('PermissionSets', []):
                    desc = sso.describe_permission_set(
                        InstanceArn=instance_arn, PermissionSetArn=arn,
                    )
                    if desc['PermissionSet'].get('Name') == ps_name:
                        ps_arn = arn
                        break
                if ps_arn:
                    break

            if not ps_arn:
                logger.warning(
                    f'[{request_id}] PS {ps_name!r} not found in IIC '
                    f'— treating all policies as new'
                )
                return set()

            existing_arns: set[str] = set()
            p = sso.get_paginator('list_managed_policies_in_permission_set')
            for page in p.paginate(InstanceArn=instance_arn, PermissionSetArn=ps_arn):
                for policy in page.get('AttachedManagedPolicies', []):
                    existing_arns.add(policy['Arn'])

            logger.info(
                f'[{request_id}] PS {ps_name!r}: {len(existing_arns)} existing policies'
            )
            return existing_arns

        except ClientError as e:
            logger.warning(
                f'[{request_id}] Failed to fetch PS policies '
                f'(treating all as new): {e}'
            )
            return set()

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

        # DeleteRole 이벤트 발화자가 해당 PS에 실제로 assign된 USER인지 확인.
        # 다른 사용자가 무관한 Role을 지워 PS가 파괴되는 사고를 차단한다.
        if not self._verify_requester_owns_ps(buf, request_id):
            logger.error(
                f'[{request_id}] === Pipeline aborted: requester '
                f'{buf.requester_iic_user!r} is not assigned to PS '
                f'(account={buf.account_id}, role={buf.role_name}) ==='
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
