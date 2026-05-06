"""RoleBuffer → Terraform 코드 → 로컬 디스크

주요 변경 (Phase 3.1~3.3):
  - PS 이름: {account_id}-{role_name} 형식, 32자 IIC 제약 검증
  - role_inline_policies: PutRolePolicy로 부착된 Role 인라인 정책 포함
  - target_account_ids: 다중 계정 Account Assignment (Phase 2.3)
  - skip_assignment: 서비스 Role에 대해 Assignment 생략 (Phase 4.3)
"""
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .buffer import RoleBuffer
from .policy_fetcher import PolicyFetcher
from .policy_utils import is_aws_managed_policy, policy_arn_to_name

logger = logging.getLogger(__name__)

# IIC Permission Set 이름 허용 문자 + 최대 길이 (Phase 3.3)
_IIC_PS_NAME_RE = re.compile(r'^[a-zA-Z0-9+=,.@_/\-]{1,32}$')
_PS_NAME_PREFIX_LEN = 13   # "{12자리 account_id}-" = 13자


PROVIDERS_TF = """terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {}
}

provider "aws" {
  region = "us-east-1"
}
"""

DATA_TF = """data "aws_ssoadmin_instances" "current" {}
"""


# ── 이름 유틸리티 ─────────────────────────────────────────────────────────────

def sanitize_resource_name(name: str) -> str:
    """Terraform 리소스 식별자용 (소문자, 영숫자+밑줄만)."""
    return re.sub(r'[^a-zA-Z0-9_]', '_', name).lower()


def make_ps_name(account_id: str, role_name: str) -> str:
    """
    Phase 3.1/3.2: IIC Permission Set 이름 생성.
    형식: {account_id}-{role_name}, 최대 32자 truncation.
    """
    max_role_chars = 32 - _PS_NAME_PREFIX_LEN   # = 19
    return f"{account_id}-{role_name[:max_role_chars]}"


def validate_ps_name(name: str) -> None:
    """Phase 3.3: IIC PS 이름 제약 검증 (32자, 허용 문자)."""
    if not _IIC_PS_NAME_RE.match(name):
        raise ValueError(
            f"PS 이름 '{name}'이 IIC 제약을 위반합니다 "
            f"(최대 32자, 허용 문자: [a-zA-Z0-9+=,.@_/-])"
        )


# ── Policy 처리 유틸리티 ──────────────────────────────────────────────────────

def merge_inline_policies(
    customer_documents: list[tuple[str, dict]],
    role_inline_docs: dict[str, dict],
) -> Optional[dict]:
    """
    Customer Managed Policy 본문 + Role 인라인 정책을 하나로 통합.

    IIC Permission Set은 Sid를 지원하지 않으므로 모든 Sid를 제거한다.
    통합할 문서가 없으면 None 반환.
    """
    merged_statements: list[dict] = []

    for _name, doc in customer_documents:
        for stmt in _iter_statements(doc):
            merged_statements.append({k: v for k, v in stmt.items() if k != 'Sid'})

    for _name, doc in role_inline_docs.items():
        for stmt in _iter_statements(doc):
            merged_statements.append({k: v for k, v in stmt.items() if k != 'Sid'})

    if not merged_statements:
        return None

    return {'Version': '2012-10-17', 'Statement': merged_statements}


def _iter_statements(doc: dict):
    stmts = doc.get('Statement', [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    yield from stmts


# ── Terraform 코드 생성 ────────────────────────────────────────────────────────

def generate_main_tf(
    buf: RoleBuffer,
    fetcher: PolicyFetcher,
    inline_max_chars: int,
    target_account_ids: Optional[list[str]] = None,
    role_inline_policies: Optional[dict[str, dict]] = None,
    skip_assignment: bool = False,
) -> str:
    """
    RoleBuffer → main.tf 콘텐츠.

    target_account_ids: None이면 buf.target_account_id 단일 계정.
    role_inline_policies: PutRolePolicy로 추가된 Role 인라인 정책 문서 {name: doc}.
    skip_assignment: True면 서비스 Role → User/Account Assignment 블록 생략.
    """
    if target_account_ids is None:
        target_account_ids = [buf.target_account_id] if buf.target_account_id else []
    if role_inline_policies is None:
        role_inline_policies = {}

    # Phase 3.1/3.2: PS 이름 결정
    ps_name = make_ps_name(buf.account_id, buf.role_name)
    validate_ps_name(ps_name)

    resource_name = sanitize_resource_name(ps_name)
    description = (
        f"Auto-generated from IAM Role '{buf.role_name}' "
        f"in account {buf.account_id}"
    )
    generated_at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    sorted_policies = sorted(buf.policy_arns)

    # AWS Managed와 Customer Managed 분리
    aws_managed = [p for p in sorted_policies if is_aws_managed_policy(p)]
    customer_managed = [p for p in sorted_policies if not is_aws_managed_policy(p)]

    # Customer Managed 본문 조회
    customer_documents: list[tuple[str, dict]] = []
    if customer_managed:
        logger.info(
            f'Fetching {len(customer_managed)} customer managed policies '
            f'from account {buf.account_id}'
        )
        for policy_arn in customer_managed:
            doc = fetcher.get_customer_policy_document(buf.account_id, policy_arn)
            customer_documents.append((policy_arn_to_name(policy_arn), doc))

    # 인라인 정책 통합 (Customer Managed + Role 인라인)
    inline_doc = merge_inline_policies(customer_documents, role_inline_policies)
    if inline_doc is not None:
        inline_json = json.dumps(inline_doc, indent=2)
        if len(inline_json) > inline_max_chars:
            raise RuntimeError(
                f'Merged inline policy size ({len(inline_json)} chars) '
                f'exceeds limit ({inline_max_chars}). '
                f'Reduce customer managed policies or split Permission Set.'
            )

    # Terraform 코드 조립
    parts = [
        f"# Auto-generated by IAM Pipeline at {generated_at}",
        f"# Source IAM Role: arn:aws:iam::{buf.account_id}:role/{buf.role_name}",
        f"# PS Name: {ps_name}",
        f"# Requester IIC User: {buf.requester_iic_user}",
        f"# AWS Managed: {len(aws_managed)}, "
        f"Customer Managed (inline): {len(customer_managed)}, "
        f"Role Inline: {len(role_inline_policies)}",
        "",
        f'resource "aws_ssoadmin_permission_set" "{resource_name}" {{',
        f'  name             = "{ps_name}"',
        f'  description      = "{description}"',
        f'  instance_arn     = tolist(data.aws_ssoadmin_instances.current.arns)[0]',
        f'  session_duration = "PT8H"',
        f'}}',
        "",
    ]

    # AWS Managed Policy 부착
    attachment_deps: list[str] = []
    for policy_arn in aws_managed:
        policy_name = policy_arn_to_name(policy_arn)
        attach_res = f"{resource_name}_attach_{sanitize_resource_name(policy_name)}"
        attachment_deps.append(
            f'    aws_ssoadmin_managed_policy_attachment.{attach_res}'
        )
        parts += [
            f'resource "aws_ssoadmin_managed_policy_attachment" "{attach_res}" {{',
            f'  instance_arn       = aws_ssoadmin_permission_set.{resource_name}.instance_arn',
            f'  permission_set_arn = aws_ssoadmin_permission_set.{resource_name}.arn',
            f'  managed_policy_arn = "{policy_arn}"',
            f'}}',
            "",
        ]

    # 통합 인라인 정책
    if inline_doc is not None:
        inline_res = f"{resource_name}_inline"
        attachment_deps.append(
            f'    aws_ssoadmin_permission_set_inline_policy.{inline_res}'
        )
        inline_json_indented = json.dumps(inline_doc, indent=2)
        parts += [
            f'resource "aws_ssoadmin_permission_set_inline_policy" "{inline_res}" {{',
            f'  instance_arn       = aws_ssoadmin_permission_set.{resource_name}.instance_arn',
            f'  permission_set_arn = aws_ssoadmin_permission_set.{resource_name}.arn',
            f'  inline_policy = <<-EOT',
            inline_json_indented,
            f'EOT',
            f'}}',
            "",
        ]

    # Phase 2.3: User data + 다중 계정 Account Assignment
    if buf.requester_iic_user and not skip_assignment and target_account_ids:
        depends_block = ',\n'.join(attachment_deps) if attachment_deps else ''

        parts += [
            f'data "aws_identitystore_user" "{resource_name}_user" {{',
            f'  identity_store_id = tolist(data.aws_ssoadmin_instances.current.identity_store_ids)[0]',
            f'  alternate_identifier {{',
            f'    unique_attribute {{',
            f'      attribute_path  = "UserName"',
            f'      attribute_value = "{buf.requester_iic_user}"',
            f'    }}',
            f'  }}',
            f'}}',
            "",
        ]

        for target_account_id in sorted(set(target_account_ids)):
            safe_acct = sanitize_resource_name(target_account_id)
            assign_res = f"{resource_name}_assign_{safe_acct}"
            parts += [
                f'resource "aws_ssoadmin_account_assignment" "{assign_res}" {{',
                f'  instance_arn       = aws_ssoadmin_permission_set.{resource_name}.instance_arn',
                f'  permission_set_arn = aws_ssoadmin_permission_set.{resource_name}.arn',
                f'  target_id          = "{target_account_id}"',
                f'  target_type        = "AWS_ACCOUNT"',
                f'  principal_id       = data.aws_identitystore_user.{resource_name}_user.user_id',
                f'  principal_type     = "USER"',
            ]
            if depends_block:
                parts += [
                    f'  depends_on = [',
                    depends_block,
                    f'  ]',
                ]
            parts += [f'}}', ""]

    return '\n'.join(parts)


def write_workspace(
    buf: RoleBuffer,
    output_base: Path,
    fetcher: PolicyFetcher,
    inline_max_chars: int,
    target_account_ids: Optional[list[str]] = None,
    role_inline_policies: Optional[dict[str, dict]] = None,
    skip_assignment: bool = False,
) -> Path:
    """RoleBuffer를 디스크에 워크스페이스로 저장. 저장된 디렉터리 반환."""
    out_dir = output_base / buf.account_id / buf.role_name
    out_dir.mkdir(parents=True, exist_ok=True)

    main_tf = generate_main_tf(
        buf,
        fetcher,
        inline_max_chars,
        target_account_ids=target_account_ids,
        role_inline_policies=role_inline_policies,
        skip_assignment=skip_assignment,
    )

    files = {
        'providers.tf': PROVIDERS_TF,
        'data.tf': DATA_TF,
        'main.tf': main_tf,
    }
    for name, content in files.items():
        (out_dir / name).write_text(content, encoding='utf-8')
        logger.info(f"Saved: {out_dir / name}")

    ps_name = make_ps_name(buf.account_id, buf.role_name)
    meta = {
        'account_id': buf.account_id,
        'role_name': buf.role_name,
        'ps_name': ps_name,
        'requester_iic_user': buf.requester_iic_user,
        'target_account_ids': sorted(set(target_account_ids)) if target_account_ids else [],
        'aws_managed_policies': sorted(
            p for p in buf.policy_arns if is_aws_managed_policy(p)
        ),
        'customer_managed_policies': sorted(
            p for p in buf.policy_arns if not is_aws_managed_policy(p)
        ),
        'role_inline_policy_names': sorted((role_inline_policies or {}).keys()),
        'first_event_at': buf.first_event_at.isoformat() if buf.first_event_at else None,
        'last_event_at': buf.last_event_at.isoformat() if buf.last_event_at else None,
        'processed_at': datetime.now(timezone.utc).isoformat(),
    }
    (out_dir / 'metadata.json').write_text(
        json.dumps(meta, indent=2, ensure_ascii=False), encoding='utf-8'
    )
    return out_dir


def write_destroy_workspace(buf: RoleBuffer, output_base: Path) -> Path:
    """Phase 1.4: DeleteRole 처리용 최소 워크스페이스 (terraform destroy 전용)."""
    out_dir = output_base / buf.account_id / buf.role_name
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'providers.tf').write_text(PROVIDERS_TF, encoding='utf-8')
    (out_dir / 'main.tf').write_text('# Destroy mode — no resources\n', encoding='utf-8')
    logger.info(f"Destroy workspace written: {out_dir}")
    return out_dir
