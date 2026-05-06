"""크로스 계정 IAM Role/Policy 상태 조회"""
import json
import logging
import urllib.parse
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class PolicyFetcher:
    """
    멤버 계정의 AuditRole을 가정하여 IAM Role 전체 상태 조회.

    인스턴스는 buffer 처리 1회당 생성/폐기 권장 (자격증명을 길게 보유하지 않기 위함).
    """

    def __init__(
        self,
        audit_role_name: str,
        session_name: str,
        duration_seconds: int = 900,
    ):
        self.audit_role_name = audit_role_name
        self.session_name = session_name
        self.duration_seconds = duration_seconds
        self._sts = boto3.client('sts')
        self._sessions: dict[str, boto3.Session] = {}

    def _assume(self, account_id: str) -> boto3.Session:
        if account_id in self._sessions:
            return self._sessions[account_id]

        role_arn = f'arn:aws:iam::{account_id}:role/{self.audit_role_name}'
        logger.info(f'Assuming role: {role_arn}')

        try:
            resp = self._sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=self.session_name,
                DurationSeconds=self.duration_seconds,
            )
        except ClientError as e:
            raise RuntimeError(
                f'AssumeRole failed for account {account_id} '
                f'(role: {self.audit_role_name}): {e}'
            ) from e

        creds = resp['Credentials']
        session = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
        )
        self._sessions[account_id] = session
        return session

    # ── 기존: Customer Managed Policy 본문 조회 ─────────────────────────────

    def get_customer_policy_document(
        self, account_id: str, policy_arn: str
    ) -> dict:
        """Customer Managed Policy의 default version 본문을 dict로 반환."""
        session = self._assume(account_id)
        iam = session.client('iam')

        try:
            policy = iam.get_policy(PolicyArn=policy_arn)
            default_version_id = policy['Policy']['DefaultVersionId']

            version = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id,
            )
            document = version['PolicyVersion']['Document']
            logger.info(
                f'Fetched policy document: {policy_arn} '
                f'(version {default_version_id})'
            )
            return document

        except ClientError as e:
            raise RuntimeError(
                f'Failed to fetch policy document for {policy_arn} '
                f'in account {account_id}: {e}'
            ) from e

    # ── Phase 1.3/1.4/1.5: Role 상태 전체 조회 ──────────────────────────────

    def get_attached_policies(self, account_id: str, role_name: str) -> list[str]:
        """역할에 부착된 모든 관리형 정책 ARN 목록 반환 (페이지네이션 처리)."""
        session = self._assume(account_id)
        iam = session.client('iam')
        arns: list[str] = []
        try:
            paginator = iam.get_paginator('list_attached_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                for p in page['AttachedPolicies']:
                    arns.append(p['PolicyArn'])
            logger.info(
                f'Role {role_name} in {account_id}: {len(arns)} attached policies'
            )
        except ClientError as e:
            raise RuntimeError(
                f'Failed to list attached policies for role {role_name} '
                f'in account {account_id}: {e}'
            ) from e
        return arns

    def get_inline_policies(
        self, account_id: str, role_name: str
    ) -> dict[str, dict]:
        """역할의 인라인 정책 이름 → 문서 매핑 반환."""
        session = self._assume(account_id)
        iam = session.client('iam')
        result: dict[str, dict] = {}
        try:
            paginator = iam.get_paginator('list_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                for name in page['PolicyNames']:
                    resp = iam.get_role_policy(RoleName=role_name, PolicyName=name)
                    doc = resp['PolicyDocument']
                    if isinstance(doc, str):
                        doc = json.loads(urllib.parse.unquote(doc))
                    result[name] = doc
            logger.info(
                f'Role {role_name} in {account_id}: {len(result)} inline policies'
            )
        except ClientError as e:
            raise RuntimeError(
                f'Failed to list inline policies for role {role_name} '
                f'in account {account_id}: {e}'
            ) from e
        return result

    def get_role_tags(self, account_id: str, role_name: str) -> dict[str, str]:
        """역할 태그 key→value 딕셔너리 반환. 실패 시 빈 딕셔너리."""
        session = self._assume(account_id)
        iam = session.client('iam')
        try:
            resp = iam.list_role_tags(RoleName=role_name)
            return {t['Key']: t['Value'] for t in resp.get('Tags', [])}
        except ClientError as e:
            logger.warning(
                f'Failed to fetch tags for role {role_name} '
                f'in account {account_id}: {e}'
            )
            return {}

    def get_trust_policy(self, account_id: str, role_name: str) -> dict:
        """역할의 Trust Policy(AssumeRolePolicyDocument) 문서 반환."""
        session = self._assume(account_id)
        iam = session.client('iam')
        try:
            resp = iam.get_role(RoleName=role_name)
            doc = resp['Role']['AssumeRolePolicyDocument']
            if isinstance(doc, str):
                doc = json.loads(urllib.parse.unquote(doc))
            return doc
        except ClientError as e:
            raise RuntimeError(
                f'Failed to fetch trust policy for role {role_name} '
                f'in account {account_id}: {e}'
            ) from e

    def close(self) -> None:
        """자격증명 세션 폐기 (참조 제거)."""
        self._sessions.clear()
