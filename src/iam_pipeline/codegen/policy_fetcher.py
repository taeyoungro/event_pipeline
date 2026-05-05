"""크로스 계정 IAM Policy 본문 조회"""
import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class PolicyFetcher:
    """
    멤버 계정의 AuditRole을 어슘하여 Customer Managed Policy 본문 조회.
    
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
        # account_id → boto3.Session
        self._sessions: dict[str, boto3.Session] = {}

    def _assume(self, account_id: str) -> boto3.Session:
        """이 인스턴스 생애 동안 같은 account_id에 한 번만 어슘"""
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

    def get_customer_policy_document(
        self, account_id: str, policy_arn: str
    ) -> dict:
        """
        Customer Managed Policy의 default version 본문을 dict로 반환.
        실패 시 RuntimeError.
        """
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
            # boto3는 Document를 이미 dict로 디코딩해서 반환
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

    def close(self) -> None:
        """자격증명 세션 폐기 (참조 제거)"""
        self._sessions.clear()
