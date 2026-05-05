"""EventBridge 이벤트 → 정규화된 정보 추출"""
from typing import Optional


def extract_iic_user(arn: str) -> Optional[str]:
    if not arn:
        return None
    parts = arn.split('/')
    if len(parts) < 3:
        return None
    return parts[-1]


def extract_event_info(data: dict) -> dict:
    if data.get('source') != 'aws.iam':
        raise ValueError(f"Unexpected source: {data.get('source')}")

    detail = data.get('detail', {})
    event_name = detail.get('eventName')
    if event_name != 'AttachRolePolicy':
        raise ValueError(f"Unexpected eventName: {event_name}")

    req_params = detail.get('requestParameters', {})
    role_name = req_params.get('roleName')
    policy_arn = req_params.get('policyArn')
    if not role_name or not policy_arn:
        raise ValueError("Missing roleName or policyArn")

    account_id = detail.get('recipientAccountId') or detail.get('account')
    if not account_id:
        raise ValueError("Missing accountId")

    user_identity = detail.get('userIdentity', {})
    iic_user = extract_iic_user(user_identity.get('arn', ''))

    return {
        'account_id': account_id,
        'role_name': role_name,
        'policy_arn': policy_arn,
        'iic_user': iic_user,
        'event_id': data.get('id'),
        'event_time': data.get('time'),
    }
