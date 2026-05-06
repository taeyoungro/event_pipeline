"""EventBridge 이벤트 → 정규화된 정보 추출

지원 이벤트:
  AttachRolePolicy  → action='ATTACH'   (policy_arn 포함)
  DetachRolePolicy  → action='REFRESH'  (policy_arn 포함)
  PutRolePolicy     → action='REFRESH'  (policy_name 포함)
  DeleteRole        → action='DELETE'
"""
from typing import Optional

# Phase 1.3/1.4/1.5: 지원 이벤트 목록
SUPPORTED_EVENTS = {
    'AttachRolePolicy',
    'DetachRolePolicy',
    'PutRolePolicy',
    'DeleteRole',
}

# 이벤트명 → 버퍼 액션 매핑
_EVENT_TO_ACTION = {
    'AttachRolePolicy': 'ATTACH',
    'DetachRolePolicy': 'REFRESH',
    'PutRolePolicy':    'REFRESH',
    'DeleteRole':       'DELETE',
}


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
    if event_name not in SUPPORTED_EVENTS:
        raise ValueError(f"Unsupported eventName: {event_name}")

    req_params = detail.get('requestParameters', {})
    role_name = req_params.get('roleName')
    if not role_name:
        raise ValueError("Missing roleName")

    account_id = detail.get('recipientAccountId') or detail.get('account')
    if not account_id:
        raise ValueError("Missing accountId")

    user_identity = detail.get('userIdentity', {})
    iic_user = extract_iic_user(user_identity.get('arn', ''))

    result: dict = {
        'event_name': event_name,
        'action': _EVENT_TO_ACTION[event_name],
        'account_id': account_id,
        'role_name': role_name,
        'iic_user': iic_user,
        'event_id': data.get('id'),
        'event_time': data.get('time'),
    }

    if event_name in ('AttachRolePolicy', 'DetachRolePolicy'):
        policy_arn = req_params.get('policyArn')
        if not policy_arn:
            raise ValueError(f"Missing policyArn for {event_name}")
        result['policy_arn'] = policy_arn

    elif event_name == 'PutRolePolicy':
        policy_name = req_params.get('policyName')
        if not policy_name:
            raise ValueError("Missing policyName for PutRolePolicy")
        result['policy_name'] = policy_name

    # DeleteRole: roleName만으로 충분

    return result
