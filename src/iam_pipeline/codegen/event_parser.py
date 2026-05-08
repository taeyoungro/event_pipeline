"""EventBridge 이벤트 → 정규화된 정보 추출

지원 이벤트:
  AttachRolePolicy  → action='ATTACH'   (policy_arn 포함)
  DetachRolePolicy  → action='REFRESH'  (policy_arn 포함)
  DeleteRole        → action='DELETE'
"""
from typing import Optional

# 지원 이벤트 목록 — Inline Policy(PutRolePolicy)는 PermissionSet에 반영하지 않음
SUPPORTED_EVENTS = {
    'AttachRolePolicy',
    'DetachRolePolicy',
    'DeleteRole',
}

# IIC/AWS가 자동 생성하는 시스템 Role — 파이프라인 처리 제외
_SKIP_ROLE_PREFIXES = (
    'AWSReservedSSO_',      # IIC Permission Set 할당 시 자동 생성
    'AWSServiceRoleFor',    # AWS 서비스 연결 역할
    'aws-reserved/',        # AWS 예약 경로 역할
)

# 이벤트명 → 버퍼 액션 매핑
_EVENT_TO_ACTION = {
    'AttachRolePolicy': 'ATTACH',
    'DetachRolePolicy': 'REFRESH',
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

    if any(role_name.startswith(prefix) for prefix in _SKIP_ROLE_PREFIXES):
        raise ValueError(f"Skipping system/reserved role: {role_name}")

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

    # DeleteRole: roleName만으로 충분

    return result
