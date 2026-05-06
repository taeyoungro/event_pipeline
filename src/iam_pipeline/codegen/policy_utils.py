"""Policy ARN 분석 + Trust Policy 분석 유틸"""


def is_aws_managed_policy(policy_arn: str) -> bool:
    return policy_arn.startswith('arn:aws:iam::aws:policy/')


def policy_arn_to_name(policy_arn: str) -> str:
    return policy_arn.rsplit('/', 1)[-1]


def is_service_role(trust_policy: dict) -> bool:
    """
    Trust Policy에 AWS/Federated Principal이 전혀 없으면 서비스 전용 Role.
    빈 trust_policy({})가 전달되면 False(판단 불가 → 서비스 Role 아님으로 처리).
    """
    statements = trust_policy.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]
    if not statements:
        return False
    for stmt in statements:
        principal = stmt.get('Principal', {})
        if isinstance(principal, str):
            return False
        if isinstance(principal, dict):
            if 'AWS' in principal or 'Federated' in principal:
                return False
    return True


def has_dangerous_trust(trust_policy: dict) -> bool:
    """Wildcard(*) Principal이 포함된 위험한 Trust Policy 감지."""
    statements = trust_policy.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        principal = stmt.get('Principal', {})
        if principal == '*':
            return True
        if isinstance(principal, dict):
            for v in principal.values():
                if v == '*' or (isinstance(v, list) and '*' in v):
                    return True
    return False

