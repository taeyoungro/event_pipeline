"""Policy ARN 분석 + Trust Policy 분석 유틸"""


def is_aws_managed_policy(policy_arn: str) -> bool:
    return policy_arn.startswith('arn:aws:iam::aws:policy/')


def policy_arn_to_name(policy_arn: str) -> str:
    return policy_arn.rsplit('/', 1)[-1]


def is_service_role(trust_policy: dict) -> bool:
    """
    Trust Policy에 사람이 수임 가능한 Principal이 없으면 서비스 전용 Role.

    사람 수임 불가 판정 조건:
      - Service Principal만 존재 (lambda.amazonaws.com 등)
      - AWS Principal이 있지만 모두 /aws-service-role/ 경로의 ARN
        (StackSets 실행 Role 등 서비스 간 교차 계정 신뢰)

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
            return False  # "*" 또는 단일 ARN 문자열 → 사람 수임 가능
        if isinstance(principal, dict):
            if 'Federated' in principal:
                return False  # SAML/OIDC 연동 → 사람 수임 가능
            if 'AWS' in principal:
                aws_arns = principal['AWS']
                if isinstance(aws_arns, str):
                    aws_arns = [aws_arns]
                # AWS Principal이 모두 /aws-service-role/ 경로이면 서비스 간 신뢰
                if not all('/aws-service-role/' in arn for arn in aws_arns):
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

