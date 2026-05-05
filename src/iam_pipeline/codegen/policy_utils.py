"""Policy ARN 분석 유틸"""


def is_aws_managed_policy(policy_arn: str) -> bool:
    return policy_arn.startswith('arn:aws:iam::aws:policy/')


def policy_arn_to_name(policy_arn: str) -> str:
    return policy_arn.rsplit('/', 1)[-1]

