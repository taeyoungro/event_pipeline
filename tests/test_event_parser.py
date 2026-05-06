import pytest
from iam_pipeline.codegen.event_parser import extract_event_info, extract_iic_user


def test_extract_iic_user():
    arn = "arn:aws:sts::718100330247:assumed-role/AWSReservedSSO_xxx/Security-Admin"
    assert extract_iic_user(arn) == "Security-Admin"


# ── AttachRolePolicy ──────────────────────────────────────────────────────────

def test_extract_event_info_attach_role_policy():
    event = {
        "source": "aws.iam",
        "id": "evt-1",
        "time": "2026-05-04T01:50:00Z",
        "account": "718100330247",
        "detail": {
            "eventName": "AttachRolePolicy",
            "recipientAccountId": "718100330247",
            "userIdentity": {
                "arn": "arn:aws:sts::718100330247:assumed-role/x/Security-Admin"
            },
            "requestParameters": {
                "roleName": "myRole",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        },
    }
    info = extract_event_info(event)
    assert info['role_name'] == 'myRole'
    assert info['account_id'] == '718100330247'
    assert info['iic_user'] == 'Security-Admin'
    assert info['action'] == 'ATTACH'
    assert info['event_name'] == 'AttachRolePolicy'
    assert info['policy_arn'] == 'arn:aws:iam::aws:policy/AdministratorAccess'


# ── DetachRolePolicy (Phase 1.3) ──────────────────────────────────────────────

def test_extract_event_info_detach_role_policy():
    event = {
        "source": "aws.iam",
        "id": "evt-2",
        "time": "2026-05-04T02:00:00Z",
        "detail": {
            "eventName": "DetachRolePolicy",
            "recipientAccountId": "718100330247",
            "userIdentity": {"arn": "arn:aws:sts::718100330247:assumed-role/x/Admin"},
            "requestParameters": {
                "roleName": "myRole",
                "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            },
        },
    }
    info = extract_event_info(event)
    assert info['action'] == 'REFRESH'
    assert info['event_name'] == 'DetachRolePolicy'
    assert info['role_name'] == 'myRole'
    assert info['policy_arn'] == 'arn:aws:iam::aws:policy/ReadOnlyAccess'


# ── PutRolePolicy (Phase 1.5) ─────────────────────────────────────────────────

def test_extract_event_info_put_role_policy():
    event = {
        "source": "aws.iam",
        "id": "evt-3",
        "time": "2026-05-04T02:05:00Z",
        "detail": {
            "eventName": "PutRolePolicy",
            "recipientAccountId": "718100330247",
            "userIdentity": {"arn": "arn:aws:sts::718100330247:assumed-role/x/Admin"},
            "requestParameters": {
                "roleName": "myRole",
                "policyName": "MyInlinePolicy",
            },
        },
    }
    info = extract_event_info(event)
    assert info['action'] == 'REFRESH'
    assert info['event_name'] == 'PutRolePolicy'
    assert info['role_name'] == 'myRole'
    assert info['policy_name'] == 'MyInlinePolicy'
    assert 'policy_arn' not in info


# ── DeleteRole (Phase 1.4) ────────────────────────────────────────────────────

def test_extract_event_info_delete_role():
    event = {
        "source": "aws.iam",
        "id": "evt-4",
        "time": "2026-05-04T02:10:00Z",
        "detail": {
            "eventName": "DeleteRole",
            "recipientAccountId": "718100330247",
            "userIdentity": {"arn": "arn:aws:sts::718100330247:assumed-role/x/Admin"},
            "requestParameters": {
                "roleName": "myRole",
            },
        },
    }
    info = extract_event_info(event)
    assert info['action'] == 'DELETE'
    assert info['event_name'] == 'DeleteRole'
    assert info['role_name'] == 'myRole'
    assert 'policy_arn' not in info


# ── 거부 케이스 ───────────────────────────────────────────────────────────────

def test_extract_event_info_rejects_unsupported_events():
    """CreateRole 등 지원하지 않는 이벤트 거부."""
    event = {"source": "aws.iam", "detail": {"eventName": "CreateRole"}}
    with pytest.raises(ValueError, match="Unsupported eventName"):
        extract_event_info(event)


def test_extract_event_info_rejects_wrong_source():
    event = {"source": "aws.s3", "detail": {"eventName": "AttachRolePolicy"}}
    with pytest.raises(ValueError, match="Unexpected source"):
        extract_event_info(event)


def test_extract_event_info_attach_missing_policy_arn():
    event = {
        "source": "aws.iam",
        "detail": {
            "eventName": "AttachRolePolicy",
            "recipientAccountId": "718100330247",
            "userIdentity": {"arn": ""},
            "requestParameters": {"roleName": "myRole"},
        },
    }
    with pytest.raises(ValueError, match="policyArn"):
        extract_event_info(event)


# ── PS 이름 생성 (Phase 3.1/3.2/3.3) ─────────────────────────────────────────

def test_make_ps_name_truncation():
    from iam_pipeline.codegen.tf_writer import make_ps_name, validate_ps_name
    name = make_ps_name("123456789012", "A" * 64)
    assert len(name) <= 32
    validate_ps_name(name)  # 예외 없어야 함


def test_validate_ps_name_rejects_too_long():
    from iam_pipeline.codegen.tf_writer import validate_ps_name
    with pytest.raises(ValueError):
        validate_ps_name("x" * 33)


def test_validate_ps_name_rejects_invalid_chars():
    from iam_pipeline.codegen.tf_writer import validate_ps_name
    with pytest.raises(ValueError):
        validate_ps_name("role with spaces")


# ── Trust Policy 분석 (Phase 4.2/4.3) ────────────────────────────────────────

def test_is_service_role_true():
    from iam_pipeline.orchestrator.pipeline import is_service_role
    trust = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }]
    }
    assert is_service_role(trust) is True


def test_is_service_role_false_federated():
    from iam_pipeline.orchestrator.pipeline import is_service_role
    trust = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::123456789012:saml-provider/AWSSSO"},
            "Action": "sts:AssumeRoleWithSAML",
        }]
    }
    assert is_service_role(trust) is False


def test_has_dangerous_trust_wildcard():
    from iam_pipeline.orchestrator.pipeline import has_dangerous_trust
    trust = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole",
        }]
    }
    assert has_dangerous_trust(trust) is True


def test_has_dangerous_trust_safe():
    from iam_pipeline.orchestrator.pipeline import has_dangerous_trust
    trust = {
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": "sts:AssumeRole",
        }]
    }
    assert has_dangerous_trust(trust) is False


# ── 다중 계정 태그 파싱 (Phase 2.2/2.5) ──────────────────────────────────────

def test_parse_target_accounts_valid():
    from iam_pipeline.orchestrator.pipeline import parse_target_accounts
    tags = {'iic-target-accounts': '111111111111, 222222222222'}
    result = parse_target_accounts(tags, '000000000000', 'iic-target-accounts')
    assert '111111111111' in result
    assert '222222222222' in result


def test_parse_target_accounts_fallback_no_tag():
    from iam_pipeline.orchestrator.pipeline import parse_target_accounts
    result = parse_target_accounts({}, '000000000000', 'iic-target-accounts')
    assert result == ['000000000000']


def test_parse_target_accounts_fallback_invalid():
    from iam_pipeline.orchestrator.pipeline import parse_target_accounts
    tags = {'iic-target-accounts': 'not-an-account'}
    result = parse_target_accounts(tags, '000000000000', 'iic-target-accounts')
    assert result == ['000000000000']
