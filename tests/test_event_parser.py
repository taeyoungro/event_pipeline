import pytest
from iam_pipeline.codegen.event_parser import extract_event_info, extract_iic_user


def test_extract_iic_user():
    arn = "arn:aws:sts::718100330247:assumed-role/AWSReservedSSO_xxx/Security-Admin"
    assert extract_iic_user(arn) == "Security-Admin"


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


def test_extract_event_info_rejects_other_events():
    event = {"source": "aws.iam", "detail": {"eventName": "CreateRole"}}
    with pytest.raises(ValueError):
        extract_event_info(event)

