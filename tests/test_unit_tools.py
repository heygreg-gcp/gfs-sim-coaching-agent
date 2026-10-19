"""Unit tests for [DEMO] HarvestLine Foodservice (HLF) SIM Coaching Agent auth, BigQuery allowlist/error classifier, and Drive tools."""

import pytest

from app.auth import AuthError, extract_user_oauth_token
from app.tools_bq import (
    TableAllowlistError,
    classify_bq_error,
    validate_table_allowlist,
)
from app.tools_drive import decode_drive_bytes, filter_accessible_playbooks


def test_extract_user_oauth_token_prefers_x_goog_agent_user_authorization():
    """Agent Engine V2 moves the user 3LO token to X-Goog-Agent-User-Authorization while Authorization holds the GE SA token."""
    headers = {
        "Authorization": "Bearer ge-service-agent-token",
        "X-Goog-Agent-User-Authorization": "Bearer end-user-3lo-token-123",
    }
    token, source_header = extract_user_oauth_token(headers)
    assert token == "end-user-3lo-token-123"
    assert source_header == "X-Goog-Agent-User-Authorization"


def test_extract_user_oauth_token_falls_back_to_authorization_on_cloud_run():
    """Cloud Run places the GE SA OIDC token in X-Serverless-Authorization and keeps the user 3LO token in Authorization."""
    headers = {
        "X-Serverless-Authorization": "Bearer ge-serverless-oidc-token",
        "Authorization": "Bearer cloud-run-end-user-token-456",
    }
    token, source_header = extract_user_oauth_token(headers)
    assert token == "cloud-run-end-user-token-456"
    assert source_header == "Authorization"


def test_extract_user_oauth_token_fails_closed_when_missing():
    """Case A-iii: When an agent has no authorizationConfig, GE sends no user token and we must fail closed."""
    with pytest.raises(AuthError) as exc_info:
        extract_user_oauth_token({})
    assert "CREDENTIALS_MISSING" in str(exc_info.value)


def test_validate_table_allowlist_allows_curated_cross_project_tables():
    """Curated SIM tables in heygreg-telco-demo and bigquery-public-data must pass allowlist check."""
    sql = """
    SELECT a.account_id, u.country
    FROM `heygreg-telco-demo.hlf_sim_sales.account_performance` AS a
    JOIN `bigquery-public-data.thelook_ecommerce.users` AS u
      ON a.public_user_id = u.id
    """
    tables = validate_table_allowlist(sql)
    assert "heygreg-telco-demo.hlf_sim_sales.account_performance" in tables
    assert "bigquery-public-data.thelook_ecommerce.users" in tables


def test_validate_table_allowlist_blocks_unapproved_tables():
    """Even if Persona P1 has IAM access to forbidden_users, the agent's table allowlist must block it (closing G2)."""
    sql = "SELECT * FROM `heygreg-telco-demo.ge_access_test_forbidden_b.forbidden_users`"
    with pytest.raises(TableAllowlistError) as exc_info:
        validate_table_allowlist(sql)
    assert "ge_access_test_forbidden_b.forbidden_users" in str(exc_info.value)


def test_classify_bq_error_distinguishes_vpc_sc_policy_tag_and_iam():
    """Must distinguish VPC-SC violations (b/568413600), policy tags (CLS), jobUser, and dataset dataViewer denials."""
    vpc_err = classify_bq_error(
        "403 Request is prohibited by organization's policy. vpcServiceControlsUniqueIdentifier: 12345"
    )
    assert vpc_err["category"] == "VPC_SERVICE_CONTROLS_VIOLATION"

    cls_err = classify_bq_error(
        'Access Denied: BigQuery BigQuery: User has neither fine-grained reader nor masked get permission to get data protected by policy tag "ge_access_test_taxonomy : pii_email_tag" on column supplier_rebate_margin_pct'
    )
    assert cls_err["category"] == "POLICY_TAG_ACCESS_DENIED"

    job_err = classify_bq_error(
        "Access Denied: Project heygreg-telco-demo: User does not have bigquery.jobs.create permission in project heygreg-telco-demo."
    )
    assert job_err["category"] == "JOB_USER_PERMISSION_DENIED"

    ds_err = classify_bq_error(
        "Access Denied: Table heygreg-telco-demo:hlf_sim_sales.account_performance: User does not have permission to query table"
    )
    assert ds_err["category"] == "DATASET_ACCESS_DENIED"


def test_decode_drive_bytes_and_filter_playbooks():
    """Bytes-first decoding guardrail and per-user Drive ACL filtering."""
    raw = b"[DEMO] HarvestLine Coaching Playbook \xe2\x80\x94 Drop Size Recovery\nStep 1: Audit cold chain."
    decoded = decode_drive_bytes(raw)
    assert "Drop Size Recovery" in decoded

    docs = [
        {"id": "doc1", "title": "[DEMO] Standard Coaching", "status_code": 200, "content": "Coach rep on drop size"},
        {"id": "doc2", "title": "[DEMO] Confidential Rebates", "status_code": 403, "content": ""},
    ]
    accessible, denied = filter_accessible_playbooks(docs)
    assert len(accessible) == 1
    assert accessible[0]["id"] == "doc1"
    assert len(denied) == 1
    assert denied[0]["id"] == "doc2"
