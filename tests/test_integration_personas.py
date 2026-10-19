"""Live End-to-End Integration Tests for GFS Sales Insight Manager (SIM) across Personas P1, P4, P3, and P6.

Verifies against live BigQuery (`heygreg-telco-demo.gfs_sim_sales.account_performance` joined cross-project
with `bigquery-public-data.thelook_ecommerce.users`) and live Google Drive API v3 (`drive.googleapis.com`):
1. P1 (National VP of Sales):
   - Sees all 8 accounts across all 4 territories (`Organic`, `Search`, `Display`, `Email`)
   - Reads Policy-Tagged column `supplier_rebate_margin_pct`
   - Reads BOTH Drive playbooks (Standard Coaching Playbook + Confidential Executive Rebate Guide)
   - Generates a combined BQ + Drive coaching plan in a single turn
2. P4 (Midwest DSM — RLS Scoped):
   - BigQuery Row-Level Security filters results to ONLY the 4 `Organic` territory accounts
   - Reads `supplier_rebate_margin_pct` for `Organic` accounts
   - Reads ONLY Drive Doc 1 (Standard Playbook); Drive Doc 2 (Confidential Rebate Guide) is denied by Drive ACLs
3. P3 (Sales Enablement Analyst — CLS Blocked on Margin):
   - Sees all 8 accounts across all 4 territories
   - Requesting `supplier_rebate_margin_pct` triggers a live Data Catalog Policy Tag denial and automatically
     falls back to non-sensitive columns while surfacing `POLICY_TAG_ACCESS_DENIED`
   - Reads ONLY Drive Doc 1 (Standard Playbook); Drive Doc 2 is denied by Drive ACLs
4. P6 (Unscoped GE User — Zero BQ / Zero Drive Grants):
   - BigQuery rejects with `JOB_USER_PERMISSION_DENIED` (`bigquery.jobs.create` missing on `heygreg-telco-demo`)
   - Google Drive rejects both docs with `DENIED_BY_DRIVE_ACL`
"""

from fastapi.testclient import TestClient

from app.agent import GFSSalesInsightCoachAgent
from app.auth import mint_persona_oauth_token
from app.server import app


def test_p1_vp_sales_full_cross_project_bq_and_both_drive_playbooks():
    token, persona = mint_persona_oauth_token("P1")
    agent = GFSSalesInsightCoachAgent()
    result = agent.run_coaching_turn(
        user_prompt="Which CRITICAL churn-risk accounts need immediate coaching and what rebate tier can we offer?",
        user_token=token,
        token_source_header="X-Goog-Agent-User-Authorization",
        persona_meta=persona,
        include_rebate_margin=True,
        synthesize_with_gemini=False,
    )
    assert result["bq_telemetry"]["status"] == "SUCCESS"
    assert result["bq_telemetry"]["row_count"] == 8
    assert result["bq_telemetry"]["user_email"] == "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"
    assert "supplier_rebate_margin_pct" in result["bq_telemetry"]["rows"][0]
    # Cross-project join column from bigquery-public-data.thelook_ecommerce.users must be populated
    assert result["bq_telemetry"]["rows"][0].get("buyer_state") is not None

    assert result["drive_context"]["accessible_count"] == 2
    assert result["drive_context"]["denied_count"] == 0
    assert "GFS-SOP-COACH-2026-01" in result["coaching_response"]
    assert "GFS-EXEC-REBATE-2026-99" in result["coaching_response"]


def test_p4_midwest_dsm_rls_restricted_and_confidential_drive_doc_blocked():
    token, persona = mint_persona_oauth_token("P4")
    agent = GFSSalesInsightCoachAgent()
    result = agent.run_coaching_turn(
        user_prompt="Show me my territory accounts at risk and how to coach Marcus Vance.",
        user_token=token,
        token_source_header="Authorization",
        persona_meta=persona,
        include_rebate_margin=True,
        synthesize_with_gemini=False,
    )
    assert result["bq_telemetry"]["status"] == "SUCCESS"
    # RLS must filter 8 total rows down to only the 4 Organic rows!
    assert result["bq_telemetry"]["row_count"] == 4
    territories = {r["sales_territory"] for r in result["bq_telemetry"]["rows"]}
    assert territories == {"Organic"}
    assert result["bq_telemetry"]["user_email"] == "ge-test-p4@heygreg-telco-demo.iam.gserviceaccount.com"

    # Drive ACL must allow Standard Playbook (Doc 1) and block Confidential Rebate Guide (Doc 2)
    assert result["drive_context"]["accessible_count"] == 1
    assert result["drive_context"]["denied_count"] == 1
    assert "CONFIDENTIAL" in result["drive_context"]["denied_playbooks"][0]["title"]


def test_p3_analyst_cls_policy_tag_redacted_with_clean_diagnostic():
    token, persona = mint_persona_oauth_token("P3")
    agent = GFSSalesInsightCoachAgent()
    result = agent.run_coaching_turn(
        user_prompt="Analyze all accounts including supplier rebate margins.",
        user_token=token,
        token_source_header="Authorization",
        persona_meta=persona,
        include_rebate_margin=True,
        synthesize_with_gemini=False,
    )
    assert result["bq_telemetry"]["status"] == "PARTIAL_SUCCESS_CLS_REDACTED"
    assert result["bq_telemetry"]["row_count"] == 8
    assert result["bq_telemetry"]["cls_denial_diagnostic"]["category"] == "POLICY_TAG_ACCESS_DENIED"
    assert "supplier_rebate_margin_pct" not in result["bq_telemetry"]["rows"][0]
    assert result["drive_context"]["accessible_count"] == 1
    assert result["drive_context"]["denied_count"] == 1


def test_p6_unscoped_user_blocked_at_bq_and_drive_with_clean_403():
    token, persona = mint_persona_oauth_token("P6")
    agent = GFSSalesInsightCoachAgent()
    result = agent.run_coaching_turn(
        user_prompt="Show me all GFS sales accounts.",
        user_token=token,
        token_source_header="Authorization",
        persona_meta=persona,
        include_rebate_margin=False,
        synthesize_with_gemini=False,
    )
    assert result["bq_telemetry"]["status"] == "ERROR"
    assert result["bq_telemetry"]["error_diagnostic"]["category"] == "JOB_USER_PERMISSION_DENIED"
    assert result["drive_context"]["accessible_count"] == 0
    assert result["drive_context"]["denied_count"] == 2


def test_fastapi_server_endpoints_and_security_headers():
    client = TestClient(app)
    card_resp = client.get("/.well-known/agent.json")
    assert card_resp.status_code == 200
    assert card_resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert card_resp.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert "Content-Security-Policy" in card_resp.headers
    assert card_resp.json()["name"] == "GFS Sales Insight Manager (SIM) Coaching Agent"
