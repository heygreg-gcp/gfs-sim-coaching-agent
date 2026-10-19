"""GFS Sales Insight Manager (SIM) Unified Coaching Agent (Cross-Project BigQuery + Google Drive).

Follows the `deploy_enterprise_agents` Reference Architecture:
1. Compile-time injected global constants
2. Zero-argument constructor
3. Lazy client initialization inside tool methods
4. Structured single-line JSON telemetry logging (never logging OAuth tokens)
"""

import json
import logging
import subprocess
from typing import Any, Dict, Optional

from app.tools_bq import (
    BILLING_PROJECT_ID,
    CROSS_PROJECT_PUBLIC_TABLE,
    PRIMARY_TABLE,
    query_gfs_sales_performance,
)
from app.tools_drive import fetch_gfs_coaching_playbooks

GCP_PROJECT_ID = "heygreg-telco-demo"
GCP_LOCATION = "us-central1"
MODEL_ID = "gemini-2.5-flash"

logger = logging.getLogger("gfs_sim_coaching_agent")
if not logger.handlers:
    handler = logging.StreamHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class GFSSalesInsightCoachAgent:
    """Unified ADK / A2A Sales Insight Manager (SIM) Agent combining Cross-Project BQ + Google Drive."""

    def __init__(self) -> None:
        self.project_id = GCP_PROJECT_ID
        self.location = GCP_LOCATION
        self.model_id = MODEL_ID

    def log_telemetry(self, event_tag: str, payload: Dict[str, Any]) -> str:
        """Emits structured single-line JSON telemetry without sensitive tokens."""
        log_entry = {
            "tag": event_tag,
            "project_id": self.project_id,
            **payload,
        }
        serialized = json.dumps(log_entry)
        logger.info(serialized)
        return "Telemetry logged."

    def _synthesize_deterministic_coaching_brief(
        self,
        user_prompt: str,
        persona_meta: Dict[str, Any],
        token_source_header: str,
        bq_result: Dict[str, Any],
        drive_result: Dict[str, Any],
    ) -> str:
        """Builds a structured, deterministic coaching brief citing exact BQ rows and Drive playbooks."""
        lines = [
            f"### GFS Sales Insight Manager (SIM) — Single-Turn Coaching Synthesis",
            f"- **Caller Identity (Data-Access Principal):** `{persona_meta.get('email', 'caller-oauth-principal')}` (`{persona_meta.get('id', 'USER')}: {persona_meta.get('name', 'End User')}`)",
            f"- **3LO Token Header Propagated:** `{token_source_header}` -> Forwarded to **BigQuery** (`{BILLING_PROJECT_ID}`) AND **Google Drive API v3**",
            "",
        ]

        bq_status = bq_result.get("status")
        if bq_status == "ERROR":
            diag = bq_result.get("error_diagnostic", {})
            lines.extend([
                "#### 1. Cross-Project BigQuery Telemetry (`BLOCKED BY IAM / PERIMETER`)",
                f"- **Diagnostic Category:** `{diag.get('category')}`",
                f"- **Root Cause:** {diag.get('summary')}",
                f"- **Recommended Fix:** {diag.get('remediation')}",
                "",
            ])
        else:
            rows = bq_result.get("rows", [])
            territories = sorted({r.get("sales_territory", "") for r in rows})
            lines.extend([
                f"#### 1. Cross-Project BigQuery Telemetry (`{bq_status}` — `{len(rows)}` Accounts Visible)",
                f"- **BigQuery Job ID:** `{bq_result.get('job_id')}` (Billed to `{bq_result.get('billing_project')}` via `roles/bigquery.jobUser`)",
                f"- **Cross-Project Tables Joined:** `{PRIMARY_TABLE}` $\\bowtie$ `{CROSS_PROJECT_PUBLIC_TABLE}`",
                f"- **Territories Visible After Row-Level Security (RLS):** `{', '.join(territories)}`",
            ])
            if bq_status == "PARTIAL_SUCCESS_CLS_REDACTED":
                cls_diag = bq_result.get("cls_denial_diagnostic", {})
                lines.append(
                    f"- **Column-Level Security (Policy Tag) Notice:** `{cls_diag.get('category')}` — "
                    f"`supplier_rebate_margin_pct` was blocked by Data Catalog Policy Tag `pii_email_tag` and automatically redacted."
                )
            lines.append("")
            for r in rows:
                margin_str = (
                    f" | **Supplier Rebate Margin (Policy-Tagged):** `{r['supplier_rebate_margin_pct']}%`"
                    if "supplier_rebate_margin_pct" in r
                    else " | **Supplier Rebate Margin:** `[REDACTED BY POLICY TAG]`"
                )
                lines.append(
                    f"- **`{r['account_id']}` — {r['customer_name']}** ({r['segment']}, Territory: `{r['sales_territory']}`, "
                    f"Buyer Hub: `{r.get('buyer_city')}, {r.get('buyer_state')}`, Rep: **{r['assigned_rep']}**): "
                    f"Weekly Rev `${r['weekly_revenue_usd']:,.0f}` | QoQ Case Vol `{r['qoq_case_volume_change_pct']:+.1f}%` | "
                    f"Late Drops (90d): `{r['late_deliveries_90d']}` | Risk: **`{r['churn_risk_tier']}`**"
                    f"{margin_str}\n  - *Pain Point:* {r['primary_pain_point']}"
                )
            lines.append("")

        accessible_docs = drive_result.get("accessible_playbooks", [])
        denied_docs = drive_result.get("denied_playbooks", [])
        lines.append(
            f"#### 2. Unstructured Google Drive Coaching Playbooks (`{len(accessible_docs)}` Accessible, `{len(denied_docs)}` Denied by Drive ACL)"
        )
        for doc in accessible_docs:
            lines.append(f"- **PERMITTED:** [{doc['title']}]({doc['url']}) (`{doc['id']}`)")
        for doc in denied_docs:
            lines.append(f"- **BLOCKED BY DRIVE ACL (`HTTP {doc['status_code']}`):** `{doc['title']}` (`{doc['id']}`)")
        lines.append("")

        if bq_status != "ERROR" and accessible_docs:
            lines.append("#### 3. Actionable Rep Coaching Plan (Blended BQ Telemetry + Drive Playbook Guidance)")
            at_risk = [r for r in bq_result.get("rows", []) if r.get("churn_risk_tier") in ("CRITICAL", "HIGH")]
            has_exec_rebate_doc = any("GFS-EXEC-REBATE-2026-99" in d.get("content", "") for d in accessible_docs)

            for r in at_risk:
                lines.append(f"- **Coaching Plan for {r['assigned_rep']} on `{r['account_id']}` ({r['customer_name']}):**")
                if r.get("late_deliveries_90d", 0) >= 2:
                    lines.append(
                        "  1. **Apply `GFS-SOP-COACH-2026-01` Playbook A (Cold-Chain Service Recovery):** "
                        f"Schedule a 24-hour joint DSM + rep kitchen walk-through to address `{r['late_deliveries_90d']}` late cold-chain drops, "
                        "shift to a priority morning dock window, and offer a 60-day service-level guarantee with Gordon Choice spec matching."
                    )
                else:
                    lines.append(
                        "  1. **Apply `GFS-SOP-COACH-2026-01` Playbook B (Drop-Size & Culinary Pairing):** "
                        "Consolidate delivery drop size above 65 cases and pair a GFS Culinary Specialist for Clear Choice portion-cut alternatives."
                    )

                if has_exec_rebate_doc and "supplier_rebate_margin_pct" in r:
                    margin = float(r["supplier_rebate_margin_pct"])
                    if margin >= 18.0:
                        lines.append(
                            f"  2. **Apply `GFS-EXEC-REBATE-2026-99` Tier 1 Executive Save (Confidential Margin `{margin}% >= 18.0%`):** "
                            "Authorized to re-invest up to **4.5% of gross invoice value** as a quarterly volume retention rebate upon 12-month Prime Vendor renewal."
                        )
                    elif margin >= 14.0:
                        lines.append(
                            f"  2. **Apply `GFS-EXEC-REBATE-2026-99` Tier 2 Healthcare/System Save (Confidential Margin `{margin}%`):** "
                            "Authorized to re-invest up to **2.75% of gross invoice value** in deviated manufacturer pricing and waive fuel surcharges for 90 days."
                        )
                elif not has_exec_rebate_doc:
                    lines.append(
                        "  2. *Executive Rebate Tier Guidance Redacted:* Caller does not hold Google Drive ACL access to `GFS-EXEC-REBATE-2026-99`."
                    )

        return "\n".join(lines)

    def _synthesize_with_gemini_llm(self, deterministic_brief: str, user_prompt: str) -> Optional[str]:
        """Optionally calls Vertex AI Gemini 2.5 Flash to polish the grounded BQ + Drive brief."""
        try:
            from google import genai
            from google.oauth2 import credentials as oauth2_credentials

            res = subprocess.run(
                ["gcloud", "auth", "print-access-token"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            admin_token = res.stdout.strip().splitlines()[-1].strip()
            creds = oauth2_credentials.Credentials(token=admin_token)
            client = genai.Client(vertexai=True, project=self.project_id, location=self.location, credentials=creds)
            prompt = (
                "You are the Gordon Food Service (GFS) Sales Insight Manager (SIM) Coaching Agent.\n"
                "Using ONLY the verified BigQuery telemetry and Google Drive playbook excerpts below, "
                "answer the user's question concisely while preserving all Account IDs, Rep names, "
                "Document IDs (`GFS-SOP-COACH-2026-01`, `GFS-EXEC-REBATE-2026-99`), BigQuery Job IDs, "
                "and any RLS/CLS/Drive ACL redaction notices.\n\n"
                f"USER PROMPT: {user_prompt}\n\n"
                f"VERIFIED GROUNDING DATA:\n{deterministic_brief}"
            )
            resp = client.models.generate_content(model=self.model_id, contents=prompt)
            if resp and resp.text:
                return resp.text.strip() + "\n\n---\n" + deterministic_brief
        except Exception as exc:
            self.log_telemetry("GEMINI_SYNTHESIS_FALLBACK", {"reason": str(exc)[:200]})
        return None

    def run_coaching_turn(
        self,
        user_prompt: str,
        user_token: str,
        token_source_header: str = "Authorization",
        persona_meta: Optional[Dict[str, Any]] = None,
        territory_filter: Optional[str] = None,
        include_rebate_margin: bool = True,
        synthesize_with_gemini: bool = False,
    ) -> Dict[str, Any]:
        """Executes a single unified SIM turn combining cross-project BigQuery + Google Drive with the user's OAuth token."""
        persona_info = persona_meta or {
            "id": "CALLER",
            "name": "3LO OAuth End User",
            "email": "end-user-oauth-bearer",
            "role_summary": "Governed by Caller's 3LO OAuth Token",
        }

        bq_result = query_gfs_sales_performance(
            user_token=user_token,
            territory_filter=territory_filter,
            include_rebate_margin=include_rebate_margin,
            auto_fallback_on_cls_denial=True,
        )

        drive_result = fetch_gfs_coaching_playbooks(user_token=user_token)

        deterministic_brief = self._synthesize_deterministic_coaching_brief(
            user_prompt=user_prompt,
            persona_meta=persona_info,
            token_source_header=token_source_header,
            bq_result=bq_result,
            drive_result=drive_result,
        )

        coaching_response = deterministic_brief
        if synthesize_with_gemini and bq_result.get("status") != "ERROR":
            llm_text = self._synthesize_with_gemini_llm(deterministic_brief, user_prompt)
            if llm_text:
                coaching_response = llm_text

        self.log_telemetry(
            "SIM_COACHING_TURN",
            {
                "persona_id": persona_info.get("id"),
                "token_source_header": token_source_header,
                "bq_status": bq_result.get("status"),
                "bq_job_id": bq_result.get("job_id"),
                "bq_row_count": bq_result.get("row_count", 0),
                "drive_accessible_count": drive_result.get("accessible_count", 0),
                "drive_denied_count": drive_result.get("denied_count", 0),
            },
        )

        return {
            "persona": persona_info,
            "token_source_header": token_source_header,
            "bq_telemetry": bq_result,
            "drive_context": drive_result,
            "coaching_response": coaching_response,
        }
