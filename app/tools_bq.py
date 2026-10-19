"""Cross-Project BigQuery tool with server-side SQL table allowlist, RLS/CLS support, and error classification."""

import re
from typing import Any, Dict, List, Optional
from google.api_core import exceptions as gcp_exceptions
from google.cloud import bigquery
from google.oauth2 import credentials as oauth2_credentials

BILLING_PROJECT_ID = "heygreg-telco-demo"
PRIMARY_TABLE = "heygreg-telco-demo.hlf_sim_sales.account_performance"
CROSS_PROJECT_PUBLIC_TABLE = "bigquery-public-data.thelook_ecommerce.users"

ALLOWED_TABLES = frozenset({
    PRIMARY_TABLE,
    CROSS_PROJECT_PUBLIC_TABLE,
})

TABLE_REF_REGEX = re.compile(
    r"(?:FROM|JOIN)\s+`?([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)`?",
    re.IGNORECASE,
)


class TableAllowlistError(Exception):
    """Raised when a query attempts to reference a table outside the agent's curated allowlist."""


def validate_table_allowlist(sql: str) -> List[str]:
    """Extracts all referenced `project.dataset.table` identifiers and enforces ALLOWED_TABLES."""
    referenced = TABLE_REF_REGEX.findall(sql or "")
    if not referenced:
        raise TableAllowlistError("Query must explicitly reference an allowed project.dataset.table.")
    disallowed = [t for t in referenced if t not in ALLOWED_TABLES]
    if disallowed:
        raise TableAllowlistError(
            f"Query is invalid. Attempting to access tables outside the agent's curated context allowlist. "
            f"Allowed tables: {sorted(ALLOWED_TABLES)}. Disallowed tables: {disallowed}."
        )
    return referenced


def classify_bq_error(error_message: str) -> Dict[str, str]:
    """Classifies BigQuery 403/400 errors into actionable diagnostic categories (resolving b/568413600)."""
    msg = error_message or ""
    lower = msg.lower()

    if "vpcservicecontrol" in lower or "organization's policy" in lower or "vpc_service_controls" in lower:
        return {
            "category": "VPC_SERVICE_CONTROLS_VIOLATION",
            "summary": "VPC Service Controls perimeter blocked cross-project BigQuery access.",
            "remediation": (
                "Add an ingress/egress rule allowing the Gemini Enterprise / Agent host project "
                "to reach the target BigQuery Data Project (see b/568413600)."
            ),
            "raw_message": msg,
        }
    if "policy tag" in lower or "fine-grained reader" in lower or "masked get permission" in lower:
        return {
            "category": "POLICY_TAG_ACCESS_DENIED",
            "summary": "Column-Level Security (Data Catalog Policy Tag) blocked reading sensitive margin column.",
            "remediation": (
                "Grant roles/datacatalog.categoryFineGrainedReader on the policy tag to the user's "
                "Google Group, or retry the query excluding `supplier_rebate_margin_pct`."
            ),
            "raw_message": msg,
        }
    if "bigquery.jobs.create" in lower:
        return {
            "category": "JOB_USER_PERMISSION_DENIED",
            "summary": f"Caller lacks `bigquery.jobs.create` on billing/agent host project `{BILLING_PROJECT_ID}`.",
            "remediation": (
                f"Grant `roles/bigquery.jobUser` on `{BILLING_PROJECT_ID}` to the user's Google Group "
                "(this also supplies `cloudaicompanion.topics.create` and `geminidataanalytics.locations.chat`)."
            ),
            "raw_message": msg,
        }
    if "permission to query table" in lower or "bigquery.tables.getdata" in lower or "access denied: table" in lower:
        return {
            "category": "DATASET_ACCESS_DENIED",
            "summary": "Caller lacks `roles/bigquery.dataViewer` on the target BigQuery dataset/table.",
            "remediation": (
                "Grant `roles/bigquery.dataViewer` at the DATASET level on the Data Project to the user's Google Group."
            ),
            "raw_message": msg,
        }
    return {
        "category": "BIGQUERY_EXECUTION_ERROR",
        "summary": "BigQuery returned an execution error.",
        "remediation": "Inspect the raw error message and Cloud Audit Logs.",
        "raw_message": msg,
    }


def query_hlf_sales_performance(
    user_token: str,
    territory_filter: Optional[str] = None,
    include_rebate_margin: bool = False,
    auto_fallback_on_cls_denial: bool = True,
) -> Dict[str, Any]:
    """Executes a parameterized cross-project BigQuery query using the caller's 3LO OAuth token.

    - Bills `bigquery.jobs.create` to `heygreg-telco-demo` (Agent Host Project).
    - Joins `heygreg-telco-demo.hlf_sim_sales.account_performance` with `bigquery-public-data.thelook_ecommerce.users`
      (Cross-Project Data Project).
    - Natively enforces BigQuery Row-Level Security (RLS) and Column-Level Policy Tags (CLS) on the caller's identity.
    """
    creds = oauth2_credentials.Credentials(token=user_token)
    client = bigquery.Client(project=BILLING_PROJECT_ID, credentials=creds)

    def _build_sql(with_margin: bool) -> str:
        margin_col = ", a.supplier_rebate_margin_pct" if with_margin else ""
        where_clause = "WHERE a.sales_territory = @territory" if territory_filter else ""
        return f"""
        SELECT
            a.account_id,
            a.customer_name,
            a.segment,
            a.sales_territory,
            a.assigned_rep,
            a.weekly_revenue_usd,
            a.qoq_case_volume_change_pct,
            a.late_deliveries_90d,
            a.churn_risk_tier,
            a.primary_pain_point,
            u.city AS buyer_city,
            u.state AS buyer_state,
            u.traffic_source AS public_benchmark_channel{margin_col}
        FROM `{PRIMARY_TABLE}` AS a
        LEFT JOIN `{CROSS_PROJECT_PUBLIC_TABLE}` AS u
          ON a.public_user_id = u.id
        {where_clause}
        ORDER BY a.qoq_case_volume_change_pct ASC, a.weekly_revenue_usd DESC
        """

    sql = _build_sql(include_rebate_margin)
    referenced_tables = validate_table_allowlist(sql)

    params = []
    if territory_filter:
        params.append(bigquery.ScalarQueryParameter("territory", "STRING", territory_filter))

    job_config = bigquery.QueryJobConfig(query_parameters=params, use_query_cache=False)

    cls_fallback_notice = None
    try:
        query_job = client.query(sql, job_config=job_config, location="US")
        rows = [dict(r.items()) for r in query_job.result()]
        return {
            "status": "SUCCESS",
            "billing_project": BILLING_PROJECT_ID,
            "referenced_tables": referenced_tables,
            "job_id": query_job.job_id,
            "user_email": query_job.user_email,
            "row_count": len(rows),
            "include_rebate_margin_requested": include_rebate_margin,
            "include_rebate_margin_returned": include_rebate_margin,
            "cls_fallback_notice": cls_fallback_notice,
            "rows": rows,
        }
    except gcp_exceptions.GoogleAPICallError as exc:
        classified = classify_bq_error(str(exc))
        if (
            classified["category"] == "POLICY_TAG_ACCESS_DENIED"
            and include_rebate_margin
            and auto_fallback_on_cls_denial
        ):
            fallback_sql = _build_sql(with_margin=False)
            validate_table_allowlist(fallback_sql)
            retry_job = client.query(fallback_sql, job_config=job_config, location="US")
            rows = [dict(r.items()) for r in retry_job.result()]
            return {
                "status": "PARTIAL_SUCCESS_CLS_REDACTED",
                "billing_project": BILLING_PROJECT_ID,
                "referenced_tables": referenced_tables,
                "job_id": retry_job.job_id,
                "user_email": retry_job.user_email,
                "row_count": len(rows),
                "include_rebate_margin_requested": True,
                "include_rebate_margin_returned": False,
                "cls_denial_diagnostic": classified,
                "rows": rows,
            }
        return {
            "status": "ERROR",
            "billing_project": BILLING_PROJECT_ID,
            "referenced_tables": referenced_tables,
            "error_diagnostic": classified,
            "rows": [],
        }
