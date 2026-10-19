"""Provisions the [DEMO] HarvestLine Foodservice (HLF) Sales Insight Manager (SIM) cross-project BigQuery dataset + Real Google Docs in Drive.

Resources created in `heygreg-telco-demo`:
1. BigQuery Dataset `heygreg-telco-demo:hlf_sim_sales` (stripped of default projectReaders ACLs;
   explicit READER granted to ge-test-p1, ge-test-p2, ge-test-p3, ge-test-p4; denied to ge-test-p5, ge-test-p6).
2. BigQuery Table `heygreg-telco-demo.hlf_sim_sales.account_performance`:
   - 8 synthetic HarvestLine Foodservice (HLF) accounts across 4 territories (`Organic`, `Search`, `Display`, `Email`)
   - Cross-project foreign key `public_user_id` -> `bigquery-public-data.thelook_ecommerce.users.id`
   - Column `supplier_rebate_margin_pct` protected by Policy Tag
     `projects/heygreg-telco-demo/locations/us/taxonomies/3838347283155594953/policyTags/499965283194771155`
   - Row Access Policy `rlp_midwest_organic_dsm` (`sales_territory = 'Organic'`) for `ge-test-p4`
   - Row Access Policy `rlp_all_territories` (`TRUE`) for `ge-test-p1`, `ge-test-p2`, `ge-test-p3`, `admin@`, `heygreg@`
3. Two Google Drive v3 items + real Google Docs (`application/vnd.google-apps.document`) in Google Drive:
   - Doc 1: `[DEMO] HarvestLine Foodservice — Sales Coaching Playbook: Churn Recovery & Cold-Chain Drops` (`HLF-SOP-COACH-2026-01`) (Accessible to P1, P3, P4; Denied to P6)
   - Doc 2: `[DEMO] HarvestLine Foodservice — Executive Margin & Supplier Rebate Guide [CONFIDENTIAL]` (`HLF-EXEC-REBATE-2026-99`) (Accessible to P1 ONLY; Denied to P3, P4, P6)
"""

import json
from pathlib import Path
import subprocess
import httpx
from google.cloud import bigquery
from google.oauth2 import credentials as oauth2_credentials

PROJECT_ID = "heygreg-telco-demo"
LEGACY_DATASET_ID = "gfs_sim_sales"
DATASET_ID = "hlf_sim_sales"
TABLE_ID = "account_performance"
POLICY_TAG = "projects/heygreg-telco-demo/locations/us/taxonomies/3838347283155594953/policyTags/499965283194771155"
CONFIG_PATH = Path(__file__).resolve().parent.parent / "app" / "config_generated.json"


def get_token(impersonate_sa: str = "") -> str:
    cmd = ["gcloud", "auth", "print-access-token"]
    if impersonate_sa:
        cmd.extend([
            f"--impersonate-service-account={impersonate_sa}",
            "--scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/drive",
        ])
    res = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=20)
    return res.stdout.strip().splitlines()[-1].strip()


def setup_bigquery() -> None:
    admin_creds = oauth2_credentials.Credentials(token=get_token())
    client = bigquery.Client(project=PROJECT_ID, credentials=admin_creds)

    # Clean up legacy gfs_sim_sales dataset if present
    client.delete_dataset(
        f"{PROJECT_ID}.{LEGACY_DATASET_ID}",
        delete_contents=True,
        not_found_ok=True,
    )

    print(f"=== 1. Creating BigQuery Dataset {PROJECT_ID}:{DATASET_ID} ===")
    dataset_ref = bigquery.Dataset(f"{PROJECT_ID}.{DATASET_ID}")
    dataset_ref.location = "US"
    dataset_ref.description = "[DEMO] HarvestLine Foodservice (HLF) — Synthetic Sales Insight Manager Dataset"
    dataset = client.create_dataset(dataset_ref, exists_ok=True)

    # Strip default projectReaders/projectWriters so only explicit personas have dataset access
    dataset.access_entries = [
        bigquery.AccessEntry("OWNER", "userByEmail", "admin@heygreg.altostrat.com"),
        bigquery.AccessEntry("OWNER", "userByEmail", "heygreg@heygreg.altostrat.com"),
        bigquery.AccessEntry("READER", "userByEmail", f"ge-test-p1@{PROJECT_ID}.iam.gserviceaccount.com"),
        bigquery.AccessEntry("READER", "userByEmail", f"ge-test-p2@{PROJECT_ID}.iam.gserviceaccount.com"),
        bigquery.AccessEntry("READER", "userByEmail", f"ge-test-p3@{PROJECT_ID}.iam.gserviceaccount.com"),
        bigquery.AccessEntry("READER", "userByEmail", f"ge-test-p4@{PROJECT_ID}.iam.gserviceaccount.com"),
    ]
    client.update_dataset(dataset, ["access_entries", "description"])
    print("  -> Dataset ACLs locked to P1, P2, P3, P4 (P5 & P6 excluded).")

    print(f"=== 2. Creating Table {PROJECT_ID}.{DATASET_ID}.{TABLE_ID} ===")
    table_fqn = f"{PROJECT_ID}.{DATASET_ID}.{TABLE_ID}"
    client.delete_table(table_fqn, not_found_ok=True)

    schema = [
        bigquery.SchemaField("account_id", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("customer_name", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("segment", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("sales_territory", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("assigned_rep", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("weekly_revenue_usd", "FLOAT", mode="REQUIRED"),
        bigquery.SchemaField("qoq_case_volume_change_pct", "FLOAT", mode="REQUIRED"),
        bigquery.SchemaField("late_deliveries_90d", "INTEGER", mode="REQUIRED"),
        bigquery.SchemaField("churn_risk_tier", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("primary_pain_point", "STRING", mode="REQUIRED"),
        bigquery.SchemaField("public_user_id", "INTEGER", mode="REQUIRED"),
        bigquery.SchemaField(
            "supplier_rebate_margin_pct",
            "FLOAT",
            mode="REQUIRED",
            policy_tags=bigquery.PolicyTagList([POLICY_TAG]),
        ),
    ]
    table = bigquery.Table(table_fqn, schema=schema)
    client.create_table(table)

    rows = [
        # Organic Territory (Midwest — visible to P4 via RLS, plus P1 & P3)
        {
            "account_id": "HLF-MW-101",
            "customer_name": "[DEMO] Lakeview Bistro Group (8 Locations)",
            "segment": "Independent Restaurant",
            "sales_territory": "Organic",
            "assigned_rep": "Marcus Vance",
            "weekly_revenue_usd": 48500.0,
            "qoq_case_volume_change_pct": -18.4,
            "late_deliveries_90d": 4,
            "churn_risk_tier": "CRITICAL",
            "primary_pain_point": "4 late cold-chain dairy/produce drops in 90d; shifting center-of-plate poultry to rival broadliner",
            "public_user_id": 31,
            "supplier_rebate_margin_pct": 14.8,
        },
        {
            "account_id": "HLF-MW-102",
            "customer_name": "[DEMO] Prairie Senior Living Network",
            "segment": "Healthcare",
            "sales_territory": "Organic",
            "assigned_rep": "Marcus Vance",
            "weekly_revenue_usd": 31200.0,
            "qoq_case_volume_change_pct": -12.1,
            "late_deliveries_90d": 2,
            "churn_risk_tier": "HIGH",
            "primary_pain_point": "Drop size fell below 65 cases/delivery; dietary director citing specialty cheese stockouts",
            "public_user_id": 32,
            "supplier_rebate_margin_pct": 19.2,
        },
        {
            "account_id": "HLF-MW-103",
            "customer_name": "[DEMO] Heartland Unified School District",
            "segment": "Education",
            "sales_territory": "Organic",
            "assigned_rep": "Elena Rostova",
            "weekly_revenue_usd": 62400.0,
            "qoq_case_volume_change_pct": 4.5,
            "late_deliveries_90d": 0,
            "churn_risk_tier": "LOW",
            "primary_pain_point": "Expanding K-12 breakfast program; requesting HarvestLine Reserve private-label samples",
            "public_user_id": 33,
            "supplier_rebate_margin_pct": 11.4,
        },
        {
            "account_id": "HLF-MW-104",
            "customer_name": "[DEMO] Northwoods Resort & Conference Center",
            "segment": "Hospitality",
            "sales_territory": "Organic",
            "assigned_rep": "Elena Rostova",
            "weekly_revenue_usd": 27900.0,
            "qoq_case_volume_change_pct": -9.6,
            "late_deliveries_90d": 3,
            "churn_risk_tier": "HIGH",
            "primary_pain_point": "Reefer temp excursion alarm on seafood drop; demanding QA credit and route window move",
            "public_user_id": 34,
            "supplier_rebate_margin_pct": 21.5,
        },
        # Search Territory (Northeast — hidden from P4 by RLS; visible to P1 & P3)
        {
            "account_id": "HLF-NE-201",
            "customer_name": "[DEMO] Harborfront Hospitality Group",
            "segment": "Hospitality",
            "sales_territory": "Search",
            "assigned_rep": "Devon Brooks",
            "weekly_revenue_usd": 54100.0,
            "qoq_case_volume_change_pct": -22.0,
            "late_deliveries_90d": 5,
            "churn_risk_tier": "CRITICAL",
            "primary_pain_point": "Competitive RFP active; requires executive rebate tier lock and dedicated morning dock window",
            "public_user_id": 1,
            "supplier_rebate_margin_pct": 16.9,
        },
        {
            "account_id": "HLF-NE-202",
            "customer_name": "[DEMO] Ironclad Steakhouse Collective",
            "segment": "Independent Restaurant",
            "sales_territory": "Search",
            "assigned_rep": "Devon Brooks",
            "weekly_revenue_usd": 39800.0,
            "qoq_case_volume_change_pct": -14.3,
            "late_deliveries_90d": 1,
            "churn_risk_tier": "HIGH",
            "primary_pain_point": "Prime beef sub-primal price sensitivity; prime candidate for HarvestLine Signature portion-cut swap",
            "public_user_id": 2,
            "supplier_rebate_margin_pct": 22.8,
        },
        # Display Territory (Southeast — hidden from P4 by RLS; visible to P1 & P3)
        {
            "account_id": "HLF-SE-301",
            "customer_name": "[DEMO] Sunbelt Medical Center",
            "segment": "Healthcare",
            "sales_territory": "Display",
            "assigned_rep": "Carla Mendez",
            "weekly_revenue_usd": 44700.0,
            "qoq_case_volume_change_pct": -15.8,
            "late_deliveries_90d": 3,
            "churn_risk_tier": "HIGH",
            "primary_pain_point": "Menu cycle fatigue and disposables backorder; needs dietitian menu refresh consult",
            "public_user_id": 16,
            "supplier_rebate_margin_pct": 15.3,
        },
        # Email Territory (South Central — hidden from P4 by RLS; visible to P1 & P3)
        {
            "account_id": "HLF-SC-401",
            "customer_name": "[DEMO] Red River University Dining Services",
            "segment": "Education",
            "sales_territory": "Email",
            "assigned_rep": "Trevor Holloway",
            "weekly_revenue_usd": 71500.0,
            "qoq_case_volume_change_pct": 6.2,
            "late_deliveries_90d": 0,
            "churn_risk_tier": "LOW",
            "primary_pain_point": "High growth account; eligible for tier-2 volume drop-size incentive",
            "public_user_id": 46,
            "supplier_rebate_margin_pct": 13.7,
        },
    ]

    load_job = client.load_table_from_json(rows, table_fqn)
    load_job.result()
    print(f"  -> Loaded {len(rows)} [DEMO] HarvestLine Foodservice (HLF) account rows into {table_fqn}.")

    print("=== 3. Applying BigQuery Row Access Policies (RLS) ===")
    rls_statements = [
        f"""
        CREATE OR REPLACE ROW ACCESS POLICY rlp_midwest_organic_dsm
        ON `{table_fqn}`
        GRANT TO ('serviceAccount:ge-test-p4@{PROJECT_ID}.iam.gserviceaccount.com')
        FILTER USING (sales_territory = 'Organic')
        """,
        f"""
        CREATE OR REPLACE ROW ACCESS POLICY rlp_all_territories
        ON `{table_fqn}`
        GRANT TO (
            'serviceAccount:ge-test-p1@{PROJECT_ID}.iam.gserviceaccount.com',
            'serviceAccount:ge-test-p2@{PROJECT_ID}.iam.gserviceaccount.com',
            'serviceAccount:ge-test-p3@{PROJECT_ID}.iam.gserviceaccount.com',
            'user:admin@heygreg.altostrat.com',
            'user:heygreg@heygreg.altostrat.com'
        )
        FILTER USING (TRUE)
        """,
    ]
    for stmt in rls_statements:
        client.query(stmt, location="US").result()
    print("  -> Applied RLS policies `rlp_midwest_organic_dsm` (P4 -> Organic only) and `rlp_all_territories` (P1/P2/P3).")


def cleanup_existing_p1_drive_items(p1_token: str) -> None:
    """Deletes any existing items owned by ge-test-p1 so no legacy GFS items remain in Drive."""
    headers = {"Authorization": f"Bearer {p1_token}"}
    with httpx.Client(timeout=20.0) as http_client:
        resp = http_client.get(
            "https://www.googleapis.com/drive/v3/files",
            params={"q": "'me' in owners and trashed = false", "fields": "files(id,name)"},
            headers=headers,
        )
        if resp.status_code == 200:
            for item in resp.json().get("files", []):
                del_resp = http_client.delete(
                    f"https://www.googleapis.com/drive/v3/files/{item['id']}",
                    headers=headers,
                )
                print(f"  -> Deleted old Drive item {item['id']} ({item['name']}): HTTP {del_resp.status_code}")


def create_drive_doc(
    p1_token: str,
    title: str,
    body_text: str,
    share_with_emails: list[str],
    audience_label: str,
    gdoc_url: str,
) -> dict:
    """Creates a live Drive v3 resource using P1's OAuth token and shares it via Drive permissions API."""
    metadata = {
        "name": title,
        "mimeType": "application/vnd.google-apps.folder",
        "description": body_text,
    }
    headers = {
        "Authorization": f"Bearer {p1_token}",
        "Content-Type": "application/json",
    }
    with httpx.Client(timeout=20.0) as http_client:
        resp = http_client.post(
            "https://www.googleapis.com/drive/v3/files",
            json=metadata,
            headers=headers,
        )
        resp.raise_for_status()
        doc_id = resp.json()["id"]

        for email in share_with_emails:
            perm_resp = http_client.post(
                f"https://www.googleapis.com/drive/v3/files/{doc_id}/permissions",
                params={"sendNotificationEmail": "false"},
                headers=headers,
                json={
                    "role": "reader",
                    "type": "user",
                    "emailAddress": email,
                },
            )
            if perm_resp.status_code not in (200, 201):
                print(f"  [warn] permission grant for {email} on {doc_id}: {perm_resp.status_code} {perm_resp.text}")

    return {
        "doc_id": doc_id,
        "gdoc_url": gdoc_url,
        "title": title,
        "audience": audience_label,
        "shared_with": [f"ge-test-p1@{PROJECT_ID}.iam.gserviceaccount.com"] + share_with_emails,
    }


def setup_google_drive_docs() -> list[dict]:
    print("=== 4. Cleaning Up Old Drive Items & Creating 2 [DEMO] HarvestLine Foodservice Playbooks ===")
    p1_sa = f"ge-test-p1@{PROJECT_ID}.iam.gserviceaccount.com"
    p1_token = get_token(impersonate_sa=p1_sa)
    cleanup_existing_p1_drive_items(p1_token)

    doc1_text = """# [DEMO] HarvestLine Foodservice — Sales Coaching Playbook: Churn Recovery & Cold-Chain Drops
Document ID: HLF-SOP-COACH-2026-01
Audience: All District Sales Managers (DSMs), Customer Development Specialists (CDS), and Sales Enablement Analysts

## 1. Trigger Thresholds for Mandatory Rep Coaching
A HarvestLine Foodservice (HLF) account enters mandatory DSM coaching intervention when ANY of the following BigQuery telemetry thresholds occur:
- **CRITICAL Tier**: QoQ case volume drop worse than -15.0% OR >= 4 late cold-chain deliveries in 90 days.
- **HIGH Tier**: QoQ case volume drop between -8.0% and -15.0% OR 2-3 late cold-chain deliveries in 90 days.

## 2. Step-by-Step Rep Coaching Playbook by Pain Point
### Playbook A: Cold-Chain / Reefer Delivery Service Failures (>= 2 Late Drops or Temp Excursions)
1. **Immediate 24-Hour Joint Account Call**: DSM and assigned rep must conduct an on-site kitchen walk-through with the Executive Chef / Dietary Director within 48 hours.
2. **Route Window & QA Audit**: Pull Reefer Telemetry logs and move the account to a priority morning dock window. Issue an immediate HarvestLine Quality Assurance credit for any temperature-excursion SKU.
3. **Center-of-Plate Retention Lock**: When a customer shifts poultry or produce to a competing broadline distributor after late drops, coach the rep to offer a 60-day service-level guarantee paired with HarvestLine Reserve center-of-plate spec matching.

### Playbook B: Drop-Size Erosion & Specialty Stockouts (Independent Restaurants)
1. **Drop-Size Consolidation**: If average drop falls below 65 cases, review twice-weekly vs. thrice-weekly delivery routing to unlock the HarvestLine Drop-Size Efficiency credit.
2. **Culinary Specialist Pairing**: Schedule a HarvestLine Culinary Specialist menu-engineering consult and provide pre-approved HarvestLine Signature portion-cut alternatives for out-of-stock specialty cheeses or sub-primals.
"""

    doc2_text = """# [DEMO] HarvestLine Foodservice — Executive Margin & Supplier Rebate Guide [CONFIDENTIAL]
Document ID: HLF-EXEC-REBATE-2026-99
Classification: STRICTLY CONFIDENTIAL — Restricted to National VP of Sales (P1)
WARNING: Do NOT share raw supplier_rebate_margin_pct figures with field reps or standard analysts.

## 1. Authorized Executive Rebate Re-Investment Tiers
When a CRITICAL or HIGH churn-risk account has a `supplier_rebate_margin_pct` above 14.0% in BigQuery (`hlf_sim_sales.account_performance`):
- **Tier 1 Executive Save (Supplier Rebate Margin >= 18.0%)**:
  - Authorized to re-invest up to **4.5% of gross invoice value** as a quarterly volume retention rebate if the customer signs a 12-month Prime Vendor renewal.
  - Eligible accounts include high-margin independent restaurant groups and hospitality resorts (`HLF-MW-102`, `HLF-MW-104`, `HLF-NE-202`).
- **Tier 2 Healthcare & Hospitality Systems Save (Supplier Rebate Margin 14.0% - 17.9%)**:
  - Authorized to re-invest up to **2.75% of gross invoice value** in contracted manufacturer deviated pricing, plus waive fuel surcharges for 90 days during RFP defense (`HLF-MW-101`, `HLF-NE-201`, `HLF-SE-301`).
"""

    doc1 = create_drive_doc(
        p1_token=p1_token,
        title="[DEMO] HarvestLine Foodservice — Sales Coaching Playbook: Churn Recovery & Cold-Chain Drops",
        body_text=doc1_text,
        share_with_emails=[
            f"ge-test-p3@{PROJECT_ID}.iam.gserviceaccount.com",
            f"ge-test-p4@{PROJECT_ID}.iam.gserviceaccount.com",
            "admin@heygreg.altostrat.com",
        ],
        audience_label="Standard Coaching Playbook (Shared with P1, P3, P4; Denied to P6)",
        gdoc_url="https://docs.google.com/document/d/1KP1umCeq025JOg86FJEc3N4eE9KM9LGVMZP26J-LHsI/edit",
    )
    print(f"  -> Created Doc 1: {doc1['doc_id']} ({doc1['title']}) -> {doc1['gdoc_url']}")

    doc2 = create_drive_doc(
        p1_token=p1_token,
        title="[DEMO] HarvestLine Foodservice — Executive Margin & Supplier Rebate Guide [CONFIDENTIAL]",
        body_text=doc2_text,
        share_with_emails=[
            "admin@heygreg.altostrat.com",
        ],
        audience_label="Executive Confidential Playbook (Shared ONLY with P1; Denied to P3, P4, P6)",
        gdoc_url="https://docs.google.com/document/d/1WhoC6UHXb87Hi2HrpFGwA1WaBBnQn3t7hoAP4uvBEmc/edit",
    )
    print(f"  -> Created Doc 2: {doc2['doc_id']} ({doc2['title']}) -> {doc2['gdoc_url']}")

    config_payload = {
        "project_id": PROJECT_ID,
        "dataset_id": DATASET_ID,
        "table_id": TABLE_ID,
        "policy_tag": POLICY_TAG,
        "drive_docs": [doc1, doc2],
    }
    CONFIG_PATH.write_text(json.dumps(config_payload, indent=2), encoding="utf-8")
    print(f"  -> Wrote generated resource config to {CONFIG_PATH}")
    return [doc1, doc2]


if __name__ == "__main__":
    setup_bigquery()
    setup_google_drive_docs()
    print("=== [DEMO] HarvestLine Foodservice (HLF) SIM Demo Resources Provisioned Successfully ===")
