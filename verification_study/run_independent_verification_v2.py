#!/usr/bin/env python3
"""Independent Verification Run #2 (v2) for BigQuery & Gemini Enterprise Access Control.

Uses a completely different dataset domain (Credit Card Default & Census Income from
bigquery-public-data.ml_datasets), brand-new datasets, a brand-new Policy Tag, a brand-new
Row Access Policy, 5 brand-new service account principals (ge-v2-alpha through ge-v2-omega),
and a brand-new published BigQuery Data Agent (ge_verify_v2_credit_agent) registered in
Gemini Enterprise.
"""

import json
import subprocess
import time
from typing import Any
import google.auth
import google.auth.transport.requests
import google.oauth2.credentials
from google.cloud import bigquery
import requests

PROJECT_ID = "heygreg-telco-demo"
PROJECT_NUMBER = "395808028747"
LOCATION = "us"
TAXONOMY_ID = "projects/heygreg-telco-demo/locations/us/taxonomies/3838347283155594953"
ENGINE_ID = "ge-bq-access-test-engine"

DS_PERMITTED = "ge_verify_v2_permitted"
DS_RESTRICTED = "ge_verify_v2_restricted"
TBL_PERMITTED = "credit_accounts"
TBL_RESTRICTED = "census_income_records"
DATA_AGENT_ID = "ge_verify_v2_credit_agent"

PRINCIPALS = {
    "alpha": {
        "sa_id": "ge-v2-alpha",
        "desc": "Full access across Permitted + Restricted datasets, FineGrainedReader, all RLS rows",
    },
    "beta": {
        "sa_id": "ge-v2-beta",
        "desc": "Permitted dataset ONLY, FineGrainedReader, all RLS rows, NO roles/datacatalog.viewer",
    },
    "gamma": {
        "sa_id": "ge-v2-gamma",
        "desc": "Permitted dataset, all RLS rows, NO FineGrainedReader on policy tag (CLS restricted)",
    },
    "delta": {
        "sa_id": "ge-v2-delta",
        "desc": "Permitted dataset, FineGrainedReader, RLS restricted to education_level = '1' ONLY",
    },
    "omega": {
        "sa_id": "ge-v2-omega",
        "desc": "GE + GDA agent user only, ZERO BigQuery roles (tests whether Service Agent BQ grants help)",
    },
}


def get_admin_token() -> str:
  return subprocess.check_output(
      ["gcloud", "auth", "print-access-token"], text=True
  ).strip()


def get_sa_token(sa_email: str) -> str:
  """Mint an OAuth2 access token for a test service account via gcloud impersonation."""
  return subprocess.check_output(
      [
          "gcloud",
          "auth",
          "print-access-token",
          f"--impersonate-service-account={sa_email}",
      ],
      text=True,
      stderr=subprocess.DEVNULL,
  ).strip()


def ensure_service_accounts() -> dict[str, str]:
  admin_token = get_admin_token()
  headers = {
      "Authorization": f"Bearer {admin_token}",
      "X-Goog-User-Project": PROJECT_ID,
  }
  emails = {}
  for key, info in PRINCIPALS.items():
    sa_id = info["sa_id"]
    sa_email = f"{sa_id}@{PROJECT_ID}.iam.gserviceaccount.com"
    emails[key] = sa_email
    url = f"https://iam.googleapis.com/v1/projects/{PROJECT_ID}/serviceAccounts/{sa_email}"
    r = requests.get(url, headers=headers, timeout=20)
    if r.status_code == 404:
      create_url = f"https://iam.googleapis.com/v1/projects/{PROJECT_ID}/serviceAccounts"
      cr = requests.post(
          create_url,
          headers=headers,
          json={
              "accountId": sa_id,
              "serviceAccount": {
                  "displayName": f"GE Verify V2 {key.upper()}",
                  "description": info["desc"],
              },
          },
          timeout=20,
      )
      cr.raise_for_status()
      print(f"[+] Created SA: {sa_email}")
    else:
      print(f"[=] SA exists: {sa_email}")
    # Ensure serviceAccountTokenCreator is granted directly on the SA resource
    sa_iam_url = f"https://iam.googleapis.com/v1/projects/{PROJECT_ID}/serviceAccounts/{sa_email}:setIamPolicy"
    ir = requests.post(
        sa_iam_url,
        headers=headers,
        json={
            "policy": {
                "bindings": [{
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "members": [
                        "user:admin@heygreg.altostrat.com",
                        "user:heygreg@heygreg.altostrat.com",
                    ],
                }]
            }
        },
        timeout=20,
    )
    ir.raise_for_status()
  return emails


def ensure_policy_tag() -> str:
  admin_token = get_admin_token()
  url = f"https://datacatalog.googleapis.com/v1/{TAXONOMY_ID}/policyTags"
  r = requests.get(
      url,
      headers={
          "Authorization": f"Bearer {admin_token}",
          "X-Goog-User-Project": PROJECT_ID,
      },
      timeout=20,
  )
  r.raise_for_status()
  for pt in r.json().get("policyTags", []):
    if pt.get("displayName") == "credit_limit_confidential_v2":
      print(f"[=] Policy tag exists: {pt['name']}")
      return pt["name"]
  cr = requests.post(
      url,
      headers={
          "Authorization": f"Bearer {admin_token}",
          "X-Goog-User-Project": PROJECT_ID,
      },
      json={
          "displayName": "credit_limit_confidential_v2",
          "description": "Run #2 CLS tag protecting credit limit_balance column",
      },
      timeout=20,
  )
  cr.raise_for_status()
  pt_name = cr.json()["name"]
  print(f"[+] Created Policy tag: {pt_name}")
  return pt_name


def setup_datasets_and_tables(sa_emails: dict[str, str], policy_tag_name: str) -> None:
  client = bigquery.Client(
      project=PROJECT_ID,
      credentials=google.oauth2.credentials.Credentials(token=get_admin_token()),
  )

  for ds_id in [DS_PERMITTED, DS_RESTRICTED]:
    ds_ref = bigquery.Dataset(f"{PROJECT_ID}.{ds_id}")
    ds_ref.location = "US"
    ds = client.create_dataset(ds_ref, exists_ok=True)
    # Strip projectReaders and projectWriters so only explicit dataset IAM applies
    clean_entries = [
        e
        for e in ds.access_entries
        if e.special_group not in ("projectReaders", "projectWriters", "allAuthenticatedUsers")
    ]
    # Add dataset-specific viewer bindings
    if ds_id == DS_PERMITTED:
      for k in ["alpha", "beta", "gamma", "delta"]:
        clean_entries.append(
            bigquery.AccessEntry("READER", "userByEmail", sa_emails[k])
        )
      # Also grant Google-managed service agents READER on Permitted dataset to prove
      # service-agent dataset access does NOT let 'omega' query data!
      clean_entries.append(
          bigquery.AccessEntry(
              "READER",
              "userByEmail",
              f"service-{PROJECT_NUMBER}@gcp-sa-discoveryengine.iam.gserviceaccount.com",
          )
      )
      clean_entries.append(
          bigquery.AccessEntry(
              "READER",
              "userByEmail",
              f"service-{PROJECT_NUMBER}@gcp-sa-geminidataanalytics.iam.gserviceaccount.com",
          )
      )
    elif ds_id == DS_RESTRICTED:
      clean_entries.append(
          bigquery.AccessEntry("READER", "userByEmail", sa_emails["alpha"])
      )
    ds.access_entries = clean_entries
    client.update_dataset(ds, ["access_entries"])
    print(f"[+] Configured stripped ACLs on dataset {ds_id} ({len(clean_entries)} entries)")

  # Populate Permitted Table from bigquery-public-data.ml_datasets.credit_card_default
  q_permitted = f"""
  CREATE OR REPLACE TABLE `{PROJECT_ID}.{DS_PERMITTED}.{TBL_PERMITTED}` AS
  WITH sampled AS (
    SELECT
      CAST(id AS INT64) AS account_id,
      CAST(education_level AS STRING) AS education_level,
      CAST(marital_status AS STRING) AS marital_status,
      CAST(age AS INT64) AS holder_age,
      CAST(limit_balance AS FLOAT64) AS limit_balance,
      CAST(bill_amt_1 AS FLOAT64) AS latest_bill_amount,
      CAST(default_payment_next_month AS STRING) AS default_flag,
      ROW_NUMBER() OVER (PARTITION BY education_level ORDER BY id) AS rn
    FROM `bigquery-public-data.ml_datasets.credit_card_default`
    WHERE education_level IN ('1', '2', '3')
  )
  SELECT
    account_id,
    education_level,
    marital_status,
    holder_age,
    limit_balance,
    latest_bill_amount,
    default_flag
  FROM sampled
  WHERE rn <= 30
  """
  client.query(q_permitted).result()
  print(f"[+] Populated {DS_PERMITTED}.{TBL_PERMITTED} (90 rows across 3 education_level partitions)")

  # Attach Policy Tag to limit_balance
  tbl = client.get_table(f"{PROJECT_ID}.{DS_PERMITTED}.{TBL_PERMITTED}")
  new_schema = []
  for field in tbl.schema:
    if field.name == "limit_balance":
      new_schema.append(
          bigquery.SchemaField(
              name=field.name,
              field_type=field.field_type,
              mode=field.mode,
              policy_tags=bigquery.PolicyTagList([policy_tag_name]),
          )
      )
    else:
      new_schema.append(field)
  tbl.schema = new_schema
  client.update_table(tbl, ["schema"])
  print(f"[+] Attached policy tag to {DS_PERMITTED}.{TBL_PERMITTED}.limit_balance")

  # Create Row Access Policies on credit_accounts
  rls_all_sql = f"""
  CREATE OR REPLACE ROW ACCESS POLICY rls_all_edu_levels
  ON `{PROJECT_ID}.{DS_PERMITTED}.{TBL_PERMITTED}`
  GRANT TO (
    'serviceAccount:{sa_emails["alpha"]}',
    'serviceAccount:{sa_emails["beta"]}',
    'serviceAccount:{sa_emails["gamma"]}',
    'user:admin@heygreg.altostrat.com'
  )
  FILTER USING (TRUE)
  """
  client.query(rls_all_sql).result()

  rls_edu1_sql = f"""
  CREATE OR REPLACE ROW ACCESS POLICY rls_edu_level_1
  ON `{PROJECT_ID}.{DS_PERMITTED}.{TBL_PERMITTED}`
  GRANT TO ('serviceAccount:{sa_emails["delta"]}')
  FILTER USING (education_level = '1')
  """
  client.query(rls_edu1_sql).result()
  print(f"[+] Applied Row Access Policies rls_all_edu_levels & rls_edu_level_1")

  # Populate Restricted Table from bigquery-public-data.ml_datasets.census_adult_income
  q_restricted = f"""
  CREATE OR REPLACE TABLE `{PROJECT_ID}.{DS_RESTRICTED}.{TBL_RESTRICTED}` AS
  SELECT
    age,
    TRIM(workclass) AS workclass,
    TRIM(education) AS education,
    TRIM(occupation) AS occupation,
    capital_gain,
    hours_per_week,
    TRIM(income_bracket) AS income_bracket
  FROM `bigquery-public-data.ml_datasets.census_adult_income`
  LIMIT 50
  """
  client.query(q_restricted).result()
  print(f"[+] Populated {DS_RESTRICTED}.{TBL_RESTRICTED} (50 rows)")


def configure_iam_bindings(sa_emails: dict[str, str], policy_tag_name: str) -> None:
  admin_token = get_admin_token()
  headers = {
      "Authorization": f"Bearer {admin_token}",
      "X-Goog-User-Project": PROJECT_ID,
  }

  # 1. Policy Tag FineGrainedReader for alpha, beta, delta (NOT gamma, NOT omega)
  pt_iam_url = f"https://datacatalog.googleapis.com/v1/{policy_tag_name}:setIamPolicy"
  pt_members = [
      f"serviceAccount:{sa_emails['alpha']}",
      f"serviceAccount:{sa_emails['beta']}",
      f"serviceAccount:{sa_emails['delta']}",
      "user:admin@heygreg.altostrat.com",
  ]
  r = requests.post(
      pt_iam_url,
      headers=headers,
      json={
          "policy": {
              "bindings": [{
                  "role": "roles/datacatalog.categoryFineGrainedReader",
                  "members": pt_members,
              }]
          }
      },
      timeout=20,
  )
  r.raise_for_status()
  print("[+] Configured FineGrainedReader on policy tag for alpha, beta, delta (excluded gamma)")

  # 2. Project-level IAM bindings
  crm_get_url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT_ID}:getIamPolicy"
  pr = requests.post(crm_get_url, headers=headers, json={}, timeout=20)
  pr.raise_for_status()
  policy = pr.json()

  role_map: dict[str, set[str]] = {}
  for b in policy.get("bindings", []):
    role_map[b["role"]] = set(b.get("members", []))

  def add_role(role: str, member: str):
    role_map.setdefault(role, set()).add(member)

  add_role("roles/iam.serviceAccountTokenCreator", "user:admin@heygreg.altostrat.com")

  # All 5 principals get GE & GDA & cloudaicompanion & mcp.toolUser so they can reach the agents/MCP
  for k in ["alpha", "beta", "gamma", "delta", "omega"]:
    m = f"serviceAccount:{sa_emails[k]}"
    add_role("roles/discoveryengine.agentspaceUser", m)
    add_role("roles/geminidataanalytics.dataAgentUser", m)
    add_role("roles/cloudaicompanion.user", m)
    add_role("roles/mcp.toolUser", m)

  # Only alpha, beta, gamma, delta get bigquery.jobUser (omega has ZERO BigQuery roles)
  for k in ["alpha", "beta", "gamma", "delta"]:
    m = f"serviceAccount:{sa_emails[k]}"
    add_role("roles/bigquery.jobUser", m)

  # Ensure service agents have bigquery.jobUser at project level to prove service-agent grants don't help omega
  add_role(
      "roles/bigquery.jobUser",
      f"serviceAccount:service-{PROJECT_NUMBER}@gcp-sa-discoveryengine.iam.gserviceaccount.com",
  )
  add_role(
      "roles/bigquery.jobUser",
      f"serviceAccount:service-{PROJECT_NUMBER}@gcp-sa-geminidataanalytics.iam.gserviceaccount.com",
  )

  # Note: beta intentionally does NOT get roles/datacatalog.viewer!
  # Only alpha gets roles/datacatalog.viewer.
  add_role("roles/datacatalog.viewer", f"serviceAccount:{sa_emails['alpha']}")

  policy["bindings"] = [
      {"role": r, "members": sorted(list(ms))} for r, ms in role_map.items()
  ]
  crm_set_url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT_ID}:setIamPolicy"
  sr = requests.post(
      crm_set_url, headers=headers, json={"policy": policy}, timeout=30
  )
  sr.raise_for_status()
  print("[+] Updated project-level IAM bindings for ge-v2-alpha..omega")


def ensure_published_data_agent(sa_emails: dict[str, str]) -> str:
  admin_token = get_admin_token()
  headers = {
      "Authorization": f"Bearer {admin_token}",
      "X-Goog-User-Project": PROJECT_ID,
      "Content-Type": "application/json",
  }
  agent_name = f"projects/{PROJECT_ID}/locations/global/dataAgents/{DATA_AGENT_ID}"
  get_url = f"https://geminidataanalytics.googleapis.com/v1beta/{agent_name}"
  r = requests.get(get_url, headers=headers, timeout=20)
  payload = {
      "displayName": "GE Verify V2 Credit Accounts Agent",
      "description": "Run #2 verification data agent over ge_verify_v2_permitted.credit_accounts",
      "dataAnalyticsAgent": {
          "publishedContext": {
              "datasourceReferences": {
                  "bq": {
                      "tableReferences": [{
                          "projectId": PROJECT_ID,
                          "datasetId": DS_PERMITTED,
                          "tableId": TBL_PERMITTED,
                      }]
                  }
              },
              "systemInstruction": (
                  "You are a precise credit analytics data agent. Always query the "
                  f"`{PROJECT_ID}.{DS_PERMITTED}.{TBL_PERMITTED}` table using SQL to answer user questions."
              ),
          }
      },
  }
  if r.status_code == 404:
    create_url = f"https://geminidataanalytics.googleapis.com/v1beta/projects/{PROJECT_ID}/locations/global/dataAgents?data_agent_id={DATA_AGENT_ID}"
    cr = requests.post(create_url, headers=headers, json=payload, timeout=30)
    cr.raise_for_status()
    print(f"[+] Created Published GDA Data Agent: {agent_name}")
    time.sleep(3)
  else:
    print(f"[=] Published GDA Data Agent exists: {agent_name}")

  # Set IAM policy on the GDA Data Agent so alpha..omega have dataAgentUser
  iam_url = f"https://geminidataanalytics.googleapis.com/v1beta/{agent_name}:setIamPolicy"
  members = [f"serviceAccount:{sa_emails[k]}" for k in ["alpha", "beta", "gamma", "delta", "omega"]]
  members.append("user:admin@heygreg.altostrat.com")
  ir = requests.post(
      iam_url,
      headers=headers,
      json={
          "policy": {
              "bindings": [
                  {"role": "roles/geminidataanalytics.dataAgentOwner", "members": ["user:admin@heygreg.altostrat.com"]},
                  {"role": "roles/geminidataanalytics.dataAgentUser", "members": members},
              ]
          }
      },
      timeout=20,
  )
  ir.raise_for_status()
  print(f"[+] Granted dataAgentUser on {DATA_AGENT_ID} to ge-v2-alpha..omega")
  return agent_name


def call_gda_agent(token: str, prompt: str) -> dict[str, Any]:
  url = f"https://geminidataanalytics.googleapis.com/v1beta/a2a/projects/{PROJECT_ID}/locations/global/dataAgents/{DATA_AGENT_ID}/v1/message:stream"
  headers = {
      "Authorization": f"Bearer {token}",
      "X-Goog-User-Project": PROJECT_ID,
      "Content-Type": "application/json",
  }
  body = {
      "message": {
          "messageId": f"v2-{int(time.time()*1000)}",
          "role": "ROLE_USER",
          "content": [{"text": prompt}],
      }
  }
  r = requests.post(url, headers=headers, json=body, timeout=90)
  text_out = r.text
  return {
      "http_status": r.status_code,
      "snippet": text_out[:900],
      "has_error": ("error" in text_out.lower() and r.status_code != 200) or "Access Denied" in text_out or "permission" in text_out.lower(),
      "raw": text_out,
  }


def call_bq_mcp(token: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
  url = "https://bigquery.googleapis.com/mcp"
  headers = {
      "Authorization": f"Bearer {token}",
      "X-Goog-User-Project": PROJECT_ID,
      "Content-Type": "application/json",
  }
  payload = {
      "jsonrpc": "2.0",
      "id": 1,
      "method": "tools/call",
      "params": {"name": tool_name, "arguments": arguments},
  }
  r = requests.post(url, headers=headers, json=payload, timeout=30)
  return {
      "http_status": r.status_code,
      "body": r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text,
  }


def main():
  print("=== STARTING INDEPENDENT VERIFICATION RUN #2 (v2) ===")
  sa_emails = ensure_service_accounts()
  pt_name = ensure_policy_tag()
  setup_datasets_and_tables(sa_emails, pt_name)
  configure_iam_bindings(sa_emails, pt_name)
  ensure_published_data_agent(sa_emails)

  print("\n[*] Waiting 12 seconds for IAM propagation...")
  time.sleep(12)

  results: dict[str, Any] = {
      "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
      "project_id": PROJECT_ID,
      "datasets": {
          "permitted": f"{PROJECT_ID}.{DS_PERMITTED}.{TBL_PERMITTED}",
          "restricted": f"{PROJECT_ID}.{DS_RESTRICTED}.{TBL_RESTRICTED}",
      },
      "policy_tag": pt_name,
      "data_agent": f"projects/{PROJECT_ID}/locations/global/dataAgents/{DATA_AGENT_ID}",
      "principals": sa_emails,
      "mcp_tests": {},
      "gda_tests": {},
      "okta_token_test": {},
      "audit_log_jobs": [],
  }

  sql_safe_cols = f"SELECT education_level, COUNT(*) AS cnt, ROUND(AVG(latest_bill_amount), 2) AS avg_bill FROM `{PROJECT_ID}.{DS_PERMITTED}.{TBL_PERMITTED}` GROUP BY education_level ORDER BY education_level"
  sql_cls_col = f"SELECT education_level, ROUND(AVG(limit_balance), 2) AS avg_limit FROM `{PROJECT_ID}.{DS_PERMITTED}.{TBL_PERMITTED}` GROUP BY education_level ORDER BY education_level"
  sql_restricted_ds = f"SELECT education, COUNT(*) AS cnt FROM `{PROJECT_ID}.{DS_RESTRICTED}.{TBL_RESTRICTED}` GROUP BY education LIMIT 5"

  for key, email in sa_emails.items():
    print(f"\n--- Testing Principal {key.upper()} ({email}) ---")
    token = get_sa_token(email)

    # 1. MCP Path B tests
    mcp_safe = call_bq_mcp(token, "execute_sql", {"projectId": PROJECT_ID, "query": sql_safe_cols})
    mcp_cls = call_bq_mcp(token, "execute_sql", {"projectId": PROJECT_ID, "query": sql_cls_col})
    mcp_restr = call_bq_mcp(token, "execute_sql", {"projectId": PROJECT_ID, "query": sql_restricted_ds})
    results["mcp_tests"][key] = {
        "safe_query": mcp_safe,
        "cls_query": mcp_cls,
        "restricted_dataset_query": mcp_restr,
    }
    print(f"  [MCP] safe_query={mcp_safe['http_status']} | cls_query={mcp_cls['http_status']} | restricted_ds={mcp_restr['http_status']}")

    # 2. Published Data Agent Path A tests
    gda_safe = call_gda_agent(
        token,
        f"Run a SQL query on `{PROJECT_ID}.{DS_PERMITTED}.{TBL_PERMITTED}` grouping by education_level and returning COUNT(*) and AVG(latest_bill_amount). Do not select limit_balance.",
    )
    gda_cls = call_gda_agent(
        token,
        f"Run a SQL query on `{PROJECT_ID}.{DS_PERMITTED}.{TBL_PERMITTED}` returning AVG(limit_balance) grouped by education_level.",
    )
    results["gda_tests"][key] = {
        "safe_query": {"http_status": gda_safe["http_status"], "snippet": gda_safe["snippet"]},
        "cls_query": {"http_status": gda_cls["http_status"], "snippet": gda_cls["snippet"]},
    }
    print(f"  [GDA] safe_query={gda_safe['http_status']} | cls_query={gda_cls['http_status']}")

  # 3. Test Simulated Okta / 3P OAuth Access Token against BigQuery MCP & BigQuery REST API
  fake_okta_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im9rdGEtcustom-idp-keyIn0.eyJpc3MiOiJodHRwczovL2dmcy5va3RhLmNvbS9oauth2/defaultIiwic3ViIjoiYW1iZXIucHJhdXNlQGdmcy5jb20iLCJhdWQiOiJapi://defaultIn0.signature"
  okta_mcp_res = call_bq_mcp(fake_okta_jwt, "execute_sql", {"projectId": PROJECT_ID, "query": sql_safe_cols})
  results["okta_token_test"] = okta_mcp_res
  print(f"\n--- Testing Raw Okta JWT against BigQuery MCP: HTTP {okta_mcp_res['http_status']} ---")

  # 4. Query INFORMATION_SCHEMA.JOBS_BY_PROJECT to prove user_email for every Run #2 query
  client = bigquery.Client(
      project=PROJECT_ID,
      credentials=google.oauth2.credentials.Credentials(token=get_admin_token()),
  )
  audit_sql = f"""
  SELECT
    creation_time,
    job_id,
    user_email,
    statement_type,
    error_result.reason AS error_reason,
     LEFT( error_result.message, 140) AS error_message,
    LEFT(query, 120) AS query_prefix
  FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
  WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 15 MINUTE)
    AND user_email LIKE 'ge-v2-%@{PROJECT_ID}.iam.gserviceaccount.com'
  ORDER BY creation_time DESC
  LIMIT 40
  """
  audit_rows = [dict(row) for row in client.query(audit_sql).result()]
  for r in audit_rows:
    r["creation_time"] = str(r["creation_time"])
  results["audit_log_jobs"] = audit_rows
  print(f"\n[+] Captured {len(audit_rows)} INFORMATION_SCHEMA.JOBS_BY_PROJECT rows for ge-v2-* principals!")

  out_path = "/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/verification_study/independent_verification_v2_results.json"
  with open(out_path, "w") as f:
    json.dump(results, f, indent=2)
  print(f"[+] Saved full Run #2 JSON evidence to {out_path}")


if __name__ == "__main__":
  main()
