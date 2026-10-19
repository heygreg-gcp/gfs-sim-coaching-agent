# GFS Sales Insight Manager (SIM) Cross-Project BigQuery + Google Drive Coaching Agent — Design Spec

**Date:** 2026-10-19
**Project:** `heygreg-telco-demo` (`395808028747`) + Cross-Project Join to `bigquery-public-data` + Real Google Drive Coaching Playbooks
**Target Use Case:** Gordon Food Service (GFS) Flagship Proof-of-Value (`Sales Insight Manager / Sales Manager Coaching Agent`, Decision `W1`, Gaps `G2`, `G3a`, `G3b` / `b/568413600`, and `b/570110182`)

---

## 1. Problem Statement & First-Principles Foundation

GFS's #1 flagship agentic use case—the **Sales Insight Manager (SIM) / Sales Manager Coaching Agent**—requires a single conversational agent registered in Gemini Enterprise that:
1. **Combines structured BigQuery sales/delivery telemetry with unstructured Google Drive coaching playbooks in a single turn** (closing **Gap `G3a`**).
2. **Queries BigQuery across projects** while billing `bigquery.jobs.insert` to the Agent/GE host project (`heygreg-telco-demo`) and reading datasets in a separate data project (`bigquery-public-data` + `heygreg-telco-demo.gfs_sim_sales`), with explicit error classification distinguishing **VPC-SC perimeter blocks** from **IAM permission denials** and **Column Policy Tag denials** (closing **Gap `G3b` / `b/568413600`**).
3. **Propagates the end-user's 3LO OAuth token (`X-Goog-Agent-User-Authorization` / `Authorization`)** to both BigQuery and Google Drive so that:
   - BigQuery **Row-Level Security (RLS)** restricts regional District Sales Managers (`ge-test-p4`) to their assigned territory (`Organic`),
   - BigQuery **Column-Level Security (Data Catalog Policy Tags)** blocks unauthorized analysts (`ge-test-p3`) from reading confidential supplier rebate margins (`supplier_rebate_margin_pct`),
   - A **hard server-side SQL table allowlist** prevents over-privileged users (`ge-test-p1`) from querying unapproved tables through the agent (closing **Gap `G2`**), and
   - **Google Drive per-document ACLs** restrict confidential executive rebate playbooks to `ge-test-p1` while allowing standard coaching playbooks for `ge-test-p1`, `ge-test-p3`, and `ge-test-p4`.

---

## 2. Architecture

### 2.1 Dual-Header 3LO OAuth Extraction (`app/auth.py`)
Per `cloud/ml/discoveryengine/dolphin/python_agent/sub_agents/a2a_agent.py:1475-1551`:
- When Gemini Enterprise invokes a **Cloud Run** A2A endpoint (`*.run.app`), the Discovery Engine Service Agent OIDC token is placed in `X-Serverless-Authorization` while the **end user's 3LO OAuth token** is sent in `Authorization: Bearer <user_token>`.
- When Gemini Enterprise invokes a **Vertex AI Agent Engine V2** A2A endpoint (`reasoningEngines`), the Discovery Engine Service Agent token is placed in `Authorization` while the **end user's 3LO OAuth token** is moved to `X-Goog-Agent-User-Authorization: Bearer <user_token>`.
- `extract_user_oauth_token(headers)` inspects `X-Goog-Agent-User-Authorization` first, then falls back to `Authorization`, strips the `Bearer ` prefix, validates the token format, and constructs a short-lived `google.oauth2.credentials.Credentials(token=raw_token)` object per request. It **never** falls back to a privileged runtime service account for data access (fail-closed per Principle of Least Privilege).

### 2.2 Cross-Project BigQuery Tool (`app/tools_bq.py`)
- **Table Allowlist Guardrail**: Only permits queries against `heygreg-telco-demo.gfs_sim_sales.account_performance` and `bigquery-public-data.thelook_ecommerce.users`. Any attempt to reference another table (such as `ge_access_test_forbidden_b.forbidden_users`) is rejected before calling BigQuery.
- **Parameterized Queries Only**: Uses `google.cloud.bigquery.QueryJobConfig(query_parameters=[...])` exclusively—never string interpolation on user inputs.
- **Cross-Project Execution**: Initializes `bigquery.Client(project="heygreg-telco-demo", credentials=user_creds)` so `bigquery.jobs.create` is checked and billed on `heygreg-telco-demo` while reading `heygreg-telco-demo.gfs_sim_sales.account_performance` joined with `bigquery-public-data.thelook_ecommerce.users`.
- **Clean Error Classifier (`classify_bq_error`)**: Inspects `google.api_core.exceptions.Forbidden` / `BadRequest` payloads and classifies failures into:
  - `VPC_SERVICE_CONTROLS_VIOLATION` (`reason == "VPC_SERVICE_CONTROLS"`)
  - `POLICY_TAG_ACCESS_DENIED` (Data Catalog fine-grained reader denial on `supplier_rebate_margin_pct`)
  - `JOB_USER_PERMISSION_DENIED` (missing `bigquery.jobs.create` on billing project)
  - `DATASET_ACCESS_DENIED` (missing `bigquery.tables.getData` on dataset)

### 2.3 Google Drive Coaching Playbook Tool (`app/tools_drive.py`)
- Uses the caller's `Credentials(token=raw_token)` to query `https://www.googleapis.com/drive/v3/files` (scoped to the created GFS coaching doc IDs) and exports content as `text/plain` using raw bytes (`response.content.decode("utf-8", errors="ignore")`).
- Because each request carries the calling persona's OAuth token, Google Drive natively enforces file-level sharing ACLs:
  - **Doc 1 (`GFS Sales Coaching Playbook: Churn Recovery & Cold-Chain Service Drops`)**: Accessible to `ge-test-p1`, `ge-test-p3`, `ge-test-p4`.
  - **Doc 2 (`GFS Executive Margin & Supplier Rebate Negotiation Guide [CONFIDENTIAL]`)**: Accessible **only** to `ge-test-p1`.

### 2.4 Unified SIM Coaching Orchestrator & A2A + Web Demo Server (`app/agent.py`, `app/server.py`)
- Combines BigQuery KPI retrieval + Google Drive playbook retrieval + Gemini 2.5 Flash coaching synthesis in a single turn.
- Exposes:
  - `GET /.well-known/agent.json`: A2A Agent Card for Gemini Enterprise registration.
  - `POST /v1/message:stream` and `POST /api/chat`: Accepts either a direct caller `Authorization` / `X-Goog-Agent-User-Authorization` header or (in local demo mode bound to `127.0.0.1` / authenticated Cloudtop session) a server-side persona selector (`P1`, `P4`, `P3`, `P6`) that mints a short-lived impersonated OAuth token for that service account and passes it through the exact same `Authorization` header pipeline.
  - Strict security headers (`Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Cache-Control: no-store`) and safe DOM manipulation (`createElement` / `textContent`, zero `innerHTML`).
