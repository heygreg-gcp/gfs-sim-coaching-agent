# GFS Sales Insight Manager (SIM) Cross-Project BigQuery + Google Drive Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and empirically verify a GFS Sales Insight Manager (SIM) ADK/A2A agent that combines cross-project BigQuery data (with Row-Level Security & Column-Level Policy Tags) and real Google Drive coaching playbooks in a single turn using end-user 3LO OAuth token passthrough.

**Architecture:** A modular Python FastAPI + Google GenAI / ADK application (`app/auth.py`, `app/tools_bq.py`, `app/tools_drive.py`, `app/agent.py`, `app/server.py`) backed by live BigQuery tables (`heygreg-telco-demo.gfs_sim_sales.account_performance` joined cross-project with `bigquery-public-data.thelook_ecommerce.users`) and real Google Docs in Google Drive shared per persona (`ge-test-p1`, `ge-test-p3`, `ge-test-p4`, `ge-test-p6`).

**Tech Stack:** Python 3.11+, `google-cloud-bigquery`, `google-auth`, `google-genai`, `fastapi`, `uvicorn`, `httpx`, `pytest`.

---

### Task 1: Dual-Header 3LO OAuth Extractor & Error Classifier (`app/auth.py`, `app/tools_bq.py`)

**Files:**
- Create: `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/app/__init__.py`
- Create: `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/app/auth.py`
- Create: `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/app/tools_bq.py`
- Create: `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/app/tools_drive.py`
- Test: `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/tests/test_unit_tools.py`

- [ ] **Step 1: Write the failing unit tests** in `tests/test_unit_tools.py` testing:
  1. `extract_user_oauth_token` prioritizing `X-Goog-Agent-User-Authorization` over `Authorization` (matching `a2a_agent.py:1475-1551`) and failing closed when missing.
  2. `validate_table_allowlist` permitting `heygreg-telco-demo.gfs_sim_sales.account_performance` and `bigquery-public-data.thelook_ecommerce.users` while rejecting `ge_access_test_forbidden_b.forbidden_users`.
  3. `classify_bq_error` distinguishing `VPC_SERVICE_CONTROLS`, `POLICY_TAG_ACCESS_DENIED`, `JOB_USER_PERMISSION_DENIED`, and `DATASET_ACCESS_DENIED`.
  4. `search_gfs_coaching_playbooks` decoding Google Drive export bytes using `raw_bytes.decode("utf-8", errors="ignore")` and respecting Drive 403/404 per-user ACL filtering.
- [ ] **Step 2: Run `pytest tests/test_unit_tools.py` to verify RED**
- [ ] **Step 3: Implement `app/auth.py`, `app/tools_bq.py`, and `app/tools_drive.py`**
- [ ] **Step 4: Run `pytest tests/test_unit_tools.py` to verify GREEN**

### Task 2: Provision Live BigQuery (`gfs_sim_sales` with RLS & Policy Tags) & Real Google Docs in Drive

**Files:**
- Create: `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/scripts/setup_demo_resources.py`
- Create: `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/scripts/teardown_demo_resources.sh`

- [ ] **Step 1: Create and run `scripts/setup_demo_resources.py`** to:
  1. Create dataset `heygreg-telco-demo:gfs_sim_sales` (stripping default `projectReaders` ACLs so only explicit grants apply).
  2. Create table `heygreg-telco-demo.gfs_sim_sales.account_performance` with 16 realistic GFS foodservice accounts across 4 territories (`Organic`, `Search`, `Display`, `Email`), linked via `public_user_id` to `bigquery-public-data.thelook_ecommerce.users.id`, with `supplier_rebate_margin_pct` tagged with policy tag `projects/heygreg-telco-demo/locations/us/taxonomies/6890567710194462441/policyTags/1587113067653520593` (`pii_email_tag`).
  3. Create Row Access Policy `rlp_midwest_organic_dsm` on `account_performance` (`FILTER USING (sales_territory = 'Organic')`) granted to `serviceAccount:ge-test-p4@heygreg-telco-demo.iam.gserviceaccount.com`, and `rlp_all_territories` (`FILTER USING (TRUE)`) granted to `ge-test-p1`, `ge-test-p2`, `ge-test-p3`, and `heygreg@heygreg.altostrat.com`.
  4. Grant dataset `READER` (`roles/bigquery.dataViewer`) on `gfs_sim_sales` to `ge-test-p1`, `ge-test-p2`, `ge-test-p3`, and `ge-test-p4` (NOT `ge-test-p5` or `ge-test-p6`).
  5. Create 2 real Google Docs in Google Drive:
     - Doc 1: `GFS Sales Coaching Playbook: Churn Recovery & Cold-Chain Service Drops` (shared `reader` with `ge-test-p1`, `ge-test-p3`, `ge-test-p4`).
     - Doc 2: `GFS Executive Margin & Supplier Rebate Negotiation Guide [CONFIDENTIAL]` (shared `reader` with `ge-test-p1` ONLY).
  6. Save the created Doc IDs to `app/config_generated.json`.

### Task 3: Implement Unified SIM Agent, A2A Endpoint & Secure Persona-Switcher Web UI (`app/agent.py`, `app/server.py`, `web/index.html`)

**Files:**
- Create: `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/app/agent.py`
- Create: `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/app/server.py`
- Create: `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/web/index.html`
- Test: `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent/tests/test_integration_personas.py`

- [ ] **Step 1: Write the failing integration test suite (`tests/test_integration_personas.py`)** verifying real live execution across `P1`, `P4`, `P3`, and `P6`.
- [ ] **Step 2: Implement `app/agent.py` and `app/server.py` + `web/index.html`** (using safe DOM `createElement`/`textContent`, strict CSP headers, and parameterized SQL).
- [ ] **Step 3: Run `pytest` across unit and integration tests and verify 100% pass rate.**

### Task 4: Create GitHub Repository (`heygreg-gcp/gfs-sim-coaching-agent`), Push & Launch Live Preview Server

- [ ] **Step 1: Initialize Git repo in `/usr/local/google/home/heygreg/Repos/gfs-sim-coaching-agent`, commit all code, docs, and verification study files.**
- [ ] **Step 2: Create GitHub repo under `heygreg-gcp/gfs-sim-coaching-agent` and push `main`.**
- [ ] **Step 3: Start the live demo server and trigger IDE port forwarding.**

---

## Verification Plan

### Automated Security Check
- **Security Guidelines Enforcement**:
  - **SQL Injection Prevention**: All BigQuery queries in `app/tools_bq.py` use parameterized `bigquery.ScalarQueryParameter` and a strict hardcoded table allowlist (`ALLOWED_TABLES`). User strings are never concatenated into SQL.
  - **XSS Prevention**: `web/index.html` uses `document.createElement()` and `element.textContent` exclusively (zero `innerHTML`, `outerHTML`, or `document.write`).
  - **Authentication & Authorization**: Server-side 3LO OAuth bearer token extraction (`X-Goog-Agent-User-Authorization` / `Authorization`) fails closed (`401`/`403`) if no valid token is supplied; zero hardcoded secrets or fallback tokens in source code; no tokens stored in `localStorage` or `sessionStorage`.
  - **HTTP Security Headers**: FastAPI middleware sets `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and `Cache-Control: no-store`.
  - **PII Masking**: Sensitive rebate/email fields and principal emails are masked or scoped in UI badges as appropriate, and structured logs use single-line JSON without logging bearer tokens.
- **Security Scanner**: Run a scan on all newly created files to identify common vulnerabilities (e.g., XSS, SQL injection). If findings are detected, auto-apply the fix and document the results.
- **Security Audit**: Audit the new code for design-level security issues (input validation, secrets handling, auth checks).
