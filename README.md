# [DEMO] HarvestLine Foodservice (HLF) — Cross-Project BigQuery + Google Drive Sales Insight Manager (SIM) Coaching Agent

> **Note:** All synthetic demo datasets, accounts, and Google Drive documents use the fictitious **`[DEMO] HarvestLine Foodservice (HLF)`** name so they are cleanly isolated in Google Drive and BigQuery search results.

This repository contains:
1. **The `[DEMO] HarvestLine Foodservice (HLF)` Sales Insight Manager (SIM) Unified Coaching Agent (`app/`, `web/`, `tests/`, `scripts/`)**:
   - Solves **Gap `G3a`** (combining structured BigQuery telemetry + unstructured Google Drive coaching playbooks in a single turn).
   - Solves **Gap `G3b` / `b/568413600`** (cross-project BigQuery execution where `bigquery.jobs.create` is billed to the Agent Host Project `heygreg-telco-demo` while joining data across `heygreg-telco-demo.hlf_sim_sales.account_performance` and `bigquery-public-data.thelook_ecommerce.users`, with explicit error classification distinguishing VPC-SC perimeter drops from IAM and Policy Tag denials).
   - Solves **Gap `G2` & `b/570110182`** (extracting the caller's 3LO OAuth token from `X-Goog-Agent-User-Authorization` or `Authorization` per `a2a_agent.py:1475-1551` and enforcing a hard server-side SQL table allowlist, BigQuery Row-Level Security, Data Catalog Policy Tags, and Google Drive per-file ACLs).
2. **The Complete Empirical Verification Study (`verification_study/`)**:
   - [`verification_study/BIGQUERY_GEMINI_ACCESS_CONTROL_FINDINGS.md`](verification_study/BIGQUERY_GEMINI_ACCESS_CONTROL_FINDINGS.md): Full Phase 0–5 static and live empirical verification of how Gemini Enterprise reaches BigQuery (Published BigQuery Data Agent vs. Managed BigQuery MCP Connector).
   - [`verification_study/repro_live.sh`](verification_study/repro_live.sh): Live audience reproduction script for all 6 claims (`P1`–`P6`).
   - [`verification_study/teardown.sh`](verification_study/teardown.sh): Full teardown script for the study harness.

---

## Quick Start

```bash
# 1. Provision BigQuery dataset (with RLS & Policy Tags) + [DEMO] Google Drive Playbooks
.venv/bin/python3 scripts/setup_demo_resources.py

# 2. Run Unit + Live Persona Integration Tests (P1, P4, P3, P6)
.venv/bin/pytest -v

# 3. Launch the Interactive SIM Demo Console + A2A Server
.venv/bin/uvicorn app.server:app --host 0.0.0.0 --port 8085
```

---

## Persona Access Matrix Verified End-to-End

| Persona | Service Account Identity | Cross-Project BigQuery (`hlf_sim_sales` $\bowtie$ `bigquery-public-data`) | Policy-Tagged Column (`supplier_rebate_margin_pct`) | Google Drive Playbooks (`drive.googleapis.com/drive/v3`) |
| :--- | :--- | :--- | :--- | :--- |
| **`P1` (National VP of Sales)** | `ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com` | **8 / 8 accounts** across all 4 territories (`Organic`, `Search`, `Display`, `Email`) | **PERMITTED** (`FineGrainedReader` granted) | **2 / 2 Docs** (`[DEMO] HarvestLine Foodservice — Sales Coaching Playbook` + `[DEMO] HarvestLine Foodservice — Executive Margin & Supplier Rebate Guide [CONFIDENTIAL]`) |
| **`P4` (Midwest DSM — RLS Scoped)** | `ge-test-p4@heygreg-telco-demo.iam.gserviceaccount.com` | **4 / 8 accounts** (`rlp_midwest_organic_dsm` filters to `sales_territory = 'Organic'` only) | **PERMITTED** (for `Organic` rows only) | **1 / 2 Docs** (`[DEMO] Standard Coaching Playbook` permitted; `[DEMO] Confidential Rebate Guide` blocked `404/403` by Drive ACL) |
| **`P3` (Sales Enablement Analyst — CLS Blocked)** | `ge-test-p3@heygreg-telco-demo.iam.gserviceaccount.com` | **8 / 8 accounts** across all 4 territories | **REDACTED BY POLICY TAG** (`POLICY_TAG_ACCESS_DENIED`, auto-falls back to non-sensitive columns) | **1 / 2 Docs** (`[DEMO] Standard Coaching Playbook` permitted; `[DEMO] Confidential Rebate Guide` blocked by Drive ACL) |
| **`P6` (Unscoped GE User)** | `ge-test-p6@heygreg-telco-demo.iam.gserviceaccount.com` | **BLOCKED (`403 JOB_USER_PERMISSION_DENIED`)** (`bigquery.jobs.create` missing on `heygreg-telco-demo`) | **BLOCKED** | **0 / 2 Docs** (Both blocked by Drive ACL) |
| **`NO_AUTH` (Case A-iii)** | *(Empty `authorizationConfig: {}`)* | **BLOCKED (`401 CREDENTIALS_MISSING`)** | **BLOCKED** | **BLOCKED** |
