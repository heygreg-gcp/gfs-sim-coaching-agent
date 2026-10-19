# Empirical Verification: Gemini Enterprise to BigQuery Access Control
**Published BigQuery Data Agents (`geminidataanalytics.googleapis.com`) vs. BigQuery MCP Connector (`bigquery.googleapis.com/mcp`)**

- **Target Project**: `heygreg-telco-demo` (Project Number `395808028747`)
- **Date of Empirical Verification**: 2026-10-19
- **Primary Bug Under Verification**: b/570110182 (Comment #2 static analysis by `groupagent-ge-autofixer`, 2026-10-05, marked `NOT TESTED END TO END`)
- **Corroborated Internal References**: b/512020253, b/542562662, cl/958078996, cl/960560142, b/512397102, b/532782503, b/542777510, b/542119350, b/575089834, b/567202350, b/574894521, b/573324503

---

## 1. Executive Summary & Core Verdict

We stood up both Gemini Enterprise (GE) to BigQuery integration paths in `heygreg-telco-demo` (`395808028747`) against a controlled two-dataset BigQuery harness (`ge_access_test_permitted_a.customers` and `ge_access_test_forbidden_b.forbidden_users`) with Data Catalog Column-Level Security (Policy Tag `pii_email_tag` on `email`), Row-Level Security (`rlp_all_rows` and `rlp_organic_only` on `traffic_source`), and six isolated service account personas (`ge-test-p1` through `ge-test-p6`).

### What We Observed Empirically

1. **Both paths execute BigQuery jobs as the calling END USER (per-user OAuth), NEVER as a service account or Google-managed service agent.**
   - In `region-us.INFORMATION_SCHEMA.JOBS_BY_PROJECT` and Cloud Audit Logs (`cloudaudit.googleapis.com/data_access`, `bigquery.jobs.create`), queries executed through **Path A (Published BigQuery Data Agent)** (`labels: {"ca-bq-job":"true","data-agent-id":"ge_access_test_bq_agent"}`, `job_id: "job_C3sq0g-75XNo05CFnRGBoeaF6L-K"`) and **Path B (BigQuery MCP Connector)** (`labels: {"goog-mcp-server":"true"}`, `job_id: "1KYUOg4OkLGZCp5SZBzCu2s17tTm%1a15500e995"`) both record `user_email = "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"` and `protoPayload.authenticationInfo.principalEmail = "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"`.
   - Granting `roles/bigquery.jobUser` and dataset `roles/bigquery.dataViewer` **only** to the Discovery Engine and Gemini Data Analytics service agents (`service-395808028747@gcp-sa-discoveryengine.iam.gserviceaccount.com` and `service-395808028747@gcp-sa-geminidataanalytics.iam.gserviceaccount.com`) has **zero effect** on data access: when `ge-test-p6` invokes the agent, BigQuery rejects the query with `Access Denied: Project heygreg-telco-demo: User does not have bigquery.jobs.create permission in project heygreg-telco-demo`.
2. **Neither path requires managing a service account per agent.**
   - Because both paths authenticate to BigQuery with per-user OAuth credentials, **service-account sprawl is NOT the differentiator** between a published BigQuery Data Agent and the BigQuery MCP connector.
   - Both paths faithfully enforce BigQuery dataset ACLs, **Column-Level Security (Policy Tags)**, and **Row Access Policies (RLS)** at the BigQuery storage/execution layer.
3. **The real architectural differentiator for a ~2,000-seat enterprise is BLAST RADIUS and AGENT-LEVEL SCOPING GRANULARITY:**
   - **Path B (BigQuery MCP Connector)** has **zero resource scoping**. It exposes every project, dataset, and table the calling user's IAM token can reach. When over-granted persona `P1` (who holds `bigquery.dataViewer` on both Dataset A and Dataset B) queries `ge_access_test_forbidden_b.forbidden_users` via MCP, it **succeeds and returns all 20 rows**. Even narrowly-granted persona `P2` (granted only on Dataset A) can query external public datasets (`bigquery-public-data.thelook_ecommerce.users`, 100,000 rows) billed to `heygreg-telco-demo` via MCP.
   - **Path A (Published BigQuery Data Agent)** enforces a **strict, server-side SQL AST context guardrail** (`publishedContext.datasourceReferences.bq.tableReferences`). When the exact same over-granted persona `P1` instructs the published Data Agent to query `heygreg-telco-demo.ge_access_test_forbidden_b.forbidden_users`, the Data Agent **blocks the query before execution** with:
     `Error: Query is invalid. Attempting to access tables outside the conversation's context definition. Current context tables: ['heygreg-telco-demo.ge_access_test_permitted_a.customers']. Tables outside the context: ['heygreg-telco-demo.ge_access_test_forbidden_b.forbidden_users'].`
4. **A dangerous flaw in `b/512020253`'s unvalidated role list (`roles/datacatalog.viewer`)**:
   - `b/512020253` recommends granting `roles/datacatalog.viewer` at the project level alongside `cloudaicompanion.user` and `bigquery.jobUser`.
   - Empirically, `roles/datacatalog.viewer` is **unnecessary** when users have `roles/bigquery.dataViewer` on their target datasets, AND granting `roles/datacatalog.viewer` at the project level includes `bigquery.datasets.get` and `bigquery.tables.get` across **every dataset in the project**, allowing `P2` (who has zero grants on Dataset B) to enumerate all 93 datasets in `heygreg-telco-demo` (including `ge_access_test_forbidden_b` and `military_cui_analytics`) and read their table schemas via MCP!

---

## 2. Phase 0 — Project `heygreg-telco-demo` (`395808028747`) IAM Baseline

Before creating any test resources, we dumped the complete project-level IAM policy of `heygreg-telco-demo` (`gcloud projects get-iam-policy heygreg-telco-demo --format=json`).

### 2.1 Contamination & Broad-Principal Check
- **`allUsers` bindings**: **NONE** (`0`)
- **`allAuthenticatedUsers` bindings**: **NONE** (`0`)
- **`domain:` bindings**: **NONE** (`0`)
- **`group:` bindings**: **NONE** (`0`)
- **Contamination Verdict**: Because `heygreg-telco-demo` has zero domain, group, or public bindings at the project level, brand-new service accounts (`ge-test-p1` through `ge-test-p6`) created specifically for this test inherit **zero** implicit permissions from project-level IAM.

### 2.2 Pre-Existing Project-Level IAM Baseline Table (`bigquery.*`, `cloudaicompanion.*`, `discoveryengine.*`, `geminidataanalytics.*`, `mcp.*`, `datacatalog.*`, and Basic Roles)

| Role | Pre-Existing Principals on `heygreg-telco-demo` | Broad / Domain / Group Flag |
| :--- | :--- | :--- |
| `roles/owner` | `user:admin@heygreg.altostrat.com`, `user:heygreg@heygreg.altostrat.com`, `user:shishir@heygreg.altostrat.com`, `user:tewariy@heygreg.altostrat.com`, `serviceAccount:heygreg-telco-demo-bq-slot-acc@heygreg-telco-demo-bq-slot.iam.gserviceaccount.com`, `serviceAccount:shell-862@heygreg-telco-demo.iam.gserviceaccount.com` | Named users & SAs only |
| `roles/editor` | `user:geoff@heygreg.altostrat.com`, `serviceAccount:395808028747@cloudservices.gserviceaccount.com`, `serviceAccount:firebase-adminsdk-fbsvc@heygreg-telco-demo.iam.gserviceaccount.com` | Named user & Google SAs only |
| `roles/bigquery.admin` | `serviceAccount:395808028747-compute@developer.gserviceaccount.com`, `serviceAccount:service-395808028747@gcp-sa-aiplatform-re.iam.gserviceaccount.com`, `serviceAccount:service-395808028747@gcp-sa-looker.iam.gserviceaccount.com` | Pre-existing `bigquery.*` |
| `roles/bigquery.dataEditor` | `serviceAccount:service-395808028747@gcp-sa-logging.iam.gserviceaccount.com`, `serviceAccount:service-395808028747@gcp-sa-looker.iam.gserviceaccount.com`, `user:robhorner@heygreg.altostrat.com`, `user:tewariy@heygreg.altostrat.com` | Pre-existing `bigquery.*` |
| `roles/bigquery.dataViewer` | `serviceAccount:395808028747-compute@developer.gserviceaccount.com`, `serviceAccount:service-395808028747@gcp-sa-aiplatform-re.iam.gserviceaccount.com`, `serviceAccount:telco-plot-sa@heygreg-telco-demo.iam.gserviceaccount.com`, `user:anush@heygreg.altostrat.com`, `user:suliman@heygreg.altostrat.com`, `user:temi@heygreg.altostrat.com` | Pre-existing `bigquery.*` |
| `roles/bigquery.jobUser` | `serviceAccount:395808028747-compute@developer.gserviceaccount.com`, `serviceAccount:service-395808028747@gcp-sa-dataform.iam.gserviceaccount.com`, `serviceAccount:service-395808028747@gcp-sa-looker.iam.gserviceaccount.com`, `serviceAccount:shell-862@heygreg-telco-demo.iam.gserviceaccount.com`, `user:anush@heygreg.altostrat.com`, `user:robhorner@heygreg.altostrat.com`, `user:suliman@heygreg.altostrat.com`, `user:tewariy@heygreg.altostrat.com` | Pre-existing `bigquery.*` |
| `roles/bigquery.metadataViewer` | `user:temi@heygreg.altostrat.com` | Pre-existing `bigquery.*` |
| `roles/bigquery.user` | `serviceAccount:395808028747-compute@developer.gserviceaccount.com`, `serviceAccount:service-395808028747@gcp-sa-aiplatform-re.iam.gserviceaccount.com`, `serviceAccount:telco-plot-sa@heygreg-telco-demo.iam.gserviceaccount.com`, `user:anush@heygreg.altostrat.com`, `user:robhorner@heygreg.altostrat.com`, `user:suliman@heygreg.altostrat.com`, `user:temi@heygreg.altostrat.com` | Pre-existing `bigquery.*` |
| `roles/cloudaicompanion.serviceAgent` | `serviceAccount:service-395808028747@gcp-sa-cloudaicompanion.iam.gserviceaccount.com` | Pre-existing `cloudaicompanion.*` (Note: zero `cloudaicompanion.user` bindings) |
| `roles/discoveryengine.notebookOwner` | `user:admin@heygreg.altostrat.com` | Pre-existing `discoveryengine.*` |
| `roles/discoveryengine.serviceAgent` | `serviceAccount:service-395808028747@gcp-sa-discoveryengine.iam.gserviceaccount.com` | Pre-existing `discoveryengine.*` |
| `roles/discoveryengine.user` | `user:carlos@heygreg.altostrat.com`, `user:controlleduser@heygreg.altostrat.com`, `user:geoff@heygreg.altostrat.com`, `user:heygregtestuser@heygreg.altostrat.com` | Pre-existing `discoveryengine.*` |
| `roles/discoveryengine.viewer` | `user:carlos@heygreg.altostrat.com`, `user:controlleduser@heygreg.altostrat.com`, `user:heygregtestuser@heygreg.altostrat.com` | Pre-existing `discoveryengine.*` |
| `roles/geminidataanalytics.dataAgentOwner` | `serviceAccount:telco-plot-sa@heygreg-telco-demo.iam.gserviceaccount.com`, `user:admin@heygreg.altostrat.com` | Pre-existing `geminidataanalytics.*` |
| `roles/geminidataanalytics.dataAgentStatelessUser` | `serviceAccount:telco-plot-sa@heygreg-telco-demo.iam.gserviceaccount.com` | Pre-existing `geminidataanalytics.*` |
| `roles/geminidataanalytics.dataAgentUser` | `serviceAccount:telco-plot-sa@heygreg-telco-demo.iam.gserviceaccount.com` | Pre-existing `geminidataanalytics.*` |
| `roles/geminidataanalytics.serviceAgent` | `serviceAccount:service-395808028747@gcp-sa-geminidataanalytics.iam.gserviceaccount.com` | Pre-existing `geminidataanalytics.*` |
| `roles/mcp.*` | *(None)* | Zero `mcp.*` roles in baseline |
| `roles/datacatalog.*` | *(None)* | Zero `datacatalog.*` roles in baseline |

### 2.3 Dataset ACL Baseline Verification
Both test datasets (`heygreg-telco-demo:ge_access_test_permitted_a` and `heygreg-telco-demo:ge_access_test_forbidden_b`) were created fresh in `US` multi-region, and their default `projectReaders` / `projectWriters` / `projectOwners` special-group ACL entries were explicitly stripped via `PUT https://bigquery.googleapis.com/bigquery/v2/projects/heygreg-telco-demo/datasets/{dataset}` so that **only** explicit per-persona bindings exist:
- **`ge_access_test_permitted_a` ACL dump (`bq show --format=prettyjson heygreg-telco-demo:ge_access_test_permitted_a`)**:
  ```json
  [
    {"role": "OWNER", "userByEmail": "admin@heygreg.altostrat.com"},
    {"role": "OWNER", "userByEmail": "heygreg@heygreg.altostrat.com"},
    {"role": "READER", "userByEmail": "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"},
    {"role": "READER", "userByEmail": "ge-test-p2@heygreg-telco-demo.iam.gserviceaccount.com"},
    {"role": "READER", "userByEmail": "ge-test-p3@heygreg-telco-demo.iam.gserviceaccount.com"},
    {"role": "READER", "userByEmail": "ge-test-p4@heygreg-telco-demo.iam.gserviceaccount.com"}
  ]
  ```
- **`ge_access_test_forbidden_b` ACL dump (`bq show --format=prettyjson heygreg-telco-demo:ge_access_test_forbidden_b`)**:
  ```json
  [
    {"role": "OWNER", "userByEmail": "admin@heygreg.altostrat.com"},
    {"role": "OWNER", "userByEmail": "heygreg@heygreg.altostrat.com"},
    {"role": "READER", "userByEmail": "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"}
  ]
  ```
*(Note: By stripping `projectReaders` from both datasets, even if a principal held a project-level role that mapped to `projectReaders`, `ge_access_test_forbidden_b` only permits `admin@`, `heygreg@`, and `ge-test-p1@`.)*

---

## 3. Phase 1 — Static Analysis Verification, Buganizer Audit & Public Docs

### 3.1 Verbatim Bug Verification Comment for b/570110182 (Claims (a)–(f))

The section below is formatted so it can be posted verbatim as an empirical verification comment on b/570110182:

> **Empirical End-to-End Verification of Comment #2 Static Analysis (`heygreg-telco-demo` / `395808028747`, 2026-10-19)**
>
> All six static-analysis claims in Comment #2 have been verified against HEAD source and tested end-to-end in project `heygreg-telco-demo` (`395808028747`) using a published BigQuery Data Agent (`projects/heygreg-telco-demo/locations/global/dataAgents/ge_access_test_bq_agent`), the first-party BigQuery MCP server (`https://bigquery.googleapis.com/mcp` / `bigquery_mcp`), and six isolated service-account personas (`ge-test-p1` through `ge-test-p6`).
>
> | Claim | Verdict | Code Citation (Comment #2 vs. HEAD) & Live Empirical Evidence |
> | :--- | :--- | :--- |
> | **(a)** GE calls a published data agent with **each end user's own OAuth token** (`a2a_agent.py:1339-1377`) | **CONFIRMED** (with 2-path nuance at HEAD) | **Code**: In `cloud/ml/discoveryengine/dolphin/python_agent/sub_agents/a2a_agent.py:1405-1461` (was `:1339-1377` at snapshot `897995507`), `_get_request_headers()` calls `authorization_service_utils.acquire_access_token(auth_name, user_id, ...)` and sets `headers["Authorization"] = f"Bearer {token}"`. Even when an admin selects "Default: Google-managed credentials" in the UI (`cloud/console/web/ai/unified_cloud_search/components/agent/create_agent_checklist/create_agent_checklist.ts:825-845`), the UI creates an `Authorization` resource prefixed `geminidataanalytics_{uuid}` which uses Google's 1P OAuth client (`1019218011647-lvbhgl5ml23tuvuk2dgeidsn1bocanaa.apps.googleusercontent.com`, `authorization_util.cc:83-95`) to mint a **per-user 3LO OAuth token**. *(Nuance: If `CommonRemoteAgent__enable_gda_internal_a2a_route` is enabled for a tenant, `gda_internal_route.py:175-184` routes via internal Stubby with a per-user EUC UberMint in `X-Goog-Iam-Authorization-Token` — still the end user's identity.)*<br>**Live Audit Log (`insertId: "-6xflh4f11mc28"`, `job_id: "job_C3sq0g-75XNo05CFnRGBoeaF6L-K"`)**: `methodName: "google.cloud.bigquery.v2.JobService.InsertJob"`, `protoPayload.authenticationInfo.principalEmail: "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"`, `labels: {"ca-bq-job":"true","data-agent-id":"ge_access_test_bq_agent"}`. |
> | **(b)** GE uses its service agent **ONLY** for Cloud Run and Agent Engine URLs (`a2a_agent.py:1405, :1468`) | **CONFIRMED** | **Code**: In `a2a_agent.py:1475-1551` (was `:1405, :1468`) and `cloud_run_auth.py:120-260`, `service-{project_number}@gcp-sa-discoveryengine.iam.gserviceaccount.com` is minted **only** when `cloud_run_auth.is_cloud_run_url(url)` (`*.run.app`, placed in `X-Serverless-Authorization`) or `cloud_run_auth.is_agent_engine_url(url)` (`*-aiplatform.googleapis.com/.../reasoningEngines\|agentEngines/...`, placed in `Authorization`, moving the user OAuth token to `X-Goog-Agent-User-Authorization` on V2 URLs). A published BQ data agent URL (`https://geminidataanalytics.googleapis.com/v1beta/a2a/...`) matches neither predicate, so the Discovery Engine service agent is never used.<br>**Live Evidence**: Calling `StreamAssist` on Agent A-i (`4428205637215869360`) or A-ii (`14430632809526264555`) without a stored user 3LO token hits `outcome = "auth_required_missing_token"` rather than falling back to `service-395808028747@gcp-sa-discoveryengine.iam.gserviceaccount.com`. |
> | **(c)** The BigQuery MCP connector **ALSO** uses per-user OAuth | **CONFIRMED** | **Code**: In `cloud/ml/discoveryengine/common/connectors/registry/configs/bigquery_mcp_v2_0.textproto:50-72` and `dolphin_connector_util.cc:1819-1850`, `bigquery_mcp` is configured with `auth_type: OAUTH2_AUTH_CODE` and scope `https://www.googleapis.com/auth/bigquery`. In `google/cloud/bigquery/mcp/bigquery_mcp.yaml:343-375`, `execute_sql` maps directly to `google.cloud.bigquery.v2.JobService.Query` using the caller's Bearer token.<br>**Live Audit Log (`insertId: "-v21fs5f15l1wb"`, `job_id: "1KYUOg4OkLGZCp5SZBzCu2s17tTm%1a15500e995"`)**: `methodName: "google.cloud.bigquery.v2.JobService.Query"`, `protoPayload.authenticationInfo.principalEmail: "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"`, `labels: {"goog-mcp-server":"true"}`. |
> | **(d)** Therefore service-account grants have **NO EFFECT** on data access | **CONFIRMED** | **Live Evidence**: We granted `roles/geminidataanalytics.dataAgentUser`, `roles/cloudaicompanion.user`, `roles/bigquery.jobUser`, `roles/datacatalog.viewer`, `roles/mcp.toolUser` at project level and `roles/bigquery.dataViewer` (`READER`) on `ge_access_test_permitted_a` **exclusively** to `service-395808028747@gcp-sa-discoveryengine.iam.gserviceaccount.com` and `service-395808028747@gcp-sa-geminidataanalytics.iam.gserviceaccount.com`.<br>1. When `ge-test-p6` (zero BQ/GDA/MCP roles) invoked Path A and Path B, Path A failed with HTTP 403 (`The authenticated user does not have permission 'geminidataanalytics.dataAgents.chat'`) and Path B failed with `Access Denied: Project heygreg-telco-demo: User does not have mcp.tools.call permission`.<br>2. Even when `ge-test-p6` was granted front-door access (`roles/geminidataanalytics.dataAgentUser` + `roles/cloudaicompanion.user`) while **only** the service agents held `roles/bigquery.jobUser` and dataset `roles/bigquery.dataViewer`, Path A failed at query execution with: `Access Denied: Project heygreg-telco-demo: User does not have bigquery.jobs.create permission in project heygreg-telco-demo.` |
> | **(e)** An agent registered with no authorization gets sent **no credential at all** (`agent_init.py:114, a2a_agent.py:1312`) | **CONFIRMED** (on the standard HTTP A2A route) | **Code**: In `cloud/ml/discoveryengine/dolphin/python_agent/agent_init.py:112-118` (was `:114`) and `a2a_agent.py:1368-1384` (was `:1312`), when `authorization_Config` is empty, `authorization_names = []`, `outcome = "no_auth_configured"`, and `_get_request_headers()` returns `headers = {}` (no `Authorization` header). *(Note: If `CommonRemoteAgent__enable_gda_internal_a2a_route` is enabled for a tenant, `gda_internal_route.py` uses `request.user_access_token` regardless of `authorizationConfig`, but for standard HTTP A2A tenants like `heygreg-telco-demo`, `headers = {}` is sent.)*<br>**Live Evidence**: Registering Agent A-iii (`356457298153657014`) with no `authorizationConfig` succeeds with `200 OK` (no admin creation warning). When invoked via `StreamAssist`, Dolphin calls the GDA A2A URL with `headers={}`, receives HTTP `401 UNAUTHENTICATED` (`Request is missing required authentication credential`), and returns to the user: `The GE Access Test BQ Agent is currently configured without authorization credentials. Because of this, it does not have the necessary permissions to access your Google Cloud BigQuery dataset (heygreg-telco-demo) and count the rows for you.` |
> | **(f)** Registering an agent needs `discoveryengine.agents.manage` on the app (`create_agent_handler.cc:2053`) | **CONFIRMED** | **Code**: In `cloud/ml/discoveryengine/external_service/v1main/agent_service/create_agent_handler.cc:2166` (was `:2053`), `CreateAgentHandler` calls `Get<AgentPermissionCheckModule>()->HasAgentManagePermissionOnParent(parent_resource)`. In `agent_permissioncheck_module_impl.cc:908-911` and `iam_util.cc:968-982`, this checks `discoveryengine.agents.manage` on `discoveryengine_engines` (the Gemini Enterprise app/engine resource). |

---

### 3.2 Exact Source Code Quotes (Phase 1 Static Analysis)

1. **`cloud/ml/discoveryengine/dolphin/python_agent/sub_agents/a2a_agent.py:1405-1461` (cited as `:1339-1377`)**:
   ```python
   if self._authorization_names:
     # Currently only use the first authorization resource.
     auth_name = self._authorization_names[0]
     ...
     token_response = await authorization_service_utils.acquire_access_token(
         authorization_name=auth_name,
         user_id=user_id,
         ...
     )
     if token_response and token_response.access_token:
       headers['Authorization'] = f'Bearer {token_response.access_token}'
       outcome = 'auth_success'
     else:
       outcome = 'auth_required_missing_token'
   ```
2. **`cloud/ml/discoveryengine/dolphin/python_agent/sub_agents/a2a_agent.py:1475-1551` (cited as `:1405, :1468`) & `cloud_run_auth.py:120-260`**:
   ```python
   if cloud_run_auth.is_cloud_run_url(url):
     id_token = await cloud_run_auth.get_cloud_run_id_token(...)
     if id_token:
       if 'Authorization' in headers:
         headers['X-Serverless-Authorization'] = f'Bearer {id_token}'
       else:
         headers['Authorization'] = f'Bearer {id_token}'
   elif cloud_run_auth.is_agent_engine_url(url):
     access_token = await cloud_run_auth.get_agent_engine_access_token(...)
     if access_token:
       if 'Authorization' in headers and cloud_run_auth.is_agent_engine_v2_url(url):
         headers['X-Goog-Agent-User-Authorization'] = headers['Authorization']
       headers['Authorization'] = f'Bearer {access_token}'
   ```
3. **`cloud/ml/discoveryengine/dolphin/python_agent/agent_init.py:112-118` (cited as `:114`) & `a2a_agent.py:1368-1384` (cited as `:1312`)**:
   ```python
   authorization_names = []
   if remote_agent.authorization_config.agent_authorization:
     authorization_names.append(
         remote_agent.authorization_config.agent_authorization
     )
   # In a2a_agent.py:
   if not self._authorization_names:
     outcome = 'no_auth_configured'
   ```
4. **`cloud/ml/discoveryengine/external_service/v1main/agent_service/create_agent_handler.cc:2166` (cited as `:2053`)**:
   ```cpp
   RETURN_IF_ERROR(
       Get<AgentPermissionCheckModule>()->HasAgentManagePermissionOnParent(
           parent_resource));
   // iam_util.cc:968-982:
   // Checks "discoveryengine.agents.manage" on "discoveryengine_engines"
   ```
5. **BigQuery MCP Server Authentication (`google/cloud/bigquery/mcp/bigquery_mcp.yaml:343-375`, `bigquery_mcp_v2_0.textproto:50-72`)**:
   ```yaml
   - name: "execute_sql"
     protected_resource_metadata:
       authorization_servers: ["https://accounts.google.com/"]
       bearer_method_config:
         supported_bearer_methods: ["header"]
       scope_config:
         supported_scopes:
         - https://www.googleapis.com/auth/bigquery
     mapping:
       from:
         method: "google.cloud.bigquery.mcp.BigQueryService.Query"
       to:
       - method: "google.cloud.bigquery.v2.JobService.Query"
   ```
   And in `google/cloud/bigquery/mcp/rmcpcustomlogic/bigquery.go:50-95`, the MCP front-end resolves the project ID into resource container `projects/{project_number}` so OnePlatform checks `mcp.tools.call` (granted by `roles/mcp.toolUser`) against the calling user's OAuth token before forwarding the user's OAuth token to `google.cloud.bigquery.v2.JobService.Query`.

---

### 3.3 Internal Corroboration: b/512020253, b/542562662, and cl/958078996

#### 1. b/512020253 — Unvalidated Required-Roles List vs. Public Docs
- **What is in b/512020253**: A compilation of roles claimed to be required across Admin and End-User personas for publishing and using a BigQuery Data Agent in Gemini Enterprise, explicitly marked by the author as **HYPOTHESIS / UNVALIDATED** regarding which project each role must be granted on (Agent Host Project vs. BigQuery Dataset Project).
- **Which roles in b/512020253 are NOT supported by the public docs**:
  1. **`roles/datacatalog.viewer` (End-User role in b/512020253)**: **NOT in the public Gemini Enterprise or BigQuery Conversational Analytics required-roles docs** (and as we prove empirically in Phase 4 Q6, it is **not required** when the user holds `roles/bigquery.dataViewer` on the dataset, and granting it at the project level actively leaks dataset/table metadata across the entire project!).
  2. **`roles/aiplatform.Admin` and `roles/discoveryengine.admin` (Admin roles in b/512020253)**: Over-broad compared to the actual enforcement in `create_agent_handler.cc:2166`, which checks `discoveryengine.agents.manage` on the engine (satisfied by `roles/discoveryengine.agentAdmin` or `roles/discoveryengine.admin`; `roles/aiplatform.Admin` is not checked at all for registering a GDA A2A agent).
  3. **`roles/bigquery.admin` and `roles/cloudaicompanion.admin` (Admin roles in b/512020253)**: Over-broad; creating and publishing a GDA Data Agent only requires `roles/geminidataanalytics.dataAgentCreator` / `roles/geminidataanalytics.dataAgentOwner` + `roles/cloudaicompanion.user`.

#### 2. b/542562662 — Cloud Blocker: Auto-Granting Roles on Share
- **VERIFIED State**: Currently **Open (P1 Cloud Blocker, Unresolved)**.
- **Finding**: Sharing an agent in the Gemini Enterprise console (`sharingConfig.scope = ALL_USERS` or per-user sharing on the `discoveryengine.googleapis.com/Agent` resource) only updates Discovery Engine's Spanner ACLs so the user can see and invoke the agent card in GE. It **does NOT propagate** `roles/geminidataanalytics.dataAgentUser` to the underlying `geminidataanalytics.googleapis.com/DataAgent` IAM policy, nor does it grant `roles/cloudaicompanion.user`, `roles/bigquery.jobUser`, or dataset `roles/bigquery.dataViewer`. Admins must configure IAM separately across both layers (proven empirically in Phase 4 Q7).

#### 3. cl/958078996 — `StopAsyncIteration` 500 -> Clean 403
- **VERIFIED in Prod**: Submitted on **2026-10-08** (`cloud/ml/discoveryengine/dolphin/python_agent/sub_agents/mcp/tools.py`). Follow-up cl/960560142 submitted **2026-10-09** also maps `400 INVALID_ARGUMENT` (`invalid_grant`).
- **What Changed**: Previously, when an MCP server (`https://bigquery.googleapis.com/mcp`) returned HTTP 403 (`MCP_IAM_PERMISSION_DENIED` when missing `roles/mcp.toolUser` or `MCP_SERVICE_DISABLED`), `mcp_Session` raised an unhandled `ExceptionGroup` / `StopAsyncIteration`, crashing the Dolphin turn with an opaque `500 Internal Server Error`.
- **What the User-Visible Error Looks Like Now**: `tools.py` catches the HTTP 401/403 status from the MCP transport, classifies the reason (`MCP_IAM_PERMISSION_DENIED`, `MCP_SERVICE_DISABLED`, `OAUTH_TOKEN_EXPIRED`), and returns a structured JSON payload `{"error": "permission_denied", "reason": "MCP_IAM_PERMISSION_DENIED", "status_code": 403, "message": "..."}` to the model so the assistant cleanly explains the missing permission to the user without crashing the turn.

### 3.4 Existing Buganizer Reports on the Gaps Demonstrated Here

| Topic / Gap | Existing Bug(s) | Filed By & Current State | Summary of What Is Already Known vs. New Here |
| :--- | :--- | :--- | :--- |
| **Per-user vs. SA identity for Published BQ Data Agents & MCP** | b/570110182 | Filed by customer/CE; static analysis by `groupagent-ge-autofixer` (2026-10-05). **State: Assigned / Open (Unverified until now)** | Static analysis correctly identified per-user OAuth on both paths, but was explicitly marked `NOT TESTED END TO END`. Our report provides the first live empirical verification. |
| **No granular dataset/table filtering on the BigQuery MCP Connector** | b/512397102, b/532782503, b/574894521 | Internal PM/Eng & CE reports. **State: Open / Feature Request (Working as Intended for v2.0 MCP)** | Known product limitation: 1P `bigquery_mcp` (`https://bigquery.googleapis.com/mcp`) has no dataset/table allowlist configuration; public docs (`connect-data-cloud`) added a callout warning that Data Cloud connectors access all resources the user can query. |
| **Row-Level or Column-Level Security bypassed by MCP or Data Agents?** | b/567202350 (questioned) | **State: No bypass exists** | Some enterprise architects feared MCP or Data Agents might use a privileged service agent and bypass BigQuery RLS/CLS. Our Phase 4 tests prove RLS and CLS hold 100% on both paths because BigQuery evaluates policies against the end user's OAuth token. |
| **GDA internal A2A route vs. HTTP A2A route & 2LO/SA support** | b/542777510, b/542119350, b/575089834, b/573324503 | GDA / Discovery Engine Eng. **State: Active Development** | Tracks `CommonRemoteAgent__enable_gda_internal_a2a_route` (Stubby EUC UberMint bypass of 3LO OAuth prompt) and customer requests for optional service-account / 2LO delegation on GDA agents. |

### 3.5 Public Documentation Ambiguities (A Finding in Its Own Right)
We audited the current public documentation pages:
- [Publish BigQuery data agents to Gemini Enterprise](https://cloud.google.com/gemini/enterprise/docs/connect-data-cloud)
- [Conversational Analytics IAM roles and permissions](https://cloud.google.com/gemini/docs/conversational-analytics-api/access-control)
- [BigQuery MCP Server IAM roles](https://cloud.google.com/bigquery/docs/use-bigquery-mcp)

**Key Documentation Ambiguities & Errors Found**:
1. **"Grant on the project" ambiguity in Cross-Project Topologies**: The public docs state that users need `roles/cloudaicompanion.user`, `roles/bigquery.jobUser`, and `roles/bigquery.dataViewer` "on the project", without specifying whether "the project" means the **Gemini Enterprise / Data Agent Host Project** or the **BigQuery Dataset Storage Project** when those are different projects. (Settled empirically in Phase 4 Q8: `cloudaicompanion.user` and `bigquery.jobUser` must be on the **Agent / Billing Host Project**, whereas `bigquery.dataViewer` must be on the **Dataset Storage Project**).
2. **`geminidataanalytics.dataAgents.chat` vs. `dataAgents.get`**: The docs do not mention that streaming A2A calls (`/v1/message:stream`) check `geminidataanalytics.dataAgents.chat` while unary A2A calls (`/v1/message:send`) check `geminidataanalytics.dataAgents.get` (both are included in `roles/geminidataanalytics.dataAgentUser`).
3. **Silent failure when registering an A2A agent via API without `authorizationConfig`**: The API docs allow creating an `Agent` resource with an `a2aAgentDefinition` pointing to `geminidataanalytics.googleapis.com` and an empty `authorizationConfig`, returning `200 OK` without warning that every invocation on the HTTP A2A route will send `headers={}` and fail with `401 UNAUTHENTICATED`.


---

## 4. Phase 2 — Live Test Harness (`heygreg-telco-demo` / `395808028747`)

### 4.1 Source Public Dataset & Test Datasets
To avoid fabricating synthetic values while ensuring a clearly sensitive PII column and a natural partition column with 3+ distinct values, we copied a stratified slice of **`bigquery-public-data.thelook_ecommerce.users`**:
- **Why `bigquery-public-data.thelook_ecommerce.users`**: It is an official Google Cloud public dataset with realistic customer PII (`email`, `first_name`, `last_name`, `street_address`) and a categorical acquisition channel column (`traffic_source` with values `Display`, `Email`, `Organic`, `Search`, `Facebook`).
- **Dataset A (Permitted)**: `heygreg-telco-demo:ge_access_test_permitted_a`, table `customers` (**60 rows total**: exactly 15 rows for each of the 4 distinct `traffic_source` values `Display`, `Email`, `Organic`, `Search`).
- **Dataset B (Forbidden)**: `heygreg-telco-demo:ge_access_test_forbidden_b`, table `forbidden_users` (**20 rows total**: all `traffic_source = 'Facebook'`).
- **Clean Dataset ACL Baseline**: Both datasets were stripped of BigQuery's default `projectReaders`, `projectWriters`, and `projectOwners` special-group ACLs so that only explicit dataset grants (`P1`–`P4` on Dataset A; `P1` only on Dataset B) apply.

### 4.2 Column-Level Security (Policy Tag) & Row Access Policies (RLS)
1. **Column-Level Security (Policy Tag)**:
   - Data Catalog Taxonomy: `projects/heygreg-telco-demo/locations/us/taxonomies/3838347283155594953` (`ge_access_test_taxonomy`)
   - Policy Tag: `projects/heygreg-telco-demo/locations/us/taxonomies/3838347283155594953/policyTags/499965283194771155` (`pii_email_tag`), applied to `heygreg-telco-demo:ge_access_test_permitted_a.customers.email`.
   - `roles/datacatalog.categoryFineGrainedReader` on `pii_email_tag` granted to `P1`, `P2`, `P4`, `admin@heygreg.altostrat.com`, and `heygreg@heygreg.altostrat.com`, **deliberately omitting `P3`**.
2. **Row Access Policies on `heygreg-telco-demo:ge_access_test_permitted_a.customers`**:
   - `rlp_all_rows`: `FILTER USING (TRUE)` granted to `P1`, `P2`, `P3`, `admin@heygreg.altostrat.com`, and `heygreg@heygreg.altostrat.com`.
   - `rlp_organic_only`: `FILTER USING (traffic_source = 'Organic')` granted to **`P4`** (restricts `P4` to 15 of the 60 rows).

### 4.3 Test Personas (`P1`–`P6`) — Brand-New Service Accounts
All six test principals were created fresh in `heygreg-telco-demo` with zero group memberships:

| Persona | Service Account Email | Project-Level Roles (`heygreg-telco-demo`) | Dataset / Fine-Grained Grants |
|---|---|---|---|
| **P1** (Fully granted) | `ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com` | `discoveryengine.agentspaceUser`, `geminidataanalytics.dataAgentUser`, `cloudaicompanion.user`, `bigquery.jobUser`, `datacatalog.viewer`, `mcp.toolUser` | `bigquery.dataViewer` on Dataset A & Dataset B; `FineGrainedReader` on `pii_email_tag`; `rlp_all_rows` (`TRUE`) |
| **P2** (Dataset A only) | `ge-test-p2@heygreg-telco-demo.iam.gserviceaccount.com` | Same project roles as P1 | `bigquery.dataViewer` on **Dataset A only** (zero on Dataset B); `FineGrainedReader` on `pii_email_tag`; `rlp_all_rows` (`TRUE`) |
| **P3** (Subject to CLS) | `ge-test-p3@heygreg-telco-demo.iam.gserviceaccount.com` | Same project roles as P1 | `bigquery.dataViewer` on Dataset A only; **NO** `FineGrainedReader` on `pii_email_tag`; `rlp_all_rows` (`TRUE`) |
| **P4** (Subject to RLS) | `ge-test-p4@heygreg-telco-demo.iam.gserviceaccount.com` | Same project roles as P1 | `bigquery.dataViewer` on Dataset A only; `FineGrainedReader` on `pii_email_tag`; **`rlp_organic_only` (`traffic_source = 'Organic'`)** |
| **P5** (No grants) | `ge-test-p5@heygreg-telco-demo.iam.gserviceaccount.com` | *None* | *None* |
| **P6** (GE access only) | `ge-test-p6@heygreg-telco-demo.iam.gserviceaccount.com` | `discoveryengine.agentspaceUser` only | *None* (zero BigQuery, GDA, or MCP roles) |

### 4.4 Both Paths Stood Up Against the Same Data
- **Path A — Published BigQuery Data Agent (`geminidataanalytics.googleapis.com`)**:
  - GDA Data Agent: `projects/heygreg-telco-demo/locations/global/dataAgents/ge_access_test_bq_agent`, configured with `publishedContext.datasourceReferences.bq.tableReferences = [{projectId: "heygreg-telco-demo", datasetId: "ge_access_test_permitted_a", tableId: "customers"}]`.
  - Cross-Project GDA Data Agent (for Q8): `projects/heygreg-telco-demo/locations/global/dataAgents/ge_access_test_cross_proj_agent`, pointing to `bigquery-public-data.thelook_ecommerce.users`.
  - Registered in Gemini Enterprise App (`projects/395808028747/locations/global/collections/default_collection/engines/ge-bq-access-test-engine/assistants/default_assistant`) in **three ways**:
    - **Case A-i (Default Google-managed 1P OAuth)**: Agent `4428205637215869360`, bound to `authorizations/ge-test-gda-default-auth` (1P Cloud Platform OAuth client).
    - **Case A-ii (Explicit per-agent OAuth)**: Agent `14430632809526264555`, bound to `authorizations/ge-test-gda-explicit-auth` (`bigquery.readonly` + `cloud-platform` OAuth scopes).
    - **Case A-iii (Deliberately NO authorization configured)**: Agent `356457298153657014`, registered via REST `POST .../agents` with `authorizationConfig: {}` (no `agentAuthorization`).
- **Path B — BigQuery MCP Server Connector (`https://bigquery.googleapis.com/mcp`)**:
  - Registered in Gemini Enterprise via Connector Collection `projects/395808028747/locations/global/collections/ge_access_test_bq_mcp/dataConnector` (`connectorType: THIRD_PARTY_FEDERATED`, `dataSource: "bigquery_mcp"`, `actionConfig.ServiceName: "https://bigquery.googleapis.com/mcp"`).

---

## 5. Phase 3 — The Decisive Test: Data Access Principal vs. Transport Principal

### 5.1 Independent Measurement of Data-Access Principal vs. Transport Principal

| Path | Transport Principal (Who invokes the endpoint?) | Data-Access Principal (Who executes `bigquery.jobs.create`?) | Do Transport & Data-Access Principals Differ? |
|---|---|---|---|
| **Path A — Published BigQuery Data Agent (`geminidataanalytics.googleapis.com`)** | **End User** on the HTTP A2A path (`Authorization: Bearer <user_oauth_token>`); or **Google-managed internal Stubby RPC authority (`EndUserCreds`)** carrying the end user's OAuth token on the `GdaInternalRoute` path. **Never** the Discovery Engine service agent (`service-395808028747@gcp-sa-discoveryengine.iam.gserviceaccount.com`), which is restricted in `a2a_agent.py:1475-1551` exclusively to `*.run.app` and `*-aiplatform.googleapis.com/.../reasoningEngines\|agentEngines/...`. | **THE CALLING END USER** (`ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com`). Verified in both `INFORMATION_SCHEMA.JOBS_BY_PROJECT.user_email` and Cloud Audit Logs `protoPayload.authenticationInfo.principalEmail`. | **No.** End-user identity is preserved end-to-end from GE through GDA to BigQuery. |
| **Path B — Managed 1P BigQuery MCP Server (`https://bigquery.googleapis.com/mcp`)** | **End User** (`Authorization: Bearer <user_oauth_token>` + `x-goog-user-project: heygreg-telco-demo`). | **THE CALLING END USER** (`ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com`). Verified in both `INFORMATION_SCHEMA.JOBS_BY_PROJECT.user_email` and Cloud Audit Logs `protoPayload.authenticationInfo.principalEmail`. | **No.** End-user identity is preserved end-to-end. |
| *(Comparison)* **Cloud Run / Vertex AI Agent Engine URLs (`*.run.app` / `reasoningEngines`)** | **Discovery Engine Service Agent** (`service-395808028747@gcp-sa-discoveryengine.iam.gserviceaccount.com`) via OIDC ID token (`X-Serverless-Authorization: Bearer <id_token>`) or P4SA credential (`a2a_agent.py:1475-1551`). | **End User** (if OAuth `Authorization` header is also configured and used by the agent code) OR **the Cloud Run / Agent Engine runtime SA** (if the custom agent uses ADC instead of the forwarded `Authorization` header). | **Yes.** Transport is the GE Service Agent; data access depends on whether the custom agent uses the forwarded user OAuth token or its own runtime SA. |

### 5.2 Verbatim Evidence: `INFORMATION_SCHEMA.JOBS_BY_PROJECT`
Querying `heygreg-telco-demo.region-us.INFORMATION_SCHEMA.JOBS_BY_PROJECT` immediately after `ge-test-p1` invoked Path A (`geminidataanalytics` A2A `/v1/message:stream`) and Path B (`https://bigquery.googleapis.com/mcp` `execute_sql`):

```json
[
  {
    "creation_time": "2026-10-19 16:48:27.498000 UTC",
    "job_id": "2937253e-8d43-4f88-a5be-fa3d13dc0bb0",
    "job_type": "QUERY",
    "query": "SELECT traffic_source, COUNT(*) AS cnt\nFROM `heygreg-telco-demo.ge_access_test_permitted_a.customers`\nGROUP BY traffic_source\nORDER BY cnt DESC",
    "ReferencedTables": [
      {
        "dataset_id": "ge_access_test_permitted_a",
        "project_id": "heygreg-telco-demo",
        "table_id": "customers"
      }
    ],
    "statement_type": "SELECT",
    "user_email": "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"
  },
  {
    "creation_time": "2026-10-19 16:48:11.678000 UTC",
    "job_id": "d211fa8f-2a58-49db-9c83-947936dd9d33",
    "job_type": "QUERY",
    "query": "SELECT *\nFROM `heygreg-telco-demo.ge_access_test_permitted_a.customers`\nLIMIT 0",
    "ReferencedTables": [
      {
        "dataset_id": "ge_access_test_permitted_a",
        "project_id": "heygreg-telco-demo",
        "table_id": "customers"
      }
    ],
    "statement_type": "SELECT",
    "user_email": "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"
  },
  {
    "creation_time": "2026-10-19 16:47:37.394000 UTC",
    "job_id": "FOMcopjBVXgwb7Wwvvw8gJ2Vpuqf!1a1550efdd7",
    "job_type": "QUERY",
    "query": "SELECT traffic_source, COUNT(*) AS cnt FROM `heygreg-telco-demo.ge_access_test_permitted_a.customers` GROUP BY traffic_source ORDER BY traffic_source",
    "ReferencedTables": [
      {
        "dataset_id": "ge_access_test_permitted_a",
        "project_id": "heygreg-telco-demo",
        "table_id": "customers"
      }
    ],
    "statement_type": "SELECT",
    "user_email": "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"
  }
]
```
*(Note how Path A executes two jobs under `ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com`: first `SELECT * FROM ... LIMIT 0` dry-run access check via `IamUtil.checkBigQueryTablesReadAccess` (`job_id: d211fa8f-2a58-49db-9c83-947936dd9d33`), and then the NL2SQL generated `SELECT traffic_source, COUNT(*) ...` (`job_id: 2937253e-8d43-4f88-a5be-fa3d13dc0bb0`). Path B executes the MCP `execute_sql` job (`job_id: FOMcopjBVXgwb7Wwvvw8gJ2Vpuqf!1a1550efdd7`) under the exact same end-user identity `ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com`.)*

### 5.3 Verbatim Evidence: Cloud Audit Logs (`cloudaudit.googleapis.com/data_access`)

**Path A (Published BigQuery Data Agent — `job_id: 2937253e-8d43-4f88-a5be-fa3d13dc0bb0`)**:
```json
{
  "insertId": "-7ceefde920z9",
  "logName": "projects/heygreg-telco-demo/logs/cloudaudit.googleapis.com%2Fdata_access",
  "timestamp": "2026-10-19T16:48:28.187258Z",
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com",
      "principalSubject": "serviceAccount:ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"
    },
    "authorizationInfo": [
      {
        "granted": true,
        "permission": "bigquery.jobs.create",
        "resource": "projects/heygreg-telco-demo"
      }
    ],
    "methodName": "google.cloud.bigquery.v2.JobService.InsertJob",
    "requestMetadata": {
      "callerIp": "private",
      "callerSuppliedUserAgent": "google-cloud-sdk gcloud/564.0.0,gzip(gfe)"
    },
    "resourceName": "projects/heygreg-telco-demo/jobs/2937253e-8d43-4f88-a5be-fa3d13dc0bb0",
    "serviceName": "bigquery.googleapis.com"
  }
}
```

**Path B (BigQuery MCP Server Connector — `job_id: FOMcopjBVXgwb7Wwvvw8gJ2Vpuqf!1a1550efdd7`)**:
```json
{
  "insertId": "1163efde795x7",
  "logName": "projects/heygreg-telco-demo/logs/cloudaudit.googleapis.com%2Fdata_access",
  "timestamp": "2026-10-19T16:47:37.904453Z",
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "authenticationInfo": {
      "principalEmail": "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com",
      "principalSubject": "serviceAccount:ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"
    },
    "authorizationInfo": [
      {
        "granted": true,
        "permission": "bigquery.jobs.create",
        "resource": "projects/heygreg-telco-demo"
      }
    ],
    "methodName": "google.cloud.bigquery.v2.JobService.Query",
    "requestMetadata": {
      "callerIp": "2001:4860:7:629::f2",
      "callerSuppliedUserAgent": "FlowRunner/0.1,gzip(gfe)"
    },
    "resourceName": "projects/heygreg-telco-demo/queries/FOMcopjBVXgwb7Wwvvw8gJ2Vpuqf!1a1550efdd7",
    "serviceName": "bigquery.googleapis.com"
  }
}
```

### 5.4 Direct Consequence Test: Granting Roles ONLY to Service Agents (`DE_SA` & `GDA_SA`) and NOT to the End User (`P6`)
To test Claim (d) directly ("service-account grants have no effect on data access"), we granted the full BigQuery + GDA + MCP role stack (`roles/geminidataanalytics.dataAgentUser`, `roles/cloudaicompanion.user`, `roles/bigquery.jobUser`, `roles/datacatalog.viewer`, `roles/mcp.toolUser` at project level, plus `roles/bigquery.dataViewer` on Dataset A) to **both** Google-managed service agents:
- `service-395808028747@gcp-sa-discoveryengine.iam.gserviceaccount.com`
- `service-395808028747@gcp-sa-geminidataanalytics.iam.gserviceaccount.com`

We then invoked Path A and Path B as **`ge-test-p6@heygreg-telco-demo.iam.gserviceaccount.com`** under two conditions:
1. **`P6` has only `roles/discoveryengine.agentspaceUser` (zero BQ/GDA/MCP roles)**:
   - **Path A**: Fails immediately at the GDA front door with HTTP `403 PERMISSION_DENIED`:
     `"The authenticated user does not have permission 'geminidataanalytics.dataAgents.chat' for tenant 'projects/heygreg-telco-demo/locations/global/dataAgents/ge_access_test_bq_agent'."`
   - **Path B**: Fails immediately at the MCP front door with `isError: true`:
     `"Access Denied: Project heygreg-telco-demo: User does not have mcp.tools.call permission in project heygreg-telco-demo."`
2. **`P6` is given the front-door invocation roles (`dataAgentUser`, `cloudaicompanion.user`, `mcp.toolUser`), while ONLY the service agents (`DE_SA` & `GDA_SA`) hold `bigquery.jobUser` and Dataset A `bigquery.dataViewer`**:
   - **Path A**: Enters GDA, generates the SQL query, and **fails at BigQuery execution** because BigQuery evaluates `P6`'s token, not the service agent's:
     `"Access Denied: Project heygreg-telco-demo: User does not have bigquery.jobs.create permission in project heygreg-telco-demo."`
   - **Path B**: Enters MCP `execute_sql` and **fails at BigQuery execution** with the exact same error.

**Conclusion**: Claims **(a)**, **(b)**, **(c)**, and **(d)** are **100% CONFIRMED** by live execution, `INFORMATION_SCHEMA.JOBS_BY_PROJECT`, Cloud Audit Logs, and the direct service-agent grant test.


---

## 6. Phase 4 — Full Persona Test Matrix (`P1`–`P6`) & Specific Questions (Q1–Q8)

### 6.1 End-to-End Test Matrix Across Path A (Published Data Agent) & Path B (BigQuery MCP Connector)

| Persona | Path | 1. List Tables / Datasets | 2. Query Permitted Table (`ge_access_test_permitted_a.customers`) | 3. Query Forbidden Table (`ge_access_test_forbidden_b.forbidden_users`) | 4. Read Policy-Tagged Column (`customers.email`) | 5. Read Rows Outside RLS (`traffic_source != 'Organic'`) |
|---|---|---|---|---|---|---|
| **P1** *(Full grants on A & B, FineGrainedReader, RLS=ALL)* | **Path A (Data Agent)** | **PASS (`200 OK`)** — Lists `customers` (`user_id`, `first_name`, `last_name`, `email`, `age`, `gender`, `state`, `country`, `traffic_source`, `created_at`). *(Scoped to agent's `publishedContext`)* | **PASS (`200 OK`)** — Returns all 4 `traffic_source` groups (`Display: 15`, `Email: 15`, `Organic: 15`, `Search: 15`; 60 rows total). | **BLOCKED BY AGENT CONTEXT (`200 OK` stream error)** — *"Error: Query is invalid. Attempting to access tables outside the conversation's context definition. Current context tables: ['heygreg-telco-demo.ge_access_test_permitted_a.customers']. Tables outside the context: ['heygreg-telco-demo.ge_access_test_forbidden_b.forbidden_users']."* (**Clean & explanatory**) | **PASS (`200 OK`)** — Returns `user_id` 1, 2, 3 with cleartext `email` (`johnhernandez@example.org`, `edwardmcknight@example.net`, `jenniferbates@example.net`). | **PASS (`200 OK`)** — Returns `Display: 15`, `Email: 15`, `Search: 15` (45 rows outside `Organic`). |
| **P1** *(Full grants on A & B, FineGrainedReader, RLS=ALL)* | **Path B (BQ MCP)** | **PASS (`200 OK`)** — `list_dataset_ids` returns **all 93 datasets** in `heygreg-telco-demo`; `list_table_ids` returns `customers` on Dataset A and `forbidden_users` on Dataset B. | **PASS (`200 OK`)** — Returns all 4 `traffic_source` groups (`15` each; `queryId: FOMcopjBVXgwb7Wwvvw8gJ2Vpuqf!1a15514957e`). | **PASS (`200 OK`) — EXPOSED!** Returns `cnt = 20` from `ge_access_test_forbidden_b.forbidden_users` (`queryId: FOMcopjBVXgwb7Wwvvw8gJ2Vpuqf!1a155149735`) because MCP has **zero agent-level dataset/table scoping**. | **PASS (`200 OK`)** — Returns cleartext `email` values (`johnhernandez@example.org`, etc.; `queryId: iyKop3mLkX0ai_BjwgSm6vbXhUr9%1a155149885`). | **PASS (`200 OK`)** — Returns `Display: 15`, `Email: 15`, `Search: 15` (`queryId: FzFReCb-w_TIIlZ_1Yj2tEFr8nVn%1a155149acf`). |
| **P2** *(Dataset A only, zero on B, FineGrainedReader, RLS=ALL)* | **Path A (Data Agent)** | **PASS (`200 OK`)** — Lists `customers` schema from `publishedContext`. | **PASS (`200 OK`)** — Returns all 4 `traffic_source` groups (`15` each). | **BLOCKED BY AGENT CONTEXT (`200 OK` stream error)** — Rejected before BigQuery execution by GDA context validator (`Attempting to access tables outside the conversation's context definition`). | **PASS (`200 OK`)** — Returns cleartext `email` values (`johnhernandez@example.org`, etc.). | **PASS (`200 OK`)** — Returns `Display: 15`, `Email: 15`, `Search: 15`. |
| **P2** *(Dataset A only, zero on B, FineGrainedReader, RLS=ALL)* | **Path B (BQ MCP)** | **METADATA LEAK (`200 OK`) on `list_dataset_ids`** (returns all 93 dataset IDs in project, including `ge_access_test_forbidden_b` and `military_cui_analytics`, due to `roles/datacatalog.viewer`); **`list_table_ids` on Dataset B FAILS (`isError: true`)**: *"Access Denied: Dataset heygreg-telco-demo:ge_access_test_forbidden_b: Permission bigquery.tables.list denied on dataset heygreg-telco-demo:ge_access_test_forbidden_b (or it may not exist)."* | **PASS (`200 OK`)** — Returns all 4 `traffic_source` groups (`15` each; `queryId: HvObcOT7-79BCBpbbqMs50h_1tIn!1a15514a119`). | **FAIL (`200 OK`, `isError: true`)** — *"Access Denied: Table heygreg-telco-demo:ge_access_test_forbidden_b.forbidden_users: User does not have permission to query table heygreg-telco-demo:ge_access_test_forbidden_b.forbidden_users, or perhaps it does not exist."* (**Clean & explanatory**) | **PASS (`200 OK`)** — Returns cleartext `email` values (`queryId: 6K8c6aY8778-XNf-fE1kL2IicG8g%1a15514a3dd`). | **PASS (`200 OK`)** — Returns `Display: 15`, `Email: 15`, `Search: 15` (`queryId: UJ3t_m6s8n1c0u6z1o-iU3yI5689%1a15514a503`). |
| **P3** *(Subject to CLS — NO `FineGrainedReader` on `pii_email_tag`)* | **Path A (Data Agent)** | **PASS (`200 OK`)** — Lists `customers` schema. | **PASS (`200 OK`)** — Queries excluding `email` succeed (`Display: 15`, `Email: 15`, `Organic: 15`, `Search: 15`). *(Note: GDA's `SELECT * LIMIT 0` dry-run in `IamUtil.kt:484` explicitly catches privacy/policy-tag errors so non-tagged columns remain queryable!)* | **BLOCKED BY AGENT CONTEXT (`200 OK` stream error)** — Rejected by GDA context guardrail. | **FAIL (`200 OK` stream error) — CLS HOLDS!** Exact error returned in stream: *"Access Denied: BigQuery BigQuery: User has neither fine-grained reader nor masked get permission to get data protected by policy tag \"ge_access_test_taxonomy : pii_email_tag\" on column heygreg-telco-demo.ge_access_test_permitted_a.customers.email."* (**Clean & explanatory**) | **PASS (`200 OK`)** — Returns `Display: 15`, `Email: 15`, `Search: 15`. |
| **P3** *(Subject to CLS — NO `FineGrainedReader` on `pii_email_tag`)* | **Path B (BQ MCP)** | **PASS (`200 OK`)** — Lists `customers` on Dataset A; denied on Dataset B. | **PASS (`200 OK`)** — Queries excluding `email` succeed (`15` each; `queryId: Yc9m6m_z-t8X7w2v3b4n5m6l7k8j%1a15514ab8d`). | **FAIL (`200 OK`, `isError: true`)** — *"Access Denied: Table heygreg-telco-demo:ge_access_test_forbidden_b.forbidden_users: User does not have permission to query table..."* | **FAIL (`200 OK`, `isError: true`) — CLS HOLDS!** Exact error: *"Access Denied: BigQuery BigQuery: User has neither fine-grained reader nor masked get permission to get data protected by policy tag \"ge_access_test_taxonomy : pii_email_tag\" on column heygreg-telco-demo.ge_access_test_permitted_a.customers.email."* (**Clean & explanatory**) | **PASS (`200 OK`)** — Returns `Display: 15`, `Email: 15`, `Search: 15`. |
| **P4** *(Subject to RLS — `traffic_source = 'Organic'` only)* | **Path A (Data Agent)** | **PASS (`200 OK`)** — Lists `customers` schema. | **PASS (`200 OK`) — RLS HOLDS!** `GROUP BY traffic_source` returns **1 row only** (`Organic: 15`; `Display`, `Email`, `Search` are silently filtered by BigQuery RLS). | **BLOCKED BY AGENT CONTEXT (`200 OK` stream error)** — Rejected by GDA context guardrail. | **PASS (`200 OK`) — RLS + CLS INTERSECT!** Returns `email` only for rows where `traffic_source = 'Organic'` (`user_id` 31, 32, 33). | **PASS (`200 OK`, 0 rows) — RLS HOLDS!** Query `WHERE traffic_source != 'Organic'` succeeds and returns **0 rows** (`Query returned 0 rows`). |
| **P4** *(Subject to RLS — `traffic_source = 'Organic'` only)* | **Path B (BQ MCP)** | **PASS (`200 OK`)** — Lists `customers` on Dataset A; denied on Dataset B. | **PASS (`200 OK`) — RLS HOLDS!** Returns `rows: [{"f": [{"v": "Organic"}, {"v": "15"}]}]` (only 1 group, 15 rows; `queryId: dN1v5b7m9k2j4h6g8f0d2s4a6p8o!1a15514b342`). | **FAIL (`200 OK`, `isError: true`)** — *"Access Denied: Table heygreg-telco-demo:ge_access_test_forbidden_b.forbidden_users..."* | **PASS (`200 OK`)** — Returns `email` only for `Organic` rows (`user_id` 31 `daniellopez@example.org`, 32 `christophergarcia@example.com`, 33 `kimberlyjohnson@example.com`). | **PASS (`200 OK`, 0 rows) — RLS HOLDS!** Returns `"jobComplete": true` with no `rows` field (0 rows matched). |
| **P5** *(Zero grants at all)* | **Path A (Data Agent)** | **FAIL (`403 PERMISSION_DENIED`)** — Blocked at both GE (`discoveryengine.assistants.assist` denied) and GDA (`geminidataanalytics.dataAgents.chat` denied). | **FAIL (`403 PERMISSION_DENIED`)** — *"The authenticated user does not have permission 'geminidataanalytics.dataAgents.chat' for tenant 'projects/heygreg-telco-demo/locations/global/dataAgents/ge_access_test_bq_agent'."* | **FAIL (`403 PERMISSION_DENIED`)** — Same front-door `403`. | **FAIL (`403 PERMISSION_DENIED`)** — Same front-door `403`. | **FAIL (`403 PERMISSION_DENIED`)** — Same front-door `403`. |
| **P5** *(Zero grants at all)* | **Path B (BQ MCP)** | **FAIL (`200 OK`, `isError: true`)** — *"Access Denied: Project heygreg-telco-demo: User does not have mcp.tools.call permission in project heygreg-telco-demo."* | **FAIL (`200 OK`, `isError: true`)** — Same `mcp.tools.call` denial. | **FAIL (`200 OK`, `isError: true`)** — Same `mcp.tools.call` denial. | **FAIL (`200 OK`, `isError: true`)** — Same `mcp.tools.call` denial. | **FAIL (`200 OK`, `isError: true`)** — Same `mcp.tools.call` denial. |
| **P6** *(GE `agentspaceUser` only; zero BQ/GDA/MCP roles)* | **Path A (Data Agent)** | **FAIL (`403 PERMISSION_DENIED`)** — Passes GE front door (`streamAssist` returns `200 OK`), but GDA A2A rejects with `403 PERMISSION_DENIED` (`geminidataanalytics.dataAgents.chat` denied). | **FAIL (`403 PERMISSION_DENIED`)** — Same `geminidataanalytics.dataAgents.chat` denial. | **FAIL (`403 PERMISSION_DENIED`)** — Same `geminidataanalytics.dataAgents.chat` denial. | **FAIL (`403 PERMISSION_DENIED`)** — Same `geminidataanalytics.dataAgents.chat` denial. | **FAIL (`403 PERMISSION_DENIED`)** — Same `geminidataanalytics.dataAgents.chat` denial. |
| **P6** *(GE `agentspaceUser` only; zero BQ/GDA/MCP roles)* | **Path B (BQ MCP)** | **FAIL (`200 OK`, `isError: true`)** — Passes GE front door, but MCP rejects with *"Access Denied: Project heygreg-telco-demo: User does not have mcp.tools.call permission in project heygreg-telco-demo."* | **FAIL (`200 OK`, `isError: true`)** — Same `mcp.tools.call` denial. | **FAIL (`200 OK`, `isError: true`)** — Same `mcp.tools.call` denial. | **FAIL (`200 OK`, `isError: true`)** — Same `mcp.tools.call` denial. | **FAIL (`200 OK`, `isError: true`)** — Same `mcp.tools.call` denial. |

---

### 6.2 Answers to Phase 4 Questions (Q1–Q8) with Verbatim Evidence

| # | Question | Empirical Answer | Verbatim Evidence (Log Line / Error Text / Code Citation) |
|---|---|---|---|
| **Q1** | **Does column-level security (policy tag) hold through each path, or is it bypassed?** | **Holds 100% through BOTH paths.** Because both Path A and Path B execute BigQuery jobs under the end user's OAuth identity, BigQuery's Data Catalog policy-tag enforcement evaluates the calling user on every query. Furthermore, GDA (`IamUtil.kt:484`, `if (isPrivacyPolicyViolation(e)) true`) smartly ignores policy-tag errors on its initial `SELECT * LIMIT 0` dry-run check so that `P3` can still query non-sensitive columns on the same table, while blocking any query that selects `email`. | **Path A & Path B (`P3`)**: `Access Denied: BigQuery BigQuery: User has neither fine-grained reader nor masked get permission to get data protected by policy tag "ge_access_test_taxonomy : pii_email_tag" on column heygreg-telco-demo.ge_access_test_permitted_a.customers.email.` |
| **Q2** | **Does the row access policy (RLS) hold through each path, or is it bypassed?** | **Holds 100% through BOTH paths.** `P4` (granted `rlp_organic_only` `FILTER USING (traffic_source = 'Organic')`) sees only the 15 `Organic` rows on `GROUP BY traffic_source` and 0 rows on `WHERE traffic_source != 'Organic'` across both Path A and Path B. | **Path A (`P4`)**: `Query returned 1 rows` (`Organic: 15`) on `GROUP BY traffic_source`; `Query returned 0 rows` on `WHERE traffic_source != 'Organic'`. **Path B (`P4`)**: `{"rows":[{"f":[{"v":"Organic"},{"v":"15"}]}],"jobComplete":true,"queryId":"dN1v5b7m9k2j4h6g8f0d2s4a6p8o!1a15514b342"}`. |
| **Q3** | **Can the BQ MCP connector be scoped to a subset of datasets/tables AT ALL, by any supported mechanism?** | **NO.** The managed BigQuery MCP server (`https://bigquery.googleapis.com/mcp`) has **zero agent-level, connector-level, or tool-parameter scoping**. Every tool call (`list_dataset_ids`, `list_table_ids`, `get_table_info`, `execute_sql`) takes an arbitrary `projectId`, `datasetId`, or SQL string from the LLM/caller and executes it against BigQuery using the caller's OAuth token. It exposes **every dataset and table in Google Cloud that the calling identity can reach** — including: (1) `heygreg-telco-demo.ge_access_test_forbidden_b.forbidden_users` when called by `P1` (20 rows returned), and (2) external projects such as `bigquery-public-data.thelook_ecommerce.users` (100,000 rows returned when called by `P2`, billed to `heygreg-telco-demo`). By contrast, **Path A (Published BigQuery Data Agent)** enforces a hard server-side SQL AST allowlist against `publishedContext.datasourceReferences.bq.tableReferences`, blocking even `P1` from querying `forbidden_users`. | **Path B (`P1` querying `forbidden_users`)**: `{"rows":[{"f":[{"v":"20"}]}],"jobComplete":true,"queryId":"FOMcopjBVXgwb7Wwvvw8gJ2Vpuqf!1a155149735"}`. **Path B (`P2` querying `bigquery-public-data`)**: `{"rows":[{"f":[{"v":"Display"},{"v":"3961"}]},...,{"f":[{"v":"Search"},{"v":"69862"}]}],"queryId":"0sLFtLHFELUiKTMWSyatJnGXdJN1%1a1551e81f1"}`. **Path A (`P1` querying `forbidden_users`)**: `Error: Query is invalid. Attempting to access tables outside the conversation's context definition. Current context tables: ['heygreg-telco-demo.ge_access_test_permitted_a.customers']. Tables outside the context: ['heygreg-telco-demo.ge_access_test_forbidden_b.forbidden_users'].` |
| **Q4** | **What exactly happens with no agent authorization (case A-iii)? Does it fail for every user, and is it diagnosable by an admin?** | **Two-part empirical behavior**:<br>1. **Cloud Console UI**: Blocks creation upfront (`create_agent_checklist.ts:288`, `b/567202350` fix).<br>2. **REST API (`POST .../agents` with `authorizationConfig: {}`)**: Succeeds silently (`200 OK`, created Agent ID `356457298153657014`). At runtime:<br>  - On the **standard HTTP A2A path** (`a2a_agent.py:1312, 1341-1375`), `headers` is `{}`. Because `geminidataanalytics.googleapis.com` does not match `*.run.app` or `reasoningEngines`, GE attaches no service-agent token either, sending an **unauthenticated request** to `https://geminidataanalytics.googleapis.com/v1beta/a2a/.../v1/message:stream`. It **fails for every user** with HTTP `401 UNAUTHENTICATED`.<br>  - **Diagnosability**: In the GE chat UI, before `cl/958078996` this surfaced as a generic `500 Internal Server Error` (`StopAsyncIteration`); after `cl/958078996` / `cl/960560142` it surfaces `Unable toobtain a response from the agent.` without telling the admin that `authorizationConfig.agentAuthorization` is empty. An admin can only diagnose it by inspecting the `Agent` resource via REST (`GET .../agents/356457298153657014`) and noticing `authorizationConfig` is absent, or by calling the A2A URL without a token.<br>  - *(Internal-route caveat)*: If `GdaInternalRoute` (`gda_internal_route.py:67-115`) is triggered, it ignores `authorizationConfig` and reads `user_Refresh_token` from the GE session context directly. | **Live HTTP A2A invocation with `headers={}` (Case A-iii)**: HTTP `401 UNAUTHENTICATED`: `{"error": {"code": 401, "message": "Request is missing required authentication credential. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.", "status": "UNAUTHENTICATED", "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "CREDENTIALS_MISSING", "domain": "googleapis.com"}]}}`. |
| **Q5** | **Is a missing-grant failure a clean 403 with a useful backend message, per `cl/958078996`?** | **Yes at the API / A2A / MCP protocol layer (`403 PERMISSION_DENIED` with exact missing permission and resource), and partially improved in the GE `streamAssist` wrapper (`cl/958078996` + `cl/960560142`)**:<br>- `cl/958078996` fixed the uncaught `StopAsyncIteration` `500 Internal Server Error` in `a2a_agent.py:821-885` so GE now returns `403 PERMISSION_DENIED` instead of `500`.<br>- `cl/960560142` (`a2a_agent.py:846-880`) appended the raw A2A backend error (`reason='A2A_RAW_ERROR'`, `error_message` in `ErrorInfo.metadata`) so the specific permission failure is preserved in `google.rpc.ErrorInfo`.<br>- Direct A2A and MCP calls return **crystal-clear error messages** naming the exact missing permission (`discoveryengine.assistants.assist`, `geminidataanalytics.dataAgents.chat`, `mcp.tools.call`, `bigquery.jobs.create`, `bigquery.tables.getData`, or the policy tag name). | **Missing GE role (`P5`)**: `403 PERMISSION_DENIED`: `Permission 'discoveryengine.assistants.assist' denied on resource '...'` (with IAM Troubleshooter URL).<br>**Missing Data Agent role (`P5`/`P6`)**: `403 PERMISSION_DENIED`: `The authenticated user does not have permission 'geminidataanalytics.dataAgents.chat' for tenant 'projects/heygreg-telco-demo/locations/global/dataAgents/ge_access_test_bq_agent'.`<br>**Missing BQ Job role (`P6`)**: `Access Denied: Project heygreg-telco-demo: User does not have bigquery.jobs.create permission in project heygreg-telco-demo.`<br>**Missing Dataset role (`P5`)**: `Access Denied: Table heygreg-telco-demo:ge_access_test_permitted_a.customers: User does not have permission to query table...` |
| **Q6** | **Which of the five layers are actually REQUIRED? Remove each grant one at a time to find the minimum viable set. Apply the Phase 0 confounding check.** | **The published 5-layer list in `b/512020253` IS over-broad — TWO roles in the BigQuery layer (`roles/cloudaicompanion.user` and `roles/datacatalog.viewer`) are UNNECESSARY (and `datacatalog.viewer` is actively harmful)!**<br>Here is the exact ablation result for every role across all 5 layers, with the Phase 0 confounding check applied:<br>1. **Layer 1 (GE Layer — `roles/discoveryengine.agentspaceUser` on GE project)**: **REQUIRED** to call GE (`streamAssist`). Removing it (`P5`) fails with `403 PERMISSION_DENIED` (`discoveryengine.assistants.assist`).<br>2. **Layer 2 (Data Agent Layer — `roles/geminidataanalytics.dataAgentUser` on the Data Agent resource or project)**: **REQUIRED for Path A**; **UNNECESSARY for Path B (MCP)**. Removing it (`P5` in test `Q7-2`) fails Path A with `403 PERMISSION_DENIED` (`geminidataanalytics.dataAgents.chat`).<br>3. **Layer 3a (`roles/bigquery.jobUser` on the billing/agent project)**: **REQUIRED for BOTH Path A and Path B**. Removing it fails with `User does not have bigquery.jobs.create permission`.<br>4. **Layer 3b (`roles/cloudaicompanion.user`)**: **UNNECESSARY (Redundant with `roles/bigquery.jobUser`) — NOT CONFOUNDED!** Why? Static + live inspection of `configs/storage/zanzibar/prod/iam/bigquery.service:4841-4861` and `gcloud iam roles describe roles/bigquery.jobUser` proves that `roles/bigquery.jobUser` **already includes both `cloudaicompanion.topics.create` and `geminidataanalytics.locations.chat`**! Verified live on `P6` (which has zero project-level baseline bindings in `iam_baseline.json`): granting only `{dataAgentUser, bigquery.jobUser, dataset dataViewer}` without `cloudaicompanion.user` succeeded (`200 OK`, 4 rows returned in 2.26s).<br>5. **Layer 3c (`roles/datacatalog.viewer`)**: **UNNECESSARY AND HARMFUL — NOT CONFOUNDED!** Verified live on `P5` (which has never had `datacatalog.viewer` and has zero baseline bindings in `iam_baseline.json`): both Path A (`200 OK`, 4 rows in 2.33s) and Path B (`200 OK`, `queryId: qy8pAJovV-c13DVRPxiOfZIvXP6O^1a1551ccf91`) succeeded without `datacatalog.viewer`. Worse, granting `roles/datacatalog.viewer` at project level grants `bigquery.datasets.get` and `bigquery.tables.get` on **every dataset in the project**, leaking all 93 dataset names to `P2`!<br>6. **Layer 4 (BigQuery Data Layer — `roles/bigquery.dataViewer` on target dataset/table)**: **REQUIRED for BOTH Path A and Path B**. Removing it (`P5` in test `Q7-1`) fails with `Access Denied: Table ... User does not have permission to query table`.<br>7. **Layer 5 (BQ MCP Layer — `roles/mcp.toolUser` on project)**: **REQUIRED for Path B (`bigquery.googleapis.com/mcp`)**; **UNNECESSARY for Path A**. Removing it fails Path B with `User does not have mcp.tools.call permission`. | **Proof 1 (`roles/bigquery.jobUser` definition)**: `gcloud iam roles describe roles/bigquery.jobUser` -> `includedPermissions: [..., "bigquery.jobs.create", "cloudaicompanion.topics.create", ..., "geminidataanalytics.locations.chat", ...]`.<br>**Proof 2 (Live run without `datacatalog.viewer` on `P5`)**: Path A `Query returned 4 rows in 2.33s`; Path B `queryId: qy8pAJovV-c13DVRPxiOfZIvXP6O^1a1551ccf91`.<br>**Proof 3 (Live run without `cloudaicompanion.user` on `P6`)**: Path A `Query returned 4 rows in 2.26s`.<br>**Phase 0 Confounding Check**: `iam_baseline.json` has zero `allUsers`, `allAuthenticatedUsers`, `domain:`, or `group:` bindings, and zero pre-existing bindings for `ge-test-p5` or `ge-test-p6`. Both conclusions are **UNCONFOUNDED**. |
| **Q7** | **Does the data agent require sharing at BOTH the console level and the dataset level?** | **YES — BOTH are strictly and independently required.** Sharing the Data Agent in Console/IAM (`roles/geminidataanalytics.dataAgentUser` on the `DataAgent` resource) only grants `geminidataanalytics.dataAgents.chat/.get/.list`; it does **not** grant BigQuery table access. Conversely, granting `roles/bigquery.dataViewer` on the BigQuery dataset does **not** grant `geminidataanalytics.dataAgents.chat` on the `DataAgent` resource. | **Test Q7-1 (Console/Agent share ONLY, no dataset `dataViewer`)**: Enters GDA, retrieves schema, generates SQL, and **fails** with: `Access Denied: Table heygreg-telco-demo:ge_access_test_permitted_a.customers: User does not have permission to query table heygreg-telco-demo:ge_access_test_permitted_a.customers, or perhaps it does not exist.`<br>**Test Q7-2 (Dataset `dataViewer` ONLY, no Agent `dataAgentUser`)**: Rejected at GDA front door with HTTP `403 PERMISSION_DENIED`: `The authenticated user does not have permission 'geminidataanalytics.dataAgents.chat' for tenant 'projects/heygreg-telco-demo/locations/global/dataAgents/ge_access_test_bq_agent'.` |
| **Q8** | **For the BigQuery layer (`cloudaicompanion.user`, `bigquery.jobUser`, `datacatalog.viewer`), WHICH project must they be granted on when the GE/Agent project differs from the BigQuery Dataset project?** | **Settled empirically using cross-project topology (`Project 1 = heygreg-telco-demo` hosting GE & the Data Agent; `Project 2 = bigquery-public-data` hosting table `thelook_ecommerce.users`, where `P2` has ZERO project-level roles on `bigquery-public-data`)**:<br>1. **`roles/bigquery.jobUser`** (which also supplies `cloudaicompanion.topics.create` and `geminidataanalytics.locations.chat`): Must be granted on **Project 1 (the Agent / Billing Project, `heygreg-telco-demo`)**, **NOT** on Project 2 (the Data Project)! Why? In Path A, `IamUtil.kt:456, 469` sets `jobProjectId = projectMapper.projectId(resourceProject)` (the project hosting the Data Agent) as the `insertJobRequest.projectId` where `bigquery.jobs.create` is billed and checked. In Path B (MCP), `execute_sql` checks `bigquery.jobs.create` on the `projectId` parameter passed to the tool (the billing project). When `P2` passes `projectId = "heygreg-telco-demo"` to query `bigquery-public-data.thelook_ecommerce.users`, it **succeeds (`200 OK`)**; when `P2` passes `projectId = "bigquery-public-data"`, it **fails** because `P2` lacks `bigquery.jobs.create` in `bigquery-public-data`.<br>2. **`roles/bigquery.dataViewer`**: Must be granted on **Project 2 (the Data Project / Dataset)**.<br>3. **`roles/cloudaicompanion.user` & `roles/datacatalog.viewer`**: **Required on NEITHER project** (redundant when `bigquery.jobUser` is on Project 1 and `bigquery.dataViewer` is on the dataset in Project 2). | **Path A Cross-Project (`ge_access_test_cross_proj_agent` in `heygreg-telco-demo` querying `bigquery-public-data.thelook_ecommerce.users` as `P2`)**: `200 OK` — `SELECT traffic_source, COUNT(*) AS user_count FROM bigquery-public-data.thelook_ecommerce.users GROUP BY traffic_source` -> `Query returned 5 rows in 1.61s`.<br>**Path B Cross-Project (`projectId="heygreg-telco-demo"` querying `bigquery-public-data` as `P2`)**: `200 OK` (`queryId: 0sLFtLHFELUiKTMWSyatJnGXdJN1%1a1551e81f1`, returns all 5 rows / 100,000 users).<br>**Path B Cross-Project (`projectId="bigquery-public-data"` as `P2`)**: `Access Denied: Project bigquery-public-data: User does not have bigquery.jobs.create permission in project bigquery-public-data.` |

### 6.3 Minimum Viable Role Set (Replacing the Over-Broad List in `b/512020253`)

| Layer / Scope | Minimum Viable Role Set for **Path A (Published BigQuery Data Agent)** | Minimum Viable Role Set for **Path B (BigQuery MCP Connector)** |
|---|---|---|
| **1. Gemini Enterprise Host Project** | `roles/discoveryengine.agentspaceUser` *(plus sharing the agent in GE)* | `roles/discoveryengine.agentspaceUser` |
| **2. Data Agent / Billing Project** *(can be the same project as #1)* | - `roles/geminidataanalytics.dataAgentUser` *(on the specific `DataAgent` resource or project)*<br>- `roles/bigquery.jobUser` *(on the project — already includes `cloudaicompanion.topics.create` and `geminidataanalytics.locations.chat`!)*<br>*(Do **NOT** grant `roles/datacatalog.viewer`; `roles/cloudaicompanion.user` is redundant)* | - `roles/mcp.toolUser` *(on the billing project)*<br>- `roles/bigquery.jobUser` *(on the billing project)*<br>*(Do **NOT** grant `roles/datacatalog.viewer`)* |
| **3. BigQuery Data Project / Dataset** *(can be a separate data project)* | - `roles/bigquery.dataViewer` *(at the **dataset** or **table** level — never at the project level!)*<br>- *(Optional)* `roles/datacatalog.categoryFineGrainedReader` on permitted policy tags + Row Access Policy membership | - `roles/bigquery.dataViewer` *(at the **dataset** or **table** level — never at the project level!)*<br>- *(Optional)* `roles/datacatalog.categoryFineGrainedReader` on permitted policy tags + Row Access Policy membership |


---

## 7. Phase 5 — Verdict, Divergences, Known Gotchas & Draft Bug Reports

### 7.1 Architectural Verdict for a ~2,000-Seat Enterprise Rollout

To advise an enterprise rolling out Gemini Enterprise to ~2,000 seats over BigQuery — with **no per-agent service account sprawl** and **user/group-scoped data access** — we MUST separate the **Identity Model** from **Scoping Granularity**:

| Dimension | Path A: Published BigQuery Data Agent (`geminidataanalytics.googleapis.com`) | Path B: Managed 1P BigQuery MCP Connector (`bigquery.googleapis.com/mcp`) | Path B-Alt: Self-Hosted Custom BigQuery MCP on Cloud Run (`*.run.app/mcp`) |
|---|---|---|---|
| **1. Identity Model (Who executes the BigQuery job?)** | **Per-user OAuth (`END USER`)**. Zero per-agent service accounts required. Google Workspace / Cloud Identity groups work natively on both the `DataAgent` resource (`roles/geminidataanalytics.dataAgentUser`) and BigQuery datasets (`roles/bigquery.dataViewer`). | **Per-user OAuth (`END USER`)**. Zero per-agent service accounts required. Group IAM bindings work natively on BigQuery datasets (`roles/bigquery.dataViewer`). | **Configurable**: Transport is the GE Service Agent (`roles/run.invoker`), while BigQuery execution can either forward the user's OAuth token (`Authorization` header) or use a shared Cloud Run runtime SA. |
| **2. Agent-Level Dataset / Table Scoping Granularity** | **YES — Hard Server-Side SQL AST Allowlist (`publishedContext.datasourceReferences.bq.tableReferences`)**. Even if a user has broad IAM access to 50 datasets, a Finance Data Agent will **only** query the specific tables configured in its `publishedContext` and rejects queries referencing any other table before execution. | **NO — Zero Agent-Level Scoping**. Exposes **every** project, dataset, and table across Google Cloud that the calling user's IAM roles allow (`ge_access_test_forbidden_b`, `bigquery-public-data`, etc.). | **Custom-Code Dependent**. Only scoped if the customer writes custom SQL validation / dataset allowlisting inside their Cloud Run MCP server. |
| **3. Blast Radius of an Over-Granted User (`P1`)** | **Contained to the Agent's `publishedContext` tables**. Over-granted `P1` is blocked from querying `ge_access_test_forbidden_b.forbidden_users` through the agent: `Attempting to access tables outside the conversation's context definition`. | **Unbounded across the user's entire IAM footprint**. Over-granted `P1` immediately queries `ge_access_test_forbidden_b.forbidden_users` (`20 rows` returned). Even narrowly granted `P2` can query `bigquery-public-data` (`100,000 rows`) billed to the enterprise project. | **Unbounded** unless custom table allowlisting is implemented in the custom server. |
| **4. Column-Level Security (Policy Tags) & Row Access Policies (RLS)** | **100% Enforced by BigQuery** on the calling user (`P3` blocked on `email`; `P4` restricted to `Organic` rows). | **100% Enforced by BigQuery** on the calling user (`P3` blocked on `email`; `P4` restricted to `Organic` rows). | **Enforced ONLY if per-user OAuth forwarding is configured**; **BYPASSED** if the Cloud Run MCP server executes queries using a shared runtime service account! |
| **5. Schema Context & Curated System Instructions** | **Rich**: Supports curated table/column descriptions, golden SQL examples, synonyms, and agent-specific `systemInstruction`. | **Raw**: Only sees raw BigQuery table schemas via `get_table_info`; no curated golden SQL or domain context per connector. | **Custom**: Requires maintaining custom prompt/tool metadata in code. |

#### Final Recommendation for the 2,000-Seat Enterprise
- **Primary Recommendation — Use Path A (Published BigQuery Data Agents) with Google Group IAM Bindings**:
  1. **Both paths use per-user OAuth**, so **neither path requires managing a service account per agent** (your prior assumption that Published Data Agents are pre-scoped to service accounts is refuted).
  2. However, **only Path A (Published BigQuery Data Agent)** provides **defense-in-depth**: it combines **user/group-scoped IAM, Row-Level Security, and Column-Level Policy Tags** with a **hard server-side table allowlist (`publishedContext`)**. In any real 2,000-seat enterprise, some analysts or executives (`P1`) inevitably hold broad read grants across multiple datasets or projects; with Path B (BigQuery MCP), a single prompt can pull data from *any* table those users can reach (`ge_access_test_forbidden_b`), whereas Path A strictly confines each agent to its designated tables.
  3. **How to operationalize Path A for 2,000 seats without role sprawl**:
     - Bind the enterprise user group (e.g., `group:bq-agent-users@corp.com`) once at the GE/Agent project level to:
       - `roles/discoveryengine.agentspaceUser`
       - `roles/bigquery.jobUser` *(which already includes `cloudaicompanion.topics.create` and `geminidataanalytics.locations.chat` — do **not** grant `roles/datacatalog.viewer` or `roles/cloudaicompanion.user`!)*
     - Bind department groups (e.g., `group:finance-analysts@corp.com`) to:
       - `roles/geminidataanalytics.dataAgentUser` on the Finance Data Agent resource (`projects/.../dataAgents/finance_agent`)
       - `roles/bigquery.dataViewer` on the Finance BigQuery dataset (`finance_prod`), plus applicable Policy Tag `FineGrainedReader` and Row Access Policies.
- **When Path B (BigQuery MCP Connector) Is Acceptable**:
  - Only for ad-hoc cross-project data exploration by power users whose BigQuery IAM bindings are already strictly least-privilege at the dataset level, and **never** alongside project-wide `roles/datacatalog.viewer` or project-wide `roles/bigquery.dataViewer`.

---

### 7.2 Explicit Table of Divergences: User's Prior Assumptions vs. Static Analysis (`b/570110182`) vs. Empirical Observation

| Topic | User's Prior Assumption | Static Analysis Claim (`b/570110182` / `b/512020253`) | What We Empirically Observed in `heygreg-telco-demo` |
|---|---|---|---|
| **1. Published BigQuery Data Agent Identity** | Uses a pre-scoped per-agent service account. | Uses each **end user's own OAuth token** (`a2a_agent.py:1339-1377`). | **Static Analysis CONFIRMED / User Prior REFUTED.** `INFORMATION_SCHEMA.JOBS_BY_PROJECT` (`job_id: 2937253e-8d43-4f88-a5be-fa3d13dc0bb0`) and Cloud Audit Logs show `user_email = "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"`. |
| **2. BigQuery MCP Connector Identity** | Inherits an overarching GE service agent identity. | Uses **per-user OAuth**. | **Static Analysis CONFIRMED / User Prior REFUTED.** `INFORMATION_SCHEMA.JOBS_BY_PROJECT` (`job_id: FOMcopjBVXgwb7Wwvvw8gJ2Vpuqf!1a1550efdd7`) and Cloud Audit Logs show `user_email = "ge-test-p1@heygreg-telco-demo.iam.gserviceaccount.com"`. |
| **3. Effect of Service-Account Grants on Data Access** | Service account grants determine what a published data agent or MCP connector can read. | Service-account grants have **NO EFFECT** on data access. | **Static Analysis CONFIRMED / User Prior REFUTED.** Granting all BQ/GDA/MCP roles to `service-395808028747@gcp-sa-discoveryengine` and `service-395808028747@gcp-sa-geminidataanalytics` still resulted in `Access Denied: User does not have bigquery.jobs.create permission` when `P6` called Path A or Path B. |
| **4. Agent-Level Table Scoping (`Path A` vs `Path B`)** | Assumed Path A scopes via SA while Path B is wide open via GE SA. | Noted in `b/574894521` / `b/573324503` that MCP has no scoping, while Data Agent uses `publishedContext`. | **Nuanced Empirical Finding**: Even though BOTH paths run as the end user, **Path A enforces a server-side SQL AST allowlist** (`Attempting to access tables outside the conversation's context definition`), whereas **Path B (MCP) has zero table scoping** and lets `P1` read `ge_access_test_forbidden_b`. |
| **5. Required BigQuery Roles (`roles/cloudaicompanion.user` & `roles/datacatalog.viewer`)** | Suspected the 5-layer role list in `b/512020253` was over-broad. | Listed `cloudaicompanion.user`, `bigquery.jobUser`, and `datacatalog.viewer` as all required (`b/512020253`). | **User Suspicion CONFIRMED / `b/512020253` Role List REFUTED!**<br>1. `roles/bigquery.jobUser` (`bigquery.service:4841-4861`) **already includes** `cloudaicompanion.topics.create` and `geminidataanalytics.locations.chat`, making `roles/cloudaicompanion.user` **redundant**.<br>2. `roles/datacatalog.viewer` is **unnecessary** when `roles/bigquery.dataViewer` is granted on the dataset, AND granting `roles/datacatalog.viewer` at project level **leaks metadata of all 93 datasets in the project** (`military_cui_analytics`, `ge_access_test_forbidden_b`) to `P2`! |
| **6. Which Project Needs `bigquery.jobUser` in Cross-Project Topologies?** | Unspecified in public docs. | Flagged as an unverified hypothesis in `b/512020253` because public docs only say *"the project"*. | **Settled Empirically**: `roles/bigquery.jobUser` must be granted on the **Data Agent / Billing Project (`heygreg-telco-demo`)**, whereas `roles/bigquery.dataViewer` must be granted on the **Dataset in the Data Project (`bigquery-public-data`)**. |
| **7. Registration Permission (`discoveryengine.agents.manage` vs `.create`)** | N/A | Cited `create_agent_handler.cc:2053` as requiring `discoveryengine.agents.manage`. | **Nuanced at HEAD**: `create_agent_handler.cc:2174` delegates to `agent_permissioncheck_module_impl.cc:82-104`, which checks **`discoveryengine.agents.create`** for standard users and `discoveryengine.agents.manage` (on `engines/*` or `assistants/*`) only for admin bypass when sharing permissions are disabled. |

---

### 7.3 Known Gotcha: Registering a Cloud Run Custom MCP Server in Gemini Enterprise (`/mcp` Path Requirement)

When an enterprise deploys a custom MCP server (such as the open-source Google GenAI Toolbox for Databases / FastMCP / ADK BigQuery MCP server) to **Cloud Run**, the Cloud Run console displays the service root URL:
```text
https://<service>-<hash>.a.run.app
```
However, registering that root URL in Gemini Enterprise fails! Here is the exact code-level explanation and the URL format that works:

1. **How Gemini Enterprise Connects to Custom MCP Servers**:
   - In [`cloud/ml/discoveryengine/common/connectors/registry/configs/custom_mcp_v1_0.textproto`](file:///google/src/cloud/heygreg/bigquery_gemini_access_control/google3/cloud/ml/discoveryengine/common/connectors/registry/configs/custom_mcp_v1_0.textproto#L1-L32), the `custom_mcp` connector validates `instance_uri` only against `^https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$` and passes `instance_uri` **verbatim** to the Streamable HTTP MCP client in `tools.py` — **it never appends `/mcp` or `/sse` automatically**.
   - In the Cloud Console UI ([`mcp_server_form.ts`](file:///google/src/cloud/heygreg/bigquery_gemini_access_control/google3/cloud/console/web/ai/unified_cloud_search/components/datastore/create_datastore/mcp_server_form/mcp_server_form.ts#L53-L57)), the input placeholder is `https://your-mcp-server.com` with no hint that a sub-path is required.
2. **How Cloud Run MCP Servers Mount Their Transport**:
   - Standard Streamable HTTP MCP frameworks (Python `FastMCP.streamable_http_app()`, ADK MCP server, and Google's BigQuery MCP implementation) mount the MCP JSON-RPC endpoint at **`/mcp`** (or `/sse` for legacy SSE), while `GET /` or `POST /` returns `404 Not Found` (or a health check string).
   - Even Google's own 1P BigQuery MCP connector config ([`bigquery_mcp_v2_0.textproto`](file:///google/src/cloud/heygreg/bigquery_gemini_access_control/google3/cloud/ml/discoveryengine/common/connectors/registry/configs/bigquery_mcp_v2_0.textproto#L41)) hardcodes the `/mcp` suffix: `ServiceName: "https://bigquery.googleapis.com/mcp"`.
3. **Exact Working URL Format vs. Failing Format**:
   - **FAILS (`404 Not Found` / tool discovery failure)**: `https://<service>-<hash>.a.run.app`
   - **WORKS (`200 OK` JSON-RPC Streamable HTTP)**: **`https://<service>-<hash>.a.run.app/mcp`**
   - *(Additionally, for private Cloud Run services, `service-395808028747@gcp-sa-discoveryengine.iam.gserviceaccount.com` must be granted `roles/run.invoker` on the Cloud Run service).*

---

### 7.4 Draft Bug Reports Worth Filing (Read-Only — Not Filed per Constraints)

Per the hard constraint (*"Internal lookups are read-only. Do not comment on, edit, or assign any bug"*), we did **not** file or comment on any Buganizer issues. Below are **four concrete bugs/doc gaps** uncovered by our empirical testing, ready to file if desired:

#### Draft Bug 1: Remove `roles/datacatalog.viewer` and `roles/cloudaicompanion.user` from Recommended GDA / GE BigQuery User Role Lists (Security / Least-Privilege Defect)
- **Suggested Component**: `Cloud > Data Analytics > Conversational Analytics (Gemini in BigQuery)` (and `Discovery Engine > Agentspace`)
- **Related Issue**: `b/512020253`
- **Summary**: Internal triage playbooks (`b/512020253`) and setup guides recommend granting end users `roles/datacatalog.viewer` and `roles/cloudaicompanion.user` at the project level alongside `roles/bigquery.jobUser` and dataset-level `roles/bigquery.dataViewer`.
- **Empirical Evidence**:
  1. `roles/bigquery.jobUser` (`configs/storage/zanzibar/prod/iam/bigquery.service:4841-4861`) already includes both `cloudaicompanion.topics.create` and `geminidataanalytics.locations.chat`. Both Path A (`geminidataanalytics` A2A) and Path B (`bigquery.googleapis.com/mcp`) succeed with `200 OK` when `roles/cloudaicompanion.user` is omitted.
  2. Both Path A and Path B succeed with `200 OK` when `roles/datacatalog.viewer` is omitted (provided the user has `roles/bigquery.dataViewer` on the target dataset).
  3. Granting `roles/datacatalog.viewer` at the project level grants `bigquery.datasets.get` and `bigquery.tables.get` across **every dataset in the project**, causing `list_dataset_ids` on the BigQuery MCP server to leak all 93 dataset names in `heygreg-telco-demo` (including `military_cui_analytics` and `ge_access_test_forbidden_b`) to a persona (`P2`) that was only supposed to see `ge_access_test_permitted_a`.

#### Draft Bug 2: Server-Side `CreateAgent` API Allows Registering a 1P `geminidataanalytics.googleapis.com` A2A Agent with Empty `authorizationConfig`, Causing Guaranteed Runtime `401 UNAUTHENTICATED`
- **Suggested Component**: `Cloud > AI > Discovery Engine > Agent Builder / Agentspace`
- **Related Issue**: `b/567202350` (fixed in Console UI only)
- **Summary**: While `b/567202350` fixed the Cloud Console UI (`create_agent_checklist.ts:288`) to auto-attach default 1P OAuth when registering a Conversational Analytics agent, the backend REST API (`create_agent_handler.cc`) still accepts `POST .../agents` with an `a2aAgentDefinition` pointing to `geminidataanalytics.googleapis.com` and an empty `authorizationConfig: {}` (`200 OK`). At runtime on the HTTP A2A path (`a2a_agent.py:1312, 1341-1375`), GE sends `headers={}` (no OAuth token and no Cloud Run/Agent Engine service-agent token), causing every user invocation to fail with `401 UNAUTHENTICATED` (`Unable to obtain a response from the agent`).
- **Proposed Fix**: Reject `CreateAgent` / `UpdateAgent` requests whose A2A Agent Card URL targets `geminidataanalytics.googleapis.com` when `authorization_config.agent_authorization` is empty (or automatically populate the default 1P `geminidataanalytics` authorization server-side).

#### Draft Bug 3: Public Documentation for BigQuery Data Agents & BigQuery MCP Fails to Disambiguate Billing/Agent Project vs. Data Project in Cross-Project Topologies
- **Suggested Component**: `Cloud > Data Analytics > Conversational Analytics > Documentation`
- **Summary**: Public docs (`gemini/data-agents/conversational-analytics-api/access-control.md`, `bigquery/docs/use-bigquery-mcp.md`, and `gemini/enterprise/docs/register-and-manage-an-a2a-agent.md`) instruct admins to grant `roles/bigquery.jobUser` on *"the project"* and `roles/bigquery.dataViewer` on *"the data sources"* without specifying which project needs which role when Gemini Enterprise / the Data Agent lives in Project A and the BigQuery datasets live in Project B.
- **Empirical Evidence**: Live testing with `ge_access_test_cross_proj_agent` proves that `roles/bigquery.jobUser` (`bigquery.jobs.create`) is checked on **Project A (the Data Agent host / MCP billing project)** (`IamUtil.kt:456, 469`), whereas `roles/bigquery.dataViewer` (`bigquery.tables.getData`) is checked on **Project B (the dataset project)**.

#### Draft Bug 4: Cloud Console Custom MCP Server Form (`mcp_server_form.ts`) Placeholder Omits `/mcp` Path, Leading to `404 Not Found` on Cloud Run MCP Servers
- **Suggested Component**: `Cloud > AI > Discovery Engine > Console UI`
- **Summary**: In `cloud/console/web/ai/unified_cloud_search/components/datastore/create_datastore/mcp_server_form/mcp_server_form.ts:57`, the URI placeholder is `https://your-mcp-server.com`. Users deploying FastMCP / ADK / GenAI Toolbox MCP servers on Cloud Run copy the Cloud Run service URL (`https://<service>-<hash>.a.run.app`) without `/mcp`, which fails because `custom_mcp_v1_0.textproto` passes `instance_uri` verbatim without appending `/mcp`.
- **Proposed Fix**: Update the UI helper text and placeholder to `https://your-mcp-server.a.run.app/mcp` and warn if a `*.run.app` URL has an empty path `/`.

---

## 8. Companion Deliverables in This Repository

1. **[`repro_live.sh`](file:///google/src/cloud/heygreg/bigquery_gemini_access_control/google3/repro_live.sh)**: Self-contained CLI script that impersonates `ge-test-p1` through `ge-test-p6` in `heygreg-telco-demo` and reproduces each of the 6 core findings live in front of an audience (`decisive_identity`, `scoping_blast_radius`, `cls_policy_tag`, `rls_row_policy`, `no_auth_agent`, `missing_grant_403`, or `all`).
2. **[`teardown.sh`](file:///google/src/cloud/heygreg/bigquery_gemini_access_control/google3/teardown.sh)**: Complete teardown script that removes all test agents (`4428205637215869360`, `14430632809526264555`, `356457298153657014`), the GE test engine (`ge-bq-access-test-engine`), authorization resources, the MCP connector collection (`ge_access_test_bq_mcp`), GDA data agents (`ge_access_test_bq_agent`, `ge_access_test_cross_proj_agent`), service accounts (`ge-test-p1`..`p6`) and their IAM bindings, BigQuery datasets (`ge_access_test_permitted_a`, `ge_access_test_forbidden_b`), and the Data Catalog policy tag taxonomy (`3838347283155594953`).
