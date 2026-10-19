#!/usr/bin/env bash
# ==============================================================================
# Teardown Script: Gemini Enterprise -> BigQuery Access Control Test Harness
# Project: heygreg-telco-demo (395808028747)
#
# Removes all dedicated resources created for this verification:
#   1. Registered A2A agents (A-i, A-ii, A-iii) & GE Engine (ge-bq-access-test-engine)
#   2. Authorization resources (geminidataanalytics_test_ai, ge-access-test-explicit-auth-2)
#   3. BigQuery MCP connector collection (ge_access_test_bq_mcp)
#   4. GDA Published Data Agents (ge_access_test_bq_agent, ge_access_test_cross_proj_agent)
#   5. BigQuery datasets (ge_access_test_permitted_a, ge_access_test_forbidden_b)
#   6. Data Catalog Policy Tag Taxonomy (projects/heygreg-telco-demo/locations/us/taxonomies/3838347283155594953)
#   7. Project-level IAM bindings and Service Accounts (ge-test-p1 .. ge-test-p6)
# ==============================================================================
set -euo pipefail

PROJECT_ID="heygreg-telco-demo"
PROJECT_NUM="395808028747"
ENGINE_ID="ge-bq-access-test-engine"
MCP_COLLECTION_ID="ge_access_test_bq_mcp"
TAXONOMY_ID="3838347283155594953"

TOK="$(gcloud auth print-access-token)"

echo "=== 1. Deleting Registered GE Agents and Engine (${ENGINE_ID}) ==="
for AID in 4428205637215869360 14430632809526264555 356457298153657014; do
  curl -sS -X DELETE \
    "https://discoveryengine.googleapis.com/v1alpha/projects/${PROJECT_NUM}/locations/global/collections/default_collection/engines/${ENGINE_ID}/assistants/default_assistant/agents/${AID}" \
    -H "Authorization: Bearer ${TOK}" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" || true
done

curl -sS -X DELETE \
  "https://discoveryengine.googleapis.com/v1alpha/projects/${PROJECT_NUM}/locations/global/collections/default_collection/engines/${ENGINE_ID}" \
  -H "Authorization: Bearer ${TOK}" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" || true

echo "=== 2. Deleting GE Authorization Resources ==="
for AUTH_ID in ge-test-gda-default-auth ge-test-gda-explicit-auth geminidataanalytics_test_ai ge-access-test-explicit-auth ge-access-test-explicit-auth-2; do
  curl -sS -X DELETE \
    "https://discoveryengine.googleapis.com/v1alpha/projects/${PROJECT_NUM}/locations/global/authorizations/${AUTH_ID}" \
    -H "Authorization: Bearer ${TOK}" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" || true
done

echo "=== 3. Deleting BigQuery MCP Connector Collection (${MCP_COLLECTION_ID}) ==="
curl -sS -X DELETE \
  "https://discoveryengine.googleapis.com/v1alpha/projects/${PROJECT_NUM}/locations/global/collections/${MCP_COLLECTION_ID}" \
  -H "Authorization: Bearer ${TOK}" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" || true

echo "=== 4. Deleting GDA Published Data Agents ==="
for DA_ID in ge_access_test_bq_agent ge_access_test_cross_proj_agent; do
  curl -sS -X DELETE \
    "https://geminidataanalytics.googleapis.com/v1beta/projects/${PROJECT_ID}/locations/global/dataAgents/${DA_ID}" \
    -H "Authorization: Bearer ${TOK}" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" || true
done

echo "=== 5. Removing Project IAM Bindings & Deleting Service Accounts (ge-test-p1..p6) ==="
ROLES=(
  "roles/discoveryengine.agentspaceUser"
  "roles/geminidataanalytics.dataAgentUser"
  "roles/cloudaicompanion.user"
  "roles/bigquery.jobUser"
  "roles/datacatalog.viewer"
  "roles/mcp.toolUser"
)
for i in 1 2 3 4 5 6; do
  SA="ge-test-p${i}@${PROJECT_ID}.iam.gserviceaccount.com"
  for ROLE in "${ROLES[@]}"; do
    gcloud projects remove-iam-policy-binding "${PROJECT_ID}" \
      --member="serviceAccount:${SA}" \
      --role="${ROLE}" \
      --all --quiet >/dev/null 2>&1 || true
  done
  gcloud iam service-accounts delete "${SA}" --project="${PROJECT_ID}" --quiet || true
done

echo "=== 6. Removing BigQuery Datasets ==="
bq rm -r -f -d "${PROJECT_ID}:ge_access_test_permitted_a" || true
bq rm -r -f -d "${PROJECT_ID}:ge_access_test_forbidden_b" || true

echo "=== 7. Deleting Data Catalog Policy Tag Taxonomy ==="
curl -sS -X DELETE \
  "https://datacatalog.googleapis.com/v1/projects/${PROJECT_ID}/locations/us/taxonomies/${TAXONOMY_ID}" \
  -H "Authorization: Bearer ${TOK}" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" || true

echo "=== Teardown Complete ==="
