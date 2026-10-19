#!/usr/bin/env bash
# ==============================================================================
# Live Audience Repro Script: Gemini Enterprise -> BigQuery Access Control
# Project: heygreg-telco-demo (395808028747)
#
# Usage:
#   ./repro_live.sh decisive_identity
#   ./repro_live.sh scoping_blast_radius
#   ./repro_live.sh cls_policy_tag
#   ./repro_live.sh rls_row_policy
#   ./repro_live.sh no_auth_agent
#   ./repro_live.sh missing_grant_403
#   ./repro_live.sh all
# ==============================================================================
set -euo pipefail

PROJECT_ID="heygreg-telco-demo"
PROJECT_NUM="395808028747"
ENGINE_ID="ge-bq-access-test-engine"
DATA_AGENT_ID="ge_access_test_bq_agent"
AGENT_A_III_ID="356457298153657014"

A2A_URL="https://geminidataanalytics.googleapis.com/v1beta/a2a/projects/${PROJECT_ID}/locations/global/dataAgents/${DATA_AGENT_ID}/v1/message:stream"
MCP_URL="https://bigquery.googleapis.com/mcp"
STREAM_ASSIST_URL="https://discoveryengine.googleapis.com/v1alpha/projects/${PROJECT_NUM}/locations/global/collections/default_collection/engines/${ENGINE_ID}/assistants/default_assistant:streamAssist"

token_for() {
  local persona="$1"
  gcloud auth print-access-token \
    "--impersonate-service-account=ge-test-${persona}@${PROJECT_ID}.iam.gserviceaccount.com" 2>/dev/null
}

call_mcp_sql() {
  local tok="$1"
  local sql="$2"
  curl -sS -X POST "${MCP_URL}" \
    -H "Authorization: Bearer ${tok}" \
    -H "Content-Type: application/json" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"execute_sql\",\"arguments\":{\"projectId\":\"${PROJECT_ID}\",\"query\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${sql}")}}}"
  echo ""
}

call_a2a() {
  local tok="$1"
  local prompt="$2"
  curl -sS -X POST "${A2A_URL}" \
    -H "Authorization: Bearer ${tok}" \
    -H "Content-Type: application/json" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    -d "{\"message\":{\"messageId\":\"live-$(date +%s)\",\"role\":\"ROLE_USER\",\"content\":[{\"text\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${prompt}")}]}}" \
  | python3 -c '
import sys, json
raw = sys.stdin.read()
try:
    data = json.loads(raw)
    if isinstance(data, list) and data and "error" in data[0]:
        print("HTTP ERROR:", json.dumps(data[0]["error"], indent=2))
    elif isinstance(data, list):
        for ev in data:
            msg = ev.get("message", {})
            for c in msg.get("content", []):
                if "text" in c and c["text"].strip():
                    print("  [A2A]", c["text"].strip())
    else:
        print(raw[:600])
except Exception:
    print(raw[:600])
'
}

run_decisive_identity() {
  echo "================================================================================"
  echo "TEST 1: DECISIVE IDENTITY TEST (Who executes the BigQuery job?)"
  echo "Persona: P1 (ge-test-p1@${PROJECT_ID}.iam.gserviceaccount.com)"
  echo "================================================================================"
  local tok
  tok="$(token_for p1)"

  echo "--> [Path A] Invoking Published BQ Data Agent (${DATA_AGENT_ID}) as P1..."
  call_a2a "${tok}" "Count rows grouped by traffic_source in ${PROJECT_ID}.ge_access_test_permitted_a.customers. Do not select email."

  echo "--> [Path B] Invoking BigQuery MCP Server (${MCP_URL}) as P1..."
  call_mcp_sql "${tok}" "SELECT traffic_source, COUNT(*) AS cnt FROM \`${PROJECT_ID}.ge_access_test_permitted_a.customers\` GROUP BY traffic_source ORDER BY traffic_source"

  echo "--> Querying region-us.INFORMATION_SCHEMA.JOBS_BY_PROJECT for actual executing user_email..."
  bq query --project_id="${PROJECT_ID}" --use_legacy_sql=false --format=prettyjson \
    "SELECT job_id, user_email, labels, LEFT(query, 120) AS query_snippet
     FROM \`${PROJECT_ID}\`. \`region-us\`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
     WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 15 MINUTE)
       AND user_email = 'ge-test-p1@${PROJECT_ID}.iam.gserviceaccount.com'
     ORDER BY creation_time DESC LIMIT 4"
}

run_scoping_blast_radius() {
  echo "================================================================================"
  echo "TEST 2: SCOPING GRANULARITY & BLAST RADIUS OF OVER-GRANTED USER (P1 & P2)"
  echo "================================================================================"
  local tok_p1 tok_p2
  tok_p1="$(token_for p1)"
  tok_p2="$(token_for p2)"

  echo "--> [Path B: BigQuery MCP] Over-granted P1 querying forbidden dataset ge_access_test_forbidden_b.forbidden_users:"
  call_mcp_sql "${tok_p1}" "SELECT COUNT(*) AS forbidden_row_count FROM \`${PROJECT_ID}.ge_access_test_forbidden_b.forbidden_users\`"

  echo "--> [Path B: BigQuery MCP] Scoped P2 querying external public dataset bigquery-public-data.thelook_ecommerce.users:"
  call_mcp_sql "${tok_p2}" "SELECT traffic_source, COUNT(*) AS cnt FROM \`bigquery-public-data.thelook_ecommerce.users\` GROUP BY traffic_source ORDER BY traffic_source"

  echo "--> [Path A: Published Data Agent] Over-granted P1 attempting to query ge_access_test_forbidden_b.forbidden_users:"
  call_a2a "${tok_p1}" "Run a SQL query to count rows in ${PROJECT_ID}.ge_access_test_forbidden_b.forbidden_users"
}

run_cls_policy_tag() {
  echo "================================================================================"
  echo "TEST 3: COLUMN-LEVEL SECURITY (Policy Tag on customers.email)"
  echo "P2 = Fine-Grained Reader granted | P3 = Fine-Grained Reader OMITTED"
  echo "================================================================================"
  local tok_p2 tok_p3
  tok_p2="$(token_for p2)"
  tok_p3="$(token_for p3)"

  echo "--> [Path B: MCP] P2 reading policy-tagged column (email):"
  call_mcp_sql "${tok_p2}" "SELECT user_id, email FROM \`${PROJECT_ID}.ge_access_test_permitted_a.customers\` ORDER BY user_id LIMIT 3"

  echo "--> [Path B: MCP] P3 reading policy-tagged column (email) [EXPECT 403 ACCESS DENIED]:"
  call_mcp_sql "${tok_p3}" "SELECT user_id, email FROM \`${PROJECT_ID}.ge_access_test_permitted_a.customers\` ORDER BY user_id LIMIT 3"

  echo "--> [Path A: Data Agent] P3 reading policy-tagged column (email) [EXPECT POLICY TAG DENIAL]:"
  call_a2a "${tok_p3}" "Select user_id and email from ${PROJECT_ID}.ge_access_test_permitted_a.customers ordered by user_id limit 3"
}

run_rls_row_policy() {
  echo "================================================================================"
  echo "TEST 4: ROW-LEVEL SECURITY (Row Access Policy rlp_organic_only on P4)"
  echo "P2 = All 60 rows (4 partitions) | P4 = Filtered to traffic_source='Organic' (15 rows)"
  echo "================================================================================"
  local tok_p4
  tok_p4="$(token_for p4)"

  echo "--> [Path B: MCP] P4 counting all rows by traffic_source:"
  call_mcp_sql "${tok_p4}" "SELECT traffic_source, COUNT(*) AS cnt FROM \`${PROJECT_ID}.ge_access_test_permitted_a.customers\` GROUP BY traffic_source"

  echo "--> [Path B: MCP] P4 querying traffic_source != 'Organic' (outside row policy):"
  call_mcp_sql "${tok_p4}" "SELECT traffic_source, COUNT(*) AS cnt FROM \`${PROJECT_ID}.ge_access_test_permitted_a.customers\` WHERE traffic_source != 'Organic' GROUP BY traffic_source"

  echo "--> [Path A: Data Agent] P4 counting all rows by traffic_source:"
  call_a2a "${tok_p4}" "Count rows grouped by traffic_source in ${PROJECT_ID}.ge_access_test_permitted_a.customers. Do not select email."
}

run_no_auth_agent() {
  echo "================================================================================"
  echo "TEST 5: CASE A-iii — AGENT REGISTERED WITH NO AUTHORIZATION"
  echo "================================================================================"
  local tok_p1
  tok_p1="$(token_for p1)"

  echo "--> [1] Raw A2A invocation with empty headers (reproducing a2a_agent.py outcome='no_auth_configured'):"
  curl -sS -X POST "${A2A_URL}" \
    -H "Content-Type: application/json" \
    -d '{"message":{"messageId":"no-auth-1","role":"ROLE_USER","content":[{"text":"Count rows in customers"}]}}'
  echo ""

  echo "--> [2] Gemini Enterprise StreamAssist invoking Agent A-iii (${AGENT_A_III_ID}, no authorizationConfig):"
  curl -sS -X POST "${STREAM_ASSIST_URL}" \
    -H "Authorization: Bearer ${tok_p1}" \
    -H "Content-Type: application/json" \
    -H "X-Goog-User-Project: ${PROJECT_ID}" \
    -d "{\"query\":{\"text\":\"Use the GE Access Test BQ Agent to count rows by traffic_source in ${PROJECT_ID}.ge_access_test_permitted_a.customers\"},\"agentsSpec\":{\"agentSpecs\":[{\"agentId\":\"${AGENT_A_III_ID}\"}]}}" \
  | python3 -c '
import sys, json
chunks = json.loads(sys.stdin.read())
out = []
for c in chunks:
    for r in c.get("answer", {}).get("replies", []):
        txt = r.get("groundedContent", {}).get("content", {}).get("text", "")
        if txt:
            out.append(txt)
print("".join(out))
'
}

run_missing_grant_403() {
  echo "================================================================================"
  echo "TEST 6: MISSING-GRANT 403 BEHAVIOR (Persona P6: GE access only, 0 BQ/GDA/MCP roles)"
  echo "================================================================================"
  local tok_p6
  tok_p6="$(token_for p6)"

  echo "--> [Path A: Published Data Agent] Invoking as P6:"
  call_a2a "${tok_p6}" "Count rows in ${PROJECT_ID}.ge_access_test_permitted_a.customers"

  echo "--> [Path B: BigQuery MCP] Invoking as P6:"
  call_mcp_sql "${tok_p6}" "SELECT COUNT(*) FROM \`${PROJECT_ID}.ge_access_test_permitted_a.customers\`"
}

TARGET="${1:-all}"
case "${TARGET}" in
  decisive_identity)    run_decisive_identity ;;
  scoping_blast_radius) run_scoping_blast_radius ;;
  cls_policy_tag)       run_cls_policy_tag ;;
  rls_row_policy)       run_rls_row_policy ;;
  no_auth_agent)        run_no_auth_agent ;;
  missing_grant_403)    run_missing_grant_403 ;;
  all)
    run_decisive_identity
    run_scoping_blast_radius
    run_cls_policy_tag
    run_rls_row_policy
    run_no_auth_agent
    run_missing_grant_403
    ;;
  *)
    echo "Unknown test target: ${TARGET}"
    exit 1
    ;;
esac
