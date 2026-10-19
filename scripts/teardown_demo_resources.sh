#!/usr/bin/env bash
# Teardown script for GFS SIM Coaching Agent Demo resources in heygreg-telco-demo
set -euo pipefail

PROJECT_ID="heygreg-telco-demo"
CONFIG_FILE="$(dirname "$0")/../app/config_generated.json"

if [ -f "${CONFIG_FILE}" ]; then
  echo "=== Deleting Google Drive Demo Docs ==="
  P1_TOK="$(gcloud auth print-access-token --impersonate-service-account=ge-test-p1@${PROJECT_ID}.iam.gserviceaccount.com --scopes=https://www.googleapis.com/auth/drive 2>/dev/null || true)"
  if [ -n "${P1_TOK}" ]; then
    for DOC_ID in $(python3 -c "import json; d=json.load(open('${CONFIG_FILE}')); print(' '.join(x['doc_id'] for x in d.get('drive_docs', [])))"); do
      curl -sS -X DELETE "https://www.googleapis.com/drive/v3/files/${DOC_ID}" \
        -H "Authorization: Bearer ${P1_TOK}" || true
      echo "  Deleted Drive Doc ${DOC_ID}"
    done
  fi
fi

echo "=== Deleting BigQuery Dataset ${PROJECT_ID}:gfs_sim_sales ==="
bq rm -r -f -d "${PROJECT_ID}:gfs_sim_sales" || true
echo "=== Teardown Complete ==="
