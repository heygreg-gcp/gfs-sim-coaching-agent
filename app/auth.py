"""Dual-header 3LO End-User OAuth token extraction and persona token minting for [DEMO] HarvestLine Foodservice SIM Agent.

Matches Gemini Enterprise (Dolphin) behavior in a2a_agent.py:1475-1551:
- Agent Engine V2 URLs move the user's 3LO OAuth token to `X-Goog-Agent-User-Authorization`
  while placing the Discovery Engine Service Agent token in `Authorization`.
- Cloud Run URLs (`*.run.app`) place the Discovery Engine Service Agent OIDC token in
  `X-Serverless-Authorization` and keep the user's 3LO OAuth token in `Authorization`.
"""

from typing import Mapping, Tuple
import subprocess
from google.oauth2 import credentials as oauth2_credentials

PROJECT_ID = "heygreg-telco-demo"

PERSONA_SERVICE_ACCOUNTS = {
    "P1": {
        "id": "P1",
        "name": "[DEMO] National VP of Sales (Full Access)",
        "email": f"ge-test-p1@{PROJECT_ID}.iam.gserviceaccount.com",
        "role_summary": "All Sales Territories + Supplier Rebate Policy Tag + All [DEMO] Drive Playbooks (incl. Confidential)",
    },
    "P4": {
        "id": "P4",
        "name": "[DEMO] Midwest District Sales Manager (RLS Scoped)",
        "email": f"ge-test-p4@{PROJECT_ID}.iam.gserviceaccount.com",
        "role_summary": "RLS Restricted to 'Organic' Territory Only + Standard [DEMO] Drive Playbook Only (Confidential Drive Doc Hidden)",
    },
    "P3": {
        "id": "P3",
        "name": "[DEMO] Sales Enablement Analyst (CLS Blocked on Margin)",
        "email": f"ge-test-p3@{PROJECT_ID}.iam.gserviceaccount.com",
        "role_summary": "All Territories, NO Fine-Grained Reader on supplier_rebate_margin_pct Policy Tag + Standard [DEMO] Drive Playbook",
    },
    "P6": {
        "id": "P6",
        "name": "[DEMO] Unscoped GE User (Zero BQ / Zero Drive Grants)",
        "email": f"ge-test-p6@{PROJECT_ID}.iam.gserviceaccount.com",
        "role_summary": "discoveryengine.agentspaceUser ONLY — Zero BigQuery jobUser/dataViewer & Zero Drive Access",
    },
}


class AuthError(Exception):
    """Raised when end-user OAuth credentials are missing or invalid (Case A-iii)."""


def extract_user_oauth_token(headers: Mapping[str, str]) -> Tuple[str, str]:
    """Extracts the end-user 3LO OAuth token and source header name.

    Fails closed if neither X-Goog-Agent-User-Authorization nor Authorization contains a Bearer token.
    """
    normalized = {k.lower(): (k, v) for k, v in headers.items()}

    for candidate_lower, canonical_name in [
        ("x-goog-agent-user-authorization", "X-Goog-Agent-User-Authorization"),
        ("authorization", "Authorization"),
    ]:
        if candidate_lower in normalized:
            _, raw_val = normalized[candidate_lower]
            val = (raw_val or "").strip()
            if val.lower().startswith("bearer "):
                token = val[7:].strip()
                if token:
                    return token, canonical_name

    raise AuthError(
        "CREDENTIALS_MISSING: Request is missing required end-user OAuth 2.0 Bearer token "
        "in 'X-Goog-Agent-User-Authorization' or 'Authorization'. Verify that the agent is "
        "registered in Gemini Enterprise with a valid authorizationConfig (not empty '{}')."
    )


def build_user_credentials(token: str) -> oauth2_credentials.Credentials:
    """Wraps a short-lived end-user 3LO OAuth access token into google.oauth2.credentials.Credentials."""
    if not token or not token.strip():
        raise AuthError("CREDENTIALS_MISSING: Empty OAuth access token.")
    return oauth2_credentials.Credentials(token=token.strip())


def mint_persona_oauth_token(persona_id: str) -> Tuple[str, dict]:
    """Mints a real short-lived OAuth 2.0 access token (bigquery + drive.readonly scopes) for a test persona SA."""
    if persona_id not in PERSONA_SERVICE_ACCOUNTS:
        raise ValueError(f"Unknown persona_id: {persona_id}")
    persona = PERSONA_SERVICE_ACCOUNTS[persona_id]
    sa_email = persona["email"]
    cmd = [
        "gcloud",
        "auth",
        "print-access-token",
        f"--impersonate-service-account={sa_email}",
        "--scopes=https://www.googleapis.com/auth/bigquery,https://www.googleapis.com/auth/drive.readonly",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=20)
    token = res.stdout.strip().splitlines()[-1].strip()
    return token, persona
