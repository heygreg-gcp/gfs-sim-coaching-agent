"""FastAPI Server for GFS Sales Insight Manager (SIM) A2A Endpoint + Interactive Persona-Switcher Demo Console.

Enforces mandatory web security controls:
- Strict Content-Security-Policy (`default-src 'self'`), `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: SAMEORIGIN`, `Cache-Control: no-store`.
- Dual-header 3LO OAuth extraction (`X-Goog-Agent-User-Authorization` / `Authorization`) matching
  `a2a_agent.py:1475-1551`.
- Fail-closed authentication when no OAuth token or valid persona is supplied.
"""

from pathlib import Path
from typing import Any, Dict, Optional
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from app.agent import GFSSalesInsightCoachAgent
from app.auth import (
    AuthError,
    PERSONA_SERVICE_ACCOUNTS,
    extract_user_oauth_token,
    mint_persona_oauth_token,
)
from app.tools_bq import ALLOWED_TABLES, BILLING_PROJECT_ID, TableAllowlistError, validate_table_allowlist

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(
    title="GFS Sales Insight Manager (SIM) Coaching Agent",
    description="Cross-Project BigQuery + Google Drive ADK/A2A Agent with End-User 3LO OAuth Passthrough",
    version="1.0.0",
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'self'; object-src 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


class ChatTurnRequest(BaseModel):
    prompt: str = Field(
        default="Which accounts are at churn risk and how should I coach the assigned sales reps?",
        max_length=2000,
    )
    persona_id: Optional[str] = Field(default="P1", pattern=r"^(P1|P3|P4|P6|NO_AUTH)$")
    simulated_header_mode: str = Field(
        default="X-Goog-Agent-User-Authorization",
        pattern=r"^(X-Goog-Agent-User-Authorization|Authorization)$",
    )
    include_rebate_margin: bool = Field(default=True)
    synthesize_with_gemini: bool = Field(default=False)
    test_unapproved_table: bool = Field(default=False)


@app.get("/.well-known/agent.json")
async def get_agent_card() -> Dict[str, Any]:
    """Returns the A2A Agent Card for registering the agent in Gemini Enterprise."""
    return {
        "name": "GFS Sales Insight Manager (SIM) Coaching Agent",
        "description": (
            "Combines cross-project BigQuery sales/cold-chain telemetry with Google Drive sales coaching "
            "playbooks in a single turn while enforcing per-user 3LO OAuth, BigQuery Row-Level Security (RLS), "
            "Data Catalog Policy Tags (CLS), SQL Table Allowlisting, and Google Drive file ACLs."
        ),
        "version": "1.0.0",
        "protocolVersion": "0.3.0",
        "authentication": {
            "schemes": ["Bearer"],
            "headersSupported": ["X-Goog-Agent-User-Authorization", "Authorization"],
            "requiredScopes": [
                "https://www.googleapis.com/auth/bigquery",
                "https://www.googleapis.com/auth/drive.readonly",
            ],
        },
        "capabilities": {
            "streaming": True,
            "billingProject": BILLING_PROJECT_ID,
            "allowedTables": sorted(ALLOWED_TABLES),
        },
    }


@app.get("/api/personas")
async def list_personas() -> Dict[str, Any]:
    """Lists the live test personas (P1, P4, P3, P6, plus NO_AUTH Case A-iii)."""
    return {
        "personas": list(PERSONA_SERVICE_ACCOUNTS.values())
        + [
            {
                "id": "NO_AUTH",
                "name": "Broken Registration — Empty authorizationConfig (Case A-iii)",
                "email": "(No Authorization Header Sent by GE)",
                "role_summary": "Reproduces GFS's 'Sales Details Test Agent' & 'test Agent' in b/570110182",
            }
        ]
    }


@app.post("/api/chat")
async def run_persona_chat(req: ChatTurnRequest, request: Request) -> JSONResponse:
    """Executes a live SIM turn using either an incoming 3LO OAuth header or an impersonated persona SA token."""
    try:
        if req.test_unapproved_table:
            validate_table_allowlist(
                "SELECT * FROM `heygreg-telco-demo.ge_access_test_forbidden_b.forbidden_users`"
            )

        if req.persona_id == "NO_AUTH":
            # Simulate Case A-iii where GE sends empty headers={}
            extract_user_oauth_token({})

        # If caller supplied an explicit Bearer token in headers, honor it; otherwise mint for the selected persona
        incoming_headers = dict(request.headers)
        if "x-goog-agent-user-authorization" in incoming_headers or "authorization" in incoming_headers:
            user_token, source_header = extract_user_oauth_token(incoming_headers)
            persona_meta = PERSONA_SERVICE_ACCOUNTS.get(req.persona_id or "P1")
        else:
            minted_token, persona_meta = mint_persona_oauth_token(req.persona_id or "P1")
            simulated_headers = {req.simulated_header_mode: f"Bearer {minted_token}"}
            user_token, source_header = extract_user_oauth_token(simulated_headers)

        agent = GFSSalesInsightCoachAgent()
        result = agent.run_coaching_turn(
            user_prompt=req.prompt,
            user_token=user_token,
            token_source_header=source_header,
            persona_meta=persona_meta,
            include_rebate_margin=req.include_rebate_margin,
            synthesize_with_gemini=req.synthesize_with_gemini,
        )
        return JSONResponse(status_code=200, content=result)

    except AuthError as auth_err:
        return JSONResponse(
            status_code=401,
            content={
                "status": "UNAUTHENTICATED",
                "category": "NO_AGENT_AUTHORIZATION_CONFIGURED",
                "message": str(auth_err),
                "remediation": (
                    "Re-register or PATCH the agent in Gemini Enterprise with a valid "
                    "authorizationConfig (e.g., Default Google-managed credentials) so GE forwards "
                    "the end user's OAuth token."
                ),
            },
        )
    except TableAllowlistError as allow_err:
        return JSONResponse(
            status_code=403,
            content={
                "status": "BLOCKED_BY_AGENT_TABLE_ALLOWLIST",
                "category": "SQL_AST_TABLE_ALLOWLIST_VIOLATION",
                "message": str(allow_err),
                "remediation": (
                    "The agent's server-side table allowlist restricts queries exclusively to "
                    f"{sorted(ALLOWED_TABLES)}, preventing even over-granted admins (P1) from "
                    "reaching out-of-scope datasets."
                ),
            },
        )


@app.post("/v1/message:stream")
async def a2a_message_stream(request: Request) -> JSONResponse:
    """Standard A2A endpoint invoked by Gemini Enterprise (`a2a_agent.py`)."""
    try:
        user_token, source_header = extract_user_oauth_token(request.headers)
    except AuthError as auth_err:
        return JSONResponse(
            status_code=401,
            content={
                "error": {
                    "code": 401,
                    "status": "UNAUTHENTICATED",
                    "message": str(auth_err),
                }
            },
        )

    body = await request.json()
    prompt = "Which accounts are at churn risk and how should I coach the assigned sales reps?"
    msg = body.get("message", {})
    for part in msg.get("content", []):
        if "text" in part and part["text"].strip():
            prompt = part["text"].strip()[:2000]
            break

    agent = GFSSalesInsightCoachAgent()
    turn = agent.run_coaching_turn(
        user_prompt=prompt,
        user_token=user_token,
        token_source_header=source_header,
        include_rebate_margin=True,
        synthesize_with_gemini=False,
    )
    return JSONResponse(
        status_code=200,
        content=[
            {
                "message": {
                    "messageId": f"sim-{uuid.uuid4()}",
                    "role": "ROLE_AGENT",
                    "content": [{"text": turn["coaching_response"]}],
                },
                "metadata": {
                    "tokenSourceHeader": turn["token_source_header"],
                    "bigQueryJobId": turn["bq_telemetry"].get("job_id"),
                    "bigQueryStatus": turn["bq_telemetry"].get("status"),
                    "driveAccessibleCount": turn["drive_context"].get("accessible_count"),
                },
            }
        ],
    )


@app.get("/")
async def serve_index():
    return FileResponse(WEB_DIR / "index.html")


@app.get("/styles.css")
async def serve_css():
    return FileResponse(WEB_DIR / "styles.css", media_type="text/css")


@app.get("/app.js")
async def serve_js():
    return FileResponse(WEB_DIR / "app.js", media_type="application/javascript")
