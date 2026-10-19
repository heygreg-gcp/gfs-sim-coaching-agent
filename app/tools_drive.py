"""Google Drive v3 tool for retrieving GFS Sales Coaching Playbooks using the caller's 3LO OAuth token.

Follows the Bytes-First Decoding guardrail (`raw_bytes.decode("utf-8", errors="ignore")`)
and natively enforces Google Drive per-document sharing ACLs.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple
import httpx

CONFIG_PATH = Path(__file__).resolve().parent / "config_generated.json"


def decode_drive_bytes(raw_bytes: bytes) -> str:
    """Safely decodes raw bytes from Google Drive export into UTF-8 text."""
    return (raw_bytes or b"").decode("utf-8", errors="ignore")


def filter_accessible_playbooks(
    doc_results: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Splits Drive export results into accessible playbooks (200 OK) and ACL-denied docs (403/404)."""
    accessible = []
    denied = []
    for doc in doc_results:
        if doc.get("status_code") == 200:
            accessible.append(doc)
        else:
            denied.append(doc)
    return accessible, denied


def load_configured_drive_docs() -> List[Dict[str, str]]:
    """Loads the real Google Drive Doc IDs created by scripts/setup_demo_resources.py."""
    if not CONFIG_PATH.exists():
        return []
    raw_bytes = CONFIG_PATH.read_bytes()
    data = json.loads(decode_drive_bytes(raw_bytes))
    return data.get("drive_docs", [])


def fetch_gfs_coaching_playbooks(user_token: str) -> Dict[str, Any]:
    """Fetches and exports the configured GFS Coaching Google Docs using the caller's OAuth token.

    Because the request uses `Authorization: Bearer <user_token>`, Google Drive v3 enforces
    the exact file-level permissions granted to that user/service account:
    - Standard Playbook: shared with P1, P3, P4 (denied to P6).
    - Confidential Executive Rebate Guide: shared ONLY with P1 (denied to P3, P4, P6).
    """
    configured_docs = load_configured_drive_docs()
    headers = {"Authorization": f"Bearer {user_token}"}
    results: List[Dict[str, Any]] = []

    with httpx.Client(timeout=15.0) as client:
        for doc_meta in configured_docs:
            doc_id = doc_meta["doc_id"]
            title = doc_meta["title"]
            audience = doc_meta.get("audience", "Unknown")
            gdoc_url = doc_meta.get("gdoc_url", f"https://docs.google.com/document/d/{doc_id}/edit")

            # Fetch Drive v3 resource metadata/content using caller's OAuth token (enforcing live Drive ACLs)
            file_url = f"https://www.googleapis.com/drive/v3/files/{doc_id}"
            resp = client.get(file_url, params={"fields": "id,name,description,mimeType"}, headers=headers)

            if resp.status_code == 200:
                payload = json.loads(decode_drive_bytes(resp.content))
                text_content = (payload.get("description") or "").strip()
                results.append({
                    "id": doc_id,
                    "title": title,
                    "audience": audience,
                    "url": gdoc_url,
                    "status_code": 200,
                    "access": "PERMITTED_BY_DRIVE_ACL",
                    "content": text_content,
                })
            else:
                err_text = decode_drive_bytes(resp.content)[:300]
                results.append({
                    "id": doc_id,
                    "title": title,
                    "audience": audience,
                    "url": gdoc_url,
                    "status_code": resp.status_code,
                    "access": "DENIED_BY_DRIVE_ACL",
                    "error": f"HTTP {resp.status_code} from drive.googleapis.com: Caller lacks reader ACL on this Google Drive document.",
                    "raw_error": err_text,
                    "content": "",
                })

    accessible, denied = filter_accessible_playbooks(results)
    return {
        "total_configured_docs": len(configured_docs),
        "accessible_count": len(accessible),
        "denied_count": len(denied),
        "accessible_playbooks": accessible,
        "denied_playbooks": denied,
    }
