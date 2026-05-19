"""Smoke-test SentinelOps AI LLM inference and deterministic fallback.

This script calls the running sentinelops-ai service and prints whether Nexus/SOP
query guidance reached the configured LLM provider or used the safe fallback path.
It does not require database writes and is safe to run while tuning Mistral config.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any


DEFAULT_QUERY = (
    "For a Sentinel Nexus incident affecting txn-mobile-ussd where the Java process "
    "and port are healthy but USSD sessions disconnect through an external tunnel, "
    "what SOP-backed checks should the operator perform before considering restart?"
)


def request_json(method: str, url: str, payload: dict[str, Any] | None = None, token: str | None = None) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url=url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} failed with HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Test SentinelOps AI LLM inference wiring.")
    parser.add_argument("--base-url", default=os.getenv("SENTINELOPS_AI_BASE_URL", "http://127.0.0.1:8010"))
    parser.add_argument("--token", default=os.getenv("SENTINELOPS_TOKEN"), help="Optional SentinelOps bearer token.")
    parser.add_argument("--query", default=DEFAULT_QUERY)
    parser.add_argument("--require-llm", action="store_true", help="Exit non-zero if the provider was not used.")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    print(f"SentinelOps AI base URL: {base_url}")

    health = request_json("GET", f"{base_url}/health", token=args.token)
    engine = health.get("engine", {})
    print("\nHealth")
    print(f"  status: {health.get('status')}")
    print(f"  mistral_available: {engine.get('mistral_available')}")
    print(f"  indexed_sops: {engine.get('sops')}")
    print(f"  indexed_chunks: {engine.get('chunks')}")

    response = request_json(
        "POST",
        f"{base_url}/api/v1/query",
        payload={
            "query": args.query,
            "scope": "incident_response",
            "trace": True,
            "stream": False,
            "user_context": {"username": "llm-smoke-test", "role": "admin"},
            "system_context": {
                "environment": "test",
                "affected_systems": ["txn-mobile-ussd", "txn-integration-idc", "idc-core"],
                "urgency": "HIGH",
            },
        },
        token=args.token,
    )

    trace = response.get("trace") or {}
    provider = trace.get("provider") or {}
    inference = trace.get("inference") or {}
    citations = response.get("citations") or []
    retrieved = response.get("retrieved_sops") or []

    print("\nInference")
    print(f"  provider_available: {provider.get('available')}")
    print(f"  model: {provider.get('model')}")
    print(f"  circuit_open: {(provider.get('circuit_breaker') or {}).get('open')}")
    print(f"  evidence_count: {inference.get('evidence_count')}")
    print(f"  llm_attempted: {inference.get('llm_attempted')}")
    print(f"  llm_answer_received: {inference.get('llm_answer_received')}")
    print(f"  fallback_used: {inference.get('fallback_used')}")
    print(f"  confidence: {response.get('confidence')}")
    print(f"  citations: {len(citations)}")
    print(f"  retrieved_sops: {len(retrieved)}")

    print("\nAnswer")
    print(response.get("answer", "").strip())

    if citations:
        print("\nTop Citations")
        for citation in citations[:3]:
            print(f"  - {citation.get('sop_id')} / {citation.get('section')} / score={citation.get('score')}")

    if response.get("warnings"):
        print("\nWarnings")
        for warning in response["warnings"]:
            print(f"  - {warning}")

    if args.require_llm and not inference.get("llm_answer_received"):
        print("\nFAIL: LLM response was required but the service used fallback or lacked evidence/provider availability.", file=sys.stderr)
        return 2

    print("\nPASS: Query endpoint responded. Review inference flags above to confirm provider wiring.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
