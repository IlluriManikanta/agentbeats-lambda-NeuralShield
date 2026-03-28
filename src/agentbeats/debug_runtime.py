import json
import time
from pathlib import Path
from typing import Any
from urllib import request


DEBUG_LOG_PATH = Path("/Users/mani/Developer/agentbeats-lambda-NeuralShield/.cursor/debug-b2eb5a.log")
DEBUG_SESSION_ID = "b2eb5a"
DEBUG_INGEST_URL = "http://127.0.0.1:7864/ingest/a79a8954-e2d9-4c00-ac4c-27d96226ca56"


def append_debug_log(
    *,
    run_id: str,
    hypothesis_id: str,
    location: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> None:
    payload = {
        "sessionId": DEBUG_SESSION_ID,
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data or {},
        "timestamp": int(time.time() * 1000),
    }
    try:
        with DEBUG_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, default=str) + "\n")
    except Exception:
        # Debug logging should never change application behavior.
        pass
    try:
        req = request.Request(
            DEBUG_INGEST_URL,
            data=json.dumps(payload, default=str).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Debug-Session-Id": DEBUG_SESSION_ID,
            },
            method="POST",
        )
        with request.urlopen(req, timeout=1):
            pass
    except Exception:
        # Debug logging should never change application behavior.
        pass
