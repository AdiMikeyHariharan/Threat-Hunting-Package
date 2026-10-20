"""FastAPI backend — a thin web layer over the Python detection engine.

The engine (``siem_hunter``) stays the single source of truth; this module only
exposes it over HTTP so the React dashboard can drive it and render results.

Run from the project root:

    uvicorn web.backend.app:app --reload --port 8000
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

# Make the project root importable when launched as `web.backend.app`.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from siem_hunter.logging_config import configure_logging, get_logger  # noqa: E402
from siem_hunter.pipeline import Pipeline  # noqa: E402
from gateway.main import app as gateway_app  # noqa: E402
from gateway.config import CORS_ORIGINS, GATEWAY_AUDIT_LOG  # noqa: E402
from gateway.auth import IdentityContext, get_client_ip, verify_jwt_token  # noqa: E402

configure_logging(log_dir=str(ROOT / "logs"), level="INFO", console=True)
log = get_logger("web.backend")

RULES_DIR = ROOT / "rules"
SAMPLE_DIR = ROOT / "sample_data"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 1024 * 1024

app = FastAPI(title="siem-threat-hunter API", version="1.0.0")

# The Vite dev server proxies /api, but allow direct cross-origin calls too.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# Mount the Micro-SASE Gateway under /api/gateway
app.mount("/api/gateway", gateway_app)


def require_siem_access(permission: str):
    """Validate gateway-issued human JWTs and apply SIEM role permissions.

    Gateway roles are reused: admin has full access, developer can analyze and
    upload, and finance is read-only (sample analysis and catalogue access).
    """
    def dependency(request: Request) -> IdentityContext:
        header = request.headers.get("authorization", "")
        parts = header.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(status_code=401, detail="Bearer access token required.")
        claims = verify_jwt_token(parts[1])
        role = claims.get("role", "")
        allowed = {
            "read": {"admin", "developer", "finance"},
            "write": {"admin", "developer"},
            "admin": {"admin"},
        }
        if role not in allowed[permission]:
            raise HTTPException(status_code=403, detail=f"Role '{role}' cannot {permission} SIEM data.")
        return IdentityContext(
            subject=claims.get("sub", "anonymous"), auth_type="jwt", role=role,
            scopes=claims.get("scopes", []),
            client_ip=get_client_ip(request),
            token_claims=claims,
        )
    return dependency


@app.get("/api/analyze-live-gateway")
def analyze_live_gateway(_identity: IdentityContext = Depends(require_siem_access("admin"))) -> dict:
    """Analyze the live gateway audit log directly and return detections."""
    if not GATEWAY_AUDIT_LOG.exists():
        return {
            "source": "gateway_audit.jsonl (live)",
            "summary": {"events": 0, "detections": 0, "by_severity": {}, "by_detector": {}},
            "detections": [],
        }
    pipeline = Pipeline(rules_dir=RULES_DIR, anomaly_field="src_ip")
    result = pipeline.analyze(GATEWAY_AUDIT_LOG, fmt="json")
    result["source"] = "gateway_audit.jsonl (live)"
    return result


def _guess_format(name: str) -> str:
    lower = name.lower()
    if lower.endswith(".json") or lower.endswith(".jsonl"):
        return "json"
    if lower.endswith(".csv"):
        return "csv"
    if lower.endswith(".xlsx"):
        return "xlsx"
    if lower.endswith(".xls"):
        return "xls"
    return "syslog"


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/rules")
def list_rules(_identity: IdentityContext = Depends(require_siem_access("read"))) -> dict:
    """Expose the loaded rule catalogue so the UI can show what's active."""
    from siem_hunter.rule_engine import load_rules

    rules = load_rules(RULES_DIR)
    return {
        "count": len(rules),
        "rules": [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity,
                "type": r.rule_type,
                "mitre": r.mitre,
            }
            for r in rules
        ],
    }


@app.get("/api/samples")
def list_samples(_identity: IdentityContext = Depends(require_siem_access("read"))) -> dict:
    """List the bundled sample log files available to analyse."""
    files = sorted(p.name for p in SAMPLE_DIR.glob("*") if p.is_file())
    return {"samples": files}


@app.get("/api/analyze")
def analyze_sample(source: str = "auth.log", _identity: IdentityContext = Depends(require_siem_access("read"))) -> dict:
    """Run the pipeline over a bundled sample log and return findings + summary."""
    log_path = (SAMPLE_DIR / source).resolve()
    # Prevent path traversal outside the sample directory.
    if SAMPLE_DIR not in log_path.parents or not log_path.is_file():
        raise HTTPException(status_code=404, detail=f"sample {source!r} not found")

    pipeline = Pipeline(rules_dir=RULES_DIR)
    result = pipeline.analyze(log_path, fmt=_guess_format(source))
    result["source"] = source
    log.info("api_analyze_sample", source=source,
             findings=result["summary"]["detections"])
    return result


@app.post("/api/analyze")
async def analyze_upload(file: UploadFile = File(...), _identity: IdentityContext = Depends(require_siem_access("write"))) -> dict:
    """Analyse a bounded uploaded log file (syslog, JSON lines, CSV, or Excel)."""
    filename = file.filename or "upload"
    fmt = _guess_format(filename)
    # Never use a client supplied filename as a filesystem path. Stream to a
    # bounded temporary file so a request cannot allocate an unbounded bytes
    # object before parsing starts.
    upload_dir = ROOT / "logs"
    upload_dir.mkdir(parents=True, exist_ok=True)
    suffix = Path(filename).suffix[:16]
    tmp: Path | None = None
    try:
        total = 0
        with tempfile.NamedTemporaryFile(
            prefix="_siem_upload_", suffix=suffix, dir=upload_dir, delete=False
        ) as handle:
            tmp = Path(handle.name)
            while chunk := await file.read(UPLOAD_CHUNK_BYTES):
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit.",
                    )
                handle.write(chunk)

        pipeline = Pipeline(rules_dir=RULES_DIR)
        result = await run_in_threadpool(pipeline.analyze, tmp, fmt)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)

    result["source"] = filename
    log.info("api_analyze_upload", source=filename,
             findings=result["summary"]["detections"])
    return result
