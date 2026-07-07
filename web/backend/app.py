"""FastAPI backend — a thin web layer over the Python detection engine.

The engine (``siem_hunter``) stays the single source of truth; this module only
exposes it over HTTP so the React dashboard can drive it and render results.

Run from the project root:

    uvicorn web.backend.app:app --reload --port 8000
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

# Make the project root importable when launched as `web.backend.app`.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from siem_hunter.logging_config import configure_logging, get_logger  # noqa: E402
from siem_hunter.pipeline import Pipeline  # noqa: E402

configure_logging(log_dir=str(ROOT / "logs"), level="INFO", console=True)
log = get_logger("web.backend")

RULES_DIR = ROOT / "rules"
SAMPLE_DIR = ROOT / "sample_data"

app = FastAPI(title="siem-threat-hunter API", version="1.0.0")

# The Vite dev server proxies /api, but allow direct cross-origin calls too.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _guess_format(name: str) -> str:
    return "json" if name.endswith(".json") or name.endswith(".jsonl") else "syslog"


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/rules")
def list_rules() -> dict:
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
def list_samples() -> dict:
    """List the bundled sample log files available to analyse."""
    files = sorted(p.name for p in SAMPLE_DIR.glob("*") if p.is_file())
    return {"samples": files}


@app.get("/api/analyze")
def analyze_sample(source: str = "auth.log") -> dict:
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
async def analyze_upload(file: UploadFile = File(...)) -> dict:
    """Analyse an uploaded log file (syslog or JSON lines)."""
    content = (await file.read()).decode("utf-8", errors="replace")
    tmp = ROOT / "logs" / f"_upload_{file.filename}"
    tmp.write_text(content, encoding="utf-8")
    try:
        pipeline = Pipeline(rules_dir=RULES_DIR)
        result = pipeline.analyze(tmp, fmt=_guess_format(file.filename or ""))
    finally:
        tmp.unlink(missing_ok=True)
    result["source"] = file.filename
    log.info("api_analyze_upload", source=file.filename,
             findings=result["summary"]["detections"])
    return result
