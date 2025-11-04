# backend/app.py
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from maldet.detector import explain_url
from pydantic import BaseModel

# ---------- simple local persistence / cache ----------
DATA_PROCESSED = Path("data/processed")
HISTORY_FILE = DATA_PROCESSED / "scan_history.jsonl"
DATA_PROCESSED.mkdir(parents=True, exist_ok=True)

# lightweight in-memory cache for demo (replace with Redis)
SCAN_CACHE: Dict[str, Dict[str, Any]] = {}  # url_hash -> scan_record

app = FastAPI(title="MalURL Scanner")


# ---------- models ----------
class ScanRequest(BaseModel):
    # keep as plain str so IPs / schemeless still pass (we normalize)
    url: str


class ScanResponse(BaseModel):
    id: str
    url: str
    timestamp: datetime
    rule_score: float
    rule_label: int
    explain: dict
    ml_proba: Optional[float] = None
    ml_label: Optional[int] = None


# ---------- helpers ----------
def url_key(url: str) -> str:
    s = url.strip().lower()
    # normalize: ensure scheme so feature extraction behaves consistently
    if "://" not in s:
        s = "http://" + s
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _persist(record: Dict[str, Any]) -> None:
    """Append a compact record to JSONL (demo; replace with DB in prod)."""
    with HISTORY_FILE.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "id": record["id"],
                    "url": record["url"],
                    "timestamp": record["timestamp"].isoformat(),
                    "rule_score": record["rule_score"],
                    "rule_label": record["rule_label"],
                    "ml_proba": record["ml_proba"],
                }
            )
            + "\n"
        )


# ---------- routes ----------
@app.post("/api/scan", response_model=ScanResponse)
async def scan_url(req: ScanRequest, background_tasks: BackgroundTasks):
    url = req.url.strip()
    key = url_key(url)

    # 1) fast cache hit
    if key in SCAN_CACHE:
        return SCAN_CACHE[key]

    # 2) synchronous rule-based explain (no network I/O)
    ex = explain_url(url)  # dict with score, contributions, features
    rule_score = float(ex["score"])
    rule_label = int(ex["label"])

    # 3) optional ML (stubbed for now)
    ml_proba: Optional[float] = None
    ml_label: Optional[int] = None
    # try:
    #     ml_proba = predict_with_model(url)
    #     ml_label = 1 if ml_proba >= 0.5 else 0
    # except Exception:
    #     ml_proba = None

    # 4) assemble + cache + persist (async)
    rec: Dict[str, Any] = {
        "id": key,
        "url": url,
        "timestamp": datetime.utcnow(),
        "rule_score": rule_score,
        "rule_label": rule_label,
        "explain": ex,
        "ml_proba": ml_proba,
        "ml_label": ml_label,
    }
    SCAN_CACHE[key] = rec
    background_tasks.add_task(_persist, rec)
    return rec


@app.get("/api/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str):
    rec = SCAN_CACHE.get(scan_id)
    if rec:
        return rec

    # fallback: look in history file (demo-only)
    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as fh:
            for line in fh:
                r = json.loads(line)
                if r["id"] == scan_id:
                    full = explain_url(r["url"])
                    return {
                        "id": r["id"],
                        "url": r["url"],
                        "timestamp": datetime.fromisoformat(r["timestamp"]),
                        "rule_score": float(full["score"]),
                        "rule_label": 1 if float(full["score"]) >= 2.5 else 0,
                        "explain": full,
                        "ml_proba": r.get("ml_proba"),
                        "ml_label": None,
                    }
    except FileNotFoundError:
        pass

    raise HTTPException(status_code=404, detail="Scan not found")


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")
