"""Flask web app for the Phishing Detection Tool.

Endpoints:
  GET  /                 -> dashboard (stats + recent scans + charts)
  GET  /scan            -> scan form
  POST /api/scan        -> scan a URL or email; returns JSON decision
  GET  /api/history     -> list past scans (logs)
  GET  /reports         -> reports page (aggregated)
  GET  /api/report/<id> -> single report

Data is stored in data/store.json (append-only JSON lines). No external DB needed.
Safe: Google Safe Browsing key comes from env (SAFE_BROWSING_API_KEY); never logged.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_from_directory


def _ctime(ts):
    try:
        import datetime
        return datetime.datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ts)


app = Flask(__name__)
app.jinja_env.filters["ctime"] = _ctime

# Serve under a path prefix (e.g. /phishing behind a reverse proxy).
# The Blueprint url_prefix drives route matching; templates/JS get APP_ROOT
# via a context processor so asset + fetch URLs stay correct.
APP_ROOT = os.environ.get("APP_ROOT", "/").rstrip("/")

from flask import Blueprint

bp = Blueprint("phish", __name__, url_prefix=APP_ROOT)


@app.context_processor
def inject_app_root():
    return {"app_root": APP_ROOT}


from features import extract_all
from email_analysis import analyze_email
from detector import Detector

BASE = Path(__file__).resolve().parent
PROJECT_ROOT = BASE.parent  # phishing-detection-tool/
MODELS_DIR = PROJECT_ROOT / "models"
DATA = BASE / "data"
DATA.mkdir(exist_ok=True)
STORE = DATA / "store.jsonl"

detector = Detector(model_dir=str(MODELS_DIR))
SB_KEY = os.environ.get("SAFE_BROWSING_API_KEY") or ""


def _load_history(limit: int = 200):
    out = []
    if STORE.exists():
        for line in reversed(STORE.read_text().splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
            if len(out) >= limit:
                break
    return out


def _save_record(rec: dict):
    with STORE.open("a") as f:
        f.write(json.dumps(rec) + "\n")


def _analyze(input_value: str, kind: str) -> dict:
    input_value = (input_value or "").strip()
    if kind == "email":
        feats = analyze_email(input_value)
        feats["input_kind"] = "email"
        feats["input_preview"] = input_value[:120].replace("\n", " ")
    else:
        # URL
        feats = extract_all(input_value, sb_api_key=SB_KEY or None)
        feats["input_kind"] = "url"
        feats["input_preview"] = input_value[:160]
    decision = detector.decide(feats)
    rec = {
        "id": uuid.uuid4().hex[:12],
        "ts": int(time.time()),
        "kind": kind,
        "input": input_value[:400],
        "features": feats,
        "decision": decision,
    }
    _save_record(rec)
    return rec


@bp.route("/")
def dashboard():
    history = _load_history(50)
    stats = {"total": len(history), "phishing": 0, "suspicious": 0, "legit": 0}
    for h in history:
        v = h.get("decision", {}).get("verdict")
        if v == "PHISHING":
            stats["phishing"] += 1
        elif v == "SUSPICIOUS":
            stats["suspicious"] += 1
        elif v == "LEGIT":
            stats["legit"] += 1
    return render_template("dashboard.html", stats=stats, history=history,
                           ml_available=detector.ml_available)


@bp.route("/scan")
def scan_page():
    return render_template("scan.html")


@bp.route("/reports")
def reports_page():
    history = _load_history(200)
    return render_template("reports.html", history=history)


@bp.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    value = data.get("input") or request.form.get("input") or ""
    kind = (data.get("kind") or request.form.get("kind") or "url").lower()
    if not value:
        return jsonify({"error": "no input provided"}), 400
    if kind not in ("url", "email"):
        kind = "url"
    try:
        rec = _analyze(value, kind)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)[:200]}), 500
    return jsonify(rec)


@bp.route("/api/history")
def api_history():
    return jsonify(_load_history(100))


@bp.route("/api/report/<rid>")
def api_report(rid):
    for h in _load_history(500):
        if h.get("id") == rid:
            return jsonify(h)
    return jsonify({"error": "not found"}), 404


@bp.route("/healthz")
def health():
    return jsonify({"status": "ok", "ml_available": detector.ml_available})


@bp.route("/static/<path:p>")
def static_files(p):
    return send_from_directory(BASE / "static", p)


app.register_blueprint(bp)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
