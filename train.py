"""Train the ML models (Logistic Regression + optional XGBoost) for phishing detection.

Uses a small built-in synthetic dataset so the project is self-contained and
reproducible without external downloads. Replace SAMPLE_ROWS with a real labeled
dataset (e.g. PhishTank / OpenPhish) for production accuracy.

Feature order MUST match app/detector.py ML_FEATURES.
"""
from __future__ import annotations
import json
import os
from pathlib import Path

import joblib

MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_DIR.mkdir(exist_ok=True)

# Feature keys (keep in sync with detector.ML_FEATURES)
FEATURES = [
    "url_length", "uses_https", "has_at_symbol", "has_hyphen_in_host",
    "ip_in_url", "subdomain_count", "dot_count", "url_entropy", "host_entropy",
    "suspicious_tld", "brand_impersonation", "keyword_hits", "digit_count_host",
    "ssl_valid", "ssl_days_left", "domain_age_days", "sb_threat",
    "reply_to_mismatch", "auth_fail", "display_name_spoof", "body_brand_impersonation",
    "urgency_words", "has_links",
]


def _num(v):
    try:
        return 0.0 if v in (None, False) else 1.0 if v is True else float(v)
    except (TypeError, ValueError):
        return 0.0


def vec(f):
    return [_num(f.get(k)) for k in FEATURES]


# --- Tiny labeled sample (illustrative; expand with real data) ---
# Each row: features dict + label (1=phishing, 0=legit)
SAMPLE = [
    # phishing-ish
    ({"url_length":60,"uses_https":0,"has_at_symbol":1,"has_hyphen_in_host":1,"ip_in_url":1,"subdomain_count":4,"dot_count":5,"url_entropy":4.6,"host_entropy":4.3,"suspicious_tld":1,"brand_impersonation":1,"brand_matched":"paypal","keyword_hits":4,"digit_count_host":7,"ssl_valid":0,"ssl_days_left":None,"domain_age_days":4,"sb_threat":0,"reply_to_mismatch":0,"auth_fail":0,"display_name_spoof":0,"body_brand_impersonation":0,"urgency_words":3,"has_links":1}, 1),
    ({"url_length":75,"uses_https":0,"has_at_symbol":0,"has_hyphen_in_host":1,"ip_in_url":0,"subdomain_count":3,"dot_count":4,"url_entropy":4.2,"host_entropy":4.0,"suspicious_tld":1,"brand_impersonation":1,"brand_matched":"microsoft","keyword_hits":3,"digit_count_host":5,"ssl_valid":0,"ssl_days_left":None,"domain_age_days":10,"sb_threat":0,"reply_to_mismatch":0,"auth_fail":0,"display_name_spoof":0,"body_brand_impersonation":0,"urgency_words":2,"has_links":1}, 1),
    # legit-ish
    ({"url_length":30,"uses_https":1,"has_at_symbol":0,"has_hyphen_in_host":0,"ip_in_url":0,"subdomain_count":1,"dot_count":2,"url_entropy":2.1,"host_entropy":2.0,"suspicious_tld":0,"brand_impersonation":0,"brand_matched":"","keyword_hits":0,"digit_count_host":0,"ssl_valid":1,"ssl_days_left":120,"domain_age_days":3000,"sb_threat":0,"reply_to_mismatch":0,"auth_fail":0,"display_name_spoof":0,"body_brand_impersonation":0,"urgency_words":0,"has_links":1}, 0),
    ({"url_length":40,"uses_https":1,"has_at_symbol":0,"has_hyphen_in_host":0,"ip_in_url":0,"subdomain_count":2,"dot_count":3,"url_entropy":2.5,"host_entropy":2.2,"suspicious_tld":0,"brand_impersonation":0,"brand_matched":"","keyword_hits":1,"digit_count_host":1,"ssl_valid":1,"ssl_days_left":60,"domain_age_days":1500,"sb_threat":0,"reply_to_mismatch":0,"auth_fail":0,"display_name_spoof":0,"body_brand_impersonation":0,"urgency_words":0,"has_links":1}, 0),
]

X = [vec(f) for f, _ in SAMPLE]
y = [lbl for _, lbl in SAMPLE]

# Logistic Regression
from sklearn.linear_model import LogisticRegression
lr = LogisticRegression(max_iter=1000)
lr.fit(X, y)
joblib.dump(lr, MODEL_DIR / "logreg.joblib")
print("Saved LogisticRegression ->", MODEL_DIR / "logreg.joblib")

# XGBoost (optional)
try:
    import xgboost as xgb
    clf = xgb.XGBClassifier(n_estimators=50, max_depth=3, eval_metric="logloss")
    clf.fit(X, y)
    joblib.dump(clf, MODEL_DIR / "xgb.joblib")
    print("Saved XGBoost ->", MODEL_DIR / "xgb.joblib")
except Exception as e:
    print("XGBoost skipped:", e)

# Save feature list for reference
MODEL_DIR.joinpath("features.json").write_text(json.dumps(FEATURES, indent=2))
print("Done. Models in", MODEL_DIR)
