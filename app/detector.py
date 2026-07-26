"""Rule-based engine + ML model for phishing decision.

Two paths:
  1. Rule engine  -> always available, transparent, no training needed.
  2. ML model     -> Logistic Regression (and optionally XGBoost) trained on extracted
                     features. If sklearn/xgboost are missing, we fall back to the
                     rule engine only and mark ml_model="none".

Final decision = combine(rule_score, ml_prob). Both are logged for transparency.
"""
from __future__ import annotations

import json
import os
from typing import Optional

# Feature keys used by the ML model (must match order used during training)
ML_FEATURES = [
    "url_length", "uses_https", "has_at_symbol", "has_hyphen_in_host",
    "ip_in_url", "subdomain_count", "dot_count", "url_entropy", "host_entropy",
    "suspicious_tld", "brand_impersonation", "keyword_hits", "digit_count_host",
    "ssl_valid", "ssl_days_left", "domain_age_days", "sb_threat",
    # email-only (default 0 for URL scans)
    "reply_to_mismatch", "auth_fail", "display_name_spoof", "body_brand_impersonation",
    "urgency_words", "has_links",
]


def _num(v, default=0.0):
    try:
        if v is None or v is False:
            return 0.0
        if v is True:
            return 1.0
        return float(v)
    except (TypeError, ValueError):
        return default


def rule_score(feats: dict) -> tuple[float, list[str]]:
    """Return (score 0..1, list of triggered reasons)."""
    score = 0.0
    reasons = []
    if feats.get("ip_in_url"):
        score += 0.25; reasons.append("IP address used in URL")
    if feats.get("brand_impersonation"):
        score += 0.30; reasons.append(f"Brand impersonation ({feats.get('brand_matched')})")
    if feats.get("suspicious_tld"):
        score += 0.15; reasons.append(f"Suspicious TLD (.{feats.get('tld')})")
    if feats.get("has_at_symbol"):
        score += 0.10; reasons.append("'@' in URL (userinfo trick)")
    if not feats.get("uses_https") and feats.get("keyword_hits", 0) > 0:
        score += 0.10; reasons.append("HTTP + credential keywords")
    if feats.get("ssl_valid") is False:
        score += 0.10; reasons.append("Invalid/expired SSL certificate")
    if feats.get("domain_age_days") is not None and feats["domain_age_days"] < 30:
        score += 0.20; reasons.append(f"Domain age {feats['domain_age_days']}d (<30d)")
    if feats.get("sb_threat"):
        score += 0.40; reasons.append("Google Safe Browsing flagged threat")
    # email signals
    if feats.get("auth_fail"):
        score += 0.25; reasons.append("SPF/DKIM/DMARC failed")
    if feats.get("reply_to_mismatch"):
        score += 0.15; reasons.append("Reply-To differs from From")
    if feats.get("display_name_spoof"):
        score += 0.20; reasons.append(f"Display-name spoof ({feats.get('claimed_brand')})")
    if feats.get("body_brand_impersonation"):
        score += 0.20; reasons.append("Body claims a brand the sender isn't")
    if feats.get("url_entropy", 0) > 4.0:
        score += 0.05; reasons.append("High URL entropy (obfuscation)")
    if feats.get("urgency_words", 0) >= 2:
        score += 0.05; reasons.append("Urgency language")
    return min(score, 1.0), reasons


class Detector:
    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.lr = None
        self.xgb = None
        self._load_models()

    def _feat_vector(self, feats: dict):
        return [_num(feats.get(k)) for k in ML_FEATURES]

    def _load_models(self):
        try:
            import joblib  # type: ignore
            lr_path = os.path.join(self.model_dir, "logreg.joblib")
            if os.path.exists(lr_path):
                self.lr = joblib.load(lr_path)
            xgb_path = os.path.join(self.model_dir, "xgb.joblib")
            if os.path.exists(xgb_path):
                self.xgb = joblib.load(xgb_path)
        except Exception:
            self.lr = None
            self.xgb = None

    @property
    def ml_available(self) -> bool:
        return self.lr is not None or self.xgb is not None

    def decide(self, feats: dict) -> dict:
        r_score, reasons = rule_score(feats)
        ml_prob = None
        ml_model = "none"
        if self.lr is not None:
            try:
                ml_prob = float(self.lr.predict_proba([self._feat_vector(feats)])[0][1])
                ml_model = "logreg"
            except Exception:
                ml_prob = None
        elif self.xgb is not None:
            try:
                ml_prob = float(self.xgb.predict_proba([self._feat_vector(feats)])[0][1])
                ml_model = "xgboost"
            except Exception:
                ml_prob = None

        # Combine: if ML present, weight rule 0.4 + ml 0.6, else rule only
        if ml_prob is not None:
            final = 0.4 * r_score + 0.6 * ml_prob
        else:
            final = r_score

        if final >= 0.6:
            verdict = "PHISHING"
        elif final >= 0.3:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LEGIT"

        return {
            "verdict": verdict,
            "risk_score": round(final, 4),
            "rule_score": round(r_score, 4),
            "ml_model": ml_model,
            "ml_probability": round(ml_prob, 4) if ml_prob is not None else None,
            "reasons": reasons,
        }


if __name__ == "__main__":
    import sys
    # quick self-test
    d = Detector()
    print("ML available:", d.ml_available)
    test = {
        "url_length": 50, "uses_https": 0, "has_at_symbol": 1, "has_hyphen_in_host": 1,
        "ip_in_url": 1, "subdomain_count": 3, "dot_count": 4, "url_entropy": 4.5,
        "host_entropy": 4.2, "suspicious_tld": 1, "brand_impersonation": 1, "brand_matched": "paypal",
        "keyword_hits": 3, "digit_count_host": 6, "ssl_valid": False, "ssl_days_left": None,
        "domain_age_days": 5, "sb_threat": False,
        "reply_to_mismatch": 0, "auth_fail": 0, "display_name_spoof": 0,
        "body_brand_impersonation": 0, "urgency_words": 2, "has_links": 1,
    }
    print(json.dumps(d.decide(test), indent=2))
