# 🛡️ Phishing Detection Tool

A **web-based** phishing detection application that analyzes **URLs and raw emails**
using a combination of:

- **Rule-based engine** (always on, transparent, no training needed)
- **Machine learning** (Logistic Regression + optional XGBoost)
- **External enrichment**: WHOIS domain-age check, SSL/TLS certificate validation,
  and Google Safe Browsing API

Built as a portfolio project for a cybersecurity graduate. Clean dashboard with
**reports, logs, and visualizations**.

---

## ✨ Features

| Feature | Description |
|--------|-------------|
| URL analysis | Extracts 20+ features (entropy, subdomain count, IP-in-URL, suspicious TLD, brand impersonation, keyword hits) |
| Email header analysis | SPF / DKIM / DMARC results, Reply-To mismatch, display-name spoofing, body brand-impersonation |
| WHOIS domain age | Flags newly-registered domains (< 30 days) |
| SSL validation | Checks cert validity, issuer, days remaining |
| Google Safe Browsing | Flags known malicious URLs (requires free API key) |
| Rule + ML decision | Combines transparent rules with Logistic Regression / XGBoost |
| Dashboard | Live stats, doughnut chart, recent scans |
| Reports & Logs | Full scan history with verdicts, risk scores, ML probabilities |
| Clean UI | Flask + Chart.js, no heavy build step |

---

## 🧠 Architecture

```
            User Input (URL or raw email)
                    ↓
        ┌───────────────────────────┐
        │   Feature Extraction       │  app/features.py
        │   - URL features           │  app/email_analysis.py
        │   - WHOIS age              │
        │   - SSL validation         │
        │   - Safe Browsing (opt)    │
        └───────────────────────────┘
                    ↓
        ┌───────────────────────────┐
        │   Rule-Based Check         │  app/detector.py
        │   + ML Model (LogReg/XGB)  │
        └───────────────────────────┘
                    ↓
            Final Decision
      (LEGIT / SUSPICIOUS / PHISHING)
                    ↓
        ┌───────────────────────────┐
        │   Web Dashboard Output      │  app/app.py (Flask)
        │   - stats + charts         │
        │   - scan history / logs    │
        │   - reports                │
        └───────────────────────────┘
```

### ML feature set
`url_length, uses_https, has_at_symbol, has_hyphen_in_host, ip_in_url,
subdomain_count, dot_count, url_entropy, host_entropy, suspicious_tld,
brand_impersonation, keyword_hits, digit_count_host, ssl_valid, ssl_days_left,
domain_age_days, sb_threat, reply_to_mismatch, auth_fail, display_name_spoof,
body_brand_impersonation, urgency_words, has_links`

Final risk = `0.4 * rule_score + 0.6 * ml_probability` (when ML is available),
else `rule_score`. Verdicts: `PHISHING ≥ 0.6`, `SUSPICIOUS ≥ 0.3`, else `LEGIT`.

---

## 🚀 Quick start (local)

```bash
git clone https://github.com/JosephBoyah/phishing-detection-tool.git
cd phishing-detection-tool
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# optional: enable Google Safe Browsing
export SAFE_BROWSING_API_KEY=your_key_here

python app/app.py
# open http://localhost:5000
```

### Train the ML models
```bash
python train.py      # writes models/logreg.joblib (+ xgb.joblib if xgboost installed)
```
The bundled sample dataset is tiny/illustrative — replace `SAMPLE` in `train.py`
with a real labeled set (PhishTank / OpenPhish) for production accuracy.

---

## 🐳 Docker

```bash
docker build -t phishing-detection-tool .
docker run -p 5000:5000 -e SAFE_BROWSING_API_KEY=xxx phishing-detection-tool
```

---

## 🔌 API

| Method | Endpoint | Body | Returns |
|--------|----------|------|---------|
| POST | `/api/scan` | `{input, kind:"url"|"email"}` | full decision JSON |
| GET  | `/api/history` | — | recent scans |
| GET  | `/api/report/<id>` | — | single report |
| GET  | `/healthz` | — | health + ML status |

Example:
```bash
curl -s -X POST http://localhost:5000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"input":"http://secure-login.paypa1.com.192.168.1.1/login","kind":"url"}'
```

---

## 🔒 Security & ethics
- This tool is for **defensive / educational** use: scanning URLs/emails you
  own or are authorized to analyze.
- Google Safe Browsing key is passed via env var, **never** committed.
- No external calls are required for a verdict — the rule engine works offline.
- The bundled dataset is synthetic; do **not** use the ML model for real
  blocking decisions without training on a representative labeled corpus.

## 📁 Structure
```
app/
  app.py            Flask web server + routes
  features.py       URL feature extraction + WHOIS/SSL/SafeBrowsing
  email_analysis.py Email header analysis (SPF/DKIM/DMARC, spoofing)
  detector.py       Rule engine + ML decision
  templates/        dashboard.html, scan.html, reports.html
  data/store.jsonl  append-only scan log
models/             trained joblib artifacts (gitignored)
train.py            trains LogReg + XGBoost
```

## ✅ TODO / improvements
- [ ] Replace sample dataset with PhishTank/OpenPhish
- [ ] Add XGBoost to CI training
- [ ] Add screenshot/HTML-analysis (lookalike login-page detection)
- [ ] Add auth + multi-user
- [ ] Deploy behind Traefik on VPS
