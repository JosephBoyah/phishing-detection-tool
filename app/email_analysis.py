"""Email header analysis for phishing detection.

Parses raw email headers (or an .eml string) and extracts signals used by the
rule engine and the ML model:
  - SPF / DKIM / DMARC results (from Authentication-Results)
  - sender domain vs. the brand the body claims to be (impersonation)
  - reply-to mismatch
  - display-name spoofing (e.g. "PayPal" but from a junk domain)
"""
from __future__ import annotations

import email
import re
from typing import Optional

# Brands -> official domains (reuse a small set; keep in sync with features.KNOWN_BRANDS)
BRAND_DOMAINS = {
    "google": "google.com", "microsoft": "microsoft.com", "paypal": "paypal.com",
    "apple": "apple.com", "amazon": "amazon.com", "github": "github.com",
    "facebook": "facebook.com", "netflix": "netflix.com", "linkedin": "linkedin.com",
}


def _auth_results(headers: dict) -> dict:
    ar = headers.get("authentication-results", "") or headers.get("Authentication-Results", "")
    out = {"spf": None, "dkim": None, "dmarc": None}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", ar, re.IGNORECASE)
        if m:
            out[mech] = m.group(1).lower()
    return out


def _domain_of(addr: str) -> str:
    m = re.search(r"@([\w.-]+)", addr or "")
    return m.group(1).lower() if m else ""


def analyze_email(raw_email: str) -> dict:
    """Analyze a raw email (.eml / headers+body). Returns a feature dict."""
    msg = email.message_from_string(raw_email)
    headers = {k: (v if isinstance(v, str) else str(v)) for k, v in msg.items()}

    from_addr = headers.get("From", "")
    to_addr = headers.get("To", "")
    reply_to = headers.get("Reply-To", "")
    subject = headers.get("Subject", "")
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode(errors="replace")
                except Exception:
                    body = ""
                break
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors="replace")
        except Exception:
            body = ""

    from_domain = _domain_of(from_addr)
    reply_domain = _domain_of(reply_to)
    auth = _auth_results(headers)

    # Display-name spoofing: "PayPal" but from a non-paypal domain
    display = re.sub(r"^.*?(\w[\w .'-]*\w)\s*<.*$", r"\1", from_addr) if "<" in from_addr else from_addr
    display_l = display.lower()
    claimed_brand = None
    for brand, dom in BRAND_DOMAINS.items():
        if brand in display_l and from_domain and from_domain != dom:
            claimed_brand = brand
            break

    # Body mentions a brand whose domain differs from sender -> impersonation
    body_l = body.lower()
    body_brand = None
    for brand, dom in BRAND_DOMAINS.items():
        if brand in body_l and from_domain and from_domain != dom and not from_domain.endswith("." + dom):
            body_brand = brand
            break

    return {
        "from_address": from_addr,
        "from_domain": from_domain,
        "to_address": to_addr,
        "reply_to": reply_to,
        "reply_to_mismatch": int(bool(reply_to) and reply_domain and reply_domain != from_domain),
        "subject": subject,
        "spf": auth["spf"],
        "dkim": auth["dkim"],
        "dmarc": auth["dmarc"],
        "auth_fail": int(
            (auth["spf"] in ("fail", "softfail", "none") or auth["dmarc"] in ("fail", "none"))
            and bool(from_domain)
        ),
        "display_name_spoof": int(bool(claimed_brand)),
        "claimed_brand": claimed_brand or body_brand or "",
        "body_brand_impersonation": int(bool(body_brand)),
        "has_links": int(bool(re.search(r"https?://", body))),
        "link_domains": sorted(set(re.findall(r"https?://([\w.-]+)", body)))[:10],
        "urgency_words": sum(
            1 for w in ("urgent", "immediately", "24 hours", "expire", "suspend",
                        "locked", "verify", "confirm", "secure your account")
            if w in body_l
        ),
    }


if __name__ == "__main__":
    import sys, json
    sample = sys.argv[1] if len(sys.argv) > 1 else (
        "From: PayPal Security <secure@paypa1-account.com>\n"
        "To: victim@gmail.com\nReply-To: attacker@evil.com\n"
        "Subject: Verify your account\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail\n\n"
        "Urgent: your account will be suspended in 24 hours. Verify at http://paypa1.com/x\n"
    )
    print(json.dumps(analyze_email(sample), indent=2))
