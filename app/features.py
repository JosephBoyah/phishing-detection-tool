"""Feature extraction for phishing detection.

Extracts a rich set of features from a URL (and optional fetched HTML) that
feed both the rule-based engine and the ML models.

Safe by design:
- No external network calls are REQUIRED for a verdict (rule engine works offline).
- WHOIS / SSL / Safe Browsing are OPTIONAL enrichment; failures degrade gracefully.
"""
from __future__ import annotations

import ipaddress
import math
import re
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

# Known legitimate domains used for brand-impersonation heuristics
KNOWN_BRANDS = {
    "google": "google.com", "gmail": "google.com", "googlemail": "google.com",
    "microsoft": "microsoft.com", "live": "microsoft.com", "outlook": "microsoft.com", "office365": "microsoft.com",
    "paypal": "paypal.com", "apple": "apple.com", "icloud": "apple.com",
    "amazon": "amazon.com", "aws": "amazon.com", "github": "github.com",
    "facebook": "facebook.com", "fb": "facebook.com", "meta": "meta.com",
    "netflix": "netflix.com", "linkedin": "linkedin.com", "twitter": "x.com",
    "x": "x.com", "instagram": "instagram.com", "bank": None,
}


def shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits/char). High entropy ~ random/obfuscated."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_url_features(url: str) -> dict:
    """Return a feature dict for a single URL."""
    feats: dict = {}
    raw = url.strip()
    feats["url_length"] = len(raw)

    try:
        parsed = urllib.parse.urlparse(raw if "://" in raw else "http://" + raw)
        host = (parsed.hostname or "").lower()
        scheme = parsed.scheme.lower() or "http"
    except Exception:
        host = ""
        scheme = "http"
        parsed = urllib.parse.urlparse("")

    feats["scheme"] = scheme
    feats["uses_https"] = int(scheme == "https")
    feats["has_at_symbol"] = int("@" in raw)
    feats["has_hyphen_in_host"] = int("-" in host)
    feats["host"] = host

    # IP in URL (host itself, or an IP-looking label anywhere in the host)
    feats["ip_in_url"] = int(
        bool(host)
        and (is_ip_address(host) or bool(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", host)))
    )

    # Subdomain count (dots in host minus the registrable domain's dots)
    host_parts = host.split(".") if host else []
    feats["dot_count"] = len(host_parts) - 1
    # crude subdomain count: labels beyond the 2nd-level.tld
    feats["subdomain_count"] = max(0, len(host_parts) - 2)

    path = parsed.path or ""
    query = parsed.query or ""
    feats["path_length"] = len(path)
    feats["query_length"] = len(query)
    feats["num_query_params"] = len([p for p in query.split("&") if p]) if query else 0
    feats["has_double_slash_redirect"] = int("//" in raw[raw.find("://") + 3:] if "://" in raw else "//" in raw)

    # URL entropy (on full url and on host)
    feats["url_entropy"] = round(shannon_entropy(raw), 4)
    feats["host_entropy"] = round(shannon_entropy(host), 4)

    # Suspicious TLDs commonly abused in phishing
    SUSP_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "country", "link", "racing", "ru", "cn"}
    tld = host_parts[-1] if host_parts else ""
    feats["tld"] = tld
    feats["suspicious_tld"] = int(tld in SUSP_TLDS)

    # Brand impersonation: does the host contain a brand name (or a close typo)
    # but is NOT the brand's official domain?
    brand_hit = None
    import difflib
    for brand, real in KNOWN_BRANDS.items():
        if not real:
            continue
        # exact substring (e.g. "paypal" inside "paypa1.com")
        if brand in host and host != real and not host.endswith("." + real):
            brand_hit = brand
            break
        # typo/lookalike: a host label is close to the brand (1-2 char edit distance)
        if not brand_hit:
            for label in host_parts:
                if 2 <= len(label) <= 12 and difflib.SequenceMatcher(None, label, brand).ratio() >= 0.8 \
                        and host != real and not host.endswith("." + real):
                    brand_hit = brand
                    break
    feats["brand_impersonation"] = int(bool(brand_hit))
    feats["brand_matched"] = brand_hit or ""

    # Count of security/digital-wallet/urgency keywords in the full URL string
    keywords = ["login", "signin", "verify", "secure", "account", "update", "bank",
                "paypal", "password", "confirm", "wallet", "crypto", "airdrop", "claim",
                "prize", "win", "reset", "ebay", "invoice"]
    low = raw.lower()
    feats["keyword_hits"] = sum(1 for k in keywords if k in low)

    # Number of digits in host (common in DGA / random subdomains)
    feats["digit_count_host"] = sum(1 for c in host if c.isdigit())

    return feats


def check_ssl(host: str, timeout: float = 5.0) -> dict:
    """Validate the TLS certificate of a host. Returns cert info + validity."""
    res = {"ssl_checked": False, "ssl_valid": False, "ssl_days_left": None,
           "ssl_issuer": None, "ssl_error": None}
    if not host or is_ip_address(host):
        res["ssl_error"] = "no_host_or_ip"
        return res
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        res["ssl_checked"] = True
        res["ssl_valid"] = True
        issuer = cert.get("issuer")
        if issuer:
            # issuer is a tuple of tuples; flatten
            parts = []
            for rdn in issuer:
                for attr, val in rdn:
                    if attr == "organizationName":
                        parts.append(val)
            res["ssl_issuer"] = ", ".join(parts) or str(issuer)
        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            res["ssl_days_left"] = days
            res["ssl_valid"] = int(days > 0)
    except Exception as e:  # noqa: BLE001
        res["ssl_error"] = str(e)[:120]
    return res


def check_whois_age(domain: str, timeout: float = 8.0) -> dict:
    """Look up domain creation/age via python-whois if available."""
    res = {"whois_checked": False, "domain_age_days": None, "domain_created": None,
           "whois_error": None}
    if not domain:
        return res
    try:
        import whois  # python-whois
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created).days
            res["domain_age_days"] = age
            res["domain_created"] = created.isoformat()
            res["whois_checked"] = True
        else:
            res["whois_error"] = "no creation_date"
    except ImportError:
        res["whois_error"] = "python-whois not installed"
    except Exception as e:  # noqa: BLE001
        res["whois_error"] = str(e)[:120]
    return res


def check_safe_browsing(url: str, api_key: Optional[str]) -> dict:
    """Query Google Safe Browsing v4 API. Requires an API key (optional)."""
    res = {"sb_checked": False, "sb_threat": None, "sb_error": None}
    if not api_key:
        res["sb_error"] = "no_api_key"
        return res
    try:
        import json
        import urllib.request
        body = {
            "client": {"clientId": "phishing-detection-tool", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        req = urllib.request.Request(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.load(r)
        matches = data.get("matches")
        res["sb_checked"] = True
        res["sb_threat"] = bool(matches)
        if matches:
            res["sb_threat_types"] = [m.get("threatType") for m in matches]
    except Exception as e:  # noqa: BLE001
        res["sb_error"] = str(e)[:120]
    return res


def extract_all(url: str, sb_api_key: Optional[str] = None) -> dict:
    """Run all feature extraction + optional enrichment and return a combined dict."""
    feats = extract_url_features(url)
    host = feats.get("host", "")
    domain = host
    if host and host.count(".") >= 2:
        # registrable domain approximation: last two labels
        domain = ".".join(host.split(".")[-2:])
    feats.update(check_ssl(host))
    feats.update(check_whois_age(domain))
    feats.update(check_safe_browsing(url, sb_api_key))
    return feats


if __name__ == "__main__":
    import sys
    u = sys.argv[1] if len(sys.argv) > 1 else "http://secure-login.paypa1.com.192.168.1.1/login"
    import json
    print(json.dumps(extract_all(u), indent=2, default=str))
