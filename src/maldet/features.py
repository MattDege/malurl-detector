from __future__ import annotations

import re
from urllib.parse import urlparse

import tldextract

_PUNCT = re.compile(r"[^A-Za-z0-9]")
_DIGITS = re.compile(r"\d")
_HEX = re.compile(r"^[0-9A-Fa-f]+$")

def _is_ip(host: str) -> int:
    parts = host.split(".")
    if len(parts) == 4:
        try:
            return int(all(0 <= int(p) <= 255 for p in parts))
        except ValueError:
            return 0
    return 0

def extract_lexical_features(url: str) -> dict:
    # ensure a scheme so urlparse works
    parsed = urlparse(url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else f"http://{url}")
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    ext = tldextract.extract(host)
    sld = ext.domain or ""
    tld = ext.suffix or ""
    sub = ext.subdomain or ""

    url_no_scheme = url.split("://", 1)[-1]

    feats = {
        "len_url": len(url),
        "len_host": len(host),
        "len_path": len(path),
        "len_query": len(query),
        "count_dots": url_no_scheme.count("."),
        "count_hyphens": url_no_scheme.count("-"),
        "count_slashes": url_no_scheme.count("/"),
        "count_digits": len(_DIGITS.findall(url)),
        "count_punct": len(_PUNCT.findall(url)),
        "has_at": int("@" in url_no_scheme),
        "has_ip_host": _is_ip(host),
        "subdomain_len": len(sub),
        "sld_len": len(sld),
        "tld_len": len(tld),
        "num_tokens_host": len([t for t in host.split(".") if t]),
        "path_depth": len([p for p in path.split("/") if p]),
        "has_hex_path": int(bool(path) and bool(_HEX.match(path.replace("/", "")))),
        "has_login": int("login" in url.lower()),
        "has_secure": int("secure" in url.lower()),
        "has_verify": int("verify" in url.lower()),
    }
    return feats
