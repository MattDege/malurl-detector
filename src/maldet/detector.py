# src/maldet/detector.py
"""Rule-based Malicious URL/Domain detector.

Uses lexical features (from maldet.features) and a small, transparent scoring
function to label URLs as malicious (1) or benign (0). Weights/threshold are
tunable.
"""
from __future__ import annotations

from typing import Dict, Tuple

from .features import extract_lexical_features

__all__ = [
    "WEIGHTS",
    "DEFAULT_THRESHOLD",
    "score_url",
    "predict_url",
    "explain_url",
]

# ---- Tunable weights (simple linear scoring) ----
WEIGHTS: Dict[str, float] = {
    # strong signals
    "has_ip_host": 4.0,  # e.g., http://1.2.3.4/...
    "has_at": 2.0,  # "@" often used to obfuscate host
    "has_login": 1.5,
    "has_verify": 1.2,
    # medium signals
    "path_depth": 0.5,
    "count_hyphens": 0.15,
    "count_dots": 0.1,
    "count_digits": 0.02,
    "count_punct": 0.02,
    # mild signals
    "len_url": 0.004,
    "subdomain_len": 0.03,
    "num_tokens_host": 0.05,
    "has_secure": 0.7,
    "has_hex_path": 0.6,
}

# score >= threshold => label=malicious (1)
DEFAULT_THRESHOLD = 2.5

# treat these as boolean 0/1
BOOLEAN_FEATURES = {
    "has_ip_host",
    "has_at",
    "has_login",
    "has_verify",
    "has_secure",
    "has_hex_path",
}


def score_url(url: str, weights: Dict[str, float] = WEIGHTS) -> float:
    """Return a numeric risk score for a single URL."""
    feats = extract_lexical_features(url)
    s = 0.0
    for k, w in weights.items():
        if k not in feats:
            continue
        v = feats[k]
        if k in BOOLEAN_FEATURES:
            val = 1.0 if bool(v) else 0.0
        else:
            try:
                val = float(v)
            except Exception:
                val = 0.0
        s += w * val
    return s


def predict_url(
    url: str,
    threshold: float = DEFAULT_THRESHOLD,
    weights: Dict[str, float] = WEIGHTS,
) -> Tuple[int, float]:
    """Return (label, score). label: 1 = malicious, 0 = benign."""
    s = score_url(url, weights)
    return (1 if s >= threshold else 0, s)


def explain_url(
    url: str,
    threshold: float = DEFAULT_THRESHOLD,
    weights: Dict[str, float] = WEIGHTS,
) -> Dict:
    """Return a dict with score breakdown + features for explainability."""
    feats = extract_lexical_features(url)
    contributions: Dict[str, float] = {}
    total = 0.0

    for k, w in weights.items():
        if k not in feats:
            continue
        if k in BOOLEAN_FEATURES:
            val = 1 if bool(feats[k]) else 0
        else:
            try:
                val = float(feats[k])
            except Exception:
                val = 0.0
        contrib = w * val
        contributions[k] = contrib
        total += contrib

    label = 1 if total >= threshold else 0
    return {
        "url": url,
        "score": float(total),
        "label": int(label),
        "threshold": float(threshold),
        "contributions": contributions,
        "features": feats,
    }


# Handy debug CLI: python -m maldet.detector --url "<url>" [--json]
if __name__ == "__main__":
    import argparse
    import json
    import sys

    ap = argparse.ArgumentParser(description="Rule-based malicious URL detector (debug CLI)")
    ap.add_argument("--url", help="Single URL to score")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not args.url:
        print(
            "Provide --url 'https://example.com/path' to score a single URL",
            file=sys.stderr,
        )
        sys.exit(2)

    out = explain_url(args.url, threshold=args.threshold)
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"URL : {out['url']}")
        print(f"SCORE: {out['score']:.4f}  THRESHOLD: {out['threshold']}")
        print(f"LABEL: {'MALICIOUS' if out['label'] == 1 else 'BENIGN'}")
        print("Top contributions:")
        top = sorted(out["contributions"].items(), key=lambda iv: -abs(iv[1]))[:10]
        for k, v in top:
            print(f"  {k:20s} -> {v:.4f}")
