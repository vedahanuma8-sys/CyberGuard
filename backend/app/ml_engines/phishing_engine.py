import collections
import ipaddress
import math
import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import tldextract

from app.core.config import settings

PHISHING_FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_question",
    "count_percent",
    "count_digits",
    "digit_ratio",
    "has_ip",
    "is_https",
    "entropy",
    "suspicious_keywords_count",
    "subdomain_depth",
    "tld_length",
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "secure", "banking",
    "signin", "confirm", "password", "credential", "alert", "wallet",
    "suspend", "support", "claim", "paypal", "apple", "microsoft",
    "security", "recovery", "auth", "token", "service"
]


def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    counts = collections.Counter(text)
    total_len = len(text)
    return -sum((count / total_len) * math.log2(count / total_len) for count in counts.values())


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extracts numerical and structural features from a URL:
    - url_length, hostname_length, path_length
    - count_dots, count_hyphens, count_at, count_question, count_percent
    - count_digits, digit_ratio, has_ip, is_https
    - entropy, suspicious_keywords_count, subdomain_depth, tld_length
    """
    url_str = str(url).strip()
    if not url_str.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse("http://" + url_str)
        is_https = 0
    else:
        parsed = urllib.parse.urlparse(url_str)
        is_https = 1 if parsed.scheme.lower() == "https" else 0

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # Check for IP address in hostname
    has_ip = 0
    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else 0

    # Token and character counts
    digits_count = sum(1 for c in url_str if c.isdigit())
    digit_ratio = digits_count / max(1, len(url_str))

    # TLD and subdomain extraction
    extracted = tldextract.extract(url_str)
    subdomain = extracted.subdomain
    subdomain_depth = len(subdomain.split(".")) if subdomain else 0
    tld_length = len(extracted.suffix) if extracted.suffix else 0

    # Suspicious keywords count in URL
    url_lower = url_str.lower()
    suspicious_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Shannon entropy of full URL
    entropy = calculate_shannon_entropy(url_str)

    features = {
        "url_length": len(url_str),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "count_dots": url_str.count("."),
        "count_hyphens": url_str.count("-"),
        "count_at": url_str.count("@"),
        "count_question": url_str.count("?"),
        "count_percent": url_str.count("%"),
        "count_digits": digits_count,
        "digit_ratio": round(digit_ratio, 4),
        "has_ip": has_ip,
        "is_https": is_https,
        "entropy": round(entropy, 4),
        "suspicious_keywords_count": suspicious_count,
        "subdomain_depth": subdomain_depth,
        "tld_length": tld_length,
    }
    return features


class PhishingEngine:
    """ML Engine for detecting phishing URLs."""

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or (settings.ARTIFACTS_DIR / "phishing_model.joblib")
        self.model = None
        self.feature_names = PHISHING_FEATURE_NAMES
        self._load_model()

    def _load_model(self) -> None:
        if self.model_path.exists():
            data = joblib.load(self.model_path)
            if isinstance(data, dict) and "model" in data:
                self.model = data["model"]
                self.feature_names = data.get("feature_names", PHISHING_FEATURE_NAMES)
            else:
                self.model = data

    def predict(self, url: str) -> Dict[str, Any]:
        """
        Predicts whether a URL is phishing or legitimate.
        Returns threat classification, confidence, risk score, indicators, and mitigation.
        """
        features = extract_url_features(url)
        indicators = []

        if features["has_ip"] == 1:
            indicators.append("URL hostname uses a raw IP address instead of a domain name.")
        if features["count_at"] > 0:
            indicators.append("URL contains '@' symbol commonly used for credential phishing/URL confusion.")
        if features["is_https"] == 0:
            indicators.append("Unencrypted HTTP protocol in use.")
        if features["entropy"] > 4.5:
            indicators.append(f"High character entropy ({features['entropy']:.2f}) indicates obfuscation or DGA.")
        if features["subdomain_depth"] >= 3:
            indicators.append(f"Excessive subdomain nesting depth ({features['subdomain_depth']}).")
        if features["suspicious_keywords_count"] >= 2:
            indicators.append(f"Found {features['suspicious_keywords_count']} high-risk keywords in URL.")
        if features["digit_ratio"] > 0.2:
            indicators.append(f"Unusually high digit ratio ({features['digit_ratio']*100:.1f}%) in URL.")

        if self.model is None and self.model_path.exists():
            self._load_model()

        if self.model is not None:
            vector = [features[k] for k in self.feature_names]
            proba = self.model.predict_proba([vector])[0]
            # Assumes classes are [0: Legitimate, 1: Phishing]
            phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            is_phishing = phishing_prob >= 0.5
            confidence = round(float(proba[1] if is_phishing else proba[0]), 4)
            risk_score = round(phishing_prob * 100, 2)
        else:
            # Fallback heuristic if model file is not yet serialized
            heuristic_score = min(100.0, len(indicators) * 25.0)
            is_phishing = heuristic_score >= 50.0
            phishing_prob = heuristic_score / 100.0
            confidence = 0.75
            risk_score = heuristic_score

        threat_class = "PHISHING" if is_phishing else "LEGITIMATE"

        if is_phishing:
            mitigation_steps = [
                "Block domain and IP at gateway firewall and DNS sinkhole.",
                "Revoke any credentials or session tokens potentially exposed to this URL.",
                "Enable MFA enforcement and notify targeted employees.",
                "Report target URL to Anti-Phishing Working Group (APWG) and Google Safe Browsing."
            ]
        else:
            mitigation_steps = [
                "Standard safe web browsing practices apply.",
                "Maintain periodic domain reputation monitoring."
            ]

        return {
            "url": url,
            "threat_classification": threat_class,
            "is_phishing": is_phishing,
            "confidence": confidence,
            "risk_score": risk_score,
            "extracted_features": features,
            "extracted_indicators": indicators,
            "mitigation_steps": mitigation_steps,
        }
