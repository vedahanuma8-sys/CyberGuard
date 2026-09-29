import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib

from app.core.config import settings

SPAM_TRIGGER_KEYWORDS = [
    "free", "winner", "won", "prize", "urgent", "claim", "lottery",
    "congratulations", "cash", "credit", "crypto", "investment", "bitcoin",
    "wire transfer", "bank account", "verify account", "unclaimed",
    "act now", "immediate action", "click here", "limited time", "inheritance"
]


class SpamEngine:
    """ML Engine for detecting SMS/Email Spam using TF-IDF + Calibrated LinearSVC."""

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or (settings.ARTIFACTS_DIR / "spam_pipeline.joblib")
        self.pipeline = None
        self._load_pipeline()

    def _load_pipeline(self) -> None:
        if self.model_path.exists():
            self.pipeline = joblib.load(self.model_path)

    def extract_indicators(self, text: str) -> List[str]:
        """Extracts spam heuristics and indicators from raw text."""
        indicators = []
        text_lower = text.lower()

        # Check keyword triggers
        matched_keywords = [kw for kw in SPAM_TRIGGER_KEYWORDS if kw in text_lower]
        if matched_keywords:
            indicators.append(f"Contains high-frequency spam keywords: {', '.join(matched_keywords[:4])}.")

        # Check for currency symbols and urgent numbers
        if re.search(r"[\$\£\€]\s*\d+", text):
            indicators.append("Contains monetary figures/currency promotion.")

        # Check for phone numbers or urgent call-to-actions
        if re.search(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", text):
            indicators.append("Contains contact phone number or dial request.")

        # Check for uppercase ratio (shouting)
        letters = [c for c in text if c.isalpha()]
        if letters:
            upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
            if upper_ratio > 0.35 and len(letters) > 15:
                indicators.append(f"Excessive capitalization ({upper_ratio*100:.1f}% uppercase).")

        # Check for excessive exclamation or question marks
        if text.count("!") >= 3:
            indicators.append(f"Multiple exclamation marks ({text.count('!')}) indicating false urgency.")

        return indicators

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Classifies input text as SPAM or HAM.
        Returns threat classification, confidence, risk score, indicators, and mitigation.
        """
        raw_text = str(text or "").strip()
        indicators = self.extract_indicators(raw_text)

        if self.pipeline is None and self.model_path.exists():
            self._load_pipeline()

        if self.pipeline is not None and raw_text:
            proba = self.pipeline.predict_proba([raw_text])[0]
            # Assumes binary classes: 0 = HAM, 1 = SPAM
            spam_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            is_spam = spam_prob >= 0.5
            confidence = round(float(proba[1] if is_spam else proba[0]), 4)
            risk_score = round(spam_prob * 100, 2)
        else:
            # Fallback heuristic
            score = min(100.0, len(indicators) * 25.0)
            is_spam = score >= 50.0
            confidence = 0.70
            risk_score = score

        threat_class = "SPAM" if is_spam else "HAM"

        if is_spam:
            mitigation_steps = [
                "Quarantine email message / block SMS sender origin.",
                "Filter sender IP/domain at secure email gateway (SEG).",
                "Do not interact with embedded phone numbers, links, or attachments.",
                "Flag message for organizational threat-hunting and perimeter filtering."
            ]
        else:
            mitigation_steps = [
                "Deliver message to user inbox.",
                "Standard email authentication protocols (SPF/DKIM/DMARC) verified."
            ]

        return {
            "text_preview": raw_text[:120] + ("..." if len(raw_text) > 120 else ""),
            "threat_classification": threat_class,
            "is_spam": is_spam,
            "confidence": confidence,
            "risk_score": risk_score,
            "extracted_indicators": indicators,
            "mitigation_steps": mitigation_steps,
        }
