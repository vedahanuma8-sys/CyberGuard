from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import numpy as np

from app.core.config import settings

DOS_FEATURE_NAMES = [
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "tot_len_fwd_pkts",
    "fwd_pkt_len_mean",
    "syn_flag_cnt",
    "ack_flag_cnt",
    "flow_bytes_s",
    "flow_pkts_s",
]

SEVERITY_MAPPING = {
    "BENIGN": "LOW",
    "DOS_SYN_FLOOD": "HIGH",
    "DOS_UDP_FLOOD": "CRITICAL",
    "DOS_SLOWLORIS": "MEDIUM",
}

RISK_MAPPING = {
    "BENIGN": 5.0,
    "DOS_SLOWLORIS": 65.0,
    "DOS_SYN_FLOOD": 85.0,
    "DOS_UDP_FLOOD": 95.0,
}


class DoSEngine:
    """ML Engine for detecting Denial-of-Service (DoS/DDoS) network flow attacks."""

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or (settings.ARTIFACTS_DIR / "dos_model.joblib")
        self.model = None
        self.feature_names = DOS_FEATURE_NAMES
        self.classes_ = ["BENIGN", "DOS_SYN_FLOOD", "DOS_UDP_FLOOD", "DOS_SLOWLORIS"]
        self._load_model()

    def _load_model(self) -> None:
        if self.model_path.exists():
            data = joblib.load(self.model_path)
            if isinstance(data, dict) and "model" in data:
                self.model = data["model"]
                self.feature_names = data.get("feature_names", DOS_FEATURE_NAMES)
                self.classes_ = getattr(self.model, "classes_", self.classes_)
            else:
                self.model = data
                self.classes_ = getattr(self.model, "classes_", self.classes_)

    def extract_indicators(self, flow: Dict[str, Any]) -> List[str]:
        """Extracts flow anomaly indicators based on network heuristics."""
        indicators = []

        syn = float(flow.get("syn_flag_cnt", 0))
        ack = float(flow.get("ack_flag_cnt", 0))
        bwd_pkts = float(flow.get("tot_bwd_pkts", 0))
        fwd_pkts = float(flow.get("tot_fwd_pkts", 0))
        duration = float(flow.get("flow_duration", 0))
        pkt_rate = float(flow.get("flow_pkts_s", 0))
        byte_rate = float(flow.get("flow_bytes_s", 0))
        pkt_len_mean = float(flow.get("fwd_pkt_len_mean", 0))

        if syn > 0 and ack == 0:
            indicators.append("Half-open TCP connection detected (SYN flags present without ACK).")
        if bwd_pkts == 0 and fwd_pkts > 10:
            indicators.append("Unidirectional packet burst with zero server backward responses.")
        if pkt_rate > 5000:
            indicators.append(f"Abnormally high packet rate ({pkt_rate:.1f} pkts/s).")
        if byte_rate > 1_000_000:
            indicators.append(f"Volumetric bandwidth surge ({byte_rate / 1_000_000:.2f} MB/s).")
        if duration > 60_000 and pkt_len_mean < 35:
            indicators.append("Prolonged session duration with microscopic payloads (Slowloris exhaustion pattern).")

        return indicators

    def predict(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classifies network flow features into BENIGN vs DOS attack categories.
        Returns threat classification, confidence, severity, risk score, indicators, and mitigation.
        """
        indicators = self.extract_indicators(flow_data)

        if self.model is None and self.model_path.exists():
            self._load_model()

        # Build feature vector
        vector = [float(flow_data.get(feat, 0.0)) for feat in self.feature_names]

        if self.model is not None:
            proba = self.model.predict_proba([vector])[0]
            predicted_idx = int(np.argmax(proba))
            threat_class = str(self.classes_[predicted_idx])
            confidence = round(float(proba[predicted_idx]), 4)
        else:
            # Fallback heuristic
            if flow_data.get("syn_flag_cnt", 0) > 0 and flow_data.get("ack_flag_cnt", 0) == 0:
                threat_class = "DOS_SYN_FLOOD"
            elif flow_data.get("flow_pkts_s", 0) > 5000:
                threat_class = "DOS_UDP_FLOOD"
            elif flow_data.get("flow_duration", 0) > 60000 and flow_data.get("fwd_pkt_len_mean", 0) < 35:
                threat_class = "DOS_SLOWLORIS"
            else:
                threat_class = "BENIGN"
            confidence = 0.80

        is_dos = threat_class != "BENIGN"
        severity = SEVERITY_MAPPING.get(threat_class, "HIGH" if is_dos else "LOW")
        risk_score = RISK_MAPPING.get(threat_class, 75.0 if is_dos else 5.0)

        # Attack-specific mitigation steps
        if threat_class == "DOS_SYN_FLOOD":
            mitigation_steps = [
                "Enable TCP SYN cookies on kernel and edge load balancer.",
                "Enforce strict per-IP connection rate limiting on ingress firewall.",
                "Reduce tcp_synack_retries and tcp_max_syn_backlog kernel timeouts."
            ]
        elif threat_class == "DOS_UDP_FLOOD":
            mitigation_steps = [
                "Engage upstream ISP / Cloud Scrubbing Center for volumetric BGP redirection.",
                "Drop unsolicited UDP traffic on non-essential ports at perimeter router.",
                "Activate strict flow rate threshold policing via ACL / iptables."
            ]
        elif threat_class == "DOS_SLOWLORIS":
            mitigation_steps = [
                "Enforce minimum HTTP data transfer rate thresholds (e.g., RequestReadTimeout).",
                "Limit maximum concurrent client connections per IP address.",
                "Deploy reverse proxy (e.g. NGINX/Envoy) to buffer slow client request headers."
            ]
        else:
            mitigation_steps = [
                "Flow matches normal baseline traffic profile.",
                "Continue standard continuous network monitoring."
            ]

        return {
            "threat_classification": threat_class,
            "is_threat": is_dos,
            "confidence": confidence,
            "severity": severity,
            "risk_score": risk_score,
            "flow_metrics": {feat: flow_data.get(feat, 0) for feat in self.feature_names},
            "extracted_indicators": indicators,
            "mitigation_steps": mitigation_steps,
        }
