from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class PhishingRequest(BaseModel):
    url: str = Field(..., description="Target URL to analyze for phishing indicators", min_length=3)


class SpamRequest(BaseModel):
    text: str = Field(..., description="Message text (email, SMS, social message) to classify", min_length=1)


class DoSRequest(BaseModel):
    flow_duration: float = Field(..., description="Duration of network flow in milliseconds")
    tot_fwd_pkts: float = Field(..., description="Total packets in forward direction")
    tot_bwd_pkts: float = Field(..., description="Total packets in backward direction")
    tot_len_fwd_pkts: float = Field(..., description="Total length of forward packets in bytes")
    fwd_pkt_len_mean: float = Field(..., description="Mean size of forward packets in bytes")
    syn_flag_cnt: int = Field(..., description="Count of TCP SYN flags observed")
    ack_flag_cnt: int = Field(..., description="Count of TCP ACK flags observed")
    flow_bytes_s: float = Field(..., description="Flow throughput in bytes per second")
    flow_pkts_s: float = Field(..., description="Flow packet rate in packets per second")


class UniversalThreatRequest(BaseModel):
    input_data: str = Field(..., description="Raw text, URL, or JSON serialized network flow string", min_length=1)
    force_type: Optional[Literal["phishing", "spam", "dos"]] = Field(
        None, description="Explicitly force analysis by a specific engine ('phishing', 'spam', 'dos')"
    )


class UnifiedThreatResponse(BaseModel):
    threat_type: str = Field(..., description="Threat category: 'PHISHING', 'SPAM', or 'DOS'")
    category: str = Field(..., description="Fine-grained threat class (e.g. LEGITIMATE, PHISHING, HAM, SPAM, BENIGN, DOS_SYN_FLOOD)")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(..., description="Categorical risk severity")
    confidence: float = Field(..., description="Model prediction confidence from 0.0 to 1.0")
    indicators: List[str] = Field(default_factory=list, description="Extracted suspicious indicators or heuristics")
    mitigation: List[str] = Field(default_factory=list, description="Recommended remediation actions")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Engine specific extracted features or metrics")
    latency_ms: float = Field(..., description="Engine inference latency in milliseconds")
