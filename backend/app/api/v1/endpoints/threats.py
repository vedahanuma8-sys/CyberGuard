import json
import re
import time
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Request

from app.ml_engines.dos_engine import DoSEngine
from app.ml_engines.phishing_engine import PhishingEngine
from app.ml_engines.spam_engine import SpamEngine
from app.schemas.threat_schemas import (
    DoSRequest,
    PhishingRequest,
    SpamRequest,
    UnifiedThreatResponse,
    UniversalThreatRequest,
)

router = APIRouter()

URL_PATTERN = re.compile(
    r"^(?:(?:https?:\/\/)|(?:www\.))"
    r"(?:(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|"
    r"(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z0-9_-]{2,})"
    r"(?::\d+)?"
    r"(?:[\/?#]\S*)?$",
    re.IGNORECASE,
)


def get_risk_level(score: float, category: str = "") -> str:
    if category in ["DOS_UDP_FLOOD"]:
        return "CRITICAL"
    if score >= 80.0:
        return "CRITICAL"
    elif score >= 60.0:
        return "HIGH"
    elif score >= 25.0:
        return "MEDIUM"
    return "LOW"


def get_phishing_engine(request: Request) -> PhishingEngine:
    engine = getattr(request.app.state, "phishing_engine", None)
    if engine is None:
        engine = PhishingEngine()
    return engine


def get_spam_engine(request: Request) -> SpamEngine:
    engine = getattr(request.app.state, "spam_engine", None)
    if engine is None:
        engine = SpamEngine()
    return engine


def get_dos_engine(request: Request) -> DoSEngine:
    engine = getattr(request.app.state, "dos_engine", None)
    if engine is None:
        engine = DoSEngine()
    return engine


@router.post("/phishing", response_model=UnifiedThreatResponse)
def analyze_phishing(payload: PhishingRequest, request: Request) -> UnifiedThreatResponse:
    """Analyzes a URL for phishing, impersonation, and domain deception indicators."""
    start_time = time.perf_counter()
    engine = get_phishing_engine(request)
    result = engine.predict(payload.url)
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    risk_score = float(result["risk_score"])
    category = result["threat_classification"]
    risk_level = get_risk_level(risk_score, category)

    return UnifiedThreatResponse(
        threat_type="PHISHING",
        category=category,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=float(result["confidence"]),
        indicators=result["extracted_indicators"],
        mitigation=result["mitigation_steps"],
        metadata={
            "url": payload.url,
            "is_phishing": result["is_phishing"],
            "features": result["extracted_features"],
        },
        latency_ms=latency_ms,
    )


@router.post("/spam", response_model=UnifiedThreatResponse)
def analyze_spam(payload: SpamRequest, request: Request) -> UnifiedThreatResponse:
    """Classifies message text as spam, scam, or ham using TF-IDF + Calibrated LinearSVC."""
    start_time = time.perf_counter()
    engine = get_spam_engine(request)
    result = engine.predict(payload.text)
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    risk_score = float(result["risk_score"])
    category = result["threat_classification"]
    risk_level = get_risk_level(risk_score, category)

    return UnifiedThreatResponse(
        threat_type="SPAM",
        category=category,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=float(result["confidence"]),
        indicators=result["extracted_indicators"],
        mitigation=result["mitigation_steps"],
        metadata={
            "text_preview": result["text_preview"],
            "is_spam": result["is_spam"],
        },
        latency_ms=latency_ms,
    )


@router.post("/dos", response_model=UnifiedThreatResponse)
def analyze_dos(payload: DoSRequest, request: Request) -> UnifiedThreatResponse:
    """Analyzes network flow metrics to detect Benign vs DoS (SYN Flood, UDP Flood, Slowloris)."""
    start_time = time.perf_counter()
    engine = get_dos_engine(request)
    flow_dict = payload.model_dump()
    result = engine.predict(flow_dict)
    latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

    risk_score = float(result["risk_score"])
    category = result["threat_classification"]
    risk_level = result["severity"] if result["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else get_risk_level(risk_score, category)

    return UnifiedThreatResponse(
        threat_type="DOS",
        category=category,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=float(result["confidence"]),
        indicators=result["extracted_indicators"],
        mitigation=result["mitigation_steps"],
        metadata={
            "is_threat": result["is_threat"],
            "flow_metrics": result["flow_metrics"],
        },
        latency_ms=latency_ms,
    )


@router.post("/triage", response_model=UnifiedThreatResponse)
def analyze_triage(payload: UniversalThreatRequest, request: Request) -> UnifiedThreatResponse:
    """
    Unified intelligent triage endpoint:
    - Parses input data automatically or uses force_type.
    - If valid JSON with flow metrics -> routes to DoS engine.
    - Else if matches URL format -> routes to Phishing engine.
    - Else -> routes to Spam/Social Engineering engine.
    - Measures execution latency and returns UnifiedThreatResponse.
    """
    raw_input = payload.input_data.strip()

    # 1. Force type overrides
    if payload.force_type == "dos":
        try:
            flow_data = json.loads(raw_input)
            req = DoSRequest(**flow_data)
            return analyze_dos(req, request)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid DoS flow metrics JSON payload: {str(e)}")
    elif payload.force_type == "phishing":
        return analyze_phishing(PhishingRequest(url=raw_input), request)
    elif payload.force_type == "spam":
        return analyze_spam(SpamRequest(text=raw_input), request)

    # 2. Dynamic auto-detection: Check for DoS JSON flow metrics
    if raw_input.startswith("{") and raw_input.endswith("}"):
        try:
            parsed = json.loads(raw_input)
            if isinstance(parsed, dict) and any(k in parsed for k in ["flow_duration", "tot_fwd_pkts", "flow_bytes_s"]):
                req = DoSRequest(
                    flow_duration=float(parsed.get("flow_duration", 0)),
                    tot_fwd_pkts=float(parsed.get("tot_fwd_pkts", 0)),
                    tot_bwd_pkts=float(parsed.get("tot_bwd_pkts", 0)),
                    tot_len_fwd_pkts=float(parsed.get("tot_len_fwd_pkts", 0)),
                    fwd_pkt_len_mean=float(parsed.get("fwd_pkt_len_mean", 0)),
                    syn_flag_cnt=int(parsed.get("syn_flag_cnt", 0)),
                    ack_flag_cnt=int(parsed.get("ack_flag_cnt", 0)),
                    flow_bytes_s=float(parsed.get("flow_bytes_s", 0)),
                    flow_pkts_s=float(parsed.get("flow_pkts_s", 0)),
                )
                return analyze_dos(req, request)
        except (ValueError, TypeError):
            pass

    # 3. Dynamic auto-detection: Check for URL (Phishing)
    # Check if starts with http/https/www or matches URL pattern without whitespace
    is_url = bool(URL_PATTERN.match(raw_input))
    if not is_url and " " not in raw_input and ("http://" in raw_input or "https://" in raw_input or raw_input.startswith("www.")):
        is_url = True

    if is_url:
        return analyze_phishing(PhishingRequest(url=raw_input), request)

    # 4. Fallback: Message text (Spam / Social Engineering)
    return analyze_spam(SpamRequest(text=raw_input), request)
