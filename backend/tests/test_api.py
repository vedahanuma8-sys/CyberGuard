import json
import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_check(client: TestClient):
    """Test 1: GET /health returns 200 and all engines True with non-empty artifacts."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "healthy"
    assert data["all_engines_ready"] is True
    assert data["engines"]["phishing_engine"] is True
    assert data["engines"]["spam_engine"] is True
    assert data["engines"]["dos_engine"] is True

    # Confirm artifact file checks
    assert data["artifacts"]["phishing_model.joblib"]["exists"] is True
    assert data["artifacts"]["phishing_model.joblib"]["size_bytes"] > 0

    assert data["artifacts"]["spam_pipeline.joblib"]["exists"] is True
    assert data["artifacts"]["spam_pipeline.joblib"]["size_bytes"] > 0

    assert data["artifacts"]["dos_model.joblib"]["exists"] is True
    assert data["artifacts"]["dos_model.joblib"]["size_bytes"] > 0


def test_analyze_phishing(client: TestClient):
    """Test 2: POST /api/v1/analyze/phishing with valid and phishing URLs."""
    # 1. Valid / Legitimate URL
    legit_payload = {"url": "https://www.google.com/search?q=cyberguard+threat+intelligence"}
    res_legit = client.post("/api/v1/analyze/phishing", json=legit_payload)
    assert res_legit.status_code == 200
    data_legit = res_legit.json()
    assert data_legit["threat_type"] == "PHISHING"
    assert data_legit["category"] == "LEGITIMATE"
    assert data_legit["risk_level"] == "LOW"
    assert data_legit["risk_score"] < 50.0
    assert data_legit["latency_ms"] >= 0

    # 2. Phishing URL
    phish_payload = {"url": "http://192.168.1.100/paypal/login.php?token=92831"}
    res_phish = client.post("/api/v1/analyze/phishing", json=phish_payload)
    assert res_phish.status_code == 200
    data_phish = res_phish.json()
    assert data_phish["threat_type"] == "PHISHING"
    assert data_phish["category"] == "PHISHING"
    assert data_phish["risk_score"] >= 50.0
    assert len(data_phish["indicators"]) > 0
    assert len(data_phish["mitigation"]) > 0


def test_analyze_spam(client: TestClient):
    """Test 3: POST /api/v1/analyze/spam with benign and spam text."""
    # 1. Benign Ham text
    ham_payload = {"text": "Hi Alex, please find attached the quarterly business report for tomorrow's meeting."}
    res_ham = client.post("/api/v1/analyze/spam", json=ham_payload)
    assert res_ham.status_code == 200
    data_ham = res_ham.json()
    assert data_ham["threat_type"] == "SPAM"
    assert data_ham["category"] == "HAM"
    assert data_ham["risk_level"] == "LOW"
    assert data_ham["confidence"] > 0.5

    # 2. Malicious Spam text
    spam_payload = {"text": "URGENT: Your bank account is locked! Claim your $50,000 cash lottery prize now at http://claim-prize.top"}
    res_spam = client.post("/api/v1/analyze/spam", json=spam_payload)
    assert res_spam.status_code == 200
    data_spam = res_spam.json()
    assert data_spam["threat_type"] == "SPAM"
    assert data_spam["category"] == "SPAM"
    assert data_spam["risk_score"] >= 75.0
    assert data_spam["risk_level"] in ["HIGH", "CRITICAL"]
    assert len(data_spam["indicators"]) > 0
    assert len(data_spam["mitigation"]) > 0


def test_analyze_dos(client: TestClient):
    """Test 4: POST /api/v1/analyze/dos with nominal and SYN flood flows."""
    # 1. Nominal / Benign flow
    nominal_payload = {
        "flow_duration": 8500.0,
        "tot_fwd_pkts": 18.0,
        "tot_bwd_pkts": 20.0,
        "tot_len_fwd_pkts": 6500.0,
        "fwd_pkt_len_mean": 361.0,
        "syn_flag_cnt": 1,
        "ack_flag_cnt": 18,
        "flow_bytes_s": 25000.0,
        "flow_pkts_s": 22.0,
    }
    res_benign = client.post("/api/v1/analyze/dos", json=nominal_payload)
    assert res_benign.status_code == 200
    data_benign = res_benign.json()
    assert data_benign["threat_type"] == "DOS"
    assert data_benign["category"] == "BENIGN"
    assert data_benign["risk_level"] == "LOW"

    # 2. SYN Flood flow
    syn_flood_payload = {
        "flow_duration": 60.0,
        "tot_fwd_pkts": 10.0,
        "tot_bwd_pkts": 0.0,
        "tot_len_fwd_pkts": 500.0,
        "fwd_pkt_len_mean": 50.0,
        "syn_flag_cnt": 10,
        "ack_flag_cnt": 0,
        "flow_bytes_s": 1500000.0,
        "flow_pkts_s": 45000.0,
    }
    res_syn = client.post("/api/v1/analyze/dos", json=syn_flood_payload)
    assert res_syn.status_code == 200
    data_syn = res_syn.json()
    assert data_syn["threat_type"] == "DOS"
    assert data_syn["category"] == "DOS_SYN_FLOOD"
    assert data_syn["risk_level"] in ["HIGH", "CRITICAL"]
    assert len(data_syn["indicators"]) > 0


def test_analyze_triage_auto_detection(client: TestClient):
    """Test 5: POST /api/v1/analyze/triage with dynamic auto-detection for all three types."""
    # 1. URL input -> Phishing
    url_req = {"input_data": "https://www.github.com/microsoft/vscode"}
    res_url = client.post("/api/v1/analyze/triage", json=url_req)
    assert res_url.status_code == 200
    data_url = res_url.json()
    assert data_url["threat_type"] == "PHISHING"
    assert data_url["category"] == "LEGITIMATE"

    # 2. Raw text input -> Spam
    text_req = {"input_data": "URGENT ACTION REQUIRED: Verify your Bitcoin wallet credentials immediately to unlock funds."}
    res_text = client.post("/api/v1/analyze/triage", json=text_req)
    assert res_text.status_code == 200
    data_text = res_text.json()
    assert data_text["threat_type"] == "SPAM"
    assert data_text["category"] == "SPAM"

    # 3. JSON flow metrics string -> DoS
    flow_dict = {
        "flow_duration": 45.0,
        "tot_fwd_pkts": 8.0,
        "tot_bwd_pkts": 0.0,
        "tot_len_fwd_pkts": 400.0,
        "fwd_pkt_len_mean": 50.0,
        "syn_flag_cnt": 8,
        "ack_flag_cnt": 0,
        "flow_bytes_s": 1200000.0,
        "flow_pkts_s": 35000.0,
    }
    dos_req = {"input_data": json.dumps(flow_dict)}
    res_dos = client.post("/api/v1/analyze/triage", json=dos_req)
    assert res_dos.status_code == 200
    data_dos = res_dos.json()
    assert data_dos["threat_type"] == "DOS"
    assert data_dos["category"] == "DOS_SYN_FLOOD"

    # 4. Explicit force_type override
    forced_req = {"input_data": "normal text message", "force_type": "spam"}
    res_forced = client.post("/api/v1/analyze/triage", json=forced_req)
    assert res_forced.status_code == 200
    assert res_forced.json()["threat_type"] == "SPAM"
