import json
import sys
import time
from pathlib import Path
import httpx

# Ensure backend root is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.main import app
from starlette.testclient import TestClient


def get_http_client():
    """Returns a client targeting either a live running server or in-process ASGI app."""
    try:
        probe = httpx.get("http://127.0.0.1:8000/health", timeout=1.0)
        if probe.status_code == 200:
            print("[INFO] Target: Live running FastAPI service at http://127.0.0.1:8000\n")
            return httpx.Client(base_url="http://127.0.0.1:8000", timeout=15.0), None
    except Exception:
        pass

    print("[INFO] Target: In-process FastAPI application with lifespan context\n")
    client = TestClient(app)
    client.__enter__()
    return client, client


def main():
    print("=" * 70)
    print("  CyberGuard Threat Intelligence Platform - End-to-End Verification")
    print("=" * 70)

    client, context_manager = get_http_client()
    passed_tests = 0
    total_tests = 5
    results = []

    try:
        # Check 1: GET /health returns status 'healthy' with all 3 engines loaded
        start = time.perf_counter()
        res1 = client.get("/health")
        lat1 = (time.perf_counter() - start) * 1000
        assert res1.status_code == 200, f"Expected 200, got {res1.status_code}"
        d1 = res1.json()
        assert d1["status"] == "healthy", f"Status not healthy: {d1.get('status')}"
        assert d1["all_engines_ready"] is True, "Not all engines are ready"
        assert d1["engines"]["phishing_engine"] is True, "Phishing engine offline"
        assert d1["engines"]["spam_engine"] is True, "Spam engine offline"
        assert d1["engines"]["dos_engine"] is True, "DoS engine offline"
        passed_tests += 1
        results.append(("Check 1: Health & Engine Lifespan Probe", "PASSED", f"{lat1:.2f} ms", f"All 3 ML engines ready (Status: {d1['status']})"))

        # Check 2: POST /api/v1/analyze/triage with phishing URL
        phish_url = "http://192.168.1.1/secure-update/login.php?user=admin"
        start = time.perf_counter()
        res2 = client.post("/api/v1/analyze/triage", json={"input_data": phish_url})
        lat2 = (time.perf_counter() - start) * 1000
        assert res2.status_code == 200, f"Expected 200, got {res2.status_code}"
        d2 = res2.json()
        assert d2["threat_type"] == "PHISHING", f"Threat type is {d2['threat_type']}"
        assert d2["category"] == "PHISHING" or d2["risk_score"] >= 50.0, f"Category/Risk unexpected: {d2['category']}, {d2['risk_score']}"
        passed_tests += 1
        results.append(("Check 2: Triage Phishing URL Detection", "PASSED", f"{lat2:.2f} ms", f"Class: {d2['category']} | Risk: {d2['risk_score']:.1f} | Conf: {d2['confidence']*100:.1f}%"))

        # Check 3: POST /api/v1/analyze/triage with spam text
        spam_msg = "CONGRATULATIONS! You have won $5,000,000 lottery cash prize! Send bank info now!"
        start = time.perf_counter()
        res3 = client.post("/api/v1/analyze/triage", json={"input_data": spam_msg})
        lat3 = (time.perf_counter() - start) * 1000
        assert res3.status_code == 200, f"Expected 200, got {res3.status_code}"
        d3 = res3.json()
        assert d3["threat_type"] == "SPAM", f"Threat type is {d3['threat_type']}"
        assert d3["category"] == "SPAM", f"Category is {d3['category']}"
        passed_tests += 1
        results.append(("Check 3: Triage Malicious Spam Detection", "PASSED", f"{lat3:.2f} ms", f"Class: {d3['category']} | Risk: {d3['risk_score']:.1f} | Conf: {d3['confidence']*100:.1f}%"))

        # Check 4: POST /api/v1/analyze/triage with NetFlow JSON
        dos_flow = {
            "flow_duration": 45.0,
            "tot_fwd_pkts": 10000.0,
            "tot_bwd_pkts": 0.0,
            "tot_len_fwd_pkts": 500000.0,
            "fwd_pkt_len_mean": 50.0,
            "syn_flag_cnt": 10000,
            "ack_flag_cnt": 0,
            "flow_bytes_s": 2500000.0,
            "flow_pkts_s": 50000.0,
        }
        start = time.perf_counter()
        res4 = client.post("/api/v1/analyze/triage", json={"input_data": json.dumps(dos_flow)})
        lat4 = (time.perf_counter() - start) * 1000
        assert res4.status_code == 200, f"Expected 200, got {res4.status_code}"
        d4 = res4.json()
        assert d4["threat_type"] == "DOS", f"Threat type is {d4['threat_type']}"
        assert d4["category"] in ["DOS_SYN_FLOOD", "DOS_ATTACK"], f"Category is {d4['category']}"
        passed_tests += 1
        results.append(("Check 4: Triage NetFlow SYN Flood Detection", "PASSED", f"{lat4:.2f} ms", f"Class: {d4['category']} | Severity: {d4['risk_level']} | Risk: {d4['risk_score']:.1f}"))

        # Check 5: POST /api/v1/analyze/triage with benign text
        benign_msg = "Team meeting is scheduled for tomorrow at 10 AM in room 4B."
        start = time.perf_counter()
        res5 = client.post("/api/v1/analyze/triage", json={"input_data": benign_msg})
        lat5 = (time.perf_counter() - start) * 1000
        assert res5.status_code == 200, f"Expected 200, got {res5.status_code}"
        d5 = res5.json()
        assert d5["risk_level"] == "LOW", f"Expected LOW risk level, got {d5['risk_level']}"
        passed_tests += 1
        results.append(("Check 5: Triage Benign Message Verification", "PASSED", f"{lat5:.2f} ms", f"Class: {d5['category']} | Level: {d5['risk_level']} | Risk: {d5['risk_score']:.1f}"))

    finally:
        if context_manager is not None:
            context_manager.__exit__(None, None, None)
        else:
            client.close()

    # Formatted Terminal Summary Report
    print(f"{'TEST NAME':<44} | {'STATUS':<8} | {'LATENCY':<10} | {'DETAILS'}")
    print("-" * 110)
    for name, status, lat, detail in results:
        print(f"{name:<44} | {status:<8} | {lat:<10} | {detail}")
    print("-" * 110)
    print(f"\nFinal Summary: {passed_tests}/{total_tests} Tests Passed Successfully (100% Pass Rate)\n")

    if passed_tests != total_tests:
        sys.exit(1)


if __name__ == "__main__":
    main()
