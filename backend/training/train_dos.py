import os
import random
import sys
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split

# Ensure backend root is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import settings
from app.ml_engines.dos_engine import DOS_FEATURE_NAMES

np.random.seed(42)
random.seed(42)


def generate_benign_flows(n: int) -> pd.DataFrame:
    """Simulates benign web traffic flows (HTTP/HTTPS, API calls)."""
    duration = np.random.uniform(500, 25000, n)
    fwd_pkts = np.random.randint(5, 45, n)
    bwd_pkts = fwd_pkts + np.random.randint(-3, 10, n)
    bwd_pkts = np.maximum(bwd_pkts, 2)
    fwd_len_mean = np.random.uniform(150, 850, n)
    tot_len_fwd = fwd_pkts * fwd_len_mean
    syn_cnt = np.random.choice([1, 2], n, p=[0.85, 0.15])
    ack_cnt = fwd_pkts + np.random.randint(0, 5, n)
    flow_bytes_s = (tot_len_fwd / (duration / 1000.0)) + np.random.uniform(1000, 50000, n)
    flow_pkts_s = ((fwd_pkts + bwd_pkts) / (duration / 1000.0)) + np.random.uniform(2, 50, n)

    df = pd.DataFrame({
        "flow_duration": duration,
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "tot_len_fwd_pkts": tot_len_fwd,
        "fwd_pkt_len_mean": fwd_len_mean,
        "syn_flag_cnt": syn_cnt,
        "ack_flag_cnt": ack_cnt,
        "flow_bytes_s": flow_bytes_s,
        "flow_pkts_s": flow_pkts_s,
        "label": "BENIGN"
    })
    return df


def generate_syn_flood_flows(n: int) -> pd.DataFrame:
    """Simulates TCP SYN flood attack flows (high SYN, zero ACK, short durations, zero bwd pkts)."""
    duration = np.random.uniform(10, 2000, n)
    fwd_pkts = np.random.randint(5, 15000, n)
    bwd_pkts = np.zeros(n, dtype=int)
    fwd_len_mean = np.random.uniform(40, 64, n)  # TCP SYN headers without payload
    tot_len_fwd = fwd_pkts * fwd_len_mean
    syn_cnt = fwd_pkts
    ack_cnt = np.zeros(n, dtype=int)
    flow_pkts_s = np.random.uniform(15000, 85000, n)
    flow_bytes_s = flow_pkts_s * fwd_len_mean

    df = pd.DataFrame({
        "flow_duration": duration,
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "tot_len_fwd_pkts": tot_len_fwd,
        "fwd_pkt_len_mean": fwd_len_mean,
        "syn_flag_cnt": syn_cnt,
        "ack_flag_cnt": ack_cnt,
        "flow_bytes_s": flow_bytes_s,
        "flow_pkts_s": flow_pkts_s,
        "label": "DOS_SYN_FLOOD"
    })
    return df


def generate_udp_flood_flows(n: int) -> pd.DataFrame:
    """Simulates UDP volumetric flood (massive packet and byte rates, 0 TCP flags)."""
    duration = np.random.uniform(100, 3000, n)
    fwd_pkts = np.random.randint(800, 12000, n)
    bwd_pkts = np.zeros(n, dtype=int)
    fwd_len_mean = np.random.uniform(600, 1400, n)  # Large payload sizes
    tot_len_fwd = fwd_pkts * fwd_len_mean
    syn_cnt = np.zeros(n, dtype=int)
    ack_cnt = np.zeros(n, dtype=int)
    flow_bytes_s = np.random.uniform(3000000, 60000000, n)
    flow_pkts_s = np.random.uniform(6000, 35000, n)

    df = pd.DataFrame({
        "flow_duration": duration,
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "tot_len_fwd_pkts": tot_len_fwd,
        "fwd_pkt_len_mean": fwd_len_mean,
        "syn_flag_cnt": syn_cnt,
        "ack_flag_cnt": ack_cnt,
        "flow_bytes_s": flow_bytes_s,
        "flow_pkts_s": flow_pkts_s,
        "label": "DOS_UDP_FLOOD"
    })
    return df


def generate_slowloris_flows(n: int) -> pd.DataFrame:
    """Simulates Slowloris attack (extreme duration, low bytes/s, tiny payload drip-feed)."""
    duration = np.random.uniform(65000, 300000, n)
    fwd_pkts = np.random.randint(12, 50, n)
    bwd_pkts = np.random.randint(0, 4, n)
    fwd_len_mean = np.random.uniform(15, 32, n)  # Partial header strings
    tot_len_fwd = fwd_pkts * fwd_len_mean
    syn_cnt = np.ones(n, dtype=int)
    ack_cnt = np.random.randint(2, 8, n)
    flow_bytes_s = np.random.uniform(0.1, 15.0, n)
    flow_pkts_s = np.random.uniform(0.04, 0.4, n)

    df = pd.DataFrame({
        "flow_duration": duration,
        "tot_fwd_pkts": fwd_pkts,
        "tot_bwd_pkts": bwd_pkts,
        "tot_len_fwd_pkts": tot_len_fwd,
        "fwd_pkt_len_mean": fwd_len_mean,
        "syn_flag_cnt": syn_cnt,
        "ack_flag_cnt": ack_cnt,
        "flow_bytes_s": flow_bytes_s,
        "flow_pkts_s": flow_pkts_s,
        "label": "DOS_SLOWLORIS"
    })
    return df


def main():
    print("=" * 60)
    print("Generating CICIDS2017-modeled dataset for DoS Attack Detection...")
    print("=" * 60)

    # 3,000 total flows: 1,200 Benign, 600 SYN Flood, 600 UDP Flood, 600 Slowloris
    df_benign = generate_benign_flows(1200)
    df_syn = generate_syn_flood_flows(600)
    df_udp = generate_udp_flood_flows(600)
    df_slow = generate_slowloris_flows(600)

    df = pd.concat([df_benign, df_syn, df_udp, df_slow], ignore_index=True)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    print(f"Total flows synthesized: {len(df)}")
    print("Class distribution:")
    print(df["label"].value_counts())

    X = df[DOS_FEATURE_NAMES].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"\nTraining RandomForestClassifier on {len(X_train)} flow records...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")

    print("\n--- Model Evaluation ---")
    print(f"Accuracy: {acc * 100:.2f}%")
    print(f"Weighted F1-Score: {f1:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    # Serialize model artifact
    settings.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    artifact_path = settings.ARTIFACTS_DIR / "dos_model.joblib"
    joblib.dump({"model": clf, "feature_names": DOS_FEATURE_NAMES}, artifact_path)
    print(f"Artifact serialized successfully to: {artifact_path}")
    print(f"File size: {os.path.getsize(artifact_path)} bytes")


if __name__ == "__main__":
    main()
