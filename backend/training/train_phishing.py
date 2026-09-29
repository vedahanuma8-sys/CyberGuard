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
from app.ml_engines.phishing_engine import (
    PHISHING_FEATURE_NAMES,
    extract_url_features,
)

random.seed(42)
np.random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "github.com", "amazon.com",
    "wikipedia.org", "stackoverflow.com", "nytimes.com", "netflix.com",
    "linkedin.com", "dropbox.com", "medium.com", "reddit.com", "cloudflare.com",
    "mozilla.org", "python.org", "mit.edu", "nih.gov", "cnn.com", "bbc.co.uk"
]

LEGIT_PATHS = [
    "about", "contact", "docs/api/v1", "search?q=cybersecurity",
    "products/item/10294", "news/2026/05/tech-insights", "wiki/Machine_learning",
    "explore/trending", "help/center", "features/security", "blog/post-105"
]

PHISH_TARGETS = ["paypal", "chase", "apple", "microsoft", "netflix", "wellsfargo", "bankofamerica", "coinbase"]
PHISH_ACTIONS = ["login", "verify-account", "security-alert", "update-billing", "suspended", "confirm-identity", "unlock"]
PHISH_TLDS = [".xyz", ".top", ".cc", ".ru", ".info", ".tk", ".club", ".vip"]


def generate_legitimate_url() -> str:
    domain = random.choice(LEGIT_DOMAINS)
    sub = random.choice(["", "www.", "blog.", "docs.", "support."])
    path = random.choice(LEGIT_PATHS)
    proto = random.choice(["https://", "https://", "https://", "http://"])
    return f"{proto}{sub}{domain}/{path}"


def generate_phishing_url() -> str:
    variant = random.randint(1, 5)
    target = random.choice(PHISH_TARGETS)
    action = random.choice(PHISH_ACTIONS)
    tld = random.choice(PHISH_TLDS)

    if variant == 1:
        # IP based
        ip = f"{random.randint(11, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        return f"http://{ip}/{target}/{action}/index.php?token={random.randint(10000, 99999)}"
    elif variant == 2:
        # Excessive subdomains with brand impersonation
        return f"http://secure.{action}.{target}.account-protection{tld}/signin?redirect=true"
    elif variant == 3:
        # @ symbol confusion
        return f"http://{target}.com@{action}-portal-secure{tld}/login.html"
    elif variant == 4:
        # High entropy DGA + random digits
        rand_str = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
        return f"http://{rand_str}{tld}/{target}-{action}?id={random.randint(100000, 999999)}"
    else:
        # Hyphenated keywords with suspicious TLD
        num = random.randint(100, 999)
        return f"http://{target}-{action}-verify-{num}{tld}/auth/checkpoint"


def main():
    print("=" * 60)
    print("Generating representative dataset for Phishing URL Detection...")
    print("=" * 60)

    urls = []
    labels = []

    # 1,000 Legitimate (0) and 1,000 Phishing (1)
    for _ in range(1000):
        urls.append(generate_legitimate_url())
        labels.append(0)

    for _ in range(1000):
        urls.append(generate_phishing_url())
        labels.append(1)

    print(f"Total URLs synthesized: {len(urls)} (1,000 Legitimate, 1,000 Phishing)")
    print("Extracting URL features...")

    features_list = [extract_url_features(u) for u in urls]
    df = pd.DataFrame(features_list)
    X = df[PHISHING_FEATURE_NAMES].values
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"Training RandomForestClassifier on {len(X_train)} samples...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n--- Model Evaluation ---")
    print(f"Accuracy: {acc * 100:.2f}%")
    print(f"F1-Score: {f1:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Serialize model artifact
    settings.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    artifact_path = settings.ARTIFACTS_DIR / "phishing_model.joblib"
    joblib.dump({"model": clf, "feature_names": PHISHING_FEATURE_NAMES}, artifact_path)
    print(f"Artifact serialized successfully to: {artifact_path}")
    print(f"File size: {os.path.getsize(artifact_path)} bytes")


if __name__ == "__main__":
    main()
