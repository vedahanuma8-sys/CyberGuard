import os
import random
import sys
from pathlib import Path
import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

# Ensure backend root is on sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import settings

random.seed(42)
np.random.seed(42)

HAM_TEMPLATES = [
    "Hi {name}, can we reschedule our sprint review to tomorrow at {time}?",
    "Please find attached the Q3 financial report and quarterly projections for your review.",
    "Team, the deployment to the staging environment completed successfully with zero downtime.",
    "Hey, let me know when you are free for lunch today. We can try that new bistro.",
    "Reminder: The weekly project sync will begin in 15 minutes in conference room B.",
    "Your package with tracking number #{num} has been delivered to your front porch.",
    "Thank you for your inquiry regarding our enterprise API support. We will get back shortly.",
    "Could you please review the pull request for the authentication bug fix on Github?",
    "Hey {name}, hope you are doing well. Just following up on the design mockups.",
    "Your appointment with Dr. {doctor} is confirmed for next Monday at {time} AM.",
    "The invoice #{num} for the cloud hosting services has been processed and paid.",
    "Can you share the updated slide deck before our client presentation this afternoon?",
    "Good morning team, please submit your timesheets by end of business today.",
    "Hi, welcome to our monthly tech meetup. Check out the agenda and guest speakers.",
    "Your password for corporate account {user} was changed successfully yesterday."
]

SPAM_TEMPLATES = [
    "URGENT: Your bank account #{num} has been suspended! Verify your credentials immediately at {url} to restore access.",
    "CONGRATULATIONS! You have won a ${amount} Walmart gift card. Click {url} or call {phone} to claim your prize now!",
    "FINAL NOTICE: IRS tax audit alert. You owe back taxes. Call immediately at {phone} to avoid arrest warrant.",
    "FREE crypto investment bonus! Deposit $100 and receive {amount} Bitcoin in 24 hours. Sign up here: {url}",
    "You have an unclaimed inheritance of ${amount},000,000 from Barrister {name}. Reply with bank details to transfer funds.",
    "Hot singles waiting in your local neighborhood! Click here to chat with verified girls now: {url}",
    "URGENT ACTION REQUIRED: Your Netflix payment failed. Update billing information within 24 hours at {url}",
    "Guaranteed personal loan up to ${amount} approved! No credit check required. Fast wire transfer today: {phone}",
    "CLAIM NOW: You were selected as the lucky winner of our annual cash sweepstakes #{num}. Click {url}",
    "Your PayPal account was locked due to suspicious activity. Log in at {url} to confirm your identity.",
    "Work from home and earn up to ${amount} per day with zero experience! Limited slots available. Act now: {url}",
    "Exclusive discount! Buy cheap prescription pills and luxury watches with 80% OFF. Visit our pharmacy: {url}",
    "ALERT: Suspicious login attempt from Russia detected on your email. Secure your account now at {url}",
    "You have 1 pending parcel held at customs. Pay shipping fee of ${num} to release your package immediately: {url}",
    "Double your Ethereum instantly! Official Giveaway event. Send 1 ETH to smart contract and get 2 ETH back: {url}"
]

NAMES = ["Alex", "Jordan", "Sarah", "Michael", "David", "Emma", "Chris", "Taylor"]
TIMES = ["10:00", "11:30", "14:00", "15:30", "16:45"]
DOCTORS = ["Smith", "Patel", "Johnson", "Williams", "Miller"]
PHONES = ["1-800-555-0199", "888-234-9988", "555-0143-221", "800-991-8271"]
URLS = ["http://verify-bank-security.xyz", "http://claim-free-prize.top", "http://urgent-account-update.cc", "http://secure-login-portal.ru"]


def generate_ham() -> str:
    template = random.choice(HAM_TEMPLATES)
    return template.format(
        name=random.choice(NAMES),
        time=random.choice(TIMES),
        doctor=random.choice(DOCTORS),
        num=random.randint(1000, 99999),
        user=f"user_{random.randint(100, 999)}"
    )


def generate_spam() -> str:
    template = random.choice(SPAM_TEMPLATES)
    return template.format(
        name=random.choice(NAMES),
        amount=random.choice([500, 1000, 5000, 10000, 50000]),
        num=random.randint(100, 9999),
        url=random.choice(URLS),
        phone=random.choice(PHONES)
    )


def main():
    print("=" * 60)
    print("Generating representative dataset for SMS/Email Spam Detection...")
    print("=" * 60)

    texts = []
    labels = []

    # 1,000 Ham (0) and 1,000 Spam (1)
    for _ in range(1000):
        texts.append(generate_ham())
        labels.append(0)

    for _ in range(1000):
        texts.append(generate_spam())
        labels.append(1)

    print(f"Total samples synthesized: {len(texts)} (1,000 Ham, 1,000 Spam)")

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.20, random_state=42, stratify=labels
    )

    print(f"Training Pipeline (TfidfVectorizer + Calibrated LinearSVC) on {len(X_train)} samples...")

    base_svc = LinearSVC(random_state=42, max_iter=2000, C=1.0)
    calibrated_clf = CalibratedClassifierCV(estimator=base_svc, cv=3)

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=4000, stop_words="english")),
        ("clf", calibrated_clf),
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n--- Model Evaluation ---")
    print(f"Accuracy: {acc * 100:.2f}%")
    print(f"F1-Score: {f1:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["HAM", "SPAM"]))

    # Serialize pipeline artifact
    settings.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    artifact_path = settings.ARTIFACTS_DIR / "spam_pipeline.joblib"
    joblib.dump(pipeline, artifact_path)
    print(f"Artifact serialized successfully to: {artifact_path}")
    print(f"File size: {os.path.getsize(artifact_path)} bytes")


if __name__ == "__main__":
    main()
