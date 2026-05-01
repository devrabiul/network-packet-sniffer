"""
ml_model.py — Machine Learning module for Network Packet Sniffer.
Handles synthetic data generation, model training, loading, and prediction.
"""

import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# ──────────────────────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────────────────────
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DATASET_PATH = os.path.join(DATA_DIR, "training_data.csv")
MODEL_PATH = os.path.join(DATA_DIR, "model.joblib")
ENCODER_PATH = os.path.join(DATA_DIR, "label_encoder.joblib")

# Protocol → numeric mapping (used at prediction time too)
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}


# ──────────────────────────────────────────────────────────────────────────────
# Training
# ──────────────────────────────────────────────────────────────────────────────
def train_model():
    """
    Loads the training dataset, preprocesses it, trains a RandomForestClassifier,
    and saves the model and label encoder via joblib.
    """
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Training data not found at: {DATASET_PATH}")

    print("[ML] Loading dataset …")
    df = pd.read_csv(DATASET_PATH)

    # Drop rows with missing values just in case
    df.dropna(inplace=True)

    # Encode protocol as integer
    df["protocol_enc"] = df["protocol"].str.upper().map(PROTOCOL_MAP).fillna(2).astype(int)

    # Feature matrix: only use numeric/encoded features
    X = df[["protocol_enc", "packet_size"]]
    y = df["label"]  # "Normal" / "Suspicious"

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("[ML] Training RandomForestClassifier …")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    # Print accuracy report
    y_pred = clf.predict(X_test)
    print("[ML] Classification Report:\n", classification_report(y_test, y_pred))

    # Persist model
    os.makedirs(DATA_DIR, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"[ML] Model saved to: {MODEL_PATH}")
    return clf


# ──────────────────────────────────────────────────────────────────────────────
# Loading
# ──────────────────────────────────────────────────────────────────────────────
def load_model():
    """
    Loads the trained model from disk. Trains a fresh one if model doesn't exist.
    Returns the classifier object.
    """
    if not os.path.exists(MODEL_PATH):
        print("[ML] No saved model found. Training now …")
        return train_model()

    print("[ML] Loading existing model …")
    clf = joblib.load(MODEL_PATH)
    return clf


# ──────────────────────────────────────────────────────────────────────────────
# Prediction
# ──────────────────────────────────────────────────────────────────────────────
def predict_packet(clf, packet) -> dict:
    """
    Predicts whether a packet is Normal or Suspicious.

    Args:
        clf: Trained RandomForestClassifier.
        packet: A models.Packet instance.

    Returns:
        dict with keys: 'prediction' ("Normal" / "Suspicious") and 'reason' (str)
    """
    protocol_enc = PROTOCOL_MAP.get(packet.protocol.upper(), 2)
    features = [[protocol_enc, packet.size]]

    prediction = clf.predict(features)[0]
    proba = clf.predict_proba(features)[0]
    confidence = round(max(proba) * 100, 1)

    # Build human-readable reason for tooltip
    reasons = []
    if packet.protocol.upper() == "ICMP" and packet.size > 1000:
        reasons.append("Large ICMP (possible ping flood)")
    elif packet.size > 1400:
        reasons.append(f"Large packet size ({packet.size} bytes)")
    elif packet.protocol.upper() == "ICMP":
        reasons.append("ICMP protocol detected")
    
    if not reasons:
        if prediction == "Suspicious":
            reasons.append("Pattern matches suspicious traffic")
        else:
            reasons.append("Normal traffic pattern")

    return {
        "prediction": prediction,
        "reason": f"{reasons[0]} (confidence: {confidence}%)"
    }


# ──────────────────────────────────────────────────────────────────────────────
# Standalone usage — train and save model
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    train_model()
    print("[ML] Done.")
