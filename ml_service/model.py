import joblib
import os
import numpy as np
import pandas as pd
from typing import Any

from feature_extractor import extract_features, get_feature_columns

# ─────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH   = os.path.join(BASE_DIR, "saved_models", "threat_model.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "saved_models", "label_encoder.pkl")


# ─────────────────────────────────────────────
# Model wrapper
# ─────────────────────────────────────────────

class ThreatModel:
    """
    Loads the trained RandomForest model and label encoder.
    Exposes a single predict() method used by api.py.
    """

    def __init__(self):
        self._model   = None
        self._encoder = None
        self._loaded  = False

    def load(self):
        """Load model and encoder from disk. Called once at API startup."""
        if self._loaded:
            return

        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. "
                f"Run train.py first."
            )
        if not os.path.exists(ENCODER_PATH):
            raise FileNotFoundError(
                f"Encoder not found at {ENCODER_PATH}. "
                f"Run train.py first."
            )

        self._model   = joblib.load(MODEL_PATH)
        self._encoder = joblib.load(ENCODER_PATH)
        self._loaded  = True
        print("✅ Model loaded successfully")

    def predict(self, raw_finding: dict[str, Any]) -> dict[str, Any]:
        """
        Takes a raw scanner finding dict and returns prediction.

        Input:
        {
            "payload":              str,
            "response_time":        int,
            "status_code":          int,
            "payload_reflected":    bool,
            "error_detected":       bool,
            "response_length_diff": int
        }

        Output:
        {
            "prediction":    str,    e.g. "XSS"
            "confidence":    float,  e.g. 0.88
            "is_vulnerable": bool
        }
        """
        if not self._loaded:
            self.load()

        # Extract features
        features = extract_features(raw_finding)

        # Build DataFrame with correct column order
        X = pd.DataFrame([features], columns=get_feature_columns())

        # Get predicted class + probability
        predicted_index     = self._model.predict(X)[0]
        predicted_label     = self._encoder.inverse_transform([predicted_index])[0]
        probabilities       = self._model.predict_proba(X)[0]
        confidence          = float(np.max(probabilities))

        is_vulnerable = predicted_label != "Clean"

        return {
            "prediction":    predicted_label,
            "confidence":    round(confidence, 4),
            "is_vulnerable": is_vulnerable,
        }


# ─────────────────────────────────────────────
# Singleton — api.py imports this instance
# ─────────────────────────────────────────────

threat_model = ThreatModel()


# ─────────────────────────────────────────────
# Quick test — run directly to verify
# ─────────────────────────────────────────────

if __name__ == "__main__":
    threat_model.load()

    test_cases = [
        {
            "name": "XSS",
            "finding": {
                "payload": "<script>alert(1)</script>",
                "response_time": 180,
                "status_code": 200,
                "payload_reflected": True,
                "error_detected": False,
                "response_length_diff": 120,
            }
        },
        {
            "name": "SQLi",
            "finding": {
                "payload": "' OR 1=1 --",
                "response_time": 450,
                "status_code": 500,
                "payload_reflected": False,
                "error_detected": True,
                "response_length_diff": 340,
            }
        },
        {
            "name": "Open Redirect",
            "finding": {
                "payload": "?next=http://evil.com",
                "response_time": 110,
                "status_code": 302,
                "payload_reflected": False,
                "error_detected": False,
                "response_length_diff": 50,
            }
        },
        {
            "name": "CSRF",
            "finding": {
                "payload": "<form method=POST action=/api/change-email>",
                "response_time": 150,
                "status_code": 200,
                "payload_reflected": False,
                "error_detected": False,
                "response_length_diff": 30,
            }
        },
        {
            "name": "Clean",
            "finding": {
                "payload": "search=laptop&page=1",
                "response_time": 90,
                "status_code": 200,
                "payload_reflected": False,
                "error_detected": False,
                "response_length_diff": 20,
            }
        },
    ]

    print("=" * 55)
    print("ThreatModel — Prediction Test")
    print("=" * 55)

    all_passed = True
    for case in test_cases:
        result = threat_model.predict(case["finding"])
        status = "✅" if result["prediction"] == case["name"] else "❌"
        if result["prediction"] != case["name"]:
            all_passed = False
        print(f"\n{status} [{case['name']}]")
        print(f"   prediction    : {result['prediction']}")
        print(f"   confidence    : {result['confidence']}")
        print(f"   is_vulnerable : {result['is_vulnerable']}")

    print("\n" + "=" * 55)
    print("All tests passed ✅" if all_passed else "Some tests failed ❌ — check model")