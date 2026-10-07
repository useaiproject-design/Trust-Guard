import os
import json
import joblib
import pandas as pd


# ============================================================
# Paths
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

ML_READY_DIR = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "ml_ready"
)

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "severity_model.pkl"
)

FEATURE_FILE = os.path.join(
    ML_READY_DIR,
    "feature_names.json"
)

TARGET_FILE = os.path.join(
    ML_READY_DIR,
    "target_names.json"
)


# ============================================================
# Load model
# ============================================================

model = joblib.load(MODEL_FILE)

with open(
    FEATURE_FILE,
    "r",
    encoding="utf-8"
) as f:
    FEATURE_NAMES = json.load(f)

with open(
    TARGET_FILE,
    "r",
    encoding="utf-8"
) as f:
    TARGET_NAMES = json.load(f)


# ============================================================
# Prediction function
# ============================================================

def predict_vulnerabilities(features: dict) -> list:

    """
    Predict vulnerabilities from a feature dictionary.

    The input dictionary must contain the features used during
    model training.
    """

    # --------------------------------------------------------
    # Build dataframe with exact training feature order
    # --------------------------------------------------------

    row = {}

    for feature in FEATURE_NAMES:
        row[feature] = features.get(feature, 0)

    X = pd.DataFrame(
        [row],
        columns=FEATURE_NAMES
    )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    predictions = model.predict(X)[0]

    # --------------------------------------------------------
    # Probabilities
    # --------------------------------------------------------

    probabilities = []

    for estimator in model.estimators_:

        probability = estimator.predict_proba(X)

        if probability.shape[1] == 2:
            probabilities.append(
                float(probability[0][1])
            )
        else:
            probabilities.append(
                float(probability[0][0])
            )

    # --------------------------------------------------------
    # Build result
    # --------------------------------------------------------

    results = []

    for index, vulnerability in enumerate(TARGET_NAMES):

        probability = probabilities[index]

        results.append(
            {
                "id": vulnerability,
                "probability": round(
                    probability,
                    4
                ),
                "detected": bool(
                    predictions[index] == 1
                )
            }
        )

    return results


# ============================================================
# Test
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("TRUSTGUARD AI - PREDICTION ENGINE TEST")
    print("=" * 70)

    # Create a zero-filled feature vector
    test_features = {
        feature: 0
        for feature in FEATURE_NAMES
    }

    result = predict_vulnerabilities(
        test_features
    )

    for vulnerability in result:

        print(
            f"{vulnerability['id']}: "
            f"{vulnerability['probability']:.4f} "
            f"detected={vulnerability['detected']}"
        )

    print("\nPrediction engine: OK")