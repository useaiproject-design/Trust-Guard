import os
import json
import joblib
import pandas as pd

from lime.lime_tabular import LimeTabularExplainer


# ============================================================
# Paths
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

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

X_TRAIN_FILE = os.path.join(
    ML_READY_DIR,
    "X_train.csv"
)

X_TEST_FILE = os.path.join(
    ML_READY_DIR,
    "X_test.csv"
)

TARGET_FILE = os.path.join(
    ML_READY_DIR,
    "target_names.json"
)


# ============================================================
# Load resources
# ============================================================

model = joblib.load(
    MODEL_FILE
)

X_train = pd.read_csv(
    X_TRAIN_FILE
)

X_test = pd.read_csv(
    X_TEST_FILE
)

with open(
    TARGET_FILE,
    "r",
    encoding="utf-8"
) as f:

    TARGET_NAMES = json.load(f)


FEATURE_NAMES = list(
    X_train.columns
)


# ============================================================
# Create reusable LIME explainer
# ============================================================

explainer = LimeTabularExplainer(
    training_data=X_train.values,
    feature_names=FEATURE_NAMES,
    class_names=[
        "Not Vulnerable",
        "Vulnerable"
    ],
    mode="classification",

    # IMPORTANT:
    # Avoid expensive forward selection.
    # Use the highest-weight features directly.
    feature_selection="highest_weights",

    discretize_continuous=True,
    random_state=42
)


# ============================================================
# Prediction function for LIME
# ============================================================

def make_probability_function(
    target_index
):

    def predict_fn(data):

        dataframe = pd.DataFrame(
            data,
            columns=FEATURE_NAMES
        )

        estimator = model.estimators_[
            target_index
        ]

        return estimator.predict_proba(
            dataframe
        )

    return predict_fn


# ============================================================
# LIME explanation
# ============================================================

def explain_prediction(
    sample,
    target_index=0,
    num_features=10
):

    """
    Generate a local LIME explanation
    for one vulnerability.

    Performance design:
    - Reuses one LIME explainer
    - Uses highest_weights feature selection
    - Uses 1000 neighborhood samples
    - Uses the real trained model
    - Preserves local feature contributions
    """

    if target_index < 0 or target_index >= len(
        TARGET_NAMES
    ):
        raise ValueError(
            "Invalid target index."
        )

    predict_fn = make_probability_function(
        target_index
    )

    explanation = explainer.explain_instance(
        sample.values[0],
        predict_fn,
        num_features=num_features,
        num_samples=1000,
        model_regressor=None
    )

    results = []

    for feature, contribution in explanation.as_list():

        results.append(
            {
                "feature": feature,
                "contribution": float(
                    contribution
                )
            }
        )

    return results


# ============================================================
# Test
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print(
        "TRUSTGUARD AI - LIME EXPLAINABILITY TEST"
    )
    print("=" * 70)

    sample = X_test.iloc[[0]]

    print(
        f"\nSample shape: {sample.shape}"
    )

    print(
        "\nGenerating LIME explanation..."
    )

    result = explain_prediction(
        sample,
        target_index=0,
        num_features=6
    )

    print(
        "\nLIME explanation:"
    )

    for item in result:

        print(
            f"  {item['feature']}: "
            f"{item['contribution']:.4f}"
        )

    print(
        "\nLIME TEST: PASS"
    )