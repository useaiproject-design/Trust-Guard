import os
import json
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    average_precision_score
)


# ============================================================
# Paths
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ML_READY_DIR = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "ml_ready"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

os.makedirs(MODEL_DIR, exist_ok=True)


# ============================================================
# Files
# ============================================================

X_TRAIN_FILE = os.path.join(
    ML_READY_DIR,
    "X_train.csv"
)

X_TEST_FILE = os.path.join(
    ML_READY_DIR,
    "X_test.csv"
)

Y_TRAIN_FILE = os.path.join(
    ML_READY_DIR,
    "y_train.csv"
)

Y_TEST_FILE = os.path.join(
    ML_READY_DIR,
    "y_test.csv"
)

TARGET_FILE = os.path.join(
    ML_READY_DIR,
    "target_names.json"
)

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "severity_model.pkl"
)

METRICS_FILE = os.path.join(
    MODEL_DIR,
    "severity_metrics.json"
)


# ============================================================
# Training
# ============================================================

def train_model():

    print("=" * 70)
    print("TRUSTGUARD AI - VULNERABILITY MODEL TRAINING")
    print("=" * 70)

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------

    print("\nLoading training data...")

    X_train = pd.read_csv(
        X_TRAIN_FILE
    )

    X_test = pd.read_csv(
        X_TEST_FILE
    )

    y_train = pd.read_csv(
        Y_TRAIN_FILE
    )

    y_test = pd.read_csv(
        Y_TEST_FILE
    )

    print(f"X_train: {X_train.shape}")
    print(f"X_test : {X_test.shape}")
    print(f"y_train: {y_train.shape}")
    print(f"y_test : {y_test.shape}")

    # --------------------------------------------------------
    # Load target names
    # --------------------------------------------------------

    with open(
        TARGET_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        target_names = json.load(f)

    print("\nTargets:")

    for target in target_names:
        print(f"  - {target}")

    # --------------------------------------------------------
    # Build model
    # --------------------------------------------------------

    print("\nCreating Random Forest model...")

    base_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42
    )

    model = MultiOutputClassifier(
        base_model,
        n_jobs=-1
    )

    # --------------------------------------------------------
    # Train
    # --------------------------------------------------------

    print("\nTraining model...")
    print("This may take some time...")

    model.fit(
        X_train,
        y_train
    )

    print("Training complete.")

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    print("\nGenerating predictions...")

    y_pred = model.predict(
        X_test
    )

    # --------------------------------------------------------
    # Probability predictions
    # --------------------------------------------------------

    print("Generating probability predictions...")

    probability_predictions = []

    for estimator in model.estimators_:

        probabilities = estimator.predict_proba(
            X_test
        )

        # RandomForest normally provides both classes.
        # Select probability for class 1.
        if probabilities.shape[1] == 2:
            probability_predictions.append(
                probabilities[:, 1]
            )
        else:
            probability_predictions.append(
                probabilities[:, 0]
            )

    y_prob = pd.DataFrame(
        dict(
            zip(
                target_names,
                probability_predictions
            )
        )
    )

    # --------------------------------------------------------
    # Evaluation
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)

    metrics = {}

    for index, target in enumerate(target_names):

        y_true = y_test.iloc[:, index]
        y_prediction = y_pred[:, index]
        y_probability = y_prob[target]

        precision = precision_score(
            y_true,
            y_prediction,
            zero_division=0
        )

        recall = recall_score(
            y_true,
            y_prediction,
            zero_division=0
        )

        f1 = f1_score(
            y_true,
            y_prediction,
            zero_division=0
        )

        try:

            roc_auc = roc_auc_score(
                y_true,
                y_probability
            )

        except ValueError:

            roc_auc = None

        try:

            pr_auc = average_precision_score(
                y_true,
                y_probability
            )

        except ValueError:

            pr_auc = None

        metrics[target] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc
        }

        print(f"\n{target}")
        print(f"  Precision : {precision:.4f}")
        print(f"  Recall    : {recall:.4f}")
        print(f"  F1        : {f1:.4f}")

        if roc_auc is not None:
            print(f"  ROC-AUC   : {roc_auc:.4f}")

        if pr_auc is not None:
            print(f"  PR-AUC    : {pr_auc:.4f}")

    # --------------------------------------------------------
    # Overall metrics
    # --------------------------------------------------------

    overall_f1 = f1_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )

    overall_precision = precision_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )

    overall_recall = recall_score(
        y_test,
        y_pred,
        average="macro",
        zero_division=0
    )

    metrics["overall"] = {
        "macro_precision": overall_precision,
        "macro_recall": overall_recall,
        "macro_f1": overall_f1
    }

    print("\n" + "-" * 70)

    print(
        f"Macro Precision: {overall_precision:.4f}"
    )

    print(
        f"Macro Recall   : {overall_recall:.4f}"
    )

    print(
        f"Macro F1       : {overall_f1:.4f}"
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    print("\nSaving trained model...")

    joblib.dump(
        model,
        MODEL_FILE
    )

    # --------------------------------------------------------
    # Save metrics
    # --------------------------------------------------------

    with open(
        METRICS_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            metrics,
            f,
            indent=2
        )

    # --------------------------------------------------------
    # Save probability predictions
    # --------------------------------------------------------

    probability_file = os.path.join(
        MODEL_DIR,
        "test_probability_predictions.csv"
    )

    y_prob.to_csv(
        probability_file,
        index=False
    )

    print("\nModel saved to:")
    print(MODEL_FILE)

    print("\nMetrics saved to:")
    print(METRICS_FILE)

    print("\nProbability predictions saved to:")
    print(probability_file)

    print("\n" + "=" * 70)
    print("MODEL TRAINING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    train_model()