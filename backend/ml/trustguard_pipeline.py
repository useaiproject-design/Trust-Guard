import sys
import os
import pandas as pd
from typing import Dict, Any, List


# ============================================================
# TRUSTGUARD AI - COMPLETE SECURITY PIPELINE
# ============================================================

BACKEND_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)


# ============================================================
# TRUSTGUARD COMPONENTS
# ============================================================

from security.vulnerability_detector import (
    detect_vulnerabilities
)

from ml.feature_engineering import (
    extract_features
)

from ml.predictor import (
    predict_vulnerabilities,
    FEATURE_NAMES
)

from ml.shap_explainer import (
    explain_prediction as shap_explain_prediction
)

from ml.lime_explainer import (
    explain_prediction as lime_explain_prediction
)

from ml.severity_engine import (
    analyze_severity
)

from security.prioritizer import (
    prioritize_vulnerabilities
)

from remediation.repair_suggester import (
    generate_repair_suggestions
)

from readiness.deployment_assessor import (
    assess_deployment_readiness,
    print_readiness_report
)


# ============================================================
# STATIC VULNERABILITY PROFILES
# ============================================================

STATIC_VULNERABILITY_PROFILES = {

    "MINT_CAPABILITY": {
        "name": "Mint Capability",
        "impact": 5,
        "exploitability": 4
    },

    "PAUSE_CAPABILITY": {
        "name": "Pause Capability",
        "impact": 3,
        "exploitability": 3
    },

    "FEE_CHANGE_CAPABILITY": {
        "name": "Fee Change Capability",
        "impact": 4,
        "exploitability": 3
    },

    "EXTERNAL_CALL_PATTERN": {
        "name": "External Call Pattern",
        "impact": 4,
        "exploitability": 4
    }
}


# ============================================================
# NORMALIZE STATIC FINDING
# ============================================================

def normalize_static_finding(
    finding: Dict
) -> Dict:

    vulnerability_id = finding.get(
        "id",
        "UNKNOWN"
    )

    profile = STATIC_VULNERABILITY_PROFILES.get(
        vulnerability_id,
        {
            "name": finding.get(
                "title",
                vulnerability_id
            ),
            "impact": 3,
            "exploitability": 3
        }
    )

    severity = finding.get(
        "severity",
        "MEDIUM"
    )

    severity_weight = {
        "CRITICAL": 100,
        "HIGH": 80,
        "MEDIUM": 60,
        "LOW": 40,
        "INFO": 20
    }

    return {
        "source": "STATIC_ANALYZER",

        "vulnerability":
            vulnerability_id,

        "name":
            profile["name"],

        "probability":
            1.0,

        "severity":
            severity,

        "severity_score":
            severity_weight.get(
                severity,
                60
            ),

        "impact":
            profile["impact"],

        "exploitability":
            profile["exploitability"],

        "detected":
            True,

        "description":
            finding.get(
                "description",
                ""
            ),

        "recommendation":
            finding.get(
                "recommendation",
                ""
            )
    }


# ============================================================
# NORMALIZE ML FINDING
# ============================================================

def normalize_ml_finding(
    prediction: Dict
) -> Dict:

    vulnerability = prediction.get(
        "id"
    )

    probability = float(
        prediction.get(
            "probability",
            0
        )
    )

    detected = bool(
        prediction.get(
            "detected",
            False
        )
    )

    return {
        "source": "ML_MODEL",

        "vulnerability":
            vulnerability,

        "name":
            vulnerability,

        "probability":
            probability,

        "detected":
            detected
    }


# ============================================================
# BUILD MODEL INPUT
# ============================================================

def build_model_dataframe(
    features: Dict
) -> pd.DataFrame:

    """
    Convert live feature dictionary into the exact
    feature matrix expected by the trained model.
    """

    row = {}

    for feature in FEATURE_NAMES:

        row[feature] = features.get(
            feature,
            0
        )

    return pd.DataFrame(
        [row],
        columns=FEATURE_NAMES
    )


# ============================================================
# GENERATE SHAP + LIME EXPLANATIONS
# ============================================================

def generate_explanations(
    model_input: pd.DataFrame,
    predictions: List[Dict],
    top_n: int = 5
) -> Dict:

    shap_results = {}
    lime_results = {}

    for index, prediction in enumerate(
        predictions
    ):

        vulnerability = prediction[
            "id"
        ]

        # ----------------------------------------------------
        # SHAP
        # ----------------------------------------------------

        try:

            shap_results[
                vulnerability
            ] = shap_explain_prediction(
                model_input,
                target_index=index,
                top_n=top_n
            )

        except Exception as error:

            shap_results[
                vulnerability
            ] = {
                "error":
                    str(error)
            }

        # ----------------------------------------------------
        # LIME
        # ----------------------------------------------------

        try:

            lime_results[
                vulnerability
            ] = lime_explain_prediction(
                model_input,
                target_index=index,
                num_features=top_n
            )

        except Exception as error:

            lime_results[
                vulnerability
            ] = {
                "error":
                    str(error)
            }

    return {
        "shap": shap_results,
        "lime": lime_results
    }


# ============================================================
# MAIN TRUSTGUARD PIPELINE
# ============================================================

def run_trustguard_pipeline(
    source_code: str,
    onchain_data: Dict | None = None,
    include_explanations: bool = True,
    explanation_top_n: int = 5
) -> Dict[str, Any]:

    if source_code is None:

        source_code = ""

    if onchain_data is None:

        onchain_data = {}

    # ========================================================
    # STEP 1 - STATIC VULNERABILITY DETECTION
    # ========================================================

    static_vulnerabilities = (
        detect_vulnerabilities(
            source_code
        )
    )

    # ========================================================
    # STEP 2 - FEATURE ENGINEERING
    # ========================================================

    features = extract_features(
        source_code=source_code,
        vulnerabilities=static_vulnerabilities,
        onchain_data=onchain_data
    )

    # ========================================================
    # STEP 3 - BUILD MODEL INPUT
    # ========================================================

    model_input = build_model_dataframe(
        features
    )

    # ========================================================
    # STEP 4 - ML PREDICTIONS
    # ========================================================

    ml_predictions = predict_vulnerabilities(
        features
    )

    # ========================================================
    # STEP 5 - SHAP + LIME
    # ========================================================

    explanations = {
        "shap": {},
        "lime": {}
    }

    if include_explanations:

        explanations = generate_explanations(
            model_input,
            ml_predictions,
            top_n=explanation_top_n
        )

    # ========================================================
    # STEP 6 - NORMALIZE STATIC FINDINGS
    # ========================================================

    unified_findings = []

    for finding in static_vulnerabilities:

        unified_findings.append(
            normalize_static_finding(
                finding
            )
        )

    # ========================================================
    # STEP 7 - NORMALIZE DETECTED ML FINDINGS
    # ========================================================

    detected_ml_findings = []

    for prediction in ml_predictions:

        normalized = normalize_ml_finding(
            prediction
        )

        if normalized[
            "detected"
        ]:

            detected_ml_findings.append(
                normalized
            )

    # ========================================================
    # STEP 8 - INTELLIGENT SEVERITY
    # ========================================================

    for finding in detected_ml_findings:

        try:

            severity_result = analyze_severity(
                vulnerability=
                    finding[
                        "vulnerability"
                    ],

                probability=
                    finding[
                        "probability"
                    ],

                evidence_strength=0.5,

                onchain_risk=0.0
            )

            finding.update(
                severity_result
            )

        except TypeError:

            # Compatibility fallback if the severity
            # engine uses a different function signature.

            pass

    # ========================================================
    # STEP 9 - ADD ML FINDINGS
    # ========================================================

    unified_findings.extend(
        detected_ml_findings
    )

    # ========================================================
    # STEP 10 - PRIORITIZATION
    # ========================================================

    priority_input = []

    for finding in unified_findings:

        priority_input.append(
            {
                "vulnerability":
                    finding[
                        "name"
                    ],

                "probability":
                    finding[
                        "probability"
                    ],

                "severity":
                    finding[
                        "severity"
                    ],

                "severity_score":
                    finding[
                        "severity_score"
                    ],

                "impact":
                    finding[
                        "impact"
                    ],

                "exploitability":
                    finding[
                        "exploitability"
                    ],

                "detected":
                    True
            }
        )

    prioritized = prioritize_vulnerabilities(
        priority_input
    )

    # ========================================================
    # STEP 11 - REPAIR SUGGESTIONS
    # ========================================================

    repair_suggestions = (
        generate_repair_suggestions(
            prioritized
        )
    )

    # ========================================================
    # STEP 12 - DEPLOYMENT READINESS
    # ========================================================

    deployment_readiness = (
        assess_deployment_readiness(
            prioritized
        )
    )

    # ========================================================
    # STEP 13 - FINAL RESULT
    # ========================================================

    return {

        "static_vulnerabilities":
            static_vulnerabilities,

        "features":
            features,

        "ml_predictions":
            ml_predictions,

        "explanations":
            explanations,

        "unified_findings":
            unified_findings,

        "prioritized_vulnerabilities":
            prioritized,

        "repair_suggestions":
            repair_suggestions,

        "deployment_readiness":
            deployment_readiness
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 70)

    print(
        "TRUSTGUARD AI - COMPLETE PIPELINE TEST"
    )

    print("=" * 70)

    test_code = """
    pragma solidity ^0.8.20;

    contract Test {

        uint256 public balance;

        function mint(
            address to,
            uint256 amount
        ) public {

            balance += amount;
        }

        function pause()
            public
        {
        }

        function setFee(
            uint256 fee
        ) public
        {
        }

        function withdraw(
            uint256 amount
        ) public
        {
            require(
                amount <= balance,
                "Insufficient balance"
            );

            (bool success, ) =
                msg.sender.call{value: amount}("");

            require(
                success,
                "Transfer failed"
            );

            balance -= amount;
        }
    }
    """

    print(
        "\nRunning TrustGuard AI pipeline..."
    )

    result = run_trustguard_pipeline(
        source_code=test_code,
        include_explanations=True,
        explanation_top_n=5
    )

    # ========================================================
    # STATIC FINDINGS
    # ========================================================

    print(
        "\nSTATIC VULNERABILITIES"
    )

    print("-" * 70)

    for finding in result[
        "static_vulnerabilities"
    ]:

        print(
            f"{finding['id']} "
            f"→ "
            f"{finding['severity']}"
        )

    # ========================================================
    # ML PREDICTIONS
    # ========================================================

    print(
        "\nML PREDICTIONS"
    )

    print("-" * 70)

    for prediction in result[
        "ml_predictions"
    ]:

        print(
            f"{prediction['id']}: "
            f"{prediction['probability']:.2%} "
            f"detected="
            f"{prediction['detected']}"
        )

    # ========================================================
    # SHAP
    # ========================================================

    print(
        "\nSHAP EXPLANATIONS"
    )

    print("-" * 70)

    for vulnerability, explanation in result[
        "explanations"
    ][
        "shap"
    ].items():

        print(
            f"\n{vulnerability}"
        )

        if isinstance(
            explanation,
            dict
        ) and "error" in explanation:

            print(
                f"  SHAP error: "
                f"{explanation['error']}"
            )

            continue

        for item in explanation:

            print(
                f"  {item['feature']}: "
                f"{item['contribution']:+.6f}"
            )

    # ========================================================
    # LIME
    # ========================================================

    print(
        "\nLIME EXPLANATIONS"
    )

    print("-" * 70)

    for vulnerability, explanation in result[
        "explanations"
    ][
        "lime"
    ].items():

        print(
            f"\n{vulnerability}"
        )

        if isinstance(
            explanation,
            dict
        ) and "error" in explanation:

            print(
                f"  LIME error: "
                f"{explanation['error']}"
            )

            continue

        for item in explanation:

            print(
                f"  {item['feature']}: "
                f"{item['contribution']:+.6f}"
            )

    # ========================================================
    # UNIFIED FINDINGS
    # ========================================================

    print(
        "\nUNIFIED FINDINGS"
    )

    print("-" * 70)

    for finding in result[
        "unified_findings"
    ]:

        print(
            f"{finding['name']} "
            f"| Source: "
            f"{finding['source']} "
            f"| Severity: "
            f"{finding['severity']}"
        )

    # ========================================================
    # PRIORITIZATION
    # ========================================================

    print(
        "\nPRIORITIZED VULNERABILITIES"
    )

    print("-" * 70)

    for finding in result[
        "prioritized_vulnerabilities"
    ]:

        print(
            f"Priority "
            f"{finding['priority']}: "
            f"{finding['vulnerability']} "
            f"| "
            f"{finding['severity']} "
            f"| Score "
            f"{finding['priority_score']}"
        )

    # ========================================================
    # REPAIR SUGGESTIONS
    # ========================================================

    print(
        "\nREPAIR SUGGESTIONS"
    )

    print("-" * 70)

    for suggestion in result[
        "repair_suggestions"
    ]:

        print(
            f"Priority "
            f"{suggestion.get('priority')}: "
            f"{suggestion['vulnerability']}"
        )

        print(
            f"→ "
            f"{suggestion['recommendation']}"
        )

    # ========================================================
    # DEPLOYMENT READINESS
    # ========================================================

    print(
        "\nDEPLOYMENT READINESS"
    )

    print("-" * 70)

    readiness = result[
        "deployment_readiness"
    ]

    print(
        f"Status          : "
        f"{readiness['status']}"
    )

    print(
        f"Readiness Score : "
        f"{readiness['readiness_score']:.1f}/100"
    )

    print(
        f"Risk Level      : "
        f"{readiness['risk_level']}"
    )

    counts = readiness[
        "vulnerability_counts"
    ]

    print(
        f"Critical        : "
        f"{counts['CRITICAL']}"
    )

    print(
        f"High            : "
        f"{counts['HIGH']}"
    )

    print(
        f"Medium          : "
        f"{counts['MEDIUM']}"
    )

    print(
        f"Low             : "
        f"{counts['LOW']}"
    )

    print(
        "\nBlocking Issues:"
    )

    if not readiness[
        "blocking_issues"
    ]:

        print(
            "None"
        )

    else:

        for issue in readiness[
            "blocking_issues"
        ]:

            print(
                f"→ "
                f"{issue['vulnerability']} "
                f"| "
                f"{issue['severity']}"
            )

    print(
        "\nRecommendations:"
    )

    for recommendation in readiness[
        "recommendations"
    ]:

        print(
            f"→ "
            f"{recommendation}"
        )

    print(
        "\n" + "=" * 70
    )

    print(
        "TRUSTGUARD AI COMPLETE PIPELINE TEST COMPLETE"
    )

    print(
        "=" * 70
    )