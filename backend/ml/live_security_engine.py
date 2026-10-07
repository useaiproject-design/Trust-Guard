"""
TrustGuard AI - Live Security Intelligence Engine

This module connects the existing TrustGuard AI ML/XAI components
into a reusable analysis engine.

It does NOT replace the existing analyzer.
It only consumes:
    - Solidity source code
    - On-chain data
    - Existing ML prediction engine
    - Existing SHAP/LIME explainers
    - Existing severity engine
    - Existing prioritization engine
    - Existing remediation engine
    - Existing deployment readiness engine
"""

from typing import Any, Dict, List

from backend.ml.feature_engineering import (
    extract_features,
)
from backend.ml.trustguard_pipeline import (
    build_model_dataframe,
)
from backend.ml.predictor import (
    predict_vulnerabilities,
    TARGET_NAMES,
)

from backend.ml.shap_explainer import (
    explain_prediction as shap_explain_prediction,
)

from backend.ml.lime_explainer import (
    explain_prediction as lime_explain_prediction,
)

from backend.ml.severity_engine import (
    analyze_severity,
)

from backend.security.prioritizer import (
    prioritize_vulnerabilities,
)

from backend.remediation.repair_suggester import (
    generate_repair_suggestions,
)

from backend.readiness.deployment_assessor import (
    assess_deployment_readiness,
)


# ============================================================
# Configuration
# ============================================================

DEFAULT_EXPLANATION_COUNT = 3
DEFAULT_EXPLANATION_FEATURES = 6


# ============================================================
# Safe helpers
# ============================================================

def _safe_float(value: Any, default: float = 0.0) -> float:
    """
    Safely convert a value to float.
    """

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_probability(value: Any) -> float:
    """
    Keep probability inside the valid 0-1 range.
    """

    probability = _safe_float(value, 0.0)

    return max(
        0.0,
        min(
            probability,
            1.0
        )
    )


def _normalize_prediction(prediction: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize one ML prediction into a consistent structure.
    """

    vulnerability_id = (
        prediction.get("id")
        or prediction.get("vulnerability")
        or prediction.get("name")
        or "Unknown"
    )

    probability = _safe_probability(
        prediction.get(
            "probability",
            prediction.get(
                "confidence",
                0.0
            )
        )
    )

    detected = bool(
        prediction.get(
            "detected",
            probability >= 0.50
        )
    )

    return {
        "id": vulnerability_id,
        "vulnerability": vulnerability_id,
        "probability": probability,
        "detected": detected,
        "source": "ML_MODEL",
    }


# ============================================================
# ML prediction normalization
# ============================================================

def _normalize_predictions(
    predictions: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Normalize all ML predictions.
    """

    normalized = []

    for prediction in predictions or []:

        if not isinstance(
            prediction,
            dict
        ):
            continue

        normalized.append(
            _normalize_prediction(
                prediction
            )
        )

    return normalized


# ============================================================
# SHAP + LIME
# ============================================================

def _generate_explanations(
    model_input,
    predictions: List[Dict[str, Any]],
    top_vulnerabilities: int = DEFAULT_EXPLANATION_COUNT,
    top_features: int = DEFAULT_EXPLANATION_FEATURES,
) -> Dict[str, Any]:
    """
    Generate SHAP and LIME explanations for the
    highest-probability ML predictions.

    The vulnerability name is mapped to the
    actual target index used by the trained model.
    """

    sorted_predictions = sorted(
        predictions,
        key=lambda item: item.get(
            "probability",
            0.0
        ),
        reverse=True
    )

    selected_predictions = (
        sorted_predictions[
            :top_vulnerabilities
        ]
    )

    shap_results = {}
    lime_results = {}

    # --------------------------------------------------------
    # Map vulnerability name to actual trained-model index
    # --------------------------------------------------------

    target_index_map = {
        vulnerability: index
        for index, vulnerability
        in enumerate(TARGET_NAMES)
    }

    # --------------------------------------------------------
    # Generate explanations
    # --------------------------------------------------------

    for prediction in selected_predictions:

        vulnerability = prediction.get(
            "id",
            "Unknown"
        )

        # ----------------------------------------------------
        # Find actual target index
        # ----------------------------------------------------

        target_index = target_index_map.get(
            vulnerability
        )

        if target_index is None:

            shap_results[
                vulnerability
            ] = {
                "error":
                    "Vulnerability target is not "
                    "present in the trained model."
            }

            lime_results[
                vulnerability
            ] = {
                "error":
                    "Vulnerability target is not "
                    "present in the trained model."
            }

            continue

        # ----------------------------------------------------
        # SHAP
        # ----------------------------------------------------

        try:

            shap_results[
                vulnerability
            ] = shap_explain_prediction(
                model_input,
                target_index=target_index,
                top_n=top_features
            )

        except Exception as error:

            shap_results[
                vulnerability
            ] = {
                "error": str(error)
            }

        # ----------------------------------------------------
        # LIME
        # ----------------------------------------------------

        try:

            lime_results[
                vulnerability
            ] = lime_explain_prediction(
                model_input,
                target_index=target_index,
                num_features=top_features
            )

        except Exception as error:

            lime_results[
                vulnerability
            ] = {
                "error": str(error)
            }

    return {
        "shap": shap_results,
        "lime": lime_results,
    }

# ============================================================
# ML Severity
# ============================================================

def _apply_ml_severity(
    predictions: List[Dict[str, Any]],
    onchain_risk: float = 0.0,
) -> List[Dict[str, Any]]:
    """
    Apply the existing intelligent severity engine
    to detected ML vulnerabilities.
    """

    findings = []

    for prediction in predictions:

        if not prediction.get(
            "detected",
            False
        ):
            continue

        vulnerability = prediction.get(
            "vulnerability",
            "Unknown"
        )

        probability = prediction.get(
            "probability",
            0.0
        )

        finding = {
            "vulnerability": vulnerability,
            "probability": probability,
            "detected": True,
            "source": "ML_MODEL",
        }

        try:

            severity_result = analyze_severity(
                vulnerability=vulnerability,
                probability=probability,
                evidence_strength=0.5,
                onchain_risk=onchain_risk,
            )

            finding.update(
                severity_result
            )

        except TypeError:

            # Compatibility fallback for older
            # versions of the severity engine.

            try:

                severity_result = analyze_severity(
                    vulnerability,
                    probability,
                    0.5,
                    onchain_risk,
                )

                if isinstance(
                    severity_result,
                    dict
                ):
                    finding.update(
                        severity_result
                    )

            except Exception:

                finding.update(
                    {
                        "severity": "MEDIUM",
                        "severity_score": (
                            probability * 100
                        ),
                        "impact": 3,
                        "exploitability": 3,
                    }
                )

        except Exception:

            finding.update(
                {
                    "severity": "MEDIUM",
                    "severity_score": (
                        probability * 100
                    ),
                    "impact": 3,
                    "exploitability": 3,
                }
            )

        findings.append(
            finding
        )

    return findings


# ============================================================
# Priority preparation
# ============================================================

def _prepare_priority_input(
    findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Convert unified findings into the format expected
    by the existing prioritization engine.
    """

    priority_input = []

    for finding in findings:

        priority_input.append(
            {
                "vulnerability":
                    finding.get(
                        "vulnerability",
                        "Unknown"
                    ),

                "probability":
                    finding.get(
                        "probability",
                        0.0
                    ),

                "severity":
                    finding.get(
                        "severity",
                        "MEDIUM"
                    ),

                "severity_score":
                    finding.get(
                        "severity_score",
                        50.0
                    ),

                "impact":
                    finding.get(
                        "impact",
                        3
                    ),

                "exploitability":
                    finding.get(
                        "exploitability",
                        3
                    ),

                "detected": True,

                "source":
                    finding.get(
                        "source",
                        "UNKNOWN"
                    ),
            }
        )

    return priority_input


# ============================================================
# Main Live Intelligence Engine
# ============================================================

def analyze_live_security(
    source_code: str,
    onchain_data: Dict[str, Any] | None = None,
    static_findings: List[Dict[str, Any]] | None = None,
    all_flags: Dict[str, Any] | None = None,
    include_explanations: bool = True,
    explanation_count: int = DEFAULT_EXPLANATION_COUNT,
    explanation_features: int = DEFAULT_EXPLANATION_FEATURES,
) -> Dict[str, Any]:
    """
    Run the complete live security intelligence pipeline.

    Existing components are reused rather than rewritten.

    Pipeline:

        Source Code
             ↓
        Feature Engineering
             ↓
        ML Prediction
             ↓
        SHAP + LIME
             ↓
        Severity
             ↓
        Unified Findings
             ↓
        Prioritization
             ↓
        Remediation
             ↓
        Deployment Readiness
    """

    if source_code is None:

        source_code = ""

    if onchain_data is None:

        onchain_data = {}

    if static_findings is None:

        static_findings = []

    if all_flags is None:

        all_flags = {}

    # ========================================================
    # STEP 1 - Feature Engineering
    # ========================================================

    try:

        features = extract_features(
            source_code=source_code,
            vulnerabilities=static_findings,
            onchain_data=onchain_data,
        )

    except Exception as error:

        return {
            "success": False,
            "error_stage": "FEATURE_ENGINEERING",
            "error": str(error),
            "static_findings": static_findings,
        }

    # ========================================================
    # STEP 2 - Build ML Model Input
    # ========================================================

    try:

        model_input = build_model_dataframe(
            features
        )

    except Exception as error:

        return {
            "success": False,
            "error_stage": "MODEL_INPUT",
            "error": str(error),
            "features": features,
            "static_findings": static_findings,
        }

    # ========================================================
    # STEP 3 - ML Predictions
    # ========================================================

    try:

        raw_predictions = predict_vulnerabilities(
            features
        )

    except Exception as error:

        return {
            "success": False,
            "error_stage": "ML_PREDICTION",
            "error": str(error),
            "features": features,
            "static_findings": static_findings,
        }

    predictions = _normalize_predictions(
        raw_predictions
    )

    # ========================================================
    # STEP 4 - SHAP + LIME
    # ========================================================

    explanations = {
        "shap": {},
        "lime": {},
    }

    if include_explanations:

        explanations = _generate_explanations(
            model_input=model_input,
            predictions=predictions,
            top_vulnerabilities=(
                explanation_count
            ),
            top_features=(
                explanation_features
            ),
        )

    # ========================================================
    # STEP 5 - ML Severity
    # ========================================================

    detected_ml_findings = _apply_ml_severity(
        predictions=predictions,
        onchain_risk=0.0,
    )

    # ========================================================
    # STEP 6 - Unified Findings
    # ========================================================

    unified_findings = []

    # Existing static findings
    for finding in static_findings:

        if not isinstance(
            finding,
            dict
        ):
            continue

        normalized_static = dict(
            finding
        )

        normalized_static.setdefault(
            "source",
            "STATIC_ANALYZER"
        )

        normalized_static.setdefault(
            "detected",
            True
        )

        unified_findings.append(
            normalized_static
        )

    # ML findings
    unified_findings.extend(
        detected_ml_findings
    )

    # ========================================================
    # STEP 7 - Prioritization
    # ========================================================

    priority_input = _prepare_priority_input(
        unified_findings
    )

    try:

        prioritized = (
            prioritize_vulnerabilities(
                priority_input
            )
        )

    except Exception as error:

        prioritized = []

        for finding in priority_input:

            fallback = dict(
                finding
            )

            fallback.setdefault(
                "priority_score",
                fallback.get(
                    "severity_score",
                    0.0
                )
            )

            prioritized.append(
                fallback
            )

    # ========================================================
    # STEP 8 - Remediation
    # ========================================================

    try:

        repair_suggestions = (
            generate_repair_suggestions(
                prioritized
            )
        )

    except Exception as error:

        repair_suggestions = [
            {
                "vulnerability":
                    finding.get(
                        "vulnerability",
                        "Unknown"
                    ),

                "recommendation":
                    "Manual security review required.",

                "ai_ready":
                    False,

                "error":
                    str(error),
            }

            for finding in prioritized
        ]

    # ========================================================
    # STEP 9 - Deployment Readiness
    # ========================================================

    try:

        deployment_readiness = (
            assess_deployment_readiness(
                prioritized
            )
        )

    except Exception as error:

        deployment_readiness = {
            "status": "UNKNOWN",
            "score": 0,
            "risk_level": "UNKNOWN",
            "error": str(error),
        }

    # ========================================================
    # STEP 10 - Intelligence Summary
    # ========================================================

    detected_predictions = [
        prediction
        for prediction in predictions
        if prediction.get(
            "detected",
            False
        )
    ]

    intelligence_summary = {
        "total_ml_predictions":
            len(predictions),

        "detected_ml_vulnerabilities":
            len(detected_predictions),

        "static_findings":
            len(static_findings),

        "unified_findings":
            len(unified_findings),

        "prioritized_findings":
            len(prioritized),

        "explanations_generated":
            bool(include_explanations),

        "xai_methods": [
            "SHAP",
            "LIME",
        ] if include_explanations else [],
    }

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {
        "success": True,

        "intelligence_summary":
            intelligence_summary,

        "features":
            features,

        "ml_predictions":
            predictions,

        "explanations":
            explanations,

        "unified_findings":
            unified_findings,

        "prioritized_vulnerabilities":
            prioritized,

        "repair_suggestions":
            repair_suggestions,

        "deployment_readiness":
            deployment_readiness,

        "static_findings":
            static_findings,

        "flags":
            all_flags,
    }


# ============================================================
# Standalone Test
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("TRUSTGUARD AI - LIVE SECURITY INTELLIGENCE ENGINE")
    print("=" * 70)

    test_source = """
    pragma solidity ^0.8.20;

    contract TestToken {

        uint256 public balance;

        function mint(
            address to,
            uint256 amount
        ) public {
            balance += amount;
        }

        function pause() public {
        }

        function setFee(
            uint256 fee
        ) public {
        }
    }
    """

    result = analyze_live_security(
        source_code=test_source,
        onchain_data={
            "total_supply": 1000000,
            "decimals": 18,
            "liquidity_pool_exists": True,
            "liquidity_burn_percentage": 0.0,
        },
        static_findings=[],
        all_flags={},
        include_explanations=True,
    )

    print()
    print("Success:")
    print(
        result.get(
            "success"
        )
    )

    print()
    print("ML Predictions:")
    print(
        len(
            result.get(
                "ml_predictions",
                []
            )
        )
    )

    print()
    print("Detected ML Findings:")
    print(
        len(
            [
                item
                for item in result.get(
                    "ml_predictions",
                    []
                )
                if item.get(
                    "detected",
                    False
                )
            ]
        )
    )

    print()
    print("Unified Findings:")
    print(
        len(
            result.get(
                "unified_findings",
                []
            )
        )
    )

    print()
    print("Prioritized Findings:")
    print(
        len(
            result.get(
                "prioritized_vulnerabilities",
                []
            )
        )
    )

    print()
    print("Repairs:")
    print(
        len(
            result.get(
                "repair_suggestions",
                []
            )
        )
    )

    print()
    print("Deployment Readiness:")
    print(
        result.get(
            "deployment_readiness"
        )
    )

    print()
    print("=" * 70)
    print("LIVE INTELLIGENCE ENGINE TEST COMPLETE")
    print("=" * 70)