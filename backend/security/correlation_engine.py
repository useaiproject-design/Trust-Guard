"""
TrustGuard AI - Vulnerability Correlation Engine

Purpose:
    Correlate signals from multiple TrustGuard security layers:

        Static findings
        ML predictions
        Security evidence
        Attack surface
        Severity
        Confidence

Important:
    Correlation does NOT prove exploitability.

    A correlated finding means that multiple independent or related
    security signals point toward the same area of concern.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ============================================================
# Helpers
# ============================================================

def _text(value: Any) -> str:
    """Safely convert a value to normalized text."""

    if value is None:
        return ""

    return str(value).strip()


def _normalize_name(value: Any) -> str:
    """
    Normalize vulnerability names so signals from different
    TrustGuard components can be compared.
    """

    text = _text(value).lower()

    replacements = {
        "access control": "access control",
        "authorization": "access control",
        "arithmetic": "arithmetic",
        "integer overflow": "arithmetic",
        "integer underflow": "arithmetic",
        "unchecked return": "unchecked return values",
        "unchecked return value": "unchecked return values",
        "dos": "dos",
        "denial of service": "dos",
        "bad randomness": "bad randomness",
        "randomness": "bad randomness",
        "front running": "front running",
        "frontrunning": "front running",
        "time manipulation": "time manipulation",
        "timestamp": "time manipulation",
        "reentrancy": "reentrancy",
    }

    for key, normalized in replacements.items():

        if key in text:
            return normalized

    return text


def _get_finding_name(finding: Dict[str, Any]) -> str:
    """Extract a vulnerability/finding name from a finding object."""

    return _normalize_name(
        finding.get("name")
        or finding.get("title")
        or finding.get("vulnerability")
        or finding.get("type")
    )


def _get_prediction_name(prediction: Dict[str, Any]) -> str:
    """Extract a vulnerability name from an ML prediction."""

    return _normalize_name(
        prediction.get("name")
        or prediction.get("target")
        or prediction.get("vulnerability")
        or prediction.get("label")
    )


def _numeric_probability(
    prediction: Dict[str, Any]
) -> Optional[float]:
    """
    Extract a probability from an ML prediction.

    Supports common probability field names.
    """

    possible_fields = [
        "probability",
        "score",
        "confidence",
        "risk_probability",
        "predicted_probability",
    ]

    for field in possible_fields:

        value = prediction.get(field)

        if isinstance(value, (int, float)):

            number = float(value)

            # Convert percentage values to 0-1.
            if number > 1:
                number = number / 100.0

            return max(
                0.0,
                min(
                    1.0,
                    number
                )
            )

    return None


def _severity_value(
    severity: Any
) -> str:
    """Normalize severity labels."""

    text = _text(severity).lower()

    if "critical" in text:
        return "critical"

    if "high" in text:
        return "high"

    if "medium" in text:
        return "medium"

    if "low" in text:
        return "low"

    if "info" in text:
        return "informational"

    return "unknown"


# ============================================================
# Signal extraction
# ============================================================

def _build_static_signal_map(
    static_findings: Optional[List[Dict[str, Any]]]
) -> Dict[str, List[Dict[str, Any]]]:

    result: Dict[str, List[Dict[str, Any]]] = {}

    for finding in static_findings or []:

        if not isinstance(finding, dict):
            continue

        name = _get_finding_name(finding)

        if not name:
            continue

        result.setdefault(
            name,
            []
        ).append(finding)

    return result


def _build_ml_signal_map(
    ml_predictions: Optional[List[Dict[str, Any]]]
) -> Dict[str, List[Dict[str, Any]]]:

    result: Dict[str, List[Dict[str, Any]]] = {}

    for prediction in ml_predictions or []:

        if not isinstance(prediction, dict):
            continue

        name = _get_prediction_name(prediction)

        if not name:
            continue

        result.setdefault(
            name,
            []
        ).append(prediction)

    return result


def _build_evidence_signal_map(
    evidence: Optional[List[Dict[str, Any]]]
) -> Dict[str, List[Dict[str, Any]]]:

    result: Dict[str, List[Dict[str, Any]]] = {}

    for item in evidence or []:

        if not isinstance(item, dict):
            continue

        text = (
            _text(item.get("title")) +
            " " +
            _text(item.get("description")) +
            " " +
            _text(item.get("type"))
        ).lower()

        possible_names = []

        if any(
            word in text
            for word in [
                "external call",
                "delegatecall",
                "low-level call",
                "reentr"
            ]
        ):
            possible_names.append(
                "reentrancy"
            )

        if any(
            word in text
            for word in [
                "owner",
                "admin",
                "access-control",
                "authorization",
                "privileged"
            ]
        ):
            possible_names.append(
                "access control"
            )

        if any(
            word in text
            for word in [
                "timestamp",
                "block timestamp"
            ]
        ):
            possible_names.append(
                "time manipulation"
            )

        if any(
            word in text
            for word in [
                "randomness",
                "random"
            ]
        ):
            possible_names.append(
                "bad randomness"
            )

        if any(
            word in text
            for word in [
                "loop",
                "gas consumption"
            ]
        ):
            possible_names.append(
                "dos"
            )

        if any(
            word in text
            for word in [
                "arithmetic",
                "overflow",
                "underflow"
            ]
        ):
            possible_names.append(
                "arithmetic"
            )

        for name in possible_names:

            result.setdefault(
                name,
                []
            ).append(item)

    return result


# ============================================================
# Correlation scoring
# ============================================================

def calculate_correlation_strength(
    *,
    static_count: int,
    ml_probability: Optional[float],
    evidence_count: int,
    attack_surface_signal: bool,
) -> Dict[str, Any]:
    """
    Calculate a transparent correlation strength.

    This is NOT a vulnerability probability.

    It represents the amount of supporting signal available
    across TrustGuard's analysis layers.
    """

    points = 0
    reasons: List[str] = []

    if static_count > 0:

        points += 30

        reasons.append(
            "Static analysis signal detected."
        )

    if ml_probability is not None:

        if ml_probability >= 0.80:

            points += 30

            reasons.append(
                "ML prediction probability is high."
            )

        elif ml_probability >= 0.50:

            points += 20

            reasons.append(
                "ML prediction probability is moderate."
            )

        elif ml_probability >= 0.25:

            points += 10

            reasons.append(
                "ML prediction probability is present."
            )

    if evidence_count > 0:

        points += min(
            25,
            evidence_count * 10
        )

        reasons.append(
            "Supporting security evidence was identified."
        )

    if attack_surface_signal:

        points += 15

        reasons.append(
            "Related attack-surface behavior was identified."
        )

    points = min(
        points,
        100
    )

    if points >= 75:

        level = "strong"

    elif points >= 50:

        level = "moderate"

    elif points >= 25:

        level = "limited"

    else:

        level = "weak"

    return {
        "score": points,
        "level": level,
        "reasons": reasons,
    }


# ============================================================
# Attack-surface relationship
# ============================================================

def _has_attack_surface_signal(
    vulnerability: str,
    attack_surface: Dict[str, Any]
) -> bool:

    if not attack_surface:
        return False

    vulnerability = _normalize_name(
        vulnerability
    )

    if vulnerability == "reentrancy":

        return bool(
            attack_surface.get(
                "external_calls",
                0
            )
            or attack_surface.get(
                "low_level_calls",
                0
            )
            or attack_surface.get(
                "delegatecall",
                False
            )
        )

    if vulnerability == "access control":

        return bool(
            attack_surface.get(
                "privileged_functions",
                0
            )
            or attack_surface.get(
                "owner_control",
                False
            )
            or attack_surface.get(
                "role_based_access",
                False
            )
        )

    if vulnerability == "bad randomness":

        return bool(
            attack_surface.get(
                "randomness_usage",
                False
            )
        )

    if vulnerability == "time manipulation":

        return bool(
            attack_surface.get(
                "timestamp_usage",
                False
            )
        )

    if vulnerability == "dos":

        return bool(
            attack_surface.get(
                "loops",
                0
            )
        )

    if vulnerability == "arithmetic":

        return bool(
            attack_surface.get(
                "arithmetic_operation_count",
                0
            )
        )

    return False


# ============================================================
# Main correlation engine
# ============================================================

def correlate_security_signals(
    *,
    static_findings: Optional[List[Dict[str, Any]]] = None,
    ml_predictions: Optional[List[Dict[str, Any]]] = None,
    evidence_result: Optional[Dict[str, Any]] = None,
    attack_surface_result: Optional[Dict[str, Any]] = None,
    severity_results: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Correlate TrustGuard's security signals.

    Returns:
        success
        correlated_findings
        correlation_count
        summary
        limitations

    Important:
        Correlation is not proof of exploitability.
    """

    try:

        static_map = _build_static_signal_map(
            static_findings
        )

        ml_map = _build_ml_signal_map(
            ml_predictions
        )

        evidence_items = []

        if isinstance(
            evidence_result,
            dict
        ):

            evidence_items = (
                evidence_result.get(
                    "evidence",
                    []
                )
                or []
            )

        evidence_map = _build_evidence_signal_map(
            evidence_items
        )

        attack_surface = {}

        if isinstance(
            attack_surface_result,
            dict
        ):

            attack_surface = (
                attack_surface_result.get(
                    "attack_surface",
                    {}
                )
                or {}
            )

        severity_map: Dict[str, Any] = {}

        if isinstance(
            severity_results,
            list
        ):

            for item in severity_results:

                if not isinstance(
                    item,
                    dict
                ):
                    continue

                name = _get_finding_name(
                    item
                )

                if name:

                    severity_map[name] = item

        # ----------------------------------------------------
        # Build unified vulnerability name set
        # ----------------------------------------------------

        vulnerability_names = set()

        vulnerability_names.update(
            static_map.keys()
        )

        vulnerability_names.update(
            ml_map.keys()
        )

        vulnerability_names.update(
            evidence_map.keys()
        )

        correlated_findings: List[Dict[str, Any]] = []

        # ----------------------------------------------------
        # Correlate each vulnerability
        # ----------------------------------------------------

        for vulnerability in sorted(
            vulnerability_names
        ):

            static_signals = (
                static_map.get(
                    vulnerability,
                    []
                )
            )

            ml_signals = (
                ml_map.get(
                    vulnerability,
                    []
                )
            )

            evidence_signals = (
                evidence_map.get(
                    vulnerability,
                    []
                )
            )

            # ------------------------------------------------
            # ML probability
            # ------------------------------------------------

            probabilities = []

            for prediction in ml_signals:

                probability = (
                    _numeric_probability(
                        prediction
                    )
                )

                if probability is not None:

                    probabilities.append(
                        probability
                    )

            ml_probability = None

            if probabilities:

                ml_probability = max(
                    probabilities
                )

            # ------------------------------------------------
            # Severity
            # ------------------------------------------------

            severity = (
                severity_map
                .get(vulnerability, {})
            )

            severity_label = _severity_value(
                severity.get(
                    "severity"
                )
                if isinstance(
                    severity,
                    dict
                )
                else None
            )

            # ------------------------------------------------
            # Attack surface
            # ------------------------------------------------

            attack_signal = (
                _has_attack_surface_signal(
                    vulnerability,
                    attack_surface
                )
            )

            # ------------------------------------------------
            # Correlation strength
            # ------------------------------------------------

            correlation = (
                calculate_correlation_strength(
                    static_count=len(
                        static_signals
                    ),
                    ml_probability=ml_probability,
                    evidence_count=len(
                        evidence_signals
                    ),
                    attack_surface_signal=attack_signal,
                )
            )

            # ------------------------------------------------
            # Signal labels
            # ------------------------------------------------

            signals = []

            if static_signals:

                signals.append(
                    "static_analysis"
                )

            if ml_signals:

                signals.append(
                    "ml_prediction"
                )

            if evidence_signals:

                signals.append(
                    "security_evidence"
                )

            if attack_signal:

                signals.append(
                    "attack_surface"
                )

            # ------------------------------------------------
            # Confidence description
            # ------------------------------------------------

            if len(signals) >= 3:

                confidence = "high"

            elif len(signals) == 2:

                confidence = "moderate"

            elif len(signals) == 1:

                confidence = "limited"

            else:

                confidence = "unknown"

            # ------------------------------------------------
            # Finding object
            # ------------------------------------------------

            finding = {

                "vulnerability":
                    vulnerability,

                "signals":
                    signals,

                "signal_count":
                    len(signals),

                "static_findings":
                    static_signals,

                "ml_predictions":
                    ml_signals,

                "evidence":
                    evidence_signals,

                "attack_surface_signal":
                    attack_signal,

                "ml_probability":
                    ml_probability,

                "severity":
                    severity_label,

                "correlation":
                    correlation,

                "correlation_score":
                    correlation["score"],

                "correlation_level":
                    correlation["level"],

                "confidence":
                    confidence,

                "exploitability_claim":
                    False,

                "interpretation":
                    (
                        "Multiple security signals are correlated "
                        "for this vulnerability category. This "
                        "correlation indicates supporting evidence "
                        "across analysis layers but does not prove "
                        "that the contract is exploitable."
                    )
            }

            correlated_findings.append(
                finding
            )

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        multi_signal_count = len(
            [
                item
                for item in correlated_findings
                if item.get(
                    "signal_count",
                    0
                ) >= 2
            ]
        )

        summary = (
            f"{len(correlated_findings)} vulnerability "
            f"category/categories were correlated. "
            f"{multi_signal_count} category/categories have "
            f"signals from at least two TrustGuard analysis layers."
        )

        return {

            "success":
                True,

            "correlated_findings":
                correlated_findings,

            "correlation_count":
                len(correlated_findings),

            "multi_signal_count":
                multi_signal_count,

            "summary":
                summary,

            "limitations": [

                "Correlation combines available security signals "
                "but does not prove exploitability.",

                "ML probability is a model output and should not "
                "be interpreted as confirmed vulnerability evidence.",

                "Pattern-based evidence may require manual review.",

                "Missing source code or incomplete analysis can "
                "reduce correlation coverage."
            ]
        }

    except Exception as error:

        return {

            "success":
                False,

            "correlated_findings":
                [],

            "correlation_count":
                0,

            "multi_signal_count":
                0,

            "summary":
                "",

            "error":
                str(error),

            "limitations": [

                "Vulnerability correlation could not be completed."
            ]
        }


# ============================================================
# Standalone test
# ============================================================

if __name__ == "__main__":

    test_static_findings = [

        {
            "name":
                "Reentrancy",

            "description":
                "External call interaction requires review."
        },

        {
            "name":
                "Access Control",

            "description":
                "Privileged access control should be reviewed."
        }
    ]

    test_ml_predictions = [

        {
            "name":
                "Reentrancy",

            "probability":
                0.87
        },

        {
            "name":
                "Access Control",

            "probability":
                0.61
        },

        {
            "name":
                "Arithmetic",

            "probability":
                0.18
        }
    ]

    test_evidence = {

        "evidence": [

            {
                "type":
                    "external_interaction",

                "title":
                    "Low-level external interaction detected",

                "description":
                    "The source contains low-level call patterns.",

                "source":
                    "source_code",

                "confidence":
                    "high"
            },

            {
                "type":
                    "access_control",

                "title":
                    "Privileged access-control pattern detected",

                "description":
                    "Owner/admin patterns were detected.",

                "source":
                    "source_code",

                "confidence":
                    "high"
            }
        ]
    }

    test_attack_surface = {

        "attack_surface": {

            "external_calls":
                2,

            "low_level_calls":
                1,

            "privileged_functions":
                2,

            "owner_control":
                True,

            "randomness_usage":
                False,

            "timestamp_usage":
                False,

            "loops":
                0,

            "arithmetic_operation_count":
                0
        }
    }

    result = correlate_security_signals(

        static_findings=
            test_static_findings,

        ml_predictions=
            test_ml_predictions,

        evidence_result=
            test_evidence,

        attack_surface_result=
            test_attack_surface,

        severity_results=[]
    )

    print("=" * 70)
    print("TRUSTGUARD AI - VULNERABILITY CORRELATION ENGINE")
    print("=" * 70)

    print()
    print(
        "Success:",
        result["success"]
    )

    print()
    print(
        "Correlation Count:",
        result["correlation_count"]
    )

    print()
    print(
        "Multi-Signal Count:",
        result["multi_signal_count"]
    )

    print()
    print(
        "Summary:"
    )

    print(
        result["summary"]
    )

    print()
    print(
        "Correlated Findings:"
    )

    for finding in result[
        "correlated_findings"
    ]:

        print()

        print(
            f"- {finding['vulnerability']}"
        )

        print(
            f"  Signals: "
            f"{', '.join(finding['signals'])}"
        )

        print(
            f"  ML Probability: "
            f"{finding['ml_probability']}"
        )

        print(
            f"  Correlation Score: "
            f"{finding['correlation_score']}"
        )

        print(
            f"  Correlation Level: "
            f"{finding['correlation_level']}"
        )

        print(
            f"  Confidence: "
            f"{finding['confidence']}"
        )

        print(
            f"  Exploitability Claim: "
            f"{finding['exploitability_claim']}"
        )

    print()
    print(
        "Limitations:"
    )

    for limitation in result[
        "limitations"
    ]:

        print(
            f"- {limitation}"
        )

    print()
    print("=" * 70)