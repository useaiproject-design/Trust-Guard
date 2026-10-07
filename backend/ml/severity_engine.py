from typing import Dict, List


# ============================================================
# TrustGuard AI - Intelligent Severity Engine
# ============================================================

VULNERABILITY_PROFILES = {

    "Reentrancy": {
        "impact": 5,
        "exploitability": 5,
        "base_severity": "CRITICAL"
    },

    "Access Control": {
        "impact": 5,
        "exploitability": 4,
        "base_severity": "CRITICAL"
    },

    "Arithmetic": {
        "impact": 4,
        "exploitability": 3,
        "base_severity": "HIGH"
    },

    "Unchecked Return Values": {
        "impact": 3,
        "exploitability": 3,
        "base_severity": "MEDIUM"
    },

    "DoS": {
        "impact": 4,
        "exploitability": 3,
        "base_severity": "HIGH"
    },

    "Bad Randomness": {
        "impact": 4,
        "exploitability": 3,
        "base_severity": "HIGH"
    },

    "Front Running": {
        "impact": 3,
        "exploitability": 3,
        "base_severity": "MEDIUM"
    },

    "Time manipulation": {
        "impact": 4,
        "exploitability": 3,
        "base_severity": "HIGH"
    }
}


# ============================================================
# Severity levels
# ============================================================

SEVERITY_LEVELS = [
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]


# ============================================================
# Convert numerical score into severity
# ============================================================

def score_to_severity(score: float) -> str:

    if score >= 85:
        return "CRITICAL"

    if score >= 70:
        return "HIGH"

    if score >= 50:
        return "MEDIUM"

    if score >= 30:
        return "LOW"

    return "INFO"


# ============================================================
# Calculate severity score
# ============================================================

def calculate_severity_score(
    vulnerability: str,
    probability: float,
    evidence_strength: float = 0.0,
    onchain_risk: float = 0.0
) -> float:

    """
    Calculate an intelligent severity score.

    probability:
        ML probability between 0 and 1.

    evidence_strength:
        Additional evidence from static/security analysis
        between 0 and 1.

    onchain_risk:
        Additional on-chain risk evidence between 0 and 1.
    """

    profile = VULNERABILITY_PROFILES.get(
        vulnerability
    )

    if profile is None:
        raise ValueError(
            f"Unknown vulnerability: {vulnerability}"
        )

    # --------------------------------------------------------
    # Normalize inputs
    # --------------------------------------------------------

    probability = max(
        0.0,
        min(1.0, probability)
    )

    evidence_strength = max(
        0.0,
        min(1.0, evidence_strength)
    )

    onchain_risk = max(
        0.0,
        min(1.0, onchain_risk)
    )

    # --------------------------------------------------------
    # Impact/exploitability contribution
    # --------------------------------------------------------

    impact_score = (
        profile["impact"] / 5
    )

    exploitability_score = (
        profile["exploitability"] / 5
    )

    # --------------------------------------------------------
    # Intelligent weighted score
    # --------------------------------------------------------

    score = (
        probability * 60
        +
        impact_score * 20
        +
        exploitability_score * 10
        +
        evidence_strength * 5
        +
        onchain_risk * 5
    )

    return round(
        min(score, 100),
        2
    )


# ============================================================
# Analyze one vulnerability
# ============================================================

def analyze_severity(
    vulnerability: str,
    probability: float,
    evidence_strength: float = 0.0,
    onchain_risk: float = 0.0
) -> Dict:

    score = calculate_severity_score(
        vulnerability=vulnerability,
        probability=probability,
        evidence_strength=evidence_strength,
        onchain_risk=onchain_risk
    )

    severity = score_to_severity(
        score
    )

    profile = VULNERABILITY_PROFILES[
        vulnerability
    ]

    return {
        "vulnerability": vulnerability,
        "probability": round(
            probability,
            4
        ),
        "severity_score": score,
        "severity": severity,
        "impact": profile["impact"],
        "exploitability": profile["exploitability"]
    }


# ============================================================
# Analyze all model predictions
# ============================================================

def analyze_all_predictions(
    predictions: List[Dict],
    evidence_strength: float = 0.0,
    onchain_risk: float = 0.0
) -> List[Dict]:

    results = []

    for prediction in predictions:

        vulnerability = prediction.get(
            "id"
        )

        probability = float(
            prediction.get(
                "probability",
                0
            )
        )

        result = analyze_severity(
            vulnerability=vulnerability,
            probability=probability,
            evidence_strength=evidence_strength,
            onchain_risk=onchain_risk
        )

        result["detected"] = prediction.get(
            "detected",
            False
        )

        results.append(
            result
        )

    # --------------------------------------------------------
    # Highest severity first
    # --------------------------------------------------------

    severity_order = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1
    }

    results.sort(
        key=lambda x: (
            severity_order[
                x["severity"]
            ],
            x["severity_score"]
        ),
        reverse=True
    )

    return results


# ============================================================
# Test
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("TRUSTGUARD AI - INTELLIGENT SEVERITY ENGINE TEST")
    print("=" * 70)

    test_predictions = [
        {
            "id": "Reentrancy",
            "probability": 0.93,
            "detected": True
        },
        {
            "id": "Access Control",
            "probability": 0.87,
            "detected": True
        },
        {
            "id": "Arithmetic",
            "probability": 0.52,
            "detected": True
        },
        {
            "id": "Front Running",
            "probability": 0.71,
            "detected": True
        }
    ]

    results = analyze_all_predictions(
        test_predictions,
        evidence_strength=0.5,
        onchain_risk=0.3
    )

    for result in results:

        print(
            f"\n{result['vulnerability']}"
        )

        print(
            f"  Probability     : "
            f"{result['probability']:.2%}"
        )

        print(
            f"  Severity Score  : "
            f"{result['severity_score']}"
        )

        print(
            f"  Severity        : "
            f"{result['severity']}"
        )

        print(
            f"  Impact          : "
            f"{result['impact']}/5"
        )

        print(
            f"  Exploitability  : "
            f"{result['exploitability']}/5"
        )

    print("\n" + "=" * 70)
    print("SEVERITY ENGINE TEST COMPLETE")
    print("=" * 70)