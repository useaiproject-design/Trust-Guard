from typing import List, Dict


# ============================================================
# TrustGuard AI - Vulnerability Prioritizer
# ============================================================

SEVERITY_WEIGHT = {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 60,
    "LOW": 40,
    "INFO": 20
}


def calculate_priority_score(
    vulnerability: Dict
) -> float:

    """
    Calculate the final vulnerability priority.

    Factors:
    - Severity
    - ML probability
    - Impact
    - Exploitability
    """

    severity = vulnerability.get(
        "severity",
        "INFO"
    )

    probability = float(
        vulnerability.get(
            "probability",
            0
        )
    )

    impact = float(
        vulnerability.get(
            "impact",
            1
        )
    )

    exploitability = float(
        vulnerability.get(
            "exploitability",
            1
        )
    )

    severity_score = SEVERITY_WEIGHT.get(
        severity,
        20
    )

    impact_score = (
        impact / 5
    ) * 100

    exploitability_score = (
        exploitability / 5
    ) * 100

    probability_score = (
        probability * 100
    )

    # --------------------------------------------------------
    # Weighted prioritization formula
    # --------------------------------------------------------

    priority_score = (
        severity_score * 0.40
        +
        probability_score * 0.30
        +
        impact_score * 0.20
        +
        exploitability_score * 0.10
    )

    return round(
        priority_score,
        2
    )


def prioritize_vulnerabilities(
    vulnerabilities: List[Dict]
) -> List[Dict]:

    """
    Assign priority rankings to vulnerabilities.
    """

    prioritized = []

    for vulnerability in vulnerabilities:

        item = vulnerability.copy()

        item["priority_score"] = (
            calculate_priority_score(
                item
            )
        )

        prioritized.append(
            item
        )

    # --------------------------------------------------------
    # Sort highest priority first
    # --------------------------------------------------------

    prioritized.sort(
        key=lambda x: x[
            "priority_score"
        ],
        reverse=True
    )

    # --------------------------------------------------------
    # Assign priority rank
    # --------------------------------------------------------

    for index, vulnerability in enumerate(
        prioritized,
        start=1
    ):

        vulnerability["priority"] = index

    return prioritized


# ============================================================
# Test
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("TRUSTGUARD AI - VULNERABILITY PRIORITIZATION TEST")
    print("=" * 70)

    test_vulnerabilities = [

        {
            "vulnerability": "Reentrancy",
            "probability": 0.93,
            "severity_score": 89.8,
            "severity": "CRITICAL",
            "impact": 5,
            "exploitability": 5
        },

        {
            "vulnerability": "Access Control",
            "probability": 0.87,
            "severity_score": 84.2,
            "severity": "HIGH",
            "impact": 5,
            "exploitability": 4
        },

        {
            "vulnerability": "Front Running",
            "probability": 0.71,
            "severity_score": 64.6,
            "severity": "MEDIUM",
            "impact": 3,
            "exploitability": 3
        },

        {
            "vulnerability": "Arithmetic",
            "probability": 0.52,
            "severity_score": 57.2,
            "severity": "MEDIUM",
            "impact": 4,
            "exploitability": 3
        }
    ]

    results = prioritize_vulnerabilities(
        test_vulnerabilities
    )

    print()

    for vulnerability in results:

        print(
            f"Priority {vulnerability['priority']}"
        )

        print(
            f"  Vulnerability   : "
            f"{vulnerability['vulnerability']}"
        )

        print(
            f"  Probability     : "
            f"{vulnerability['probability']:.2%}"
        )

        print(
            f"  Severity        : "
            f"{vulnerability['severity']}"
        )

        print(
            f"  Priority Score  : "
            f"{vulnerability['priority_score']}"
        )

        print()

    print("=" * 70)
    print("PRIORITIZATION TEST COMPLETE")
    print("=" * 70)