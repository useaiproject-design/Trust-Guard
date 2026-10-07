from backend.ml.severity_engine import analyze_all_predictions
from backend.security.prioritizer import prioritize_vulnerabilities
from backend.remediation.repair_suggester import generate_repair_suggestions


# ============================================================
# TRUSTGUARD AI - ML INTEGRATION TEST
# ============================================================

TEST_PREDICTIONS = [
    {
        "id": "Reentrancy",
        "probability": 0.93,
        "detected": True,
    },
    {
        "id": "Access Control",
        "probability": 0.87,
        "detected": True,
    },
    {
        "id": "Arithmetic",
        "probability": 0.52,
        "detected": True,
    },
    {
        "id": "Front Running",
        "probability": 0.71,
        "detected": True,
    },
]


def main():

    print("=" * 70)
    print("TRUSTGUARD AI - ML INTEGRATION TEST")
    print("=" * 70)

    # --------------------------------------------------------
    # 1. ML predictions
    # --------------------------------------------------------

    print("\n## ML PREDICTIONS")

    for prediction in TEST_PREDICTIONS:

        print(
            f"{prediction['id']}: "
            f"{prediction['probability']:.2%} "
            f"detected={prediction['detected']}"
        )

    # --------------------------------------------------------
    # 2. Severity analysis
    # --------------------------------------------------------

    severity_results = analyze_all_predictions(
        TEST_PREDICTIONS,
        evidence_strength=0.5,
        onchain_risk=0.3,
    )

    print("\n## SEVERITY")

    for result in severity_results:

        print(
            f"{result['vulnerability']} | "
            f"{result['severity']} | "
            f"Score {result['severity_score']}"
        )

    # --------------------------------------------------------
    # 3. Keep detected findings
    # --------------------------------------------------------

    detected_findings = [
        result
        for result in severity_results
        if result.get("detected", False)
    ]

    # --------------------------------------------------------
    # 4. Prioritization
    # --------------------------------------------------------

    prioritized = prioritize_vulnerabilities(
        detected_findings
    )

    print("\n## PRIORITIZED VULNERABILITIES")

    for result in prioritized:

        print(
            f"Priority {result['priority']}: "
            f"{result['vulnerability']} | "
            f"{result['severity']} | "
            f"Score {result['priority_score']}"
        )

    # --------------------------------------------------------
    # 5. Remediation
    # --------------------------------------------------------

    repairs = generate_repair_suggestions(
        prioritized
    )

    print("\n## REPAIR SUGGESTIONS")

    for repair in repairs:

        print(
            f"Priority {repair['priority']}: "
            f"{repair['vulnerability']}"
        )

        print(
            f"→ {repair['recommendation']}"
        )

        print(
            f"AI Ready: {repair['ai_ready']}"
        )

    # --------------------------------------------------------
    # 6. Final integration result
    # --------------------------------------------------------

    print("\n## INTEGRATION RESULT")

    print(
        f"ML findings       : "
        f"{len(detected_findings)}"
    )

    print(
        f"Prioritized       : "
        f"{len(prioritized)}"
    )

    print(
        f"Repair suggestions: "
        f"{len(repairs)}"
    )

    if (
        len(detected_findings) > 0
        and len(prioritized) == len(detected_findings)
        and len(repairs) == len(prioritized)
    ):

        print("\nML INTEGRATION: PASS")

    else:

        print("\nML INTEGRATION: REVIEW REQUIRED")


if __name__ == "__main__":

    main()