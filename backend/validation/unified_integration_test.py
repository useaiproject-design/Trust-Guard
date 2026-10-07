from backend.ml.severity_engine import analyze_all_predictions
from backend.security.prioritizer import prioritize_vulnerabilities
from backend.remediation.repair_suggester import (
    generate_repair_suggestions
)


# ============================================================
# TRUSTGUARD AI - UNIFIED INTEGRATION TEST
# ============================================================

STATIC_FINDINGS = [
    {
        "vulnerability": "Mint Capability",
        "probability": 1.0,
        "severity": "HIGH",
        "severity_score": 85.0,
        "impact": 5,
        "exploitability": 4,
        "detected": True,
        "source": "STATIC_ANALYZER",
    }
]


ML_PREDICTIONS = [
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
]


def main():

    print("=" * 70)
    print("TRUSTGUARD AI - UNIFIED INTEGRATION TEST")
    print("=" * 70)

    # ========================================================
    # 1. STATIC FINDINGS
    # ========================================================

    print("\n## STATIC FINDINGS")

    for finding in STATIC_FINDINGS:

        print(
            f"{finding['vulnerability']} | "
            f"{finding['severity']} | "
            f"Source: {finding['source']}"
        )

    # ========================================================
    # 2. ML PREDICTIONS
    # ========================================================

    print("\n## ML PREDICTIONS")

    for prediction in ML_PREDICTIONS:

        print(
            f"{prediction['id']}: "
            f"{prediction['probability']:.2%} "
            f"detected={prediction['detected']}"
        )

    # ========================================================
    # 3. ML → SEVERITY
    # ========================================================

    ml_severity = analyze_all_predictions(
        ML_PREDICTIONS,
        evidence_strength=0.5,
        onchain_risk=0.3,
    )

    # Add ML source information.

    for finding in ml_severity:

        finding["source"] = "ML_MODEL"

    print("\n## ML SEVERITY")

    for finding in ml_severity:

        print(
            f"{finding['vulnerability']} | "
            f"{finding['severity']} | "
            f"Score: {finding['severity_score']}"
        )

    # ========================================================
    # 4. UNIFIED FINDINGS
    # ========================================================

    unified_findings = []

    # Add static findings.

    unified_findings.extend(
        STATIC_FINDINGS
    )

    # Add detected ML findings.

    unified_findings.extend(
        [
            finding
            for finding in ml_severity
            if finding.get("detected", False)
        ]
    )

    print("\n## UNIFIED FINDINGS")

    for finding in unified_findings:

        print(
            f"{finding['vulnerability']} | "
            f"Source: {finding['source']} | "
            f"Severity: {finding['severity']}"
        )

    # ========================================================
    # 5. PRIORITIZATION
    # ========================================================

    prioritized = prioritize_vulnerabilities(
        unified_findings
    )

    print("\n## PRIORITIZED VULNERABILITIES")

    for finding in prioritized:

        print(
            f"Priority {finding['priority']}: "
            f"{finding['vulnerability']} | "
            f"{finding['severity']} | "
            f"Score {finding['priority_score']}"
        )

    # ========================================================
    # 6. REMEDIATION
    # ========================================================

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

    # ========================================================
    # 7. FINAL RESULT
    # ========================================================

    print("\n## FINAL INTEGRATION RESULT")

    print(
        f"Static findings : "
        f"{len(STATIC_FINDINGS)}"
    )

    print(
        f"ML findings     : "
        f"{len([f for f in ml_severity if f.get('detected', False)])}"
    )

    print(
        f"Unified findings: "
        f"{len(unified_findings)}"
    )

    print(
        f"Prioritized     : "
        f"{len(prioritized)}"
    )

    print(
        f"Repairs         : "
        f"{len(repairs)}"
    )

    # ========================================================
    # 8. PASS / FAIL
    # ========================================================

    expected_total = (
        len(STATIC_FINDINGS)
        +
        len(
            [
                finding
                for finding in ml_severity
                if finding.get("detected", False)
            ]
        )
    )

    if (
        len(unified_findings) == expected_total
        and len(prioritized) == expected_total
        and len(repairs) == expected_total
    ):

        print(
            "\nUNIFIED INTEGRATION: PASS"
        )

    else:

        print(
            "\nUNIFIED INTEGRATION: REVIEW REQUIRED"
        )


if __name__ == "__main__":

    main()