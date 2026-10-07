from backend.readiness.deployment_assessor import (
    assess_deployment_readiness
)


# ============================================================
# TRUSTGUARD AI - DEPLOYMENT READINESS INTEGRATION TEST
# ============================================================

TEST_VULNERABILITIES = [

    {
        "vulnerability": "Reentrancy",
        "probability": 0.93,
        "severity_score": 97.9,
        "severity": "CRITICAL",
        "impact": 5,
        "exploitability": 5,
        "detected": True,
        "source": "ML_MODEL",
        "priority_score": 97.9,
        "priority": 1
    },

    {
        "vulnerability": "Mint Capability",
        "probability": 1.0,
        "severity_score": 85.0,
        "severity": "HIGH",
        "impact": 5,
        "exploitability": 4,
        "detected": True,
        "source": "STATIC_ANALYZER",
        "priority_score": 90.0,
        "priority": 2
    },

    {
        "vulnerability": "Access Control",
        "probability": 0.87,
        "severity_score": 84.2,
        "severity": "HIGH",
        "impact": 5,
        "exploitability": 4,
        "detected": True,
        "source": "ML_MODEL",
        "priority_score": 86.1,
        "priority": 3
    },

    {
        "vulnerability": "Arithmetic",
        "probability": 0.52,
        "severity_score": 57.2,
        "severity": "MEDIUM",
        "impact": 4,
        "exploitability": 3,
        "detected": True,
        "source": "ML_MODEL",
        "priority_score": 61.6,
        "priority": 4
    }
]


def main():

    print("=" * 70)
    print("TRUSTGUARD AI - DEPLOYMENT READINESS INTEGRATION TEST")
    print("=" * 70)

    # ========================================================
    # 1. Display input findings
    # ========================================================

    print("\n## INPUT VULNERABILITIES")

    for vulnerability in TEST_VULNERABILITIES:

        print(
            f"Priority {vulnerability['priority']}: "
            f"{vulnerability['vulnerability']} | "
            f"{vulnerability['severity']} | "
            f"Source: {vulnerability['source']}"
        )

    # ========================================================
    # 2. Run deployment readiness assessment
    # ========================================================

    readiness = assess_deployment_readiness(
        TEST_VULNERABILITIES
    )

    # ========================================================
    # 3. Display readiness result
    # ========================================================

    print("\n## DEPLOYMENT READINESS")

    print(
        f"Status         : "
        f"{readiness.get('status')}"
    )

    print(
        f"Readiness Score: "
        f"{readiness.get('readiness_score')}"
    )

    print(
        f"Risk Level     : "
        f"{readiness.get('risk_level')}"
    )

    print(
        f"Total Findings : "
        f"{readiness.get('total_findings')}"
    )

    print(
        f"Detected       : "
        f"{readiness.get('detected_findings')}"
    )

    # ========================================================
    # 4. Vulnerability counts
    # ========================================================

    print("\n## VULNERABILITY COUNTS")

    counts = readiness.get(
        "vulnerability_counts",
        {}
    )

    for severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO"
    ]:

        print(
            f"{severity:<9}: "
            f"{counts.get(severity, 0)}"
        )

    # ========================================================
    # 5. Blocking issues
    # ========================================================

    print("\n## BLOCKING ISSUES")

    blocking = readiness.get(
        "blocking_issues",
        []
    )

    if blocking:

        for issue in blocking:

            if isinstance(issue, dict):

                print(
                    f"→ {issue.get('vulnerability', 'Unknown')} "
                    f"| {issue.get('severity', 'UNKNOWN')}"
                )

            else:

                print(
                    f"→ {issue}"
                )

    else:

        print("None")

    # ========================================================
    # 6. Recommendations
    # ========================================================

    print("\n## RECOMMENDATIONS")

    recommendations = readiness.get(
        "recommendations",
        []
    )

    for recommendation in recommendations:

        print(
            f"→ {recommendation}"
        )

    # ========================================================
    # 7. Integration validation
    # ========================================================

    print("\n## VALIDATION")

    total_findings = readiness.get(
        "total_findings",
        0
    )

    detected_findings = readiness.get(
        "detected_findings",
        0
    )

    returned_counts = sum(
        counts.get(severity, 0)
        for severity in [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO"
        ]
    )

    # We intentionally expect the assessment
    # NOT to be READY because the test contains
    # one CRITICAL and two HIGH findings.

    has_critical = (
        counts.get("CRITICAL", 0) > 0
    )

    has_high = (
        counts.get("HIGH", 0) > 0
    )

    if (
        total_findings == 4
        and detected_findings == 4
        and returned_counts == 4
        and has_critical
        and has_high
        and readiness.get("status") != "READY"
    ):

        print(
            "DEPLOYMENT READINESS INTEGRATION: PASS"
        )

    else:

        print(
            "DEPLOYMENT READINESS INTEGRATION: "
            "REVIEW REQUIRED"
        )

    print("\n" + "=" * 70)


if __name__ == "__main__":

    main()