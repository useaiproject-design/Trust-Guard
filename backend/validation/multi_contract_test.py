from backend.analyzer import analyze_contract


# ============================================================
# TRUSTGUARD AI - MULTI CONTRACT VALIDATION
# ============================================================

TEST_CONTRACTS = [
    {
        "name": "USDC",
        "address": "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    },

    # We will add more verified contracts after the first test.
]


def validate_contract(name: str, address: str) -> dict:

    print()
    print("=" * 70)
    print(f"Testing: {name}")
    print(f"Address: {address}")
    print("=" * 70)

    try:

        result = analyze_contract(address)

        source_available = bool(
            result.get(
                "source_code_available",
                False
            )
        )

        flags = result.get(
            "flags",
            []
        )

        findings = result.get(
            "prioritized_vulnerabilities",
            []
        )

        repairs = result.get(
            "repair_suggestions",
            []
        )

        readiness = result.get(
            "deployment_readiness",
            {}
        )

        print(
            f"Source Available : "
            f"{source_available}"
        )

        print(
            f"Flags            : "
            f"{len(flags)}"
        )

        print(
            f"Findings         : "
            f"{len(findings)}"
        )

        print(
            f"Repairs          : "
            f"{len(repairs)}"
        )

        print(
            f"Readiness        : "
            f"{readiness.get('status')}"
        )

        print(
            f"Readiness Score   : "
            f"{readiness.get('readiness_score')}"
        )

        print(
            f"Risk Level       : "
            f"{readiness.get('risk_level')}"
        )

        return {
            "name": name,
            "address": address,
            "source": source_available,
            "flags": len(flags),
            "findings": len(findings),
            "repairs": len(repairs),
            "readiness": readiness.get(
                "status",
                "UNKNOWN"
            ),
            "readiness_score": readiness.get(
                "readiness_score",
                0
            ),
            "risk_level": readiness.get(
                "risk_level",
                "UNKNOWN"
            ),
            "status": "SUCCESS",
        }

    except Exception as error:

        print(
            f"ERROR: {error}"
        )

        return {
            "name": name,
            "address": address,
            "source": False,
            "flags": 0,
            "findings": 0,
            "repairs": 0,
            "readiness": "ERROR",
            "readiness_score": 0,
            "risk_level": "UNKNOWN",
            "status": "FAILED",
        }


def main():

    print("=" * 70)
    print(
        "TRUSTGUARD AI - MULTI CONTRACT VALIDATION"
    )
    print("=" * 70)

    results = []

    for contract in TEST_CONTRACTS:

        result = validate_contract(
            contract["name"],
            contract["address"]
        )

        results.append(
            result
        )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)

    print(
        f"{'Contract':<15}"
        f"{'Source':<10}"
        f"{'Findings':<10}"
        f"{'Repairs':<10}"
        f"{'Readiness':<15}"
        f"{'Score':<10}"
    )

    print("-" * 70)

    for result in results:

        print(
            f"{result['name']:<15}"
            f"{str(result['source']):<10}"
            f"{result['findings']:<10}"
            f"{result['repairs']:<10}"
            f"{result['readiness']:<15}"
            f"{result['readiness_score']:<10}"
        )

    print("-" * 70)

    successful = sum(
        1
        for result in results
        if result["status"] == "SUCCESS"
    )

    print(
        f"\nSuccessful tests: "
        f"{successful}/{len(results)}"
    )

    if successful == len(results):

        print(
            "MULTI-CONTRACT VALIDATION: PASS"
        )

    else:

        print(
            "MULTI-CONTRACT VALIDATION: REVIEW REQUIRED"
        )


if __name__ == "__main__":

    main()