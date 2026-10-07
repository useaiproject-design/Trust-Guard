import re
from typing import Dict


# ============================================================
# Vulnerability Feature Names
# ============================================================

VULNERABILITY_FEATURES = [
    "mint_capability",
    "blacklist_capability",
    "pause_capability",
    "fee_change_capability",
    "owner_control",
    "upgradeability_risk",
    "external_call_pattern",
    "tx_origin_usage",
    "selfdestruct_capability",
    "arbitrary_external_call",
]


# ============================================================
# Helper Functions
# ============================================================

def count_pattern(pattern: str, source_code: str) -> int:
    """
    Count occurrences of a regular-expression pattern.
    """

    return len(
        re.findall(
            pattern,
            source_code,
            re.IGNORECASE
        )
    )


def count_functions(source_code: str) -> int:
    """
    Estimate the number of Solidity function declarations.
    """

    return count_pattern(
        r"\bfunction\s+\w+\s*\(",
        source_code
    )


def count_modifiers(source_code: str) -> int:
    """
    Estimate the number of Solidity modifier declarations.
    """

    return count_pattern(
        r"\bmodifier\s+\w+\s*\(",
        source_code
    )


def count_events(source_code: str) -> int:
    """
    Estimate the number of Solidity event declarations.
    """

    return count_pattern(
        r"\bevent\s+\w+\s*\(",
        source_code
    )


def count_contracts(source_code: str) -> int:
    """
    Count Solidity contract/interface/library declarations.
    """

    return count_pattern(
        r"\b(contract|interface|library)\s+\w+",
        source_code
    )


def count_external_functions(source_code: str) -> int:
    """
    Count functions explicitly declared as external.
    """

    return count_pattern(
        r"\bfunction\s+\w+\s*\([^)]*\)[^{;]*\bexternal\b",
        source_code
    )


def count_public_functions(source_code: str) -> int:
    """
    Count functions explicitly declared as public.
    """

    return count_pattern(
        r"\bfunction\s+\w+\s*\([^)]*\)[^{;]*\bpublic\b",
        source_code
    )


def count_payable_functions(source_code: str) -> int:
    """
    Count functions containing the payable modifier.
    """

    return count_pattern(
        r"\bfunction\s+\w+\s*\([^)]*\)[^{;]*\bpayable\b",
        source_code
    )


def count_state_variables(source_code: str) -> int:
    """
    Estimate state variable declarations.

    This is intentionally conservative because Solidity syntax
    can be complex. The value is treated as a model feature,
    not as a definitive parser result.
    """

    patterns = [
        r"\buint(?:8|16|32|64|128|256)?\s+(?:public\s+|private\s+|internal\s+)?\w+\s*(?:=|;)",
        r"\baddress\s+(?:public\s+|private\s+|internal\s+)?\w+\s*(?:=|;)",
        r"\bbool\s+(?:public\s+|private\s+|internal\s+)?\w+\s*(?:=|;)",
        r"\bstring\s+(?:public\s+|private\s+|internal\s+)?\w+\s*(?:=|;)",
    ]

    return sum(
        count_pattern(pattern, source_code)
        for pattern in patterns
    )


# ============================================================
# Main Feature Extraction Function
# ============================================================

def extract_features(
    source_code: str,
    vulnerabilities: list | None = None,
    onchain_data: Dict | None = None,
) -> Dict:
    """
    Convert smart-contract information into a structured
    feature dictionary suitable for machine-learning pipelines.

    Parameters
    ----------
    source_code:
        Verified Solidity source code.

    vulnerabilities:
        Structured findings returned by vulnerability_detector.py.

    onchain_data:
        Optional blockchain-derived features.

    Returns
    -------
    Dict
        Numerical feature vector.
    """

    if source_code is None:
        source_code = ""

    if vulnerabilities is None:
        vulnerabilities = []

    if onchain_data is None:
        onchain_data = {}

    # --------------------------------------------------------
    # Create lookup of detected vulnerability IDs
    # --------------------------------------------------------

    detected_ids = {
        vulnerability.get("id")
        for vulnerability in vulnerabilities
        if isinstance(vulnerability, dict)
    }

    # --------------------------------------------------------
    # Vulnerability Features
    # --------------------------------------------------------

    features = {}

    vulnerability_mapping = {
        "mint_capability": "MINT_CAPABILITY",
        "blacklist_capability": "BLACKLIST_CAPABILITY",
        "pause_capability": "PAUSE_CAPABILITY",
        "fee_change_capability": "FEE_CHANGE_CAPABILITY",
        "owner_control": "OWNER_CONTROL",
        "upgradeability_risk": "UPGRADEABILITY_RISK",
        "external_call_pattern": "EXTERNAL_CALL_PATTERN",
        "tx_origin_usage": "TX_ORIGIN_USAGE",
        "selfdestruct_capability": "SELFDESTRUCT_CAPABILITY",
        "arbitrary_external_call": "ARBITRARY_EXTERNAL_CALL",
    }

    for feature_name, vulnerability_id in vulnerability_mapping.items():
        features[feature_name] = int(
            vulnerability_id in detected_ids
        )

    # --------------------------------------------------------
    # Source-Code Structural Features
    # --------------------------------------------------------

    features["function_count"] = count_functions(source_code)

    features["modifier_count"] = count_modifiers(source_code)

    features["event_count"] = count_events(source_code)

    features["contract_count"] = count_contracts(source_code)

    features["external_function_count"] = count_external_functions(
        source_code
    )

    features["public_function_count"] = count_public_functions(
        source_code
    )

    features["payable_function_count"] = count_payable_functions(
        source_code
    )

    features["state_variable_count"] = count_state_variables(
        source_code
    )

    # --------------------------------------------------------
    # Code-Level Indicators
    # --------------------------------------------------------

    features["uses_delegatecall"] = int(
        bool(
            re.search(
                r"\bdelegatecall\s*\(",
                source_code,
                re.IGNORECASE
            )
        )
    )

    features["uses_low_level_call"] = int(
        bool(
            re.search(
                r"\.call\s*\{",
                source_code,
                re.IGNORECASE
            )
        )
    )

    features["uses_tx_origin"] = int(
        bool(
            re.search(
                r"\btx\.origin\b",
                source_code,
                re.IGNORECASE
            )
        )
    )

    features["uses_selfdestruct"] = int(
        bool(
            re.search(
                r"\bselfdestruct\s*\(|\bsuicide\s*\(",
                source_code,
                re.IGNORECASE
            )
        )
    )

    # --------------------------------------------------------
    # Source Code Size / Complexity Indicators
    # --------------------------------------------------------

    features["source_code_length"] = len(source_code)

    features["source_code_lines"] = len(
        source_code.splitlines()
    )

    features["comment_line_count"] = len(
        re.findall(
            r"//.*|/\*[\s\S]*?\*/",
            source_code
        )
    )

    # --------------------------------------------------------
    # On-chain Features
    # --------------------------------------------------------

    features["total_supply"] = float(
        onchain_data.get("total_supply", 0)
    )

    features["decimals"] = float(
        onchain_data.get("decimals", 0)
    )

    features["liquidity_pool_exists"] = int(
        bool(
            onchain_data.get(
                "liquidity_pool_exists",
                False
            )
        )
    )

    features["liquidity_burn_percentage"] = float(
        onchain_data.get(
            "liquidity_burn_percentage",
            0
        )
    )

    return features