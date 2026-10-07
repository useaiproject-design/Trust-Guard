import re
from typing import Any, Dict


# ============================================================
# TRUSTGUARD AI - ATTACK SURFACE ANALYZER
# ============================================================
#
# Purpose:
# Analyze the structural attack surface of a Solidity contract.
#
# Important:
# These checks identify capabilities and code patterns.
# They do NOT prove that a vulnerability is exploitable.
# ============================================================


# ============================================================
# Helper Functions
# ============================================================

def _count(pattern: str, source_code: str) -> int:
    """Count regex matches in Solidity source code."""
    return len(
        re.findall(
            pattern,
            source_code,
            re.IGNORECASE | re.MULTILINE
        )
    )


def _has(pattern: str, source_code: str) -> bool:
    """Return True when a regex pattern exists in the source."""
    return bool(
        re.search(
            pattern,
            source_code,
            re.IGNORECASE | re.MULTILINE
        )
    )


def _unique(items):
    """Preserve order while removing duplicates."""
    seen = set()
    result = []

    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)

    return result


# ============================================================
# Function Analysis
# ============================================================

def count_functions(source_code: str) -> int:
    """
    Count Solidity function declarations.

    This is a source-pattern estimate, not a full Solidity AST parse.
    """
    return _count(
        r"\bfunction\s+\w+\s*\(",
        source_code
    )


def count_public_functions(source_code: str) -> int:
    """Count explicitly public functions."""
    return _count(
        r"\bfunction\s+\w+\s*\([^)]*\)[^{;]*\bpublic\b",
        source_code
    )


def count_external_functions(source_code: str) -> int:
    """Count explicitly external functions."""
    return _count(
        r"\bfunction\s+\w+\s*\([^)]*\)[^{;]*\bexternal\b",
        source_code
    )


def count_payable_functions(source_code: str) -> int:
    """Count functions containing the payable modifier."""
    return _count(
        r"\bfunction\s+\w+\s*\([^)]*\)[^{;]*\bpayable\b",
        source_code
    )


def count_internal_functions(source_code: str) -> int:
    """Count explicitly internal functions."""
    return _count(
        r"\bfunction\s+\w+\s*\([^)]*\)[^{;]*\binternal\b",
        source_code
    )


def count_private_functions(source_code: str) -> int:
    """Count explicitly private functions."""
    return _count(
        r"\bfunction\s+\w+\s*\([^)]*\)[^{;]*\bprivate\b",
        source_code
    )


# ============================================================
# External Interaction Analysis
# ============================================================

def count_external_calls(source_code: str) -> int:
    """
    Estimate externally interacting call sites.

    Includes common Solidity patterns such as:
    - .call
    - .delegatecall
    - .staticcall
    - .transfer
    - .send
    """
    patterns = [
        r"\.\s*call\s*\{?",
        r"\.\s*delegatecall\s*\(",
        r"\.\s*staticcall\s*\(",
        r"\.\s*transfer\s*\(",
        r"\.\s*send\s*\("
    ]

    return sum(
        _count(pattern, source_code)
        for pattern in patterns
    )


def count_low_level_calls(source_code: str) -> int:
    """Count low-level call operations."""
    patterns = [
        r"\.\s*call\s*\{?",
        r"\.\s*delegatecall\s*\(",
        r"\.\s*staticcall\s*\("
    ]

    return sum(
        _count(pattern, source_code)
        for pattern in patterns
    )


# ============================================================
# Privileged / Access-Control Analysis
# ============================================================

def count_privileged_functions(source_code: str) -> int:
    """
    Estimate functions protected by common privileged-access patterns.
    """

    patterns = [
        r"\bonlyOwner\b",
        r"\bonlyAdmin\b",
        r"\bonlyRole\b",
        r"\bonlyMinter\b",
        r"\bonlyOperator\b",
        r"\bonlyGovernance\b",
        r"\bonlyController\b",
        r"\bonlyAuthorized\b",
        r"\bhasRole\s*\("
    ]

    return sum(
        _count(pattern, source_code)
        for pattern in patterns
    )


def detect_owner_control(source_code: str) -> bool:
    """
    Detect common owner/admin control patterns.
    """

    patterns = [
        r"\bOwnable\b",
        r"\bonlyOwner\b",
        r"\bowner\s*\(",
        r"\bowner\s*=",
        r"\b_transferOwnership\b",
        r"\brenounceOwnership\b",
        r"\b_admin\b",
        r"\badmin\s*=",
        r"\bonlyAdmin\b"
    ]

    return any(
        _has(pattern, source_code)
        for pattern in patterns
    )


def detect_role_based_access(source_code: str) -> bool:
    """Detect common role-based access-control patterns."""

    patterns = [
        r"\bAccessControl\b",
        r"\bhasRole\s*\(",
        r"\bgrantRole\s*\(",
        r"\brevokeRole\s*\(",
        r"\bonlyRole\b"
    ]

    return any(
        _has(pattern, source_code)
        for pattern in patterns
    )


# ============================================================
# Token Capability Analysis
# ============================================================

def detect_mint_capability(source_code: str) -> bool:
    """Detect common mint capability patterns."""

    patterns = [
        r"\bmint\s*\(",
        r"\b_mint\s*\(",
        r"\b_mint\b"
    ]

    return any(
        _has(pattern, source_code)
        for pattern in patterns
    )


def detect_burn_capability(source_code: str) -> bool:
    """Detect common burn capability patterns."""

    patterns = [
        r"\bburn\s*\(",
        r"\b_burn\s*\(",
        r"\b_burnFrom\s*\("
    ]

    return any(
        _has(pattern, source_code)
        for pattern in patterns
    )


def detect_pause_capability(source_code: str) -> bool:
    """Detect common pause/unpause mechanisms."""

    patterns = [
        r"\bPausable\b",
        r"\bpause\s*\(",
        r"\bunpause\s*\(",
        r"\b_paused\b",
        r"\bpaused\s*\("
    ]

    return any(
        _has(pattern, source_code)
        for pattern in patterns
    )


# ============================================================
# Upgradeability / Proxy Analysis
# ============================================================

def detect_upgradeability(source_code: str) -> bool:
    """Detect explicit upgradeability mechanisms.

    Generic words such as ``Proxy`` or ``implementation`` and raw
    delegatecall usage are intentionally excluded because they do not
    prove that the deployed contract is upgradeable.
    """

    patterns = [
        r"\bUUPSUpgradeable\b",
        r"\bTransparentUpgradeableProxy\b",
        r"\bERC1967Proxy\b",
        r"\bBeaconProxy\b",
        r"\bupgradeTo\s*\(",
        r"\bupgradeToAndCall\s*\(",
        r"\b_upgradeTo\s*\("
    ]

    return any(
        _has(pattern, source_code)
        for pattern in patterns
    )


def detect_proxy_pattern(source_code: str) -> bool:
    """Detect explicit proxy architecture patterns.

    Raw delegatecall usage is tracked separately and does not by itself
    establish that the contract is a proxy.
    """

    patterns = [
        r"\bTransparentUpgradeableProxy\b",
        r"\bERC1967Proxy\b",
        r"\bUUPSUpgradeable\b",
        r"\bBeaconProxy\b"
    ]

    return any(
        _has(pattern, source_code)
        for pattern in patterns
    )


# ============================================================
# Dangerous Operation Analysis
# ============================================================

def detect_delegatecall(source_code: str) -> bool:
    """Detect delegatecall usage."""
    return _has(
        r"\bdelegatecall\s*\(",
        source_code
    )


def detect_selfdestruct(source_code: str) -> bool:
    """Detect selfdestruct or legacy suicide usage."""
    return _has(
        r"\bselfdestruct\s*\(|\bsuicide\s*\(",
        source_code
    )


def detect_tx_origin(source_code: str) -> bool:
    """Detect tx.origin usage."""
    return _has(
        r"\btx\.origin\b",
        source_code
    )


# ============================================================
# Other Security-Relevant Patterns
# ============================================================

def count_events(source_code: str) -> int:
    """Count event declarations."""
    return _count(
        r"\bevent\s+\w+\s*\(",
        source_code
    )


def count_modifiers(source_code: str) -> int:
    """Count modifier declarations."""
    return _count(
        r"\bmodifier\s+\w+\s*\(",
        source_code
    )


def count_loops(source_code: str) -> int:
    """Count common loop constructs."""
    return _count(
        r"\b(for|while|do)\s*\(",
        source_code
    )


def detect_randomness_usage(source_code: str) -> bool:
    """Detect common randomness-related patterns."""

    patterns = [
        r"\bblock\.prevrandao\b",
        r"\bblockhash\s*\(",
        r"\bkeccak256\s*\(",
        r"\brandom\b"
    ]

    return any(
        _has(pattern, source_code)
        for pattern in patterns
    )


def detect_timestamp_usage(source_code: str) -> bool:
    """Detect block timestamp usage."""
    return _has(
        r"\bblock\.timestamp\b",
        source_code
    )


def detect_arithmetic_operations(source_code: str) -> int:
    """
    Estimate arithmetic operations.

    This is an indicator only and does not identify arithmetic
    vulnerabilities by itself.
    """

    patterns = [
        r"\+",
        r"-",
        r"\*",
        r"/",
        r"%"
    ]

    return sum(
        _count(pattern, source_code)
        for pattern in patterns
    )


# ============================================================
# Capability Evidence
# ============================================================

def _build_capability(
    name: str,
    detected: bool,
    explanation: str
) -> Dict[str, Any]:
    """
    Create a standardized capability object.
    """

    return {
        "name": name,
        "detected": bool(detected),
        "status": "YES" if detected else "NO",
        "explanation": explanation
    }


# ============================================================
# Main Attack Surface Analyzer
# ============================================================

def analyze_attack_surface(source_code: str) -> Dict[str, Any]:
    """
    Analyze the structural attack surface of a Solidity contract.

    Returns:
        {
            "success": True,
            "attack_surface": {...},
            "capabilities": [...],
            "summary": "...",
            "limitations": [...]
        }
    """

    source_code = source_code or ""

    if not source_code.strip():
        return {
            "success": False,
            "error": "No Solidity source code was provided.",
            "attack_surface": {},
            "capabilities": [],
            "summary": "",
            "limitations": [
                "Attack-surface analysis requires available Solidity source code."
            ]
        }

    # --------------------------------------------------------
    # Core structural measurements
    # --------------------------------------------------------

    total_functions = count_functions(source_code)
    public_functions = count_public_functions(source_code)
    external_functions = count_external_functions(source_code)
    payable_functions = count_payable_functions(source_code)
    internal_functions = count_internal_functions(source_code)
    private_functions = count_private_functions(source_code)

    external_calls = count_external_calls(source_code)
    low_level_calls = count_low_level_calls(source_code)
    privileged_functions = count_privileged_functions(source_code)

    modifiers = count_modifiers(source_code)
    events = count_events(source_code)
    loops = count_loops(source_code)

    owner_control = detect_owner_control(source_code)
    role_based_access = detect_role_based_access(source_code)

    mint_capability = detect_mint_capability(source_code)
    burn_capability = detect_burn_capability(source_code)
    pause_capability = detect_pause_capability(source_code)

    upgradeability = detect_upgradeability(source_code)
    proxy_pattern = detect_proxy_pattern(source_code)

    delegatecall = detect_delegatecall(source_code)
    selfdestruct = detect_selfdestruct(source_code)
    tx_origin = detect_tx_origin(source_code)

    randomness = detect_randomness_usage(source_code)
    timestamp = detect_timestamp_usage(source_code)
    arithmetic_operations = detect_arithmetic_operations(source_code)

    # --------------------------------------------------------
    # Capability objects
    # --------------------------------------------------------

    capabilities = [
        _build_capability(
            "Mint Capability",
            mint_capability,
            "The source contains mint-related functions or patterns."
        ),
        _build_capability(
            "Burn Capability",
            burn_capability,
            "The source contains burn-related functions or patterns."
        ),
        _build_capability(
            "Pause Capability",
            pause_capability,
            "The source contains pause/unpause mechanisms or OpenZeppelin Pausable patterns."
        ),
        _build_capability(
            "Owner Control",
            owner_control,
            "The source contains owner/admin control patterns."
        ),
        _build_capability(
            "Role-Based Access Control",
            role_based_access,
            "The source contains role-based authorization patterns."
        ),
        _build_capability(
            "Upgradeability",
            upgradeability,
            "The source contains common upgradeable-contract patterns."
        ),
        _build_capability(
            "Proxy Pattern",
            proxy_pattern,
            "The source contains proxy/delegatecall-related patterns."
        ),
        _build_capability(
            "Delegatecall",
            delegatecall,
            "The source contains delegatecall usage."
        ),
        _build_capability(
            "Selfdestruct",
            selfdestruct,
            "The source contains selfdestruct or legacy suicide usage."
        ),
        _build_capability(
            "tx.origin",
            tx_origin,
            "The source reads tx.origin."
        )
    ]

    # --------------------------------------------------------
    # Security indicators
    # --------------------------------------------------------

    security_indicators = []

    if payable_functions > 0:
        security_indicators.append(
            "The contract contains payable functions that can receive native cryptocurrency."
        )

    if external_calls > 0:
        security_indicators.append(
            "The contract contains external interaction points that deserve review."
        )

    if privileged_functions > 0:
        security_indicators.append(
            "Privileged access patterns were identified."
        )

    if upgradeability:
        security_indicators.append(
            "Upgradeability-related patterns were identified."
        )

    if delegatecall:
        security_indicators.append(
            "Delegatecall is present and should receive focused review."
        )

    if selfdestruct:
        security_indicators.append(
            "A selfdestruct-related capability was identified."
        )

    if tx_origin:
        security_indicators.append(
            "tx.origin usage was identified."
        )

    if loops > 0:
        security_indicators.append(
            "Loop constructs were identified and may warrant gas/DoS review depending on their bounds."
        )

    # --------------------------------------------------------
    # Beginner explanation
    # --------------------------------------------------------

    explanation_parts = []

    if total_functions > 0:
        explanation_parts.append(
            f"The contract exposes {public_functions + external_functions} "
            f"explicitly public or external functions."
        )

    if privileged_functions > 0:
        explanation_parts.append(
            f"{privileged_functions} function-level privileged access patterns were identified."
        )

    if external_calls > 0:
        explanation_parts.append(
            f"{external_calls} external interaction patterns were identified."
        )

    if mint_capability:
        explanation_parts.append(
            "The contract appears to have the ability to mint tokens."
        )

    if pause_capability:
        explanation_parts.append(
            "The contract appears to have a pause capability."
        )

    if upgradeability:
        explanation_parts.append(
            "Upgradeability-related patterns were identified, so implementation-control paths deserve review."
        )

    if not explanation_parts:
        explanation_parts.append(
            "No major attack-surface capability was identified by these source-pattern checks."
        )

    summary = " ".join(explanation_parts)

    # --------------------------------------------------------
    # Final structured result
    # --------------------------------------------------------

    attack_surface = {
        "public_functions": public_functions,
        "external_functions": external_functions,
        "payable_functions": payable_functions,
        "internal_functions": internal_functions,
        "private_functions": private_functions,
        "total_functions": total_functions,

        "external_calls": external_calls,
        "low_level_calls": low_level_calls,
        "privileged_functions": privileged_functions,

        "modifiers": modifiers,
        "events": events,
        "loops": loops,

        "mint_capability": mint_capability,
        "burn_capability": burn_capability,
        "pause_capability": pause_capability,

        "owner_control": owner_control,
        "role_based_access": role_based_access,

        "upgradeability": upgradeability,
        "proxy_pattern": proxy_pattern,

        "delegatecall": delegatecall,
        "selfdestruct": selfdestruct,
        "tx_origin": tx_origin,

        "randomness_usage": randomness,
        "timestamp_usage": timestamp,
        "arithmetic_operation_count": arithmetic_operations,

        "security_indicators": security_indicators
    }

    return {
        "success": True,
        "attack_surface": attack_surface,
        "capabilities": capabilities,
        "summary": summary,
        "limitations": [
            "Results are based on source-code pattern analysis.",
            "Pattern detection does not prove exploitability.",
            "A complete Solidity AST or manual audit may identify additional behavior.",
            "Proxy and upgradeability detection depends on the available source code."
        ]
    }


# ============================================================
# Simple Local Test
# ============================================================

if __name__ == "__main__":

    sample_contract = """
    pragma solidity ^0.8.20;

    contract SampleToken {

        address public owner;

        function mint(address to, uint256 amount)
            external
            onlyOwner
        {
        }

        function burn(uint256 amount)
            public
        {
        }

        function deposit()
            external
            payable
        {
        }

        function withdraw()
            external
        {
            payable(msg.sender).transfer(1 ether);
        }

        function upgradeTo(address implementation)
            external
            onlyOwner
        {
        }

        function execute(address target, bytes calldata data)
            external
            onlyOwner
        {
            target.delegatecall(data);
        }
    }
    """

    result = analyze_attack_surface(sample_contract)

    print("=" * 70)
    print("TRUSTGUARD AI - ATTACK SURFACE ANALYZER")
    print("=" * 70)

    print("\nSuccess:")
    print(result["success"])

    print("\nAttack Surface:")
    for key, value in result["attack_surface"].items():
        if key != "security_indicators":
            print(f"  {key}: {value}")

    print("\nCapabilities:")
    for capability in result["capabilities"]:
        print(
            f"  {capability['name']}: "
            f"{capability['status']}"
        )

    print("\nSummary:")
    print(result["summary"])

    print("\nLimitations:")
    for limitation in result["limitations"]:
        print(f"  - {limitation}")