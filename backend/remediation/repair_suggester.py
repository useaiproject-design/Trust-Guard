from typing import Dict, List


# ============================================================
# TRUSTGUARD AI - SECURE CODE REPAIR SUGGESTIONS
# ============================================================

REPAIR_PATTERNS: Dict[str, Dict[str, str]] = {
    "Reentrancy": {
        "title": "Protect external calls against reentrancy",
        "problem": (
            "An external call may allow control flow to return to the "
            "contract before state updates are completed."
        ),
        "recommendation": (
            "Apply the Checks-Effects-Interactions pattern and consider "
            "a reentrancy guard for sensitive functions."
        ),
        "secure_pattern": (
            "function withdraw(uint256 amount) external nonReentrant {\n"
            "    require(balance[msg.sender] >= amount, "
            "\"Insufficient balance\");\n"
            "    balance[msg.sender] -= amount;\n"
            "    (bool success, ) = msg.sender.call{value: amount}(\"\");\n"
            "    require(success, \"Transfer failed\");\n"
            "}"
        ),
    },

    "Access Control": {
        "title": "Strengthen access control",
        "problem": (
            "A sensitive function may be callable by an unauthorized "
            "account or may have insufficient privilege restrictions."
        ),
        "recommendation": (
            "Restrict privileged functions with an appropriate access "
            "control mechanism such as onlyOwner or role-based access."
        ),
        "secure_pattern": (
            "function sensitiveOperation() external onlyOwner {\n"
            "    // restricted operation\n"
            "}"
        ),
    },

    "Arithmetic": {
        "title": "Protect arithmetic operations",
        "problem": (
            "Arithmetic operations may produce incorrect results or "
            "unexpected behavior when values exceed expected bounds."
        ),
        "recommendation": (
            "Use Solidity 0.8+ checked arithmetic where appropriate and "
            "explicitly validate important numerical boundaries."
        ),
        "secure_pattern": (
            "require(amount <= MAX_AMOUNT, \"Amount exceeds limit\");\n"
            "uint256 newBalance = balance + amount;"
        ),
    },

    "Unchecked Return Values": {
        "title": "Check external call return values",
        "problem": (
            "An external operation may fail while execution continues "
            "without handling the failure."
        ),
        "recommendation": (
            "Explicitly verify boolean return values and handle failed "
            "external operations."
        ),
        "secure_pattern": (
            "(bool success, ) = target.call(data);\n"
            "require(success, \"External call failed\");"
        ),
    },

    "DoS": {
        "title": "Reduce denial-of-service risk",
        "problem": (
            "A loop, external call, or state dependency may allow an "
            "attacker to prevent normal contract execution."
        ),
        "recommendation": (
            "Avoid unbounded loops, minimize external calls inside loops, "
            "and use pull-based patterns where appropriate."
        ),
        "secure_pattern": (
            "function withdraw() external {\n"
            "    uint256 amount = pending[msg.sender];\n"
            "    pending[msg.sender] = 0;\n"
            "    (bool success, ) = msg.sender.call{value: amount}(\"\");\n"
            "    require(success, \"Transfer failed\");\n"
            "}"
        ),
    },

    "Bad Randomness": {
        "title": "Use secure randomness design",
        "problem": (
            "Blockchain-visible values such as block timestamp or "
            "block-related data may be predictable."
        ),
        "recommendation": (
            "Do not rely on block.timestamp, blockhash, or similar public "
            "blockchain values for security-sensitive randomness. Use a "
            "suitable verifiable randomness mechanism instead."
        ),
        "secure_pattern": (
            "// Use a trusted verifiable randomness provider\n"
            "// instead of block.timestamp or blockhash\n"
            "// for security-critical randomness."
        ),
    },

    "Front Running": {
        "title": "Mitigate transaction ordering risks",
        "problem": (
            "A sensitive transaction may be observable in the public "
            "mempool before execution."
        ),
        "recommendation": (
            "Consider commit-reveal schemes, slippage limits, deadlines, "
            "or other mechanisms appropriate to the application's "
            "threat model."
        ),
        "secure_pattern": (
            "// Example design:\n"
            "// 1. Commit a hashed action.\n"
            "// 2. Reveal the action later.\n"
            "// 3. Verify the commitment before execution."
        ),
    },

    "Time manipulation": {
        "title": "Reduce timestamp dependence",
        "problem": (
            "Contract behavior may depend heavily on block timestamps, "
            "which miners or validators can influence within protocol limits."
        ),
        "recommendation": (
            "Avoid using block.timestamp as a source of security-critical "
            "randomness and avoid overly precise timing assumptions."
        ),
        "secure_pattern": (
            "require(block.timestamp >= unlockTime, "
            "\"Tokens are still locked\");"
        ),
    },

    # --------------------------------------------------------
    # Static analyzer findings
    # --------------------------------------------------------

    "MINT_CAPABILITY": {
        "title": "Restrict and cap minting authority",
        "problem": (
            "The contract contains minting functionality that may allow "
            "additional tokens to be created."
        ),
        "recommendation": (
            "Restrict minting to a trusted role and enforce an explicit "
            "maximum supply or minting limit. Consider governance or "
            "timelock controls for privileged mint operations."
        ),
        "secure_pattern": (
            "uint256 public constant MAX_SUPPLY = 1_000_000 ether;\n\n"
            "function mint(address to, uint256 amount) external onlyOwner {\n"
            "    require(\n"
            "        totalSupply() + amount <= MAX_SUPPLY,\n"
            "        \"Maximum supply exceeded\"\n"
            "    );\n"
            "    _mint(to, amount);\n"
            "}"
        ),
    },

    "PAUSE_CAPABILITY": {
        "title": "Restrict emergency pause authority",
        "problem": (
            "The contract contains functionality that may pause "
            "contract operations."
        ),
        "recommendation": (
            "Restrict pause and unpause operations to a dedicated "
            "authorized role and define clear emergency governance."
        ),
        "secure_pattern": (
            "function pause() external onlyOwner {\n"
            "    _pause();\n"
            "}\n\n"
            "function unpause() external onlyOwner {\n"
            "    _unpause();\n"
            "}"
        ),
    },

    "FEE_CHANGE_CAPABILITY": {
        "title": "Restrict and limit fee changes",
        "problem": (
            "The contract contains functionality that may allow "
            "transaction or token fees to be modified."
        ),
        "recommendation": (
            "Restrict fee changes to an authorized role and enforce a "
            "reasonable maximum fee so privileged accounts cannot set "
            "an abusive value."
        ),
        "secure_pattern": (
            "uint256 public constant MAX_FEE = 500; // 5.00%\n\n"
            "function setFee(uint256 newFee) external onlyOwner {\n"
            "    require(newFee <= MAX_FEE, \"Fee exceeds maximum\");\n"
            "    fee = newFee;\n"
            "}"
        ),
    },

    "EXTERNAL_CALL_PATTERN": {
        "title": "Protect external contract calls",
        "problem": (
            "The contract contains an external call pattern that may "
            "introduce reentrancy or unexpected control-flow risks."
        ),
        "recommendation": (
            "Validate external call targets, update internal state before "
            "external interaction where possible, and consider a "
            "reentrancy guard for sensitive functions."
        ),
        "secure_pattern": (
            "function executeCall(\n"
            "    address target,\n"
            "    bytes calldata data\n"
            ") external onlyOwner nonReentrant {\n"
            "    require(target != address(0), \"Invalid target\");\n"
            "    (bool success, bytes memory result) = target.call(data);\n"
            "    require(success, \"External call failed\");\n"
            "}"
        ),
    },

    "ARBITRARY_EXTERNAL_CALL": {
        "title": "Restrict and validate external call targets",
        "problem": (
            "A low-level external call may use a target controlled by "
            "contract state, proposal data, or other input. Static "
            "analysis does not by itself prove exploitability."
        ),
        "recommendation": (
            "Restrict callable targets to explicitly authorized addresses "
            "or approved interfaces, validate call data and transferred "
            "value, enforce authorization before execution, and review "
            "the interaction for reentrancy and governance risks."
        ),
        "secure_pattern": (
            "function executeCall(\\n"
            "    address target,\\n"
            "    bytes calldata data,\\n"
            "    uint256 value\\n"
            ") external onlyOwner nonReentrant {\\n"
            "    require(approvedTarget[target], \"Target not approved\");\\n"
            "    (bool success, ) = target.call{value: value}(data);\\n"
            "    require(success, \"External call failed\");\\n"
            "}"
        ),
    },

    "BLACKLIST_CAPABILITY": {
        "title": "Govern and constrain address restrictions",
        "problem": (
            "The contract can restrict specific addresses or token "
            "transfers. This is a centralization or access-control "
            "capability and is not automatically malicious."
        ),
        "recommendation": (
            "Restrict who can create or modify address restrictions, "
            "define transparent blocking conditions, enforce appropriate "
            "expiry or recovery mechanisms, and ensure governance actions "
            "cannot be used for arbitrary censorship."
        ),
        "secure_pattern": (
            "function setBlocked(address account, bool blocked) "
            "external onlyGovernance {\\n"
            "    require(account != address(0), \"Invalid account\");\\n"
            "    blockedAccounts[account] = blocked;\\n"
            "    emit AddressRestrictionUpdated(account, blocked);\\n"
            "}"
        ),
    },

    "UNLOCKED_LIQUIDITY": {
        "title": "Secure and lock liquidity",
        "problem": (
            "Liquidity provider tokens appear to remain largely unlocked, "
            "which may allow liquidity to be withdrawn by the liquidity provider."
        ),
        "recommendation": (
            "Review the liquidity-management design and consider locking "
            "liquidity for an appropriate period or burning liquidity provider "
            "tokens when permanent liquidity is intended. Verify the lock or "
            "burn mechanism independently before deployment."
        ),
        "secure_pattern": (
            "// Example design guidance:\n"
            "// 1. Use a transparent liquidity-lock mechanism.\n"
            "// 2. Restrict withdrawal until the unlock time.\n"
            "// 3. If liquidity is intended to be permanent, consider burning LP tokens.\n"
            "// 4. Verify LP token ownership and the lock contract on-chain."
        ),
    },
}


# ============================================================
# Vulnerability name normalization
# ============================================================

def normalize_vulnerability_name(vulnerability: str) -> str:
    if not vulnerability:
        return ""

    normalized = vulnerability.strip()

    if normalized in REPAIR_PATTERNS:
        return normalized

    alias_map = {
        "Mint Capability": "MINT_CAPABILITY",
        "Pause Capability": "PAUSE_CAPABILITY",
        "Fee Change Capability": "FEE_CHANGE_CAPABILITY",
        "External Call Pattern": "EXTERNAL_CALL_PATTERN",
        "Arbitrary External Call": "ARBITRARY_EXTERNAL_CALL",
        "Arbitrary ExternalCall": "ARBITRARY_EXTERNAL_CALL",
        "Blacklist Capability": "BLACKLIST_CAPABILITY",
        "Address Blocking Capability": "BLACKLIST_CAPABILITY",
        "Unlocked Liquidity": "UNLOCKED_LIQUIDITY",
    }

    if normalized in alias_map:
        return alias_map[normalized]

    return normalized.upper().replace(" ", "_")


# ============================================================
# Generate one repair suggestion
# ============================================================

def generate_repair_suggestion(
    vulnerability: str,
    severity: str = "MEDIUM",
    probability: float = 0.0,
) -> Dict:

    normalized_name = normalize_vulnerability_name(vulnerability)
    pattern = REPAIR_PATTERNS.get(normalized_name)

    if pattern is None:
        return {
            "vulnerability": vulnerability,
            "severity": severity,
            "probability": round(probability, 4),
            "title": "Manual security review required",
            "problem": (
                "No predefined remediation pattern is available "
                "for this vulnerability."
            ),
            "recommendation": (
                "Review the affected code with a qualified security "
                "reviewer before deployment."
            ),
            "secure_pattern": None,
            "ai_ready": False,
        }

    return {
        "vulnerability": vulnerability,
        "severity": severity,
        "probability": round(probability, 4),
        "title": pattern["title"],
        "problem": pattern["problem"],
        "recommendation": pattern["recommendation"],
        "secure_pattern": pattern["secure_pattern"],
        "ai_ready": True,
    }


# ============================================================
# Generate repair suggestions for prioritized findings
# ============================================================

def generate_repair_suggestions(
    vulnerabilities: List[Dict],
) -> List[Dict]:

    suggestions = []

    for vulnerability in vulnerabilities:
        if not vulnerability.get("detected", True):
            continue

        suggestion = generate_repair_suggestion(
            vulnerability=vulnerability.get("vulnerability", ""),
            severity=vulnerability.get("severity", "MEDIUM"),
            probability=float(vulnerability.get("probability", 0)),
        )

        suggestion["priority"] = vulnerability.get("priority")
        suggestion["priority_score"] = vulnerability.get("priority_score")

        suggestions.append(suggestion)

    suggestions.sort(
        key=lambda item: (
            item["priority"] is None,
            item["priority"] if item["priority"] is not None else 999,
        )
    )

    return suggestions


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("TRUSTGUARD AI - SECURE CODE REPAIR TEST")
    print("=" * 70)

    test_vulnerabilities = [
        {
            "vulnerability": "Mint Capability",
            "probability": 1.0,
            "severity": "HIGH",
            "priority": 1,
            "priority_score": 90.0,
            "detected": True,
        },
        {
            "vulnerability": "External Call Pattern",
            "probability": 1.0,
            "severity": "MEDIUM",
            "priority": 2,
            "priority_score": 78.0,
            "detected": True,
        },
        {
            "vulnerability": "Fee Change Capability",
            "probability": 1.0,
            "severity": "MEDIUM",
            "priority": 3,
            "priority_score": 76.0,
            "detected": True,
        },
        {
            "vulnerability": "Pause Capability",
            "probability": 1.0,
            "severity": "MEDIUM",
            "priority": 4,
            "priority_score": 72.0,
            "detected": True,
        },
        {
            "vulnerability": "Unlocked Liquidity",
            "probability": 1.0,
            "severity": "MEDIUM",
            "priority": 5,
            "priority_score": 70.0,
            "detected": True,
        },
        {
            "vulnerability": "Reentrancy",
            "probability": 0.93,
            "severity": "CRITICAL",
            "priority": 6,
            "priority_score": 97.9,
            "detected": True,
        },
    ]

    results = generate_repair_suggestions(test_vulnerabilities)

    for result in results:
        print()
        print(f"Priority {result['priority']}")
        print(f"Vulnerability: {result['vulnerability']}")
        print(f"Severity: {result['severity']}")
        print(f"Probability: {result['probability']:.2%}")
        print(f"Title: {result['title']}")
        print()
        print("Problem:")
        print(result["problem"])
        print()
        print("Recommendation:")
        print(result["recommendation"])
        print()
        print("Secure pattern:")
        print(result["secure_pattern"])
        print()
        print(f"AI Ready: {result['ai_ready']}")

    print()
    print("=" * 70)
    print("SECURE CODE REPAIR TEST COMPLETE")
    print("=" * 70)