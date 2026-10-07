"""
TrustGuard AI - Security Evidence Engine

Purpose:
    Convert detected security signals into structured, traceable evidence.

Important:
    Evidence is not the same as exploitability.
    This module reports observable source-code/on-chain indicators
    and the reasoning behind them.

The engine is intentionally conservative:
    - It does not claim that a contract is exploitable.
    - It does not invent evidence.
    - It works from information already available to TrustGuard.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# ============================================================
# Evidence helpers
# ============================================================

def _clean_text(value: Any) -> str:
    """Safely convert a value to readable text."""
    if value is None:
        return ""

    return str(value).strip()


def _make_evidence(
    *,
    evidence_type: str,
    title: str,
    description: str,
    source: str = "source_code",
    confidence: str = "medium",
    location: Optional[str] = None,
    related_finding: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create one standardized evidence object.
    """

    evidence = {
        "type": evidence_type,
        "title": title,
        "description": description,
        "source": source,
        "confidence": confidence,
    }

    if location:
        evidence["location"] = location

    if related_finding:
        evidence["related_finding"] = related_finding

    return evidence


# ============================================================
# Source-code evidence
# ============================================================

def extract_source_evidence(
    source_code: str,
    static_findings: Optional[List[Dict[str, Any]]] = None,
    attack_surface: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Extract observable security evidence from Solidity source.

    This function deliberately uses conservative pattern matching.
    It identifies indicators; it does not prove vulnerabilities.
    """

    source = _clean_text(source_code)

    if not source:
        return []

    evidence: List[Dict[str, Any]] = []

    # --------------------------------------------------------
    # External calls
    # --------------------------------------------------------

    external_call_matches = re.findall(
        r"\.\s*(call|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\(",
        source,
        flags=re.IGNORECASE,
    )

    if external_call_matches:
        evidence.append(
            _make_evidence(
                evidence_type="external_interaction",
                title="Low-level external interaction detected",
                description=(
                    f"The source contains {len(external_call_matches)} "
                    "low-level call/delegatecall/staticcall pattern(s). "
                    "These interactions should be reviewed for call ordering, "
                    "return-value handling, and authorization."
                ),
                confidence="high",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Delegatecall
    # --------------------------------------------------------

    delegatecall_count = len(
        re.findall(
            r"\.\s*delegatecall\s*\(",
            source,
            flags=re.IGNORECASE,
        )
    )

    if delegatecall_count:
        evidence.append(
            _make_evidence(
                evidence_type="delegatecall",
                title="delegatecall usage detected",
                description=(
                    f"The source contains {delegatecall_count} "
                    "delegatecall pattern(s). Delegatecall executes code "
                    "using the caller's storage context and therefore "
                    "requires careful implementation and authorization review."
                ),
                confidence="high",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # tx.origin
    # --------------------------------------------------------

    tx_origin_count = len(
        re.findall(
            r"\btx\s*\.\s*origin\b",
            source,
            flags=re.IGNORECASE,
        )
    )

    if tx_origin_count:
        evidence.append(
            _make_evidence(
                evidence_type="authentication_pattern",
                title="tx.origin usage detected",
                description=(
                    f"The source references tx.origin {tx_origin_count} time(s). "
                    "Authentication logic using tx.origin should be reviewed "
                    "because intermediary contracts can affect the caller chain."
                ),
                confidence="high",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # block.timestamp
    # --------------------------------------------------------

    timestamp_count = len(
        re.findall(
            r"\bblock\s*\.\s*timestamp\b",
            source,
            flags=re.IGNORECASE,
        )
    )

    if timestamp_count:
        evidence.append(
            _make_evidence(
                evidence_type="timestamp_dependency",
                title="Block timestamp dependency detected",
                description=(
                    f"The source references block.timestamp {timestamp_count} "
                    "time(s). Timestamp-dependent logic should be reviewed "
                    "for assumptions about precision and miner/validator influence."
                ),
                confidence="medium",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Randomness-related patterns
    # --------------------------------------------------------

    randomness_patterns = [
        r"\bblock\s*\.\s*prevrandao\b",
        r"\bblockhash\s*\(",
        r"\bkeccak256\s*\(",
    ]

    randomness_count = 0

    for pattern in randomness_patterns:
        randomness_count += len(
            re.findall(
                pattern,
                source,
                flags=re.IGNORECASE,
            )
        )

    if randomness_count:
        evidence.append(
            _make_evidence(
                evidence_type="randomness",
                title="Randomness-related pattern detected",
                description=(
                    f"The source contains {randomness_count} "
                    "randomness-related pattern(s). If these values influence "
                    "security-sensitive decisions, their unpredictability "
                    "should be reviewed."
                ),
                confidence="medium",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Selfdestruct
    # --------------------------------------------------------

    selfdestruct_count = len(
        re.findall(
            r"\b(selfdestruct|suicide)\s*\(",
            source,
            flags=re.IGNORECASE,
        )
    )

    if selfdestruct_count:
        evidence.append(
            _make_evidence(
                evidence_type="contract_lifecycle",
                title="Contract destruction capability detected",
                description=(
                    f"The source contains {selfdestruct_count} "
                    "selfdestruct/suicide pattern(s). The authorization "
                    "and operational consequences should be reviewed."
                ),
                confidence="high",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Payable functions
    # --------------------------------------------------------

    payable_count = len(
        re.findall(
            r"\bfunction\b[\s\S]{0,500}?\bpayable\b",
            source,
            flags=re.IGNORECASE,
        )
    )

    if payable_count:
        evidence.append(
            _make_evidence(
                evidence_type="value_handling",
                title="Payable function detected",
                description=(
                    f"The source contains approximately {payable_count} "
                    "payable function declaration(s). Ether/value-handling "
                    "paths should be reviewed for authorization and accounting."
                ),
                confidence="medium",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Owner/admin controls
    # --------------------------------------------------------

    owner_patterns = [
        r"\bonlyOwner\b",
        r"\bowner\s*\(",
        r"\btransferOwnership\b",
        r"\brenounceOwnership\b",
        r"\bonlyAdmin\b",
        r"\badmin\b",
    ]

    owner_matches = 0

    for pattern in owner_patterns:
        owner_matches += len(
            re.findall(
                pattern,
                source,
                flags=re.IGNORECASE,
            )
        )

    if owner_matches:
        evidence.append(
            _make_evidence(
                evidence_type="access_control",
                title="Privileged access-control pattern detected",
                description=(
                    f"The source contains {owner_matches} owner/admin-related "
                    "pattern(s). Privileged operations should be reviewed "
                    "for authorization scope and administrative trust assumptions."
                ),
                confidence="high",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Mint capability
    # --------------------------------------------------------

    mint_matches = re.findall(
        r"\b(?:mint|_mint|mintTokens|issue)\b",
        source,
        flags=re.IGNORECASE,
    )

    if mint_matches:
        evidence.append(
            _make_evidence(
                evidence_type="token_control",
                title="Mint-related capability detected",
                description=(
                    "The source contains mint-related function or identifier "
                    "patterns. The authorization and supply-control logic "
                    "should be reviewed."
                ),
                confidence="medium",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Burn capability
    # --------------------------------------------------------

    burn_matches = re.findall(
        r"\b(?:burn|_burn|burnFrom)\b",
        source,
        flags=re.IGNORECASE,
    )

    if burn_matches:
        evidence.append(
            _make_evidence(
                evidence_type="token_control",
                title="Burn-related capability detected",
                description=(
                    "The source contains burn-related function or identifier "
                    "patterns. The authorization and accounting behavior "
                    "should be reviewed."
                ),
                confidence="medium",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Pause capability
    # --------------------------------------------------------

    pause_matches = re.findall(
        r"\b(?:pause|unpause|whenNotPaused|whenPaused)\b",
        source,
        flags=re.IGNORECASE,
    )

    if pause_matches:
        evidence.append(
            _make_evidence(
                evidence_type="emergency_control",
                title="Pause-related mechanism detected",
                description=(
                    "The source contains pause/unpause-related patterns. "
                    "The authority controlling emergency state changes "
                    "should be reviewed."
                ),
                confidence="medium",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Upgradeability
    # --------------------------------------------------------

    upgrade_patterns = [
        r"\bupgradeTo\b",
        r"\bupgradeToAndCall\b",
        r"\bimplementation\b",
        r"\bProxy\b",
        r"\bTransparentUpgradeableProxy\b",
        r"\bUUPS\b",
        r"\bERC1967\b",
    ]

    upgrade_matches = 0

    for pattern in upgrade_patterns:
        upgrade_matches += len(
            re.findall(
                pattern,
                source,
                flags=re.IGNORECASE,
            )
        )

    if upgrade_matches:
        evidence.append(
            _make_evidence(
                evidence_type="upgradeability",
                title="Upgradeability-related pattern detected",
                description=(
                    f"The source contains {upgrade_matches} "
                    "upgradeability-related pattern(s). Implementation "
                    "control, upgrade authorization, and proxy storage "
                    "behavior should be reviewed."
                ),
                confidence="high",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Loops
    # --------------------------------------------------------

    loop_count = len(
        re.findall(
            r"\b(for|while)\s*\(",
            source,
            flags=re.IGNORECASE,
        )
    )

    if loop_count:
        evidence.append(
            _make_evidence(
                evidence_type="loop",
                title="Loop construct detected",
                description=(
                    f"The source contains {loop_count} loop construct(s). "
                    "Loop bounds and gas consumption should be reviewed, "
                    "especially when iterating over user-controlled data."
                ),
                confidence="medium",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Modifiers
    # --------------------------------------------------------

    modifier_count = len(
        re.findall(
            r"\bmodifier\s+\w+",
            source,
            flags=re.IGNORECASE,
        )
    )

    if modifier_count:
        evidence.append(
            _make_evidence(
                evidence_type="access_control",
                title="Solidity modifiers detected",
                description=(
                    f"The source contains {modifier_count} modifier "
                    "declaration(s). Modifier logic should be reviewed "
                    "because modifiers can enforce authorization and state conditions."
                ),
                confidence="medium",
                location="source_code",
            )
        )

    # --------------------------------------------------------
    # Events
    # --------------------------------------------------------

    event_count = len(
        re.findall(
            r"\bevent\s+\w+",
            source,
            flags=re.IGNORECASE,
        )
    )

    if event_count:
        evidence.append(
            _make_evidence(
                evidence_type="observability",
                title="Event declarations detected",
                description=(
                    f"The source contains {event_count} event declaration(s). "
                    "Events can provide useful audit and monitoring signals "
                    "for state-changing operations."
                ),
                confidence="medium",
                location="source_code",
            )
        )

    return evidence


# ============================================================
# Finding correlation
# ============================================================

def correlate_findings_with_evidence(
    static_findings: Optional[List[Dict[str, Any]]],
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Attach relevant evidence to existing static findings.

    This does not create new vulnerability claims.
    """

    findings = static_findings or []

    if not findings:
        return []

    correlated: List[Dict[str, Any]] = []

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        finding_copy = dict(finding)

        finding_name = _clean_text(
            finding.get("name")
            or finding.get("title")
            or finding.get("vulnerability")
            or finding.get("type")
        )

        finding_text = (
            finding_name + " " +
            _clean_text(finding.get("description"))
        ).lower()

        matched_evidence = []

        for item in evidence:

            evidence_text = (
                _clean_text(item.get("title")) + " " +
                _clean_text(item.get("description"))
            ).lower()

            # Conservative keyword association.
            keywords = []

            if any(
                word in finding_text
                for word in [
                    "reentrancy",
                    "external call",
                    "call",
                ]
            ):
                keywords.extend(
                    [
                        "external",
                        "delegatecall",
                        "call",
                    ]
                )

            if any(
                word in finding_text
                for word in [
                    "access control",
                    "authorization",
                    "owner",
                    "privilege",
                ]
            ):
                keywords.extend(
                    [
                        "access-control",
                        "owner",
                        "admin",
                        "privileged",
                    ]
                )

            if any(
                word in finding_text
                for word in [
                    "timestamp",
                    "time manipulation",
                ]
            ):
                keywords.append("timestamp")

            if any(
                word in finding_text
                for word in [
                    "random",
                    "randomness",
                ]
            ):
                keywords.append("randomness")

            if any(
                word in finding_text
                for word in [
                    "delegatecall",
                    "proxy",
                    "upgrade",
                ]
            ):
                keywords.extend(
                    [
                        "delegatecall",
                        "upgradeability",
                    ]
                )

            if any(
                keyword in evidence_text
                for keyword in keywords
            ):
                matched_evidence.append(item)

        finding_copy["evidence"] = matched_evidence

        finding_copy["evidence_count"] = len(
            matched_evidence
        )

        correlated.append(finding_copy)

    return correlated


# ============================================================
# Main Evidence Engine
# ============================================================

def analyze_security_evidence(
    source_code: str = "",
    static_findings: Optional[List[Dict[str, Any]]] = None,
    attack_surface_result: Optional[Dict[str, Any]] = None,
    onchain_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Main entry point for TrustGuard Security Evidence Engine.
    """

    try:

        attack_surface = {}

        if isinstance(attack_surface_result, dict):
            attack_surface = (
                attack_surface_result.get(
                    "attack_surface",
                    {}
                )
                or {}
            )

        evidence = extract_source_evidence(
            source_code=source_code,
            static_findings=static_findings,
            attack_surface=attack_surface,
        )

        correlated_findings = correlate_findings_with_evidence(
            static_findings=static_findings,
            evidence=evidence,
        )

        # ----------------------------------------------------
        # On-chain evidence
        # ----------------------------------------------------

        chain_data = onchain_data or {}

        total_supply = chain_data.get(
            "total_supply"
        )

        decimals = chain_data.get(
            "decimals"
        )

        liquidity_pool_exists = chain_data.get(
            "liquidity_pool_exists"
        )

        liquidity_burn_percentage = chain_data.get(
            "liquidity_burn_percentage"
        )

        if total_supply is not None:

            evidence.append(
                _make_evidence(
                    evidence_type="onchain",
                    title="On-chain total supply available",
                    description=(
                        f"TrustGuard retrieved an on-chain total supply "
                        f"value of {total_supply}."
                    ),
                    source="onchain",
                    confidence="high",
                )
            )

        if decimals is not None:

            evidence.append(
                _make_evidence(
                    evidence_type="onchain",
                    title="Token decimals available",
                    description=(
                        f"TrustGuard retrieved an on-chain decimals value "
                        f"of {decimals}."
                    ),
                    source="onchain",
                    confidence="high",
                )
            )

        if liquidity_pool_exists is not None:

            evidence.append(
                _make_evidence(
                    evidence_type="liquidity",
                    title="Liquidity-pool analysis result available",
                    description=(
                        f"Liquidity-pool detection returned: "
                        f"{liquidity_pool_exists}."
                    ),
                    source="onchain",
                    confidence="medium",
                )
            )

        if liquidity_burn_percentage is not None:

            evidence.append(
                _make_evidence(
                    evidence_type="liquidity",
                    title="Liquidity burn percentage available",
                    description=(
                        "TrustGuard retrieved a liquidity burn percentage "
                        "from its on-chain liquidity analysis."
                    ),
                    source="onchain",
                    confidence="medium",
                )
            )

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        source_evidence_count = len(
            [
                item
                for item in evidence
                if item.get("source") == "source_code"
            ]
        )

        onchain_evidence_count = len(
            [
                item
                for item in evidence
                if item.get("source") == "onchain"
            ]
        )

        summary = (
            f"{len(evidence)} evidence item(s) were collected: "
            f"{source_evidence_count} from source-code analysis and "
            f"{onchain_evidence_count} from on-chain analysis."
        )

        return {
            "success": True,

            "evidence": evidence,

            "evidence_count":
                len(evidence),

            "source_evidence_count":
                source_evidence_count,

            "onchain_evidence_count":
                onchain_evidence_count,

            "correlated_findings":
                correlated_findings,

            "summary":
                summary,

            "limitations": [
                "Evidence is based on available source-code and on-chain data.",
                "Evidence does not by itself prove exploitability.",
                "Pattern-based evidence may require manual security review.",
                "Unavailable or unverified source code can reduce evidence coverage."
            ]
        }

    except Exception as error:

        return {
            "success": False,

            "evidence": [],

            "evidence_count": 0,

            "source_evidence_count": 0,

            "onchain_evidence_count": 0,

            "correlated_findings": [],

            "summary": "",

            "error": str(error),

            "limitations": [
                "Security evidence analysis could not be completed."
            ]
        }


# ============================================================
# Standalone test
# ============================================================

if __name__ == "__main__":

    test_source = """
    pragma solidity ^0.8.20;

    contract TestToken {

        address public owner;

        modifier onlyOwner() {
            require(msg.sender == owner);
            _;
        }

        function withdraw(address target)
            external
            onlyOwner
        {
            (bool success, ) =
                target.call{value: address(this).balance}("");

            require(success);
        }

        function execute(address target)
            external
            onlyOwner
        {
            target.delegatecall("");
        }

        function getRandom()
            external
            view
            returns (uint256)
        {
            return uint256(
                keccak256(
                    abi.encodePacked(
                        block.timestamp,
                        block.prevrandao
                    )
                )
            );
        }
    }
    """

    result = analyze_security_evidence(
        source_code=test_source,
        static_findings=[
            {
                "name": "Access Control",
                "description": "Privileged access control should be reviewed."
            },
            {
                "name": "Reentrancy",
                "description": "External call interaction requires review."
            }
        ],
        onchain_data={
            "total_supply": 1000000,
            "decimals": 18,
            "liquidity_pool_exists": 1,
            "liquidity_burn_percentage": 2.5
        }
    )

    print("=" * 70)
    print("TRUSTGUARD AI - SECURITY EVIDENCE ENGINE")
    print("=" * 70)

    print()
    print("Success:")
    print(result["success"])

    print()
    print("Evidence Count:")
    print(result["evidence_count"])

    print()
    print("Source Evidence:")
    print(result["source_evidence_count"])

    print()
    print("On-chain Evidence:")
    print(result["onchain_evidence_count"])

    print()
    print("Summary:")
    print(result["summary"])

    print()
    print("Evidence Items:")

    for item in result["evidence"]:

        print()
        print(
            f"- {item['title']}"
        )

        print(
            f"  Type: {item['type']}"
        )

        print(
            f"  Source: {item['source']}"
        )

        print(
            f"  Confidence: {item['confidence']}"
        )

        print(
            f"  {item['description']}"
        )

    print()
    print("Correlated Findings:")

    for finding in result["correlated_findings"]:

        print(
            f"- {finding.get('name', 'Unknown')}: "
            f"{finding.get('evidence_count', 0)} evidence item(s)"
        )

    print()
    print("Limitations:")

    for limitation in result["limitations"]:

        print(
            f"- {limitation}"
        )

    print()
    print("=" * 70)