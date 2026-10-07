# TRUSTGUARD AI - MAIN ANALYZER
import os
import re
import json
import time
import requests
# ============================================================
# Etherscan Source Cache
# ============================================================

_SOURCE_CACHE = {}

_SOURCE_CACHE_TTL = 300

_PROXY_METADATA_CACHE = {}

from web3 import Web3
from concurrent.futures import ThreadPoolExecutor
from backend.ml.live_security_engine import analyze_live_security
try:
    from backend.config import (
        ETHERSCAN_API_KEY,
        ETHERSCAN_API_URL,
        INFURA_URL
    )
    from backend.security.attack_surface import (
        analyze_attack_surface
    )

    from backend.security.evidence_engine import (
        analyze_security_evidence
    )

    from backend.security.correlation_engine import (
    correlate_security_signals
    )

    from backend.security.vulnerability_detector import (
        detect_vulnerabilities
    )

    from backend.ml.severity_engine import (
        analyze_all_predictions
    )

    from backend.security.prioritizer import (
        prioritize_vulnerabilities
    )

    from backend.remediation.repair_suggester import (
        generate_repair_suggestions
    )

    from backend.readiness.deployment_assessor import (
        assess_deployment_readiness
    )

except ModuleNotFoundError:
    from config import (
        ETHERSCAN_API_KEY,
        ETHERSCAN_API_URL,
        INFURA_URL
    )

    from security.vulnerability_detector import (
        detect_vulnerabilities
    )

    from ml.severity_engine import (
        analyze_all_predictions
    )

    from security.prioritizer import (
        prioritize_vulnerabilities
    )

    from remediation.repair_suggester import (
        generate_repair_suggestions
    )

    from readiness.deployment_assessor import (
        assess_deployment_readiness
    )


# ============================================================
# Web3 setup
# ============================================================

web3 = Web3(
    Web3.HTTPProvider(INFURA_URL)
)


# ============================================================
# Minimal ERC20 ABI
# ============================================================

MINIMAL_ERC20_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [
            {
                "type": "uint256"
            }
        ],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [
            {
                "type": "uint8"
            }
        ],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [
            {
                "name": "_owner",
                "type": "address"
            }
        ],
        "name": "balanceOf",
        "outputs": [
            {
                "type": "uint256"
            }
        ],
        "type": "function"
    }
]


# ============================================================
# Uniswap V2 Factory ABI
# ============================================================

UNISWAP_V2_FACTORY_ABI = [
    {
        "constant": True,
        "inputs": [
            {
                "type": "address"
            },
            {
                "type": "address"
            }
        ],
        "name": "getPair",
        "outputs": [
            {
                "type": "address"
            }
        ],
        "type": "function"
    }
]


# ============================================================
# Addresses
# ============================================================

UNISWAP_V2_FACTORY_ADDRESS = (
    "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
)

WETH_ADDRESS = (
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
)

DEAD_ADDRESS = (
    "0x000000000000000000000000000000000000dEaD"
)


# ============================================================
# Existing Risk Scoring
# ============================================================

FLAG_PENALTIES = {
    "NO_VERIFIED_SOURCE": 15,
    "ONCHAIN_ANALYSIS_FAILED": 10,
    "NO_LIQUIDITY_POOL_FOUND": 8,
    "ZERO_LIQUIDITY": 8,

    "MINT_CAPABILITY": 7,
    "UNLOCKED_LIQUIDITY": 0,
    "BLACKLIST_CAPABILITY": 0,
    "PAUSE_CAPABILITY": 4,
    "FEE_CHANGE_CAPABILITY": 3,

    "OWNER_CONTROL": 4,
    "UPGRADEABILITY_RISK": 4,
    "EXTERNAL_CALL_PATTERN": 0,
    "TX_ORIGIN_USAGE": 7,
    "SELFDESTRUCT_CAPABILITY": 7,
    "ARBITRARY_EXTERNAL_CALL": 0,

    "LIQUIDITY_ANALYSIS_FAILED": 2,
    "EXCESSIVE_TOTAL_SUPPLY": 1
}


# ============================================================
# Risk Level
# ============================================================

def get_risk_level(score: int) -> str:

    if score >= 18:
        return "Very Low Risk"

    if score >= 15:
        return "Low Risk"

    if score >= 10:
        return "Medium Risk"

    if score >= 5:
        return "High Risk"

    return "Very High Risk"


# ============================================================
# Etherscan Source Retrieval
# ============================================================

def get_verified_source_code(
    contract_address: str
) -> str | None:

    # --------------------------------------------------------
    # Normalize address for cache lookup
    # --------------------------------------------------------

    cache_key = contract_address.lower()

    # --------------------------------------------------------
    # Check source cache
    # --------------------------------------------------------

    cached = _SOURCE_CACHE.get(
        cache_key
    )

    if cached:

        cached_source, cached_time = cached

        if (
            time.time() - cached_time
            < _SOURCE_CACHE_TTL
        ):

            return cached_source

        # Remove expired cache entry
        _SOURCE_CACHE.pop(
            cache_key,
            None
        )

    # --------------------------------------------------------
    # Etherscan request
    # --------------------------------------------------------

    params = {
        "chainid": 1,
        "module": "contract",
        "action": "getsourcecode",
        "address": contract_address,
        "apikey": ETHERSCAN_API_KEY
    }

    try:

        response = requests.get(
            ETHERSCAN_API_URL,
            params=params,
            timeout=10
        )

        data = response.json()

        if (
            data.get("status") != "1"
            or not data.get("result")
        ):

            return None

        result = data["result"][0]

        source_code = result.get(
            "SourceCode",
            ""
        )

        abi = result.get(
            "ABI",
            ""
        )

        proxy = result.get(
            "Proxy"
        )

        implementation = result.get(
            "Implementation"
        )

        _PROXY_METADATA_CACHE[
            contract_address.lower()
        ] = {
            "is_proxy": proxy == "1",
            "implementation": implementation
        }

        # ----------------------------------------------------
        # Proxy contract
        # ----------------------------------------------------

        if (
            proxy == "1"
            and implementation
        ):

            implementation_source = (
                get_verified_source_code(
                    implementation
                )
            )

            if implementation_source:

                _SOURCE_CACHE[
                    cache_key
                ] = (
                    implementation_source,
                    time.time()
                )

            return implementation_source

        # ----------------------------------------------------
        # Multi-file / Standard JSON source
        # ----------------------------------------------------

        if source_code.startswith("{{"):

            try:

                parsed = json.loads(
                    source_code[1:-1]
                )

                combined = ""

                sources = parsed.get(
                    "sources",
                    parsed
                )

                for file_info in sources.values():

                    combined += (
                        file_info.get(
                            "content",
                            ""
                        )
                        + "\n"
                    )

                if combined.strip():

                    _SOURCE_CACHE[
                        cache_key
                    ] = (
                        combined,
                        time.time()
                    )

                    return combined

                return source_code

            except json.JSONDecodeError:

                if source_code.strip():

                    _SOURCE_CACHE[
                        cache_key
                    ] = (
                        source_code,
                        time.time()
                    )

                return source_code

        # ----------------------------------------------------
        # Normal verified source
        # ----------------------------------------------------

        if source_code.strip():

            _SOURCE_CACHE[
                cache_key
            ] = (
                source_code,
                time.time()
            )

            return source_code

        # ----------------------------------------------------
        # ABI-only verified contract
        # ----------------------------------------------------

        if (
            abi
            and abi !=
            "Contract source code not verified"
        ):

            abi_source = (
                "// ABI verified contract"
            )

            _SOURCE_CACHE[
                cache_key
            ] = (
                abi_source,
                time.time()
            )

            return abi_source

        return None

    except Exception:

        return None

    params = {
        "chainid": 1,
        "module": "contract",
        "action": "getsourcecode",
        "address": contract_address,
        "apikey": ETHERSCAN_API_KEY
    }

    try:

        response = requests.get(
            ETHERSCAN_API_URL,
            params=params,
            timeout=10
        )

        data = response.json()

        if (
            data.get("status") != "1"
            or not data.get("result")
        ):
            return None

        result = data["result"][0]

        source_code = result.get(
            "SourceCode",
            ""
        )

        abi = result.get(
            "ABI",
            ""
        )

        proxy = result.get(
            "Proxy"
        )

        implementation = result.get(
            "Implementation"
        )

        if (
            proxy == "1"
            and implementation
        ):

            return get_verified_source_code(
                implementation
            )

        if source_code.startswith("{{"):

            try:

                parsed = json.loads(
                    source_code[1:-1]
                )

                combined = ""

                sources = parsed.get(
                    "sources",
                    parsed
                )

                for file_info in sources.values():

                    combined += (
                        file_info.get(
                            "content",
                            ""
                        )
                        + "\n"
                    )

                return combined

            except json.JSONDecodeError:

                return source_code

        if source_code.strip():
            return source_code

        if (
            abi
            and abi !=
            "Contract source code not verified"
        ):
            return "// ABI verified contract"

        return None

    except Exception:

        return None


# ============================================================
# Static Source Analysis
# ============================================================

def check_for_malicious_functions(
    source_code: str
) -> dict:

    red_flags = {}

    dangerous_patterns = {

        "MINT_CAPABILITY":
            r"mint\s*\(",

        "BLACKLIST_CAPABILITY":
            r"blacklist|blockAddress",

        "PAUSE_CAPABILITY":
            r"pause",

        "FEE_CHANGE_CAPABILITY":
            r"set\w*fee"
    }

    for flag, pattern in dangerous_patterns.items():

        if re.search(
            pattern,
            source_code,
            re.IGNORECASE
        ):

            red_flags[flag] = (
                "Potentially dangerous pattern "
                f"detected: {pattern}"
            )

    return red_flags


# ============================================================
# On-chain Analysis
# ============================================================
# ============================================================
# On-chain Analysis
# ============================================================

def perform_onchain_analysis(
    contract_address: str
) -> dict:

    result = {
        "total_supply": 0,
        "decimals": 18,
        "flags": {}
    }

    try:

        checksum = (
            web3.to_checksum_address(
                contract_address
            )
        )

        contract = web3.eth.contract(
            address=checksum,
            abi=MINIMAL_ERC20_ABI
        )

        # ----------------------------------------------------
        # Run independent RPC calls in parallel
        # ----------------------------------------------------

        with ThreadPoolExecutor(
            max_workers=2
        ) as executor:

            supply_future = (
                executor.submit(
                    contract.functions
                    .totalSupply()
                    .call
                )
            )

            decimals_future = (
                executor.submit(
                    contract.functions
                    .decimals()
                    .call
                )
            )

            total_supply = (
                supply_future.result()
            )

            decimals = (
                decimals_future.result()
            )

        result["total_supply"] = (
            total_supply
        )

        result["decimals"] = (
            decimals
        )

        adjusted_supply = (
            total_supply /
            (10 ** decimals)
        )


    except Exception as e:

        result["flags"][
            "ONCHAIN_ANALYSIS_FAILED"
        ] = str(e)

    return result
# ============================================================
# Uniswap V2 Liquidity Analysis
# ============================================================

# ============================================================
# Uniswap V2 Liquidity Analysis
# ============================================================

def check_uniswap_v2_liquidity(
    token_address: str
) -> dict:

    result = {
        "liquidity_pool_exists": 0,
        "liquidity_burn_percentage": 0.0,
        "flags": {}
    }

    if (
        token_address.lower()
        ==
        WETH_ADDRESS.lower()
    ):
        return result

    try:

        factory = web3.eth.contract(

            address=
                web3.to_checksum_address(
                    UNISWAP_V2_FACTORY_ADDRESS
                ),

            abi=
                UNISWAP_V2_FACTORY_ABI
        )

        pair = (
            factory.functions
            .getPair(
                web3.to_checksum_address(
                    token_address
                ),
                web3.to_checksum_address(
                    WETH_ADDRESS
                )
            )
            .call()
        )

        if (
            pair ==
            "0x0000000000000000000000000000000000000000"
        ):

            result["flags"][
                "NO_LIQUIDITY_POOL_FOUND"
            ] = (
                "No Uniswap V2 liquidity pool "
                "found for this token."
            )

            return result

        result[
            "liquidity_pool_exists"
        ] = 1

        lp = web3.eth.contract(
            address=
                web3.to_checksum_address(
                    pair
                ),
            abi=
                MINIMAL_ERC20_ABI
        )

        # ----------------------------------------------------
        # Run independent LP RPC calls in parallel
        # ----------------------------------------------------

        with ThreadPoolExecutor(
            max_workers=2
        ) as executor:

            burned_future = (
                executor.submit(
                    lp.functions
                    .balanceOf(
                        web3.to_checksum_address(
                            DEAD_ADDRESS
                        )
                    )
                    .call
                )
            )

            total_lp_future = (
                executor.submit(
                    lp.functions
                    .totalSupply()
                    .call
                )
            )

            burned = (
                burned_future.result()
            )

            total_lp = (
                total_lp_future.result()
            )

        if total_lp == 0:

            result["flags"][
                "ZERO_LIQUIDITY"
            ] = (
                "Liquidity pool exists but "
                "LP supply is zero."
            )

        else:

            burn_pct = (
                burned /
                total_lp
            ) * 100

            result[
                "liquidity_burn_percentage"
            ] = burn_pct

    except Exception as e:

        result["flags"][
            "LIQUIDITY_ANALYSIS_FAILED"
        ] = str(e)

    return result
# ============================================================
# Convert Static Findings
# ============================================================

def _convert_static_findings(
    vulnerabilities: list,
    all_flags: dict
) -> list:

    findings = []

    for vulnerability in vulnerabilities:

        vulnerability_id = vulnerability.get(
            "id",
            vulnerability.get(
                "name",
                "UNKNOWN"
            )
        )

        findings.append(
            {
                "vulnerability": vulnerability_id,
                "probability": 1.0,
                "detected": True,
                "source": "STATIC_ANALYZER",
                "description": vulnerability.get(
                    "description",
                    "Security finding detected."
                )
            }
        )

    display_names = {

        "MINT_CAPABILITY":
            "Mint Capability",

        "UNLOCKED_LIQUIDITY":
            "Unlocked Liquidity",

        "BLACKLIST_CAPABILITY":
            "Blacklist Capability",

        "PAUSE_CAPABILITY":
            "Pause Capability",

        "FEE_CHANGE_CAPABILITY":
            "Fee Change Capability",

        "OWNER_CONTROL":
            "Owner Control",

        "UPGRADEABILITY_RISK":
            "Upgradeability Risk",

        "EXTERNAL_CALL_PATTERN":
            "External Call Pattern",

        "TX_ORIGIN_USAGE":
            "Tx Origin Usage",

        "SELFDESTRUCT_CAPABILITY":
            "Selfdestruct Capability",

        "ARBITRARY_EXTERNAL_CALL":
            "Arbitrary External Call",

        "NO_VERIFIED_SOURCE":
            "No Verified Source",

        "ONCHAIN_ANALYSIS_FAILED":
            "On-chain Analysis Failed",

        "NO_LIQUIDITY_POOL_FOUND":
            "No Liquidity Pool Found",

        "ZERO_LIQUIDITY":
            "Zero Liquidity",

        "LIQUIDITY_ANALYSIS_FAILED":
            "Liquidity Analysis Failed",

        "EXCESSIVE_TOTAL_SUPPLY":
            "Excessive Total Supply"
    }

    static_severity = {

        "MINT_CAPABILITY":
            "HIGH",

        "UNLOCKED_LIQUIDITY":
            "MEDIUM",

        "BLACKLIST_CAPABILITY":
            "HIGH",

        "PAUSE_CAPABILITY":
            "MEDIUM",

        "FEE_CHANGE_CAPABILITY":
            "MEDIUM",

        "OWNER_CONTROL":
            "HIGH",

        "UPGRADEABILITY_RISK":
            "HIGH",

        "EXTERNAL_CALL_PATTERN":
            "MEDIUM",

        "TX_ORIGIN_USAGE":
            "HIGH",

        "SELFDESTRUCT_CAPABILITY":
            "HIGH",

        "ARBITRARY_EXTERNAL_CALL":
            "HIGH",

        "NO_VERIFIED_SOURCE":
            "HIGH",

        "ONCHAIN_ANALYSIS_FAILED":
            "MEDIUM",

        "NO_LIQUIDITY_POOL_FOUND":
            "MEDIUM",

        "ZERO_LIQUIDITY":
            "MEDIUM",

        "LIQUIDITY_ANALYSIS_FAILED":
            "MEDIUM",

        "EXCESSIVE_TOTAL_SUPPLY":
            "LOW"
    }

    impact_values = {
        "CRITICAL": 5,
        "HIGH": 5,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1
    }

    exploitability_values = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1
    }

    existing_ids = {
        item["vulnerability"]
        for item in findings
    }

    for flag, description in all_flags.items():

        if flag in existing_ids:
            continue

        if flag in {
            "NO_VERIFIED_SOURCE",
            "ONCHAIN_ANALYSIS_FAILED",
            "LIQUIDITY_ANALYSIS_FAILED"
        }:
            continue

        display_name = display_names.get(
            flag,
            flag
        )

        severity = static_severity.get(
            flag,
            "MEDIUM"
        )

        findings.append(
            {
                "vulnerability": display_name,
                "probability": 1.0,
                "detected": True,
                "source": "STATIC_ANALYZER",
                "description": description,
                "severity": severity,
                "severity_score": {
                    "CRITICAL": 95.0,
                    "HIGH": 85.0,
                    "MEDIUM": 65.0,
                    "LOW": 40.0,
                    "INFO": 20.0
                }.get(
                    severity,
                    50.0
                ),
                "impact": impact_values.get(
                    severity,
                    3
                ),
                "exploitability":
                    exploitability_values.get(
                        severity,
                        3
                    )
            }
        )

        existing_ids.add(flag)

    return findings


# ============================================================
# Main TrustGuard Analyzer
# ============================================================

def analyze_contract(
    contract_address: str
) -> dict:

    analysis_start_time = time.perf_counter()

    # --------------------------------------------------------
    # Address validation
    # --------------------------------------------------------

    if not re.match(r'^0x[a-fA-F0-9]{40}$', contract_address):
        return {
            "error": "Invalid Ethereum address format."
        }

    # --------------------------------------------------------
    # 1. Source Code
    # --------------------------------------------------------

    source_code = (
        get_verified_source_code(
            contract_address
        )
    )

    vulnerabilities = []

    all_flags = {}

    if source_code is None:

        all_flags[
            "NO_VERIFIED_SOURCE"
        ] = (
            "Verified source code could not "
            "be retrieved from Etherscan."
        )

    else:

        vulnerabilities = (
            detect_vulnerabilities(
                source_code
            )
        )

        for vulnerability in vulnerabilities:

            vulnerability_id = (
                vulnerability.get(
                    "id"
                )
            )

            if vulnerability_id:

                all_flags[
                    vulnerability_id
                ] = vulnerability.get(
                    "description",
                    "Security finding detected."
                )

        legacy_flags = (
            check_for_malicious_functions(
                source_code
            )
        )

        for flag, description in (
            legacy_flags.items()
        ):

            all_flags.setdefault(
                flag,
                description
            )

    # --------------------------------------------------------
    # 2 + 3. Parallel On-chain + Liquidity Analysis
    # --------------------------------------------------------

    with ThreadPoolExecutor(
        max_workers=2
    ) as executor:

        onchain_future = (
            executor.submit(
                perform_onchain_analysis,
                contract_address
            )
        )

        liquidity_future = (
            executor.submit(
                check_uniswap_v2_liquidity,
                contract_address
            )
        )

        onchain_result = (
            onchain_future.result()
        )

        liquidity_result = (
            liquidity_future.result()
        )

    # --------------------------------------------------------
    # Merge On-chain flags
    # --------------------------------------------------------

    for flag, description in (
        onchain_result["flags"].items()
    ):

        all_flags[flag] = description

    # --------------------------------------------------------
    # Merge Liquidity flags
    # --------------------------------------------------------

    for flag, description in (
        liquidity_result["flags"].items()
    ):

        all_flags[flag] = description
    # --------------------------------------------------------
    # 4. Attack Surface Analysis
    # --------------------------------------------------------

    try:

        attack_surface_result = (
            analyze_attack_surface(
                source_code=source_code or ""
            )
        )

    except Exception as error:

        attack_surface_result = {
            "success": False,
            "error": str(error),
            "attack_surface": {},
            "capabilities": [],
            "summary": "",
            "limitations": [
                "Attack-surface analysis could not be completed."
            ]
        }
    # --------------------------------------------------------
    # 4. Existing risk score
    # --------------------------------------------------------

    total_penalty = sum(
        FLAG_PENALTIES.get(
            flag,
            1
        )
        for flag in all_flags
    )

    score = max(
        20 - total_penalty,
        0
    )

    # --------------------------------------------------------
    # 5. Static findings
    # --------------------------------------------------------

    static_findings = (
        _convert_static_findings(
            vulnerabilities,
            all_flags
        )
    )
        # --------------------------------------------------------
    # 5A. Correlate Security Evidence with Static Findings
    # --------------------------------------------------------

    try:

        evidence_result = (
            analyze_security_evidence(
                source_code=source_code or "",
                static_findings=static_findings,
                attack_surface_result=attack_surface_result,
                onchain_data={
                    "total_supply":
                        onchain_result.get(
                            "total_supply"
                        ),

                    "decimals":
                        onchain_result.get(
                            "decimals"
                        ),

                    "liquidity_pool_exists":
                        liquidity_result.get(
                            "liquidity_pool_exists"
                        ),

                    "liquidity_burn_percentage":
                        liquidity_result.get(
                            "liquidity_burn_percentage"
                        )
                }
            )
        )

    except Exception as error:

        evidence_result = {
            "success": False,
            "error": str(error),
            "evidence": [],
            "evidence_count": 0,
            "source_evidence_count": 0,
            "onchain_evidence_count": 0,
            "correlated_findings": [],
            "summary": "",
            "limitations": [
                "Security evidence correlation could not be completed."
            ]
        }

    # --------------------------------------------------------
    # 6. Add static findings to TrustGuard
    # --------------------------------------------------------

    severity_input = []

    for finding in static_findings:

        severity_input.append(
            {
                "id":
                    finding["vulnerability"],

                "probability":
                    finding["probability"],

                "detected":
                    True
            }
        )

    # --------------------------------------------------------
    # 7. Severity
    # --------------------------------------------------------

    severity_results = []

    if severity_input:

        try:

            severity_results = (
                analyze_all_predictions(
                    severity_input,
                    evidence_strength=1.0,
                    onchain_risk=0.0
                )
            )

        except ValueError:

            severity_results = []

    # --------------------------------------------------------
    # 8. Preserve static findings
    # --------------------------------------------------------

    known_names = {
        item["vulnerability"]
        for item in severity_results
    }

    for finding in static_findings:

        name = finding[
            "vulnerability"
        ]

        if name in known_names:
            continue

        display_names = {

            "MINT_CAPABILITY":
                "Mint Capability",

            "PAUSE_CAPABILITY":
                "Pause Capability",

            "FEE_CHANGE_CAPABILITY":
                "Fee Change Capability",

            "EXTERNAL_CALL_PATTERN":
                "External Call Pattern",

            "OWNER_CONTROL":
                "Owner Control",

            "UPGRADEABILITY_RISK":
                "Upgradeability Risk",

            "TX_ORIGIN_USAGE":
                "Tx Origin Usage",

            "SELFDESTRUCT_CAPABILITY":
                "Selfdestruct Capability",

            "ARBITRARY_EXTERNAL_CALL":
                "Arbitrary External Call"
        }

        display_name = display_names.get(
            name,
            name
        )

        static_severity = {

            "MINT_CAPABILITY":
                "HIGH",

            "EXTERNAL_CALL_PATTERN":
                "MEDIUM",

            "FEE_CHANGE_CAPABILITY":
                "MEDIUM",

            "PAUSE_CAPABILITY":
                "MEDIUM",

            "OWNER_CONTROL":
                "HIGH",

            "UPGRADEABILITY_RISK":
                "HIGH",

            "TX_ORIGIN_USAGE":
                "HIGH",

            "SELFDESTRUCT_CAPABILITY":
                "HIGH",

            "ARBITRARY_EXTERNAL_CALL":
                "HIGH"
        }.get(
            name,
            "MEDIUM"
        )

        impact = {
            "HIGH": 5,
            "MEDIUM": 3,
            "LOW": 2
        }.get(
            static_severity,
            3
        )

        exploitability = {
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2
        }.get(
            static_severity,
            3
        )

        severity_results.append(
            {
                "vulnerability":
                    display_name,

                "probability":
                    1.0,

                "severity_score":
                    {
                        "HIGH": 90.0,
                        "MEDIUM": 70.0,
                        "LOW": 40.0
                    }.get(
                        static_severity,
                        50.0
                    ),

                "severity":
                    static_severity,

                "impact":
                    impact,

                "exploitability":
                    exploitability,

                "detected":
                    True,

                "source":
                    "STATIC_ANALYZER"
            }
        )

    # --------------------------------------------------------
    # 9. Prioritize
    # --------------------------------------------------------

    prioritized = (
        prioritize_vulnerabilities(
            severity_results
        )
    )

    # --------------------------------------------------------
    # 10. Repair suggestions
    # --------------------------------------------------------

    repairs = (
        generate_repair_suggestions(
            prioritized
        )
    )

    # --------------------------------------------------------
    # 11. Deployment readiness
    # --------------------------------------------------------

    readiness = (
        assess_deployment_readiness(
            prioritized
        )
    )

    # --------------------------------------------------------
    # 12. Live Security Intelligence
    # --------------------------------------------------------

    try:

        live_intelligence = analyze_live_security(
    source_code=source_code or "",

    onchain_data={
        "total_supply": onchain_result.get(
            "total_supply",
            0
        ),

        "decimals": onchain_result.get(
            "decimals",
            18
        ),

        "liquidity_pool_exists": liquidity_result.get(
            "liquidity_pool_exists",
            False
        ),

        "liquidity_burn_percentage": liquidity_result.get(
            "liquidity_burn_percentage",
            0
        )
    },

    static_findings=static_findings,

    all_flags={
        "flags": vulnerabilities
    },

    include_explanations=True,

    explanation_count=3,

    explanation_features=6
)

    except Exception as error:

        live_intelligence = {

            "error":
                str(error),

            "features": {},

            "feature_count": 0,

            "ml_predictions": [],

            "ml_detected_count": 0,

            "explanations": [],

            "unified_findings": [],

            "prioritized_vulnerabilities": [],

            "repair_suggestions": [],

            "deployment_readiness": {}
        }

        # --------------------------------------------------------
    # 13. ML Probability Matrix
    # --------------------------------------------------------

    try:

        ml_probability_matrix = {
            "success": True,
            "predictions": [
                {
                    "vulnerability": prediction.get(
                        "vulnerability",
                        prediction.get("id", "Unknown")
                    ),
                    "probability": prediction.get(
                        "probability",
                        0
                    ),
                    "detected": prediction.get(
                        "detected",
                        False
                    ),
                    "source": prediction.get(
                        "source",
                        "ML_MODEL"
                    )
                }
                for prediction in live_intelligence.get(
                    "ml_predictions",
                    []
                )
            ],
            "prediction_count": len(
                live_intelligence.get(
                    "ml_predictions",
                    []
                )
            ),
            "detected_count": sum(
                1
                for prediction in live_intelligence.get(
                    "ml_predictions",
                    []
                )
                if prediction.get("detected", False)
            ),
            "summary": (
                "ML probability estimates generated for "
                f"{len(live_intelligence.get('ml_predictions', []))} "
                "vulnerability categories."
            ),
            "limitations": [
                "ML probabilities are model predictions, not proof of exploitability.",
                "Predictions should be interpreted together with static analysis, evidence, and on-chain signals."
            ]
        }

    except Exception as error:

        ml_probability_matrix = {
            "success": False,
            "predictions": [],
            "prediction_count": 0,
            "detected_count": 0,
            "summary": "",
            "error": str(error),
            "limitations": [
                "ML probability matrix could not be generated."
            ]
        }

        # --------------------------------------------------------
    # 14. SHAP / LIME Explanation Center
    # --------------------------------------------------------

    try:

        explanation_data = live_intelligence.get(
            "explanations",
            {}
        )

        shap_explanations = explanation_data.get(
            "shap",
            {}
        )

        lime_explanations = explanation_data.get(
            "lime",
            {}
        )

        shap_feature_count = sum(
            len(features)
            for features in shap_explanations.values()
        )

        lime_feature_count = sum(
            len(features)
            for features in lime_explanations.values()
        )

        explanation_center = {
            "success": True,

            "shap": {
                "available": bool(shap_explanations),
                "vulnerabilities": shap_explanations,
                "vulnerability_count": len(
                    shap_explanations
                ),
                "feature_count": shap_feature_count
            },

            "lime": {
                "available": bool(lime_explanations),
                "vulnerabilities": lime_explanations,
                "vulnerability_count": len(
                    lime_explanations
                ),
                "feature_count": lime_feature_count
            },

            "summary": (
                "SHAP and LIME explanations are available "
                "for the vulnerability categories analyzed "
                "by the ML explanation pipeline."
            ),

            "limitations": [
                "SHAP and LIME explain model behavior; they do not prove exploitability.",
                "Feature contributions indicate model influence, not causal proof.",
                "Explanations should be interpreted together with static analysis and security evidence."
            ]
        }

    except Exception as error:

        explanation_center = {
            "success": False,
            "shap": {
                "available": False,
                "vulnerabilities": {},
                "vulnerability_count": 0,
                "feature_count": 0
            },
            "lime": {
                "available": False,
                "vulnerabilities": {},
                "vulnerability_count": 0,
                "feature_count": 0
            },
            "summary": "",
            "error": str(error),
            "limitations": [
                "SHAP/LIME explanation data could not be prepared."
            ]
        }
        # --------------------------------------------------------
    # Explainable Security Score Breakdown
    # --------------------------------------------------------

    try:

        score_breakdown_items = []

        for flag_name in all_flags:

            penalty = FLAG_PENALTIES.get(
                flag_name,
                1
            )

            score_breakdown_items.append(
                {
                    "flag": flag_name,
                    "description": all_flags.get(
                        flag_name,
                        ""
                    ),
                    "penalty": penalty
                }
            )

        score_breakdown = {
            "success": True,
            "base_score": 20,
            "total_penalty": total_penalty,
            "final_score": score,
            "risk_level": get_risk_level(score),
            "active_flags": score_breakdown_items,
            "formula": "max(base_score - total_penalty, 0)",
            "summary": (
                f"Security score is {score}/20 after "
                f"applying {total_penalty} penalty point(s) "
                "from active security flags."
            ),
            "limitations": [
                "The score reflects TrustGuard's configured risk-scoring rules.",
                "The score is not a guarantee that a contract is exploitable or secure.",
                "Individual findings should be reviewed together with evidence, ML predictions, and static analysis."
            ]
        }

    except Exception as error:

        score_breakdown = {
            "success": False,
            "base_score": 20,
            "total_penalty": 0,
            "final_score": score,
            "risk_level": get_risk_level(score),
            "active_flags": [],
            "formula": "max(base_score - total_penalty, 0)",
            "summary": "",
            "error": str(error),
            "limitations": [
                "Security score breakdown could not be generated."
            ]
        }
        # --------------------------------------------------------
    # 13. Vulnerability Correlation
    # --------------------------------------------------------

    try:

        correlation_result = (
            correlate_security_signals(
                static_findings=static_findings,

                ml_predictions=(
                    live_intelligence.get(
                        "ml_predictions",
                        []
                    )
                ),

                evidence_result=evidence_result,

                attack_surface_result=(
                    attack_surface_result
                ),

                severity_results=severity_results
            )
        )

    except Exception as error:

        correlation_result = {
            "success": False,
            "correlated_findings": [],
            "correlation_count": 0,
            "multi_signal_count": 0,
            "summary": "",
            "error": str(error),
            "limitations": [
                "Vulnerability correlation could not be completed."
            ]
        }
    # --------------------------------------------------------
    # --------------------------------------------------------
    # 13. Final result
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Contract Profile
    # --------------------------------------------------------

    try:
        contract_profile = {
            "success": True,
            "contract_address": contract_address,
            "network": "Ethereum Mainnet",
            "source_code_available": source_code is not None,
            "verified_source": source_code is not None,
            "contract_type": (
                "Smart Contract"
                if source_code
                else "Unknown"
            ),
            "upgradeability": {
    "detected": (_PROXY_METADATA_CACHE.get(contract_address.lower(), {}).get("is_proxy", False) or attack_surface_result.get("attack_surface", {}).get("upgradeability", False)),
    "proxy_pattern": (_PROXY_METADATA_CACHE.get(contract_address.lower(), {}).get("is_proxy", False) or attack_surface_result.get("attack_surface", {}).get("proxy_pattern", False))
            },
            "onchain_analysis_available": bool(onchain_result),
            "liquidity_analysis_available": bool(liquidity_result),
            "analysis_complete": True,
            "limitations": [
                "Contract profile fields depend on the source-code and on-chain data available to TrustGuard.",
                "Pattern detection does not by itself prove exploitability."
            ]
        }
    except Exception as error:
        contract_profile = {
            "success": False,
            "contract_address": contract_address,
            "error": str(error),
            "limitations": [
                "Contract profile could not be generated."
            ]
        }

    # --------------------------------------------------------
    # Analysis Pipeline
    # --------------------------------------------------------

    try:
        analysis_pipeline = {
            "success": True,
            "stages": [
                {
                    "name": "Source Retrieval",
                    "completed": source_code is not None
                },
                {
                    "name": "On-chain Analysis",
                    "completed": bool(onchain_result)
                },
                {
                    "name": "Liquidity Analysis",
                    "completed": bool(liquidity_result)
                },
                {
                    "name": "Attack Surface Analysis",
                    "completed": attack_surface_result.get(
                        "success", False
                    )
                },
                {
                    "name": "Static Security Analysis",
                    "completed": True
                },
                {
                    "name": "ML Prediction",
                    "completed": bool(
                        live_intelligence.get("ml_predictions", [])
                    )
                },
                {
                    "name": "SHAP / LIME Explanation",
                    "completed": explanation_center.get(
                        "success", False
                    )
                },
                {
                    "name": "Security Evidence",
                    "completed": evidence_result.get(
                        "success", False
                    )
                },
                {
                    "name": "Vulnerability Correlation",
                    "completed": correlation_result.get(
                        "success", False
                    )
                },
                {
                    "name": "Prioritization",
                    "completed": True
                },
                {
                    "name": "Remediation",
                    "completed": True
                },
                {
                    "name": "Deployment Readiness",
                    "completed": bool(readiness)
                }
            ]
        }

        analysis_pipeline["total_stages"] = len(
            analysis_pipeline["stages"]
        )
        analysis_pipeline["completed_count"] = sum(
            1
            for stage in analysis_pipeline["stages"]
            if stage["completed"]
        )

    except Exception as error:
        analysis_pipeline = {
            "success": False,
            "stages": [],
            "completed_count": 0,
            "total_stages": 0,
            "error": str(error)
        }
    analysis_duration_seconds = round(time.perf_counter() - analysis_start_time, 3)

    performance_metrics = {
        "success": True,
        "total_analysis_duration_seconds": analysis_duration_seconds,
        "analysis_completed": True,
        "notes": [
            "Duration measures the complete TrustGuard analysis pipeline.",
            "Network latency and external service response times can affect duration."
        ]
    }

    # --------------------------------------------------------
    # Security Summary
    # --------------------------------------------------------

    security_summary = {
        "success": True,
        "security_score": score,
        "risk_level": get_risk_level(score),
        "static_findings_count": len(static_findings),
        "vulnerability_count": len(vulnerabilities),
        "ml_prediction_count": len(
            live_intelligence.get("ml_predictions", [])
        ),
        "correlated_finding_count": correlation_result.get(
            "correlation_count", 0
        ),
        "multi_signal_finding_count": correlation_result.get(
            "multi_signal_count", 0
        ),
        "attack_surface_available": attack_surface_result.get(
            "success", False
        ),
        "security_evidence_count": evidence_result.get(
            "evidence_count", 0
        ),
        "deployment_readiness": readiness,
        "key_flags": [
            {
                "name": flag.get("name"),
                "description": flag.get("description")
            }
            for flag in vulnerabilities
            if isinstance(flag, dict)
        ],
        "summary": (
            f"TrustGuard calculated a security score of {score}/20 "
            f"with a risk level of {get_risk_level(score)}. "
            f"{len(vulnerabilities)} security flag(s), "
            f"{len(live_intelligence.get('ml_predictions', []))} ML "
            f"prediction(s), and "
            f"{correlation_result.get('multi_signal_count', 0)} "
            f"multi-signal finding(s) were identified."
        ),
        "limitations": [
            "The summary reflects the analysis signals available to TrustGuard.",
            "ML predictions indicate model output and do not by themselves prove exploitability.",
            "Static patterns and evidence do not by themselves establish that a contract is exploitable."
        ]
    }
    # --------------------------------------------------------
    # Confidence & Uncertainty Assessment
    # --------------------------------------------------------

    confidence_factors = {
        "verified_source": source_code is not None,
        "onchain_analysis": bool(onchain_result),
        "liquidity_analysis": bool(liquidity_result),
        "attack_surface": attack_surface_result.get("success", False),
        "security_evidence": evidence_result.get("success", False),
        "ml_predictions": bool(
            live_intelligence.get("ml_predictions", [])
        ),
        "shap_explanations": explanation_center.get(
            "shap", {}
        ).get("available", False),
        "lime_explanations": explanation_center.get(
            "lime", {}
        ).get("available", False),
        "vulnerability_correlation": correlation_result.get(
            "success", False
        )
    }

    confidence_factor_count = sum(
        1 for value in confidence_factors.values()
        if value
    )

    confidence_assessment = {
        "success": True,
        "factor_count": confidence_factor_count,
        "total_factors": len(confidence_factors),
        "factors": confidence_factors,
        "confidence_level": (
            "High"
            if confidence_factor_count >= 8
            else "Moderate"
            if confidence_factor_count >= 5
            else "Limited"
        ),
        "uncertainty_notes": [
            "Confidence reflects availability and agreement of TrustGuard analysis signals.",
            "ML predictions are model outputs and do not prove exploitability.",
            "Static analysis and evidence depend on the source code and on-chain data available.",
            "Confidence does not represent a probability that the contract is exploitable."
        ]
    }
    # --------------------------------------------------------
    # Limitations & Evidence Notes
    # --------------------------------------------------------

    limitations_evidence_notes = {
        "success": True,
        "evidence_available": evidence_result.get(
            "success", False
        ),
        "evidence_count": evidence_result.get(
            "evidence_count", 0
        ),
        "source_evidence_count": evidence_result.get(
            "source_evidence_count", 0
        ),
        "onchain_evidence_count": evidence_result.get(
            "onchain_evidence_count", 0
        ),
        "evidence_summary": evidence_result.get(
            "summary", ""
        ),
        "evidence_limitations": evidence_result.get(
            "limitations", []
        ),
        "analysis_limitations": [
            "Analysis depends on the source code and on-chain data available to TrustGuard.",
            "ML predictions do not by themselves prove exploitability.",
            "Pattern-based findings may require manual security review.",
            "Absence of a detected signal does not guarantee absence of a vulnerability."
        ]
    }
    return {

        "success":
            True,

        "contract_address":
            contract_address,

        "attack_surface":
            attack_surface_result,

        "security_evidence":
            evidence_result,

        "ml_probability_matrix":
            ml_probability_matrix,

        "explanation_center":
            explanation_center,

        "score_breakdown":
            score_breakdown,

        "contract_profile":
            contract_profile,
            
        "analysis_pipeline":
            analysis_pipeline,

        "performance_metrics":
            performance_metrics,

        "confidence_assessment":
            confidence_assessment,

        "limitations_evidence_notes":
            limitations_evidence_notes,

        "security_summary":
            security_summary,

        "vulnerability_correlation":
            correlation_result,

        "source_code_available":
            source_code is not None,

        "score":
            score,

        "risk_level":
            get_risk_level(score),

        "flags": [

            {
                "name":
                    name,

                "description":
                    description
            }

            for name, description
            in all_flags.items()
        ],

        "vulnerabilities":
            vulnerabilities,

        "static_findings":
            static_findings,

        "severity":
            severity_results,

        "prioritized_vulnerabilities":
            prioritized,

        "repair_suggestions":
            repairs,

        "deployment_readiness":
            readiness,

        "live_intelligence":
            live_intelligence,

        "onchain":
            {
                "total_supply":
                    onchain_result[
                        "total_supply"
                    ],

                "decimals":
                    onchain_result[
                        "decimals"
                    ]
            },

        "liquidity":
            {
                "pool_exists":
                    liquidity_result[
                        "liquidity_pool_exists"
                    ],

                "burn_percentage":
                    liquidity_result[
                        "liquidity_burn_percentage"
                    ]
            }
    }
# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 70)

    print(
        "TRUSTGUARD AI - ANALYZER MODULE"
    )

    print("=" * 70)

    print(
        "\nAnalyzer module loaded successfully."
    )

    print(
        "\nAvailable function:"
    )

    print(
        "analyze_contract(contract_address)"
    )

    print(
        "\nNext step: connect this analyzer "
        "to app.py/API."
    )

    print("\n" + "=" * 70)

















