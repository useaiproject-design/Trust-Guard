import re
import json
import requests
from web3 import Web3
from config import ETHERSCAN_API_KEY, ETHERSCAN_API_URL, INFURA_URL
from security.vulnerability_detector import detect_vulnerabilities

# --- Setup Web3 ---
web3 = Web3(Web3.HTTPProvider(INFURA_URL))

# --- ABIs and Constants ---
MINIMAL_ERC20_ABI = [
    {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"type": "uint8"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}],
     "name": "balanceOf", "outputs": [{"type": "uint256"}], "type": "function"}
]

UNISWAP_V2_FACTORY_ABI = [
    {"constant": True, "inputs": [{"type": "address"}, {"type": "address"}],
     "name": "getPair", "outputs": [{"type": "address"}], "type": "function"}
]

UNISWAP_V2_FACTORY_ADDRESS = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
WETH_ADDRESS = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
DEAD_ADDRESS = "0x000000000000000000000000000000000000dEaD"

# --- Scoring System ---
FLAG_PENALTIES = {
    # Existing checks
    "NO_VERIFIED_SOURCE": 15,
    "ONCHAIN_ANALYSIS_FAILED": 10,
    "NO_LIQUIDITY_POOL_FOUND": 8,
    "ZERO_LIQUIDITY": 8,

    # Existing vulnerabilities
    "MINT_CAPABILITY": 7,
    "UNLOCKED_LIQUIDITY": 7,
    "BLACKLIST_CAPABILITY": 5,
    "PAUSE_CAPABILITY": 4,
    "FEE_CHANGE_CAPABILITY": 3,

    # New TrustGuard vulnerabilities
    "OWNER_CONTROL": 4,
    "UPGRADEABILITY_RISK": 4,
    "EXTERNAL_CALL_PATTERN": 4,
    "TX_ORIGIN_USAGE": 7,
    "SELFDESTRUCT_CAPABILITY": 7,
    "ARBITRARY_EXTERNAL_CALL": 7,

    # Other existing checks
    "LIQUIDITY_ANALYSIS_FAILED": 2,
    "EXCESSIVE_TOTAL_SUPPLY": 1
}


def get_risk_level(score: int) -> str:
    if score >= 18: return "Very Low Risk"
    if score >= 15: return "Low Risk"
    if score >= 10: return "Medium Risk"
    if score >= 5: return "High Risk"
    return "Very High Risk"


# ---------------------------------------------------
# Etherscan V2 – Source Code Fetch
# ---------------------------------------------------
def get_verified_source_code(contract_address: str) -> str | None:
    params = {
        "chainid": 1,
        "module": "contract",
        "action": "getsourcecode",
        "address": contract_address,
        "apikey": ETHERSCAN_API_KEY
    }

    try:
        response = requests.get(ETHERSCAN_API_URL, params=params, timeout=10)
        data = response.json()

        if data.get("status") != "1" or not data.get("result"):
            return None

        result = data["result"][0]

        source_code = result.get("SourceCode", "")
        abi = result.get("ABI", "")
        proxy = result.get("Proxy")
        implementation = result.get("Implementation")

        # --- Handle proxy contracts ---
        if proxy == "1" and implementation:
            return get_verified_source_code(implementation)

        # --- Handle multi-file contracts ---
        if source_code.startswith("{{"):
            try:
                parsed = json.loads(source_code[1:-1])
                combined = ""
                sources = parsed.get("sources", parsed)
                for file_info in sources.values():
                    combined += file_info.get("content", "") + "\n"
                return combined
            except json.JSONDecodeError:
                return source_code

        # --- Normal verified contract ---
        if source_code.strip():
            return source_code

        # --- ABI exists but source hidden ---
        if abi and abi != "Contract source code not verified":
            return "// ABI verified contract"

        return None

    except Exception:
        return None


# ---------------------------------------------------
# Static Source Code Analysis
# ---------------------------------------------------
def check_for_malicious_functions(source_code: str) -> dict:
    red_flags = {}

    dangerous_patterns = {
        "MINT_CAPABILITY": r'\.mint\(',
        "BLACKLIST_CAPABILITY": r'blacklist|blockAddress',
        "PAUSE_CAPABILITY": r'pause',
        "FEE_CHANGE_CAPABILITY": r'set\w*fee'
    }

    for flag, pattern in dangerous_patterns.items():
        if re.search(pattern, source_code, re.IGNORECASE):
            red_flags[flag] = f"Potentially dangerous pattern detected: {pattern}"

    return red_flags


# ---------------------------------------------------
# On-chain Analysis
# ---------------------------------------------------
def perform_onchain_analysis(contract_address: str) -> dict:
    red_flags = {}

    try:
        checksum = web3.to_checksum_address(contract_address)
        contract = web3.eth.contract(address=checksum, abi=MINIMAL_ERC20_ABI)

        total_supply = contract.functions.totalSupply().call()
        decimals = contract.functions.decimals().call()
        adjusted_supply = total_supply / (10 ** decimals)

        if adjusted_supply > 1_000_000_000_000:
            red_flags["EXCESSIVE_TOTAL_SUPPLY"] = (
                f"Total supply is extremely high ({adjusted_supply:,.2f})"
            )

    except Exception as e:
        red_flags["ONCHAIN_ANALYSIS_FAILED"] = str(e)

    return red_flags


# ---------------------------------------------------
# Uniswap V2 Liquidity Analysis
# ---------------------------------------------------
def check_uniswap_v2_liquidity(token_address: str) -> dict:
    red_flags = {}

    if token_address.lower() == WETH_ADDRESS.lower():
        return red_flags

    try:
        factory = web3.eth.contract(
            address=web3.to_checksum_address(UNISWAP_V2_FACTORY_ADDRESS),
            abi=UNISWAP_V2_FACTORY_ABI
        )

        pair = factory.functions.getPair(
            web3.to_checksum_address(token_address),
            web3.to_checksum_address(WETH_ADDRESS)
        ).call()

        if pair == "0x0000000000000000000000000000000000000000":
            red_flags["NO_LIQUIDITY_POOL_FOUND"] = (
                "No Uniswap V2 liquidity pool found for this token."
            )
            return red_flags

        lp = web3.eth.contract(address=pair, abi=MINIMAL_ERC20_ABI)
        burned = lp.functions.balanceOf(web3.to_checksum_address(DEAD_ADDRESS)).call()
        total_lp = lp.functions.totalSupply().call()

        if total_lp == 0:
            red_flags["ZERO_LIQUIDITY"] = "Liquidity pool exists but LP supply is zero."
        else:
            burn_pct = (burned / total_lp) * 100
            if burn_pct < 90:
                red_flags["UNLOCKED_LIQUIDITY"] = (
                    f"Only {burn_pct:.2f}% of LP tokens are burned."
                )

    except Exception as e:
        red_flags["LIQUIDITY_ANALYSIS_FAILED"] = str(e)

    return red_flags


# ---------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------
def analyze_contract(contract_address: str) -> dict:
    if not re.match(r'^0x[a-fA-F0-9]{40}$', contract_address):
        return {"error": "Invalid Ethereum address format."}

    all_flags = {}

        # 1. Source Code Analysis
    vulnerabilities = []

    source_code = get_verified_source_code(contract_address)

    if source_code is None:
        all_flags["NO_VERIFIED_SOURCE"] = (
            "Verified source code could not be retrieved from Etherscan."
        )
    else:
        # Enhanced vulnerability detection
        vulnerabilities = detect_vulnerabilities(source_code)

        # Convert structured vulnerabilities into the
        # existing flag format so the current UI continues working.
        for vulnerability in vulnerabilities:
            all_flags[vulnerability["id"]] = vulnerability["description"]

    # 2. On-chain Analysis
    all_flags.update(perform_onchain_analysis(contract_address))

    # 3. Liquidity Analysis
    all_flags.update(check_uniswap_v2_liquidity(contract_address))

    # 4. Score Calculation
    total_penalty = sum(FLAG_PENALTIES.get(flag, 1) for flag in all_flags)
    score = max(20 - total_penalty, 0)

    return {
        "score": score,
        "risk_level": get_risk_level(score),
        "flags": [
            {
                "name": k,
                "description": v
            }
            for k, v in all_flags.items()
        ],
        "vulnerabilities": vulnerabilities
    }
