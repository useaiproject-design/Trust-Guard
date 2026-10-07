import os
from dotenv import load_dotenv

# Load environment variables from the .env file in the same directory
load_dotenv()

# --- Ethereum Node and Etherscan API Keys ---
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")

# --- Security Checks ---
# Ensure critical keys are present, otherwise the application cannot run.
if not ETHERSCAN_API_KEY or not INFURA_PROJECT_ID:
    raise ValueError("CRITICAL ERROR: API keys for Etherscan and Infura must be set in the .env file.")

# --- Construct Full URLs ---
# Only construct the URL if the project ID is available.
INFURA_URL = f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}" if INFURA_PROJECT_ID else None
ETHERSCAN_API_URL = "https://api.etherscan.io/v2/api"
ETHEREUM_CHAIN_ID = 1