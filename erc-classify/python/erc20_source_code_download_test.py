import os
import requests
from dotenv import load_dotenv

# load_dotenv("/home/ashok/ashokTests/ERC-analysis/.env")
load_dotenv()

ADDRESS = "0x0a1b78443291ba764ae52d61c4e8e1a6cda462a7"
API_KEY = os.getenv("ETHERSCAN_API_KEY1")
OUT = f"/Users/ashokk/Documents/ERC-analysis-master/erc-classify/{ADDRESS}_TheGoblin.sol"

params = {
    "chainid": 1,
    "module": "contract",
    "action": "getsourcecode",
    "address": ADDRESS,
    "apikey": API_KEY,
}

data = requests.get("https://api.etherscan.io/v2/api", params=params, timeout=30).json()
item = data["result"][0]

source = item["SourceCode"]
name = item["ContractName"]

print("contract:", name)
print("source length:", len(source))
print("starts with JSON:", source.strip().startswith("{"))
print("contains eip712Domain:", "eip712Domain" in source)
print("contains hex\"0f\":", 'hex"0f"' in source)

with open(OUT, "w", encoding="utf-8") as f:
    f.write(source)

print("saved:", OUT)

idx = source.find("function eip712Domain")
if idx == -1:
    idx = source.find('hex"0f"')

print("\n--- eip712Domain snippet ---")
print(source[max(0, idx - 500): idx + 1200])