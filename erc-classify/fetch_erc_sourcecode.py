
import os
import requests
import pandas as pd
import sys
import json
from dotenv import load_dotenv

# Load environment variables
load_env = load_dotenv()

# Verify if .env is loaded
print(f"✅ .env Loaded: {load_env}")

# Get API key from environment variable
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

# Set recursion limit
sys.setrecursionlimit(20000)

# Define the CSV file path
csv_file_path = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/server_output/top10_processed_ethereum_deduplicated_results.csv"  # Replace with your actual CSV file

# Load the CSV file
df = pd.read_csv(csv_file_path)

# Ensure required columns exist
if "matched_erc" not in df.columns or "address" not in df.columns:
    raise ValueError("CSV file must contain 'matched_erc' and 'address' columns.")

# Remove empty ERC matches and get unique ERC types
erc_groups = df.dropna(subset=["matched_erc"]).groupby("matched_erc")

# Base directory for storing contracts
base_dir = "ERC_Solidity_Source"

# Function to fetch Solidity source code from Etherscan
def fetch_solidity_source(contract_address):
    url = f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url)
    data = response.json()

    # Check if API response is valid
    if data["status"] == "1" and data["message"] == "OK":
        source_code = data["result"][0]["SourceCode"]
        
        # Case 1: SourceCode is JSON-wrapped
        if source_code.startswith("{{") and source_code.endswith("}}") and len(source_code) > 0:
            print(f"JSON-wrapped source code detected for {contract_address}")
            try:
                # Parse the JSON-wrapped source code
                source_json = json.loads(source_code[1:-1])  # Remove outer curly braces
                sources = source_json.get("sources", {})
                
                # Iterate over each source file and extract content
                solidity_code = ""
                for file_path, file_data in sources.items():
                    content = file_data.get("content", "")
                    solidity_code += f"// File: {file_path}\n{content}\n\n"
                
                return solidity_code if solidity_code.strip() else None
            except json.JSONDecodeError:
                print(f"❌ Failed to parse JSON-wrapped source code for {contract_address}")
                return None
        
        # Case 2: SourceCode is direct Solidity code
        elif isinstance(source_code, str) and source_code.strip():
            print(f"Direct Solidity code detected for {contract_address}")
            return source_code.strip()
        
        # Case 3: Invalid or empty source code
        else:
            print(f"❌ No valid source code found for {contract_address}")
            return None
    else:
        print(f"❌ API request failed for {contract_address}: {data.get('message', 'Unknown error')}")
        return None

# Iterate over each unique ERC type
for erc_type, group in erc_groups:
    # Initialize a list to store successfully fetched addresses
    fetched_count = 0
    required_count = 10  # Adjust as needed
    processed_addresses = set()
    
    # Create a directory for this ERC type
    erc_dir = os.path.join(base_dir, erc_type)
    os.makedirs(erc_dir, exist_ok=True)
    
    while fetched_count < required_count:
        # Get more unique contract addresses if needed
        unique_addresses = group["address"].dropna().unique()
        
        for contract_address in unique_addresses:
            if fetched_count >= required_count:
                break  # Stop when 10 contracts are fetched
            
            if contract_address in processed_addresses:
                continue  # Skip already processed addresses
            
            # Fetch Solidity source code
            solidity_code = fetch_solidity_source(contract_address)
            
            if solidity_code:
                # Define file path and save Solidity code
                file_path = os.path.join(erc_dir, f"{erc_type}_{contract_address}.sol")
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(solidity_code)
                
                fetched_count += 1
                processed_addresses.add(contract_address)
                print(f"✅ Saved: {file_path}")
            else:
                print(f"❌ No source code found for {contract_address}")

print("\n🎯 Solidity contract fetching and saving complete!")