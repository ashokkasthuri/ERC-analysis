
import os
import requests
import pandas as pd
import sys
import json
import glob


import time

from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Load environment variables
# load_env = load_dotenv()
load_env = load_dotenv("/home/ashok/ERC-analysis/.env")

# Verify if .env is loaded
print(f"✅ .env Loaded: {load_env}")

# Get API key from environment variable
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

# Set recursion limit
sys.setrecursionlimit(20000)



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
        
        # # Case 3: Invalid or empty source code
        # else:
        #     print(f"❌ No valid source code found for {contract_address}")
        #     return None
    else:
        print(f"❌ API request failed for {contract_address}: {data.get('message', 'Unknown error')}")
        return None

def csv_address_source_fetch(base_dir, csv_file_path):
     # Load the CSV file
    df = pd.read_csv(csv_file_path)

    # Ensure required columns exist
    if "matched_erc" not in df.columns or "address" not in df.columns:
        raise ValueError("CSV file must contain 'matched_erc' and 'address' columns.")

    # Remove empty ERC matches and get unique ERC types
    erc_groups = df.dropna(subset=["matched_erc"]).groupby("matched_erc")
    
    # Iterate over each unique ERC type
    for erc_type, group in erc_groups:
        # Initialize a list to store successfully fetched addresses
        fetched_count = 0
        required_count = 200  # Adjust as needed
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
                #     print(f"✅ Saved: {file_path}")
                # else:
                #     print(f"❌ No source code found for {contract_address}")

    print("\n🎯 Solidity contract fetching and saving complete!")

# Base URL for Etherscan Verified Contracts (Adjust for ERC Type)
ETHERSCAN_VERIFIED_CONTRACTS_URL = "https://etherscan.io/contractsVerified"

# Number of contracts to fetch per ERC type
NUM_CONTRACTS = 10

# Output folder for saving contract details
OUTPUT_DIR = "ERC_Contracts"

# Function to scrape contract addresses from Etherscan
def scrape_contract_addresses(erc_type):
    """Scrapes verified contract addresses for a given ERC type from Etherscan"""
    response = requests.get(ETHERSCAN_VERIFIED_CONTRACTS_URL)
    soup = BeautifulSoup(response.text, "html.parser")

    # Find all contract address links
    contract_links = soup.find_all("a", href=True)

    # Extract contract addresses
    contract_addresses = []
    for link in contract_links:
        href = link["href"]
        if href.startswith("/address/"):
            contract_address = href.split("/")[-1]
            contract_addresses.append(contract_address)

        if len(contract_addresses) >= NUM_CONTRACTS:
            break  # Stop after fetching required contracts

    return contract_addresses

# Function to fetch contract details from Etherscan API
def fetch_contract_details(contract_address):
    """Fetches ABI, Bytecode, and Source Code from Etherscan API"""
    api_endpoints = {
        "abi": f"https://api.etherscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={ETHERSCAN_API_KEY}",
        "bytecode": f"https://api.etherscan.io/api?module=proxy&action=eth_getCode&address={contract_address}&apikey={ETHERSCAN_API_KEY}",
        "source_code": f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
    }

    contract_data = {}
    for key, url in api_endpoints.items():
        response = requests.get(url)
        data = response.json()
        if data["status"] == "1":
            contract_data[key] = data["result"]
        else:
            contract_data[key] = None

        time.sleep(1)  # To avoid rate limits

    return contract_data

# Function to save contract details
def save_contract_details(erc_type, contract_address, contract_data):
    """Saves ABI, Bytecode, and Source Code to respective files"""
    erc_dir = os.path.join(OUTPUT_DIR, erc_type)
    os.makedirs(erc_dir, exist_ok=True)

    # Save ABI
    abi_path = os.path.join(erc_dir, f"{contract_address}_abi.json")
    with open(abi_path, "w", encoding="utf-8") as f:
        json.dump(contract_data["abi"], f, indent=4)

    # Save Bytecode
    bytecode_path = os.path.join(erc_dir, f"{contract_address}_bytecode.txt")
    with open(bytecode_path, "w", encoding="utf-8") as f:
        f.write(contract_data["bytecode"])

    # Save Solidity Source Code
    if contract_data["source_code"]:
        source_code = json.loads(contract_data["source_code"][0]["SourceCode"])
        solidity_code = "\n".join(file_data.get("content", "") for file_data in source_code["sources"].values())

        solidity_path = os.path.join(erc_dir, f"{contract_address}.sol")
        with open(solidity_path, "w", encoding="utf-8") as f:
            f.write(solidity_code)

    print(f"✅ Saved contract data for {contract_address} in {erc_dir}")

# Main execution function
def main():
    erc_types = ["ERC4626", "ERC223"]  # Add more ERC types if needed
    
    # csv_dir = "/Users/ashokk/Downloads/evm_data/ethereum_deduplicated_results.csv"   
    # base_dir = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/ERC_Solidity_Source"
    
    # base_dir = "/home/ashok/ERC-analysis/erc-classify/ERC_Solidity_Source"
    base_dir = "/home/ashok/output/ERC1155_Solidity_SourceCode"
    base_dir = "/home/ashok/ERC-analysis/erc-classify/ERC1155-polygon"
    
    csv_dir = "/home/ashok/output/"  # Directory containing your CSV files
    
    # Find all CSV files starting with "ERC-1155"
    # 1155_safeBatchTransferFrom_ethereum_deduplicated_results.csv
    # csv_files = glob.glob(os.path.join(csv_dir, "ERC-1155_safeBatchTransferFrom_ethereum_deduplicated_results.csv"))
    csv_files = glob.glob(os.path.join(csv_dir, "ERC-1155_safeBatchTransferFrom_deduplicated_polygon.csv"))
    
    # csv_files1 = glob.glob(os.path.join(csv_dir, "ERC-7231*.csv"))
    # csv_files2 = glob.glob(os.path.join(csv_dir, "ERC-7401*.csv"))
    # csv_files3 = glob.glob(os.path.join(csv_dir, "ERC-7409*.csv"))
    # csv_files4 = glob.glob(os.path.join(csv_dir, "ERC-6606*.csv"))
    # csv_files5 = glob.glob(os.path.join(csv_dir, "ERC-erc5023*.csv"))
    # csv_files6 = glob.glob(os.path.join(csv_dir, "ERC-erc3643*.csv"))
    
    if not csv_files:
        print(f"No CSV files starting with  found in {csv_dir}")
        return
    
    for csv_file_path in csv_files:
        print(f"\nProcessing file: {csv_file_path}")
        try:
            csv_address_source_fetch(base_dir, csv_file_path)
        except Exception as e:
            print(f"Error processing {csv_file_path}: {str(e)}")
    

if __name__ == "__main__":
    main()