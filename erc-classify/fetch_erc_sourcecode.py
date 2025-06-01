
import os
import requests
import pandas as pd
import sys
import json
import glob
import random


from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm



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
BINANCE_API_KEY = os.getenv("BINANCE_API_KEY")
POLYGON_API_KEY = os.getenv("POLYGON_API_KEY")




# Set recursion limit
sys.setrecursionlimit(20000)




# Chain ID mappings
CHAIN_IDS = {
    'ethereum': 1,
    'bsc': 56,
    'polygon': 137,
    'avalanche': 43114
}

def fetch_source_code(contract_address, chain='ethereum'):
    """
    Fetch Solidity source code using Etherscan's unified API v2
    chain: 'ethereum', 'bsc', 'polygon', or 'avalanche'
    """
    chain_id = CHAIN_IDS.get(chain.lower())
    if not chain_id:
        raise ValueError(f"Unsupported chain: {chain}")
    
    url = (
        f"https://api.etherscan.io/v2/api"
        f"?chainid={chain_id}"
        f"&module=contract"
        f"&action=getsourcecode"
        f"&address={contract_address}"
        f"&apikey={ETHERSCAN_API_KEY}"
    )
    
    try:
        response = requests.get(url)
        data = response.json()
        
        if data.get("status") == "1" and data.get("message") == "OK":
            source_code = data["result"][0]["SourceCode"]
            
            # Handle JSON-wrapped source (multi-file contracts)
            if source_code.startswith("{{") and source_code.endswith("}}"):
                try:
                    source_json = json.loads(source_code[1:-1])
                    solidity_code = ""
                    for file_path, file_data in source_json.get("sources", {}).items():
                        content = file_data.get("content", "")
                        solidity_code += f"// Chain: {chain.upper()} - File: {file_path}\n{content}\n\n"
                    return solidity_code.strip() or None
                except json.JSONDecodeError:
                    print(f"❌ JSON parse error for {chain.upper()} contract {contract_address}")
                    return None
            
            # Handle direct Solidity code
            elif isinstance(source_code, str) and source_code.strip():
                return source_code.strip()
        
        print(f"❌ API failed for {chain.upper()} contract {contract_address}: {data.get('message', 'Unknown error')}")
        return None
    
    except Exception as e:
        print(f"❌ Error fetching {chain.upper()} contract {contract_address}: {str(e)}")
        return None

def csv_address_source_fetch(base_dir, csv_file_path, chain='bsc', download_limit=17666, max_workers=10):
    """
    Universal fetcher for multiple chains using Etherscan v2 API
    chain: 'ethereum', 'bsc', 'polygon', or 'avalanche'
    """
    try:
        # Load and validate CSV
        df = pd.read_csv(csv_file_path)
        if "matched_erc" not in df.columns or "address" not in df.columns:
            raise ValueError("CSV must contain 'matched_erc' and 'address' columns")

        # Group by ERC type
        erc_groups = df.dropna(subset=["matched_erc"]).groupby("matched_erc")
        
        for erc_type, group in erc_groups:
            # Create chain-specific directory
            chain_dir = os.path.join(base_dir, f"{chain}_{erc_type}")
            os.makedirs(chain_dir, exist_ok=True)
            
            # Get unique addresses
            unique_addresses = group["address"].dropna().drop_duplicates().tolist()
            
            # Prepare download list (skip existing files)
            download_list = []
            for address in unique_addresses[:download_limit]:
                file_path = os.path.join(chain_dir, f"{chain}_{erc_type}_{address}.sol")
                if not os.path.exists(file_path):
                    download_list.append(address)
            
            print(f"⏳ {chain.upper()} {erc_type}: Downloading {len(download_list)} contracts")
            
            # Parallel processing
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(
                        process_contract,
                        address=address,
                        file_path=os.path.join(chain_dir, f"{chain}_{erc_type}_{address}.sol"),
                        chain=chain
                    ) for address in download_list
                ]
                
                # Track progress
                success_count = 0
                for future in tqdm(as_completed(futures), total=len(download_list), desc=f"{chain.upper()} {erc_type}"):
                    result = future.result()
                    if result["success"]:
                        success_count += 1
                    else:
                        print(f"❌ Failed {result['address']}: {result['error']}")
            
            print(f"\n✅ {chain.upper()} {erc_type}: {success_count}/{len(download_list)} saved")
    
    except Exception as e:
        print(f"🚨 {chain.upper()} processing error: {str(e)}")
        return False
    
    return True

def process_contract(address, file_path, chain):
    """Process individual contract with chain context"""
    try:
        # Skip if file already exists (race condition check)
        if os.path.exists(file_path):
            return {
                "success": False,
                "address": address,
                "error": "File exists"
            }
        
        # Fetch source code
        solidity_code = fetch_source_code(address, chain)
        if not solidity_code:
            return {
                "success": False,
                "address": address,
                "error": "No source found"
            }
        
        # Save to file
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(solidity_code)
        
        return {
            "success": True,
            "address": address,
            "path": file_path
        }
    
    except Exception as e:
        return {
            "success": False,
            "address": address,
            "error": str(e)
        }
# def csv_address_source_fetch(base_dir, csv_file_path):
#     random.seed(42)
#      # Load the CSV file
#     df = pd.read_csv(csv_file_path)

#     # Ensure required columns exist
#     if "matched_erc" not in df.columns or "address" not in df.columns:
#         raise ValueError("CSV file must contain 'matched_erc' and 'address' columns.")

#     # Remove empty ERC matches and get unique ERC types
#     erc_groups = df.dropna(subset=["matched_erc"]).groupby("matched_erc")
    
#     # Iterate over each unique ERC type
#     for erc_type, group in erc_groups:
#         # Initialize a list to store successfully fetched addresses
#         fetched_count = 0
#         required_count = 10000  # Adjust as needed
#         processed_addresses = set()
        
#         # Create a directory for this ERC type
#         erc_dir = os.path.join(base_dir, erc_type)
#         os.makedirs(erc_dir, exist_ok=True)
        
#         while fetched_count < required_count:
#             # Get more unique contract addresses if needed
#             unique_addresses = group["address"].dropna().unique()
#             # Randomly shuffle the addresses
#             random.shuffle(unique_addresses)
            
#             for contract_address in unique_addresses:
#                 if fetched_count >= required_count:
#                     break  # Stop when 10 contracts are fetched
                
#                 if contract_address in processed_addresses:
#                     continue  # Skip already processed addresses
                
#                 # Fetch Solidity source code
#                 solidity_code = fetch_solidity_source(contract_address)
                
#                 if solidity_code:
#                     # Define file path and save Solidity code
#                     file_path = os.path.join(erc_dir, f"{erc_type}_{contract_address}.sol")
#                     with open(file_path, "w", encoding="utf-8") as f:
#                         f.write(solidity_code)
                    
#                     fetched_count += 1
#                     processed_addresses.add(contract_address)
#                 #     print(f"✅ Saved: {file_path}")
#                 # else:
#                 #     print(f"❌ No source code found for {contract_address}")

#     print("\n🎯 Solidity contract fetching and saving complete!")


# def csv_address_source_fetch(base_dir, csv_file_path, sample_size=5000, max_workers=10):
#     """Fetch Solidity source code for contracts from CSV with parallel processing"""
#     # Set random seed for reproducibility
#     # random.seed(random_seed)
    
#     try:
#         # Load the CSV file with error handling
#         df = pd.read_csv(csv_file_path)
        
#         # Validate required columns
#         if "matched_erc" not in df.columns or "address" not in df.columns:
#             raise ValueError("CSV must contain 'matched_erc' and 'address' columns")

#         # Clean and prepare data
#         erc_groups = (df.dropna(subset=["matched_erc"])
#                      .groupby("matched_erc"))
        
#         # Process each ERC type
#         for erc_type, group in erc_groups:
#             erc_dir = os.path.join(base_dir, erc_type)
#             os.makedirs(erc_dir, exist_ok=True)
            
#             # Get all unique addresses (remove duplicates and nulls)
#             unique_addresses = (group["address"]
#                               .dropna()
#                               .drop_duplicates()
#                               .tolist())
            
#             # Random sampling with minimum of sample_size or available contracts
#             # random.shuffle(unique_addresses)
#             selected_addresses = unique_addresses[:min(sample_size, len(unique_addresses))]
            
#             # Parallel processing with progress tracking
#             with ThreadPoolExecutor(max_workers=max_workers) as executor:
#                 futures = []
#                 for address in selected_addresses:
#                     futures.append(
#                         executor.submit(
#                             process_contract,
#                             address=address,
#                             erc_type=erc_type,
#                             erc_dir=erc_dir
#                         )
#                     )
                
#                 # Track progress and handle results
#                 success_count = 0
#                 for future in tqdm(as_completed(futures), 
#                                  total=len(selected_addresses),
#                                  desc=f"Fetching {erc_type}"):
#                     result = future.result()
#                     if result["success"]:
#                         success_count += 1
#                     else:
#                         print(f"❌ Failed {result['address']}: {result['error']}")
            
#             print(f"\n✅ Completed {erc_type}: {success_count}/{len(selected_addresses)} contracts saved")
    
#     except Exception as e:
#         print(f"🚨 Critical error: {str(e)}")
#         return False
    
#     return True

# def process_contract(address, erc_type, erc_dir):
#     """Worker function to process individual contracts"""
#     try:
#         solidity_code = fetch_solidity_source(address)
#         if not solidity_code:
#             return {
#                 "success": False,
#                 "address": address,
#                 "error": "No source code found"
#             }
        
#         file_path = os.path.join(erc_dir, f"{erc_type}_{address}.sol")
#         with open(file_path, "w", encoding="utf-8") as f:
#             f.write(solidity_code)
        
#         return {
#             "success": True,
#             "address": address,
#             "path": file_path
#         }
    
#     except Exception as e:
#         return {
#             "success": False,
#             "address": address,
#             "error": str(e)
#         }

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


# def csv_address_source_fetch(base_dir, csv_file_path, download_limit=9914, max_workers=10):
#     """
#     Fetch Solidity source code for contracts from CSV with parallel processing
#     Downloads first N files (without randomness), skipping existing files
#     """
#     try:
#         # Load the CSV file with error handling
#         df = pd.read_csv(csv_file_path)
        
#         # Validate required columns
#         if "matched_erc" not in df.columns or "address" not in df.columns:
#             raise ValueError("CSV must contain 'matched_erc' and 'address' columns")

#         # Clean and prepare data
#         erc_groups = (df.dropna(subset=["matched_erc"])
#                      .groupby("matched_erc"))
        
#         # Process each ERC type
#         for erc_type, group in erc_groups:
#             erc_dir = os.path.join(base_dir, erc_type)
#             os.makedirs(erc_dir, exist_ok=True)
            
#             # Get all unique addresses (remove duplicates and nulls)
#             unique_addresses = (group["address"]
#                               .dropna()
#                               .drop_duplicates()
#                               .tolist())
            
#             # Prepare download list with existence check
#             download_list = []
#             for address in unique_addresses[:download_limit]:
#                 file_path = os.path.join(erc_dir, f"{erc_type}_{address}.sol")
#                 if not os.path.exists(file_path):
#                     download_list.append(address)
#                 else:
#                     # Skip already downloaded files
#                     continue
            
#             print(f"⏳ {erc_type}: {len(download_list)} files to download (skipping {download_limit - len(download_list)} existing files)")
            
#             # Parallel processing with progress tracking
#             with ThreadPoolExecutor(max_workers=max_workers) as executor:
#                 futures = []
#                 for address in download_list:
#                     futures.append(
#                         executor.submit(
#                             process_contract,
#                             address=address,
#                             erc_type=erc_type,
#                             erc_dir=erc_dir
#                         )
#                     )
                
#                 # Track progress and handle results
#                 success_count = 0
#                 for future in tqdm(as_completed(futures), 
#                                  total=len(download_list),
#                                  desc=f"Downloading {erc_type}"):
#                     result = future.result()
#                     if result["success"]:
#                         success_count += 1
#                     else:
#                         print(f"❌ Failed {result['address']}: {result['error']}")
            
#             print(f"\n✅ Completed {erc_type}: {success_count}/{len(download_list)} new contracts saved")
    
#     except Exception as e:
#         print(f"🚨 Critical error: {str(e)}")
#         return False
    
#     return True

# def process_contract(address, erc_type, erc_dir):
#     """Worker function to process individual contracts"""
#     try:
#         # Double-check file doesn't exist (race condition protection)
#         file_path = os.path.join(erc_dir, f"{erc_type}_{address}.sol")
#         if os.path.exists(file_path):
#             return {
#                 "success": False,
#                 "address": address,
#                 "error": "File already exists (race condition)"
#             }
        
#         solidity_code = fetch_solidity_source(address)
#         if not solidity_code:
#             return {
#                 "success": False,
#                 "address": address,
#                 "error": "No source code found"
#             }
        
#         with open(file_path, "w", encoding="utf-8") as f:
#             f.write(solidity_code)
        
#         return {
#             "success": True,
#             "address": address,
#             "path": file_path
#         }
    
#     except Exception as e:
#         return {
#             "success": False,
#             "address": address,
#             "error": str(e)
#         }


# def fetch_contract_tvl(contract_address):
#     """Fetch TVL for a single contract address using Etherscan API"""
#     try:
#         url = f"https://api.etherscan.io/api?module=account&action=tokenbalance&contractaddress={contract_address}&address=0x000000000000000000000000000000000000dead&tag=latest&apikey={ETHERSCAN_API_KEY}"
#         response = requests.get(url)
#         data = response.json()
        
#         if data["status"] == "1":
#             # Convert balance from wei to ETH
#             balance_wei = int(data["result"])
#             balance_eth = balance_wei / 10**18
#             return {
#                 "success": True,
#                 "address": contract_address,
#                 "tvl": balance_eth
#             }
#         else:
#             return {
#                 "success": False,
#                 "address": contract_address,
#                 "error": data.get("message", "Unknown API error")
#             }
            
#     except Exception as e:
#         return {
#             "success": False,
#             "address": contract_address,
#             "error": str(e)
#         }

# def fetch_all_tvl(csv_file_path, output_csv_path=None, max_workers=10):
#     """
#     Fetch TVL for all contracts in CSV file
#     Args:
#         csv_file_path: Path to input CSV with contract addresses
#         output_csv_path: Optional path to save results (default: appends to input CSV)
#         max_workers: Number of parallel threads
#     Returns:
#         DataFrame with TVL results
#     """
#     try:
#         # Load CSV
#         df = pd.read_csv(csv_file_path)
        
#         # Validate columns
#         if "address" not in df.columns:
#             raise ValueError("CSV must contain 'address' column")
            
#         # Get unique addresses
#         addresses = df["address"].dropna().drop_duplicates().tolist()
        
#         print(f"⏳ Fetching TVL for {len(addresses)} contracts...")
        
#         # Parallel processing
#         results = []
#         with ThreadPoolExecutor(max_workers=max_workers) as executor:
#             futures = [executor.submit(fetch_contract_tvl, addr) for addr in addresses]
            
#             for future in tqdm(as_completed(futures), total=len(addresses), desc="Fetching TVL"):
#                 results.append(future.result())
        
#         # Process results
#         success_results = [r for r in results if r["success"]]
#         success_count = len(success_results)
#         print(f"\n✅ Completed: {success_count}/{len(addresses)} successful TVL fetches")
        
#         # Calculate total TVL
#         total_tvl = sum(r["tvl"] for r in success_results)
#         print(f"💰 Total TVL across all contracts: {total_tvl:,.2f} ETH")
        
#         # Create enhanced results DataFrame
#         tvl_df = pd.DataFrame(results)
#         tvl_df["tvl_usd"] = tvl_df["tvl"] * get_eth_price()  # Add USD conversion
        
#         # Merge with original data
#         output_df = df.merge(
#             tvl_df[["address", "tvl", "tvl_usd"]],
#             on="address",
#             how="left"
#         )
        
#         # Save results
#         if output_csv_path:
#             output_df.to_csv(output_csv_path, index=False)
#             print(f"💾 Saved results to {output_csv_path}")
            
#         return output_df, total_tvl
        
#     except Exception as e:
#         print(f"🚨 Error: {str(e)}")
#         return None, 0

# def get_eth_price():
#     """Fetch current ETH price in USD"""
#     url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
#     response = requests.get(url)
#     return response.json()["ethereum"]["usd"]




def fetch_contract_data(contract_address):
    """Fetch both TVL and transaction count for a single contract"""
    try:
        # Initialize result dict
        result = {
            "address": contract_address,
            "success": False,
            "tvl": 0,
            "tx_count": 0,
            "error": None
        }
        
        # Fetch TVL
        tvl_url = f"https://api.etherscan.io/api?module=account&action=tokenbalance&contractaddress={contract_address}&address=0x000000000000000000000000000000000000dead&tag=latest&apikey={ETHERSCAN_API_KEY}"
        tvl_response = requests.get(tvl_url)
        tvl_data = tvl_response.json()
        
        if tvl_data["status"] == "1":
            result["tvl"] = int(tvl_data["result"]) / 10**18
            result["success"] = True
        else:
            result["error"] = f"TVL error: {tvl_data.get('message', 'Unknown error')}"
            return result
        
        # Fetch transaction count
        tx_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={contract_address}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_API_KEY}"
        tx_response = requests.get(tx_url)
        tx_data = tx_response.json()
        
        if tx_data["status"] == "1":
            result["tx_count"] = len(tx_data["result"])
        else:
            result["error"] = f"Tx count error: {tx_data.get('message', 'Unknown error')}"
        
        return result
        
    except Exception as e:
        return {
            "address": contract_address,
            "success": False,
            "error": str(e),
            "tvl": 0,
            "tx_count": 0
        }

def fetch_all_contract_data(csv_file_path, output_csv_path="contracts_analysis.csv", max_workers=10):
    """
    Fetch comprehensive data for all contracts including:
    - Individual TVL and transaction counts
    - Combined totals
    - USD conversions
    """
    try:
        # Load CSV
        df = pd.read_csv(csv_file_path)
        
        if "address" not in df.columns:
            raise ValueError("CSV must contain 'address' column")
            
        addresses = df["address"].dropna().drop_duplicates().tolist()
        
        print(f"⏳ Analyzing {len(addresses)} contracts (TVL + Transactions)...")
        
        # Parallel processing
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(fetch_contract_data, addr) for addr in addresses]
            
            for future in tqdm(as_completed(futures), total=len(addresses), desc="Processing"):
                results.append(future.result())
        
        # Process results
        success_results = [r for r in results if r["success"]]
        success_count = len(success_results)
        
        # Calculate totals
        total_tvl = sum(r["tvl"] for r in success_results)
        total_txs = sum(r["tx_count"] for r in results)  # Include all attempts
        
        # Get ETH price
        try:
            eth_price = get_eth_price()
        except:
            eth_price = 1800  # Fallback value
            print("⚠️ Using fallback ETH price")
        
        # Create DataFrame
        analysis_df = pd.DataFrame(results)
        analysis_df["tvl_usd"] = analysis_df["tvl"] * eth_price
        
        # Merge with original data
        output_df = df.merge(
            analysis_df[["address", "tvl", "tvl_usd", "tx_count", "error"]],
            on="address",
            how="left"
        )
        
        # Add summary row
        summary_row = pd.DataFrame([{
            "address": "TOTAL",
            "tvl": total_tvl,
            "tvl_usd": total_tvl * eth_price,
            "tx_count": total_txs,
            "error": None
        }])
        output_df = pd.concat([output_df, summary_row], ignore_index=True)
        
        # Save results
        output_df.to_csv(output_csv_path, index=False)
        print(f"\n📊 Analysis Complete:")
        print(f"- Contracts processed: {len(addresses)}")
        print(f"- Successful analyses: {success_count}")
        print(f"- Total TVL: {total_tvl:,.2f} ETH (${total_tvl * eth_price:,.2f})")
        print(f"- Total Transactions: {total_txs:,}")
        print(f"💾 Saved full analysis to {output_csv_path}")
        
        return output_df
        
    except Exception as e:
        print(f"🚨 Critical error: {str(e)}")
        return None

# Helper function remains the same
def get_eth_price():
    """Fetch current ETH price in USD"""
    url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
    response = requests.get(url)
    return response.json()["ethereum"]["usd"]


# # Base URL for Etherscan Verified Contracts (Adjust for ERC Type)
# ETHERSCAN_VERIFIED_CONTRACTS_URL = "https://etherscan.io/contractsVerified"

# # Number of contracts to fetch per ERC type
# NUM_CONTRACTS = 10

# # Output folder for saving contract details
# OUTPUT_DIR = "ERC_Contracts"

# # Function to scrape contract addresses from Etherscan
# def scrape_contract_addresses(erc_type):
#     """Scrapes verified contract addresses for a given ERC type from Etherscan"""
#     response = requests.get(ETHERSCAN_VERIFIED_CONTRACTS_URL)
#     soup = BeautifulSoup(response.text, "html.parser")

#     # Find all contract address links
#     contract_links = soup.find_all("a", href=True)

#     # Extract contract addresses
#     contract_addresses = []
#     for link in contract_links:
#         href = link["href"]
#         if href.startswith("/address/"):
#             contract_address = href.split("/")[-1]
#             contract_addresses.append(contract_address)

#         if len(contract_addresses) >= NUM_CONTRACTS:
#             break  # Stop after fetching required contracts

#     return contract_addresses

# # Function to fetch contract details from Etherscan API
# def fetch_contract_details(contract_address):
#     """Fetches ABI, Bytecode, and Source Code from Etherscan API"""
#     api_endpoints = {
#         "abi": f"https://api.etherscan.io/api?module=contract&action=getabi&address={contract_address}&apikey={ETHERSCAN_API_KEY}",
#         "bytecode": f"https://api.etherscan.io/api?module=proxy&action=eth_getCode&address={contract_address}&apikey={ETHERSCAN_API_KEY}",
#         "source_code": f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={contract_address}&apikey={ETHERSCAN_API_KEY}"
#     }

#     contract_data = {}
#     for key, url in api_endpoints.items():
#         response = requests.get(url)
#         data = response.json()
#         if data["status"] == "1":
#             contract_data[key] = data["result"]
#         else:
#             contract_data[key] = None

#         time.sleep(1)  # To avoid rate limits

#     return contract_data

# # Function to save contract details
# def save_contract_details(erc_type, contract_address, contract_data):
#     """Saves ABI, Bytecode, and Source Code to respective files"""
#     erc_dir = os.path.join(OUTPUT_DIR, erc_type)
#     os.makedirs(erc_dir, exist_ok=True)

#     # Save ABI
#     abi_path = os.path.join(erc_dir, f"{contract_address}_abi.json")
#     with open(abi_path, "w", encoding="utf-8") as f:
#         json.dump(contract_data["abi"], f, indent=4)

#     # Save Bytecode
#     bytecode_path = os.path.join(erc_dir, f"{contract_address}_bytecode.txt")
#     with open(bytecode_path, "w", encoding="utf-8") as f:
#         f.write(contract_data["bytecode"])

#     # Save Solidity Source Code
#     if contract_data["source_code"]:
#         source_code = json.loads(contract_data["source_code"][0]["SourceCode"])
#         solidity_code = "\n".join(file_data.get("content", "") for file_data in source_code["sources"].values())

#         solidity_path = os.path.join(erc_dir, f"{contract_address}.sol")
#         with open(solidity_path, "w", encoding="utf-8") as f:
#             f.write(solidity_code)

#     print(f"✅ Saved contract data for {contract_address} in {erc_dir}")

# Main execution function
def main():
    
    
    # results = fetch_all_contract_data(
    #     csv_file_path="/home/ashok/output/ERC-1155_safeBatchTransferFrom_ethereum_deduplicated_results.csv",
    #     output_csv_path="/home/ashok/ERC-analysis/erc-classify/TVL_TXN_Data.csv",
    #     max_workers=15)

    # csv_dir = "/Users/ashokk/Downloads/evm_data/ethereum_deduplicated_results.csv"   
    # base_dir = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/ERC_Solidity_Source"
    
    
        # ERC-721_setApprovedForAll_binance_deduplicated_results.csv
        # ERC-721_setApprovedForAll_deduplicated_avalanche.csv
        # ERC-721_setApprovedForAll_deduplicated_polygon.csv
        # ERC-721_setApprovedForAll_ethereum_deduplicated_results.csv
        
    # base_dir_ethereum = "/home/ashok/ERC-analysis/erc-classify/ERC1155-ethereum"
    base_dir_binance = "/home/ashok/ERC-analysis/erc-classify/ERC1155-polygon"
    csv_dir = "/home/ashok/output/"  # Directory containing your CSV files
    # csv_files = glob.glob(os.path.join(csv_dir, "ERC-1155_safeBatchTransferFrom_ethereum_deduplicated_results.csv"))
    csv_files = glob.glob(os.path.join(csv_dir, "ERC-1155_safeBatchTransferFrom_deduplicated_polygon.csv"))
    
    
    if not csv_files:
        print(f"No CSV files starting with  found in {csv_dir}")
        return
    
    for csv_file_path in csv_files:
        print(f"\nProcessing file: {csv_file_path}")
        try:
            # csv_address_source_fetch(base_dir_ethereum, csv_file_path, download_limit=9914, max_workers=10)
            # Fetch BSC contracts
            csv_address_source_fetch(
                base_dir_binance,
                csv_file_path,
                chain="polygon",
                max_workers=10
            )
        except Exception as e:
            print(f"Error processing {csv_file_path}: {str(e)}")
    
    
    

if __name__ == "__main__":
    main()