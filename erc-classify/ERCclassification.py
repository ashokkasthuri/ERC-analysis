import os

import requests
import json
import time
import pandas as pd
import sys
import os
from dotenv import load_dotenv
from collections import defaultdict




current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, ".."))

if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import rattle

sys.setrecursionlimit(20000)

# Load .env explicitly from the main project directory

load_env = load_dotenv("/home/ashok/ERC-analysis/.env")
# load_env = load_dotenv()

# Verify if .env is loaded
print(f"✅ .env Loaded: {load_env}")

# Get API key from environment variable
API_KEY = os.getenv("ETHERSCAN_API_KEY")

if not API_KEY:
    raise ValueError("⚠️ API Key not found! Make sure to set ETHERSCAN_API_KEY in your .env file.")

print(f"🔑 Using Etherscan API Key: {API_KEY[:5]}****** (Hidden for security)")


# List of token ERCs
token_ercs = {
    "ERC20", "ERC721", "ERC777", "ERC1155", "ERC998", "ERC1046", "ERC1363", "ERC2309", 
    "ERC2612", "ERC1948", "ERC1337", "ERC2021", "ERC2019", "ERC1996", "ERC2020", 
    "ERC3135", "ERC3589", "ERC4524", "ERC3525", "ERC3643", "ERC4626", "ERC4907", 
    "ERC4955", "ERC5169", "ERC5192", "ERC5380", "ERC5507", "ERC5528", "ERC5570", 
    "ERC5585", "ERC5606", "ERC5615", "ERC5679", "ERC5725", "ERC6105", "ERC6808", "ERC6809"
}


def fetch_source_code(address: str) -> dict:
    """
    Fetch the verified source code for a contract address from Etherscan.
    """
    url = (
        f"https://api.etherscan.io/api?module=contract&action=getsourcecode"
        f"&address={address}&apikey={API_KEY}"
    )
    response = requests.get(url)
    try:
        return response.json()
    except Exception as e:
        return {"error": str(e)}

def save_source_code(address: str, source_info: dict) -> None:
    """
    Save the contract source code into a file named <address>.sol in the "contracts" folder.
    """
    result = source_info.get("result")
    if not result or len(result) == 0:
        print(f"No source code data found for {address}")
        return

    source_code = result[0].get("SourceCode")
    if not source_code:
        print(f"No source code available for {address}")
        return

    os.makedirs("contracts", exist_ok=True)
    filename = f"contracts/{address}.sol"
    base_filename = filename[:-4]
    counter = 1
    while os.path.exists(filename):
        filename = f"{base_filename}_{counter}.sol"
        counter += 1

    with open(filename, "w", encoding="utf-8") as f:
        f.write(source_code)
    print(f"Saved source code for {address} to {filename}")


def match_erc_type(bytecode, event_topics):
    event_topics = [topic.lower() for topic in event_topics]
    
    # Check if all event topics are present in the bytecode
    for topic in event_topics:
        if topic not in bytecode.lower():
            # print(f"topic not found: {topic}")  # Debugging statement
            return False
    return True
def ERC_classification():
    
    common_erc_types = {"ERC20", "ERC721", "ERC1155", "ERC173", "ERC2981", "ERC2612", "ERC3754"}
    # Load the ERC configuration JSON
    # with open("temp.json", "r") as f:
    with open("erc_config_top50.json", "r") as f:
        erc_config = json.load(f)
    
    # Load the dataset
    # df = pd.read_csv("/Users/ashokk/Downloads/ethereum_deduplicated_results.csv")
    # df_subset = pd.read_csv("/home/ashok/data/ethereum_deduplicated_results.csv")
    df = pd.read_csv("/home/ashok/data/binance_deduplicated_results.csv")
    # df_subset = pd.read_csv("/Users/ashokk/Documents/ERC-analysis-master/erc-classify/test1_erc_classification_results_top50_server.csv")
    
     # Use a subset of the data for testing
    df_subset = df.head(1000).copy()  # Adjust the number of rows as needed
    
    # Ensure "matched_erc" and "bytecode_short" columns exist (use existing if available)
    if "matched_erc" not in df_subset.columns:
        df_subset["matched_erc"] = ""

    if "bytecode_short" not in df_subset.columns:
        df_subset["bytecode_short"] = df_subset["bytecode"].str[:40]  # Create if missing

   
    
    # Initialize a list to store matched ERC types for each bytecode
    matched_erc_types = []
    # Dictionary to track the count of matches per ERC type
    erc_match_counts = defaultdict(int)
    
    # Iterate over each row in the dataset
    for idx, row in df_subset.iterrows():
        original_bytecode_str = row["bytecode"]
        current_matches = []
        
        # # Check that we have a string and remove "0x" prefix if present.
        # if isinstance(original_bytecode_str, str):
        #     if original_bytecode_str.startswith("0x") or original_bytecode_str.startswith("0X"):
        #         hex_str = original_bytecode_str[2:]
        #     else:
        #         hex_str = original_bytecode_str
        #     # Instead of converting to binary, encode the hex string as UTF-8 bytes.
        #     # This makes sure rattle.Recover gets a valid UTF-8–encoded hex string.
        #     bytecode_utf8 = hex_str.encode("utf-8")
        # else:
        #     # If already not a string, assume it's already in the correct bytes format.
        #     bytecode_utf8 = original_bytecode_str
        
        # try:
        #     # Recover the SSA form using Rattle.
        #     ssa = rattle.Recover(bytecode_utf8, edges=[], optimize=False, split_functions=False)
        # except Exception as e:
        #     print(f"Error recovering SSA for row {idx}: {e}")
        #     # Append an empty list for this row to keep lengths consistent.
        #     matched_erc_types.append([])
        #     continue
        
        # ssa_hashes = {function.hash for function in ssa.functions}
        
        # Iterate over each ERC type in the configuration
        for erc_type, config in erc_config.items():
            
            if erc_type in common_erc_types:
                continue
            # Skip if this ERC type has already reached the limit of 10 matches
            if erc_match_counts[erc_type] >= 1:
                continue
            # Get the required selectors and event topics for the ERC type
            selectors = config.get("selectors", [])
            event_topics = config.get("topics", [])
            
            # Convert selectors (hex strings) to integers for comparison.
            # selector_matched = all(int(selector, 16) in ssa_hashes for selector in selectors)
            
            # Check if all event topics are present in the bytecode
            event_matched = match_erc_type(original_bytecode_str, event_topics)
            selector_matched = match_erc_type(original_bytecode_str, selectors)
            
            # If both selectors and events match, add the ERC type to the current matches
            if selector_matched and event_matched:
                current_matches.append(erc_type)
                erc_match_counts[erc_type] += 1
        
        # Add the current matches to the list of matched ERC types
        matched_erc_types.append(current_matches)
    
    # Ensure that matched_erc_types has the same length as df_subset
    if len(matched_erc_types) != len(df_subset):
        raise ValueError(f"Length mismatch: {len(matched_erc_types)} vs {len(df_subset)}")
    
    # Add the matched ERC types to the DataFrame
    # df_subset.loc[:, "matched_erc"] = matched_erc_types
    
    # Convert matched_erc_types to a flat string before assigning (if column was empty)
    df_subset["matched_erc"] = [
        ";".join(map(str, lst)) if isinstance(lst, list) else str(lst)
        if val == "" else val  # Keep existing values
        for lst, val in zip(matched_erc_types, df_subset["matched_erc"])
    ]
    
    # Add the "Binary Token Classification" column
    df_subset["Binary Token Classification"] = df_subset["matched_erc"].apply(
        lambda x: f"YES, {x}" if x in token_ercs else ""
    )
    
    # Filter the DataFrame to only include rows where "matched_erc" is non-empty
    filtered_df = df_subset[df_subset["matched_erc"].apply(lambda x: len(x) > 0)]
    
    # Now, further filter by transaction activity.
    final_rows = []
    for idx, row in filtered_df.iterrows():
        address = row["address"]
        tx_info = fetch_tx_activity_copy(address)
        if tx_info.get("status") != "1":
            # print(f"Error fetching tx activity for {address}: {tx_info.get('message', tx_info)}")
            continue
        
        tx_list = tx_info.get("result", [])
        if not should_fetch_contract_copy(tx_list):
            # print(f"Skipping {address}: does not meet tx activity criteria.")
            continue
        
        final_rows.append(row)
    
    # Create a new DataFrame from the final rows.
    if final_rows:
        final_df = pd.DataFrame(final_rows)
        # Sort the DataFrame by matched_erc to group rows with the same ERC type together
        final_df = final_df.explode("matched_erc").sort_values(by="matched_erc")
        
        print(final_df[["address", "bytecode_short", "matched_erc", "Binary Token Classification"]])
        final_df.to_csv("test1_erc_classification_results_top50_server_binance.csv", index=False)
        # final_df.to_csv("temp_results.csv", index=False)
    else:
        print("No contracts meet both the ERC match and transaction activity criteria.")

def should_fetch_contract_copy(tx_list) -> bool:
    """
    Return True if the total number of transactions is > 100 and
    at least one transaction happened in the last 30 days.
    """
    if not tx_list:
        return False

    

    now = int(time.time())
    thirty_days = 900 * 24 * 3600
    recent = any(int(tx["timeStamp"]) >= (now - thirty_days) for tx in tx_list)
    
    if not recent:
        return False

    # Sum transaction values (in Wei)
    total_value = sum(int(tx["value"]) for tx in tx_list)
    min_total_value = 100000000000000000  # 0.1 ETH in wei

    has_min_value = total_value >= min_total_value

    # Debug prints (optional)
    # print(f"Total transactions: {total_tx}, Recent? {recent}, Total value (wei): {total_value}, has_min_value : {has_min_value}")

    # Heuristic 2: Total transaction volume
    # total_tx = len(tx_list)
    # if total_tx <= 10:
    #     print(f"Low transaction volume: {total_tx}.")
    #     return False

    # # Heuristic 3: Total transaction value
    # total_value = sum(int(tx["value"]) for tx in tx_list)
    # min_total_value = 10000000000000000
    # if total_value < min_total_value:
    #     print(f"Low transaction value: {total_value}.")
    #     return False

    # # Heuristic 4: Unique interactors
    # unique_interactors = set(tx["from"] for tx in tx_list).union(set(tx["to"] for tx in tx_list))
    # if len(unique_interactors) < 10:
    #     print(f"Low unique interactors: {len(unique_interactors)}.")
    #     return False

    # # Heuristic 5: Gas usage
    # total_gas_used = sum(int(tx["gasUsed"]) for tx in tx_list)
    # min_gas_used = 1000000
    # if total_gas_used < min_gas_used:
    #     print(f"Low gas usage: {total_gas_used}.")
    #     return False
    # return recent and has_min_value
    return True


def fetch_tx_activity_copy(address: str) -> dict:
    """
    Fetch the transaction activity for a contract address from Etherscan.
    """
    url = (
        f"https://api.etherscan.io/api?module=account&action=txlist"
        f"&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={API_KEY}"
    )
    response = requests.get(url)
    try:
        return response.json()
    except Exception as e:
        return {"error": str(e)}
   
def verify_source():
     # Load CSV file containing contract addresses (with a "address" column).
    df = pd.read_csv("test1_erc_classification_results_erc_top10.csv")  # adjust path as needed
    
    # Extract unique addresses.
    addresses = df["address"].dropna().unique()
    
    for address in addresses:
        # print(f"\nProcessing contract: {address}")
        tx_info = fetch_tx_activity(address)
        if tx_info.get("status") != "1":
            print(f"Error fetching transaction activity for {address}: {tx_info.get('message', tx_info)}")
            continue
        
        tx_list = tx_info.get("result", [])
        if not should_fetch_contract(tx_list):
            # print(f"Skipping {address}: does not meet criteria (tx count, recency, or total value)")
            continue

        source_info = fetch_source_code(address)
        if source_info.get("status") == "1":
            # save_source_code(address, source_info)
            print(f"address : {address}")
        else:
            print(f"Error fetching source code for {address}: {source_info.get('message', source_info)}")




def main():
    ERC_classification()
    # verify_source()

if __name__ == "__main__":
    main()




