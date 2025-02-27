import os

import requests
import json
import time
import pandas as pd
import sys
import os


current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, ".."))

if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

import rattle

sys.setrecursionlimit(20000)



# Replace with your actual Etherscan API key.
API_KEY = "Z8IMKB1ZVRIER3Q6U66MJPAKFY1V68IT87"

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

def fetch_tx_activity(address: str) -> dict:
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
    
def should_fetch_contract(tx_list) -> bool:
    """
    Return True if the total number of transactions is > 100 and
    at least one transaction happened in the last 30 days.
    """
    if not tx_list:
        return False

    total_tx = len(tx_list)
    if total_tx <= 100:
        return False

    now = int(time.time())
    thirty_days = 30 * 24 * 3600
    recent = any(int(tx["timeStamp"]) >= (now - thirty_days) for tx in tx_list)

    # Sum transaction values (in Wei)
    total_value = sum(int(tx["value"]) for tx in tx_list)
    min_total_value = 100000000000000000  # 0.1 ETH in wei

    has_min_value = total_value >= min_total_value

    # Debug prints (optional)
    # print(f"Total transactions: {total_tx}, Recent? {recent}, Total value (wei): {total_value}, has_min_value : {has_min_value}")

    return recent and has_min_value



def match_erc_type(bytecode, event_topics):
    event_topics = [topic.lower() for topic in event_topics]
    
    # Check if all event topics are present in the bytecode
    for topic in event_topics:
        if topic not in bytecode.lower():
            return False
    return True
def ERC_classification():
    # Load the ERC configuration JSON
    with open("test_erc_config.json", "r") as f:
        erc_config = json.load(f)
    
    # Load the dataset
    df = pd.read_csv("/Users/ashokk/Downloads/deduplicated_results.csv")
    
    # Use a subset of the data for testing
    df_subset = df.head(100000).copy()  # Adjust the number of rows as needed
    
    # Initialize a list to store matched ERC types for each bytecode
    matched_erc_types = []
    
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
        
        # Add the current matches to the list of matched ERC types
        matched_erc_types.append(current_matches)
    
    # Ensure that matched_erc_types has the same length as df_subset
    if len(matched_erc_types) != len(df_subset):
        raise ValueError(f"Length mismatch: {len(matched_erc_types)} vs {len(df_subset)}")
    
    # Add the matched ERC types to the DataFrame
    df_subset.loc[:, "matched_erc"] = matched_erc_types
    
    # Create a shortened version of the bytecode for display purposes
    df_subset.loc[:, "bytecode_short"] = df_subset["bytecode"].str[:40]
    
    # Filter the DataFrame to only include rows where "matched_erc" is non-empty
    filtered_df = df_subset[df_subset["matched_erc"].apply(lambda x: len(x) > 0)]
    
    # Now, further filter by transaction activity.
    final_rows = []
    for idx, row in filtered_df.iterrows():
        address = row["address"]
        tx_info = fetch_tx_activity(address)
        if tx_info.get("status") != "1":
            print(f"Error fetching tx activity for {address}: {tx_info.get('message', tx_info)}")
            continue
        
        tx_list = tx_info.get("result", [])
        if not should_fetch_contract(tx_list):
            # print(f"Skipping {address}: does not meet tx activity criteria.")
            continue
        
        final_rows.append(row)
    
    # Create a new DataFrame from the final rows.
    if final_rows:
        final_df = pd.DataFrame(final_rows)
        # Sort final_df if desired (e.g., by a metric such as total tx count or recency)
        # Here, we simply take the top 10 rows.
        final_df = final_df.head(10)
        print(final_df[["address", "bytecode_short", "matched_erc"]])
        final_df.to_csv("test1_erc_classification_results_top10.csv", index=False)
    else:
        print("No contracts meet both the ERC match and transaction activity criteria.")




   
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
