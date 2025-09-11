#!/usr/bin/env python3
# erc1155_batch_transfer_analysis.py

"""
End‑to‑end pipeline to extract ERC‑1155 batch transfer calls, save them, and
analyse them for common vulnerabilities.

Usage example:
    python erc1155_batch_transfer_analysis.py \
        --json /path/to/erc1155_SafeBatch.json \
        --num-addresses 50 \
        --raw-csv raw_transactions.csv \
        --annotated-csv analysed_transactions.csv
"""

import os
import re
import json
import argparse
import requests
import pandas as pd
from dotenv import load_dotenv
from typing import List, Tuple, Dict, Any, Optional



# ---------------------------------------------------------------------
# Helper functions for configuration, extraction and decoding
# ---------------------------------------------------------------------

def load_api_key() -> str:
    """
    Load ETHERSCAN_API_KEY from .env or environment.
    Raises ValueError if the key isn't found.
    """
    # load_dotenv()
    load_env = load_dotenv("/home/ashok/ERC-analysis/.env")
    api_key = os.getenv("ETHERSCAN_API_KEY")
    if not api_key:
        raise ValueError("❌ API key not found. Please set ETHERSCAN_API_KEY in .env or environment.")
    return api_key




def extract_addresses_from_json(json_path: str, max_addresses: int) -> List[str]:
    """
    Read a JSON file and return up to max_addresses Ethereum addresses
    where the contract’s all_requirements_met flag is false.

    The JSON is expected to have objects with a 'file' field (containing
    the Solidity filename) and an 'all_implementations' array.  Each
    implementation has an 'all_requirements_met' boolean.  Only contracts
    with any implementation flagged as not meeting all requirements are
    included.

    Args:
        json_path: Path to the JSON file
        max_addresses: Maximum number of addresses to return

    Returns:
        A list of Ethereum addresses (0x-prefixed strings).
    """
    with open(json_path, "r") as f:
        data = json.load(f)

    addresses: List[str] = []
    for item in data:
        implementations = item.get("all_implementations", [])
        # Is there at least one implementation where all_requirements_met is false?
        vulnerable = any(not impl.get("all_requirements_met", True) for impl in implementations)
        if not vulnerable:
            continue  # skip fully compliant contracts

        file_path = item.get("file", "")
        match = re.search(r"(0x[a-fA-F0-9]{40})", file_path)
        if match:
            addresses.append(match.group(1))
            if len(addresses) >= max_addresses:
                break

    return addresses

def extract_addresses_from_csv(csv_path: str, max_addresses: int) -> List[str]:
    """
    Read a CSV file using pandas and return up to max_addresses Ethereum addresses
    where the contract bytecode contains the signature "2eb2c2d6".

    Args:
        csv_path: Path to the CSV file
        max_addresses: Maximum number of addresses to return

    Returns:
        A list of Ethereum addresses (0x-prefixed strings).
    """
    df = pd.read_csv(csv_path)
    addresses = []
    
    for idx, row in df.iterrows():
        original_bytecode_str = str(row.get("bytecode", ""))
        if "2eb2c2d6" in original_bytecode_str:
            address = row.get("address")
            if address:
                addresses.append(address)
                if len(addresses) >= max_addresses:
                    break
    
    return addresses

def get_safeBatchTransferFrom_txs(address: str, api_key: str,
                                  start_block: int = 0,
                                  end_block: int = 99999999,
                                  sort: str = "asc") -> List[Dict[str, Any]]:
    """
    Fetch all transactions for a contract from Etherscan, then filter
    to those whose functionName is 'safeBatchTransferFrom'.
    """
    url = (
        "https://api.etherscan.io/api"
        f"?module=account&action=txlist"
        f"&address={address}"
        f"&startblock={start_block}"
        f"&endblock={end_block}"
        f"&sort={sort}"
        f"&apikey={api_key}"
    )
    try:
        resp = requests.get(url, timeout=10)
        data = resp.json()
        if data.get("status") == "1" and data.get("result"):
            target_functions = {"safeBatchTransferFrom", "setApprovalForAll"}
            return [
                tx for tx in data["result"]
                if tx.get("functionName", "").split("(")[0].strip() in target_functions
            ]
        return []
    except Exception as e:
        print(f"❌ Error fetching txs for {address}: {e}")
        return []

def decode_safeBatchTransferFrom_input(input_hex: str) -> Tuple[str, str, List[int], List[int]]:
    """
    Decode the calldata for safeBatchTransferFrom: (from, to, ids[], amounts[]).
    Raises ValueError if the payload is malformed.
    """
    data = input_hex[2:] if input_hex.startswith("0x") else input_hex
    if len(data) < 8 + 64 * 5:
        raise ValueError("Input too short")
    params_hex = data[8:]
    from_word = params_hex[0:64]
    to_word   = params_hex[64:128]
    ids_off   = int(params_hex[128:192], 16)
    amts_off  = int(params_hex[192:256], 16)
    from_addr = "0x" + from_word[-40:]
    to_addr   = "0x" + to_word[-40:]

    def decode_array(offset: int, params: str) -> List[int]:
        start = offset * 2
        length = int(params[start:start + 64], 16)
        ptr = start + 64
        items = []
        for _ in range(length):
            items.append(int(params[ptr:ptr + 64], 16))
            ptr += 64
        return items

    ids  = decode_array(ids_off, params_hex)
    amts = decode_array(amts_off, params_hex)
    return from_addr, to_addr, ids, amts

def decode_setApprovalForAll_input(input_hex: str) -> Tuple[str, bool]:
    """
    Decode the calldata for setApprovalForAll: (operator, approved).
    Raises ValueError if the payload is malformed.
    """
    # Remove '0x' prefix if present
    data = input_hex[2:] if input_hex.startswith("0x") else input_hex
    
    # Check minimum length (function selector + 2 parameters of 32 bytes each)
    if len(data) < 8 + 64 * 2:
        raise ValueError("Input too short")
    
    # Skip function selector (first 4 bytes/8 hex characters)
    params_hex = data[8:]
    
    # Extract operator (address)
    operator_word = params_hex[0:64]
    operator_addr = "0x" + operator_word[-40:]
    
    # Extract approved (bool)
    approved_word = params_hex[64:128]
    approved_value = int(approved_word, 16) != 0  # Convert to boolean
    
    return operator_addr, approved_value

def analyse_transactions(txs: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Decode and flag each safeBatchTransferFrom tx for:
      * unauthorized (caller != from_param)
      * zero_address (to == 0x0)
      * length_mismatch (ids.length != amounts.length)
    Returns a dataframe with extra columns.
    """
    df = pd.DataFrame(txs)
    df["decoded_from"] = None
    df["decoded_to"]   = None
    df["decoded_ids"]  = None
    df["decoded_amounts"] = None
    df["unauthorized"]    = False
    df["zero_address"]    = False
    df["length_mismatch"] = False
    
    df["decoded_operator"] = None
    df["operator_permission"] = False

    for idx, row in df.iterrows():
        try:
            from_addr, to_addr, ids_list, amts_list = decode_safeBatchTransferFrom_input(row.get("input",""))
            operator_addr, perm_bool = decode_setApprovalForAll_input(row.get("input",""))
        except Exception:
            continue
        df.at[idx, "decoded_from"]    = from_addr
        df.at[idx, "decoded_to"]      = to_addr
        df.at[idx, "decoded_ids"]     = ids_list
        df.at[idx, "decoded_amounts"] = amts_list
        
        df["decoded_operator"] = operator_addr
        df["operator_permission"] = perm_bool
        # unauthorised if caller doesn't match encoded from
        if from_addr.lower() != row.get("from","").lower() and from_addr.lower() == operator_addr.lower():
            
            df.at[idx, "unauthorized"] = True
        # zero address
        if to_addr == "0x0000000000000000000000000000000000000000":
            df.at[idx, "zero_address"] = True
        # length mismatch
        if len(ids_list) != len(amts_list):
            df.at[idx, "length_mismatch"] = True
    return df

# ---------------------------------------------------------------------
# High‑level orchestration
# ---------------------------------------------------------------------

def fetch_and_analyse(path: str,
                      max_addresses: int,
                      raw_csv: Optional[str],
                      annotated_csv: Optional[str]) -> None:
    """
    Extract addresses, fetch their safeBatchTransferFrom transactions,
    save raw and annotated results, and print a summary.
    """
    api_key = load_api_key()
    # addresses = extract_addresses_from_json(json_path, max_addresses)
    addresses = extract_addresses_from_csv(path, max_addresses)
    print(f"📄 Extracted {len(addresses)} addresses from {path}")

    all_txs = []
    for addr in addresses:
        # print(f"🔍 Fetching safeBatchTransferFrom transactions for {addr}…")
        txs = get_safeBatchTransferFrom_txs(addr, api_key)
        for tx in txs:
            tx["contract_address"] = addr
        all_txs.extend(txs)

    print(f"✅ Fetched {len(all_txs)} transactions across all addresses")

    if raw_csv:
        pd.DataFrame(all_txs).to_csv(raw_csv, index=False)
        print(f"💾 Raw transactions saved to {raw_csv}")

    analysed_df = analyse_transactions(all_txs)
    # Summarise issues
    summary = analysed_df[['unauthorized', 'zero_address', 'length_mismatch']].sum()
    print("\nSummary of flagged issues:")
    print(summary)

    # Print contract addresses for each flag
    if analysed_df['unauthorized'].any():
        unauthorized_contracts = analysed_df.loc[analysed_df['unauthorized'], 'contract_address'].unique()
        print("Contracts with unauthorized transfers:", list(unauthorized_contracts))
    if analysed_df['zero_address'].any():
        zero_addr_contracts = analysed_df.loc[analysed_df['zero_address'], 'contract_address'].unique()
        print("Contracts with zero‑address transfers:", list(zero_addr_contracts))
    if analysed_df['length_mismatch'].any():
        mismatch_contracts = analysed_df.loc[analysed_df['length_mismatch'], 'contract_address'].unique()
        print("Contracts with length‑mismatch issues:", list(mismatch_contracts))

    if annotated_csv:
        analysed_df.to_csv(annotated_csv, index=False)
        print(f"💾 Annotated results saved to {annotated_csv}")
    else:
        print("\nPreview of annotated data (first 5 rows):")
        print(analysed_df.head())
        
    
    analysed_with_contracts = augment_with_contract_checks(analysed_df, api_key)
    
   # Filter rows where either check is False
    false_rows = analysed_with_contracts[
        (~analysed_with_contracts['to_is_contract']) | 
        (~analysed_with_contracts['on_batch_received_impl'])
    ]
    
    print(f"Number of false rows: {len(false_rows)}")
    # Display the filtered DataFrame
    print(false_rows[['decoded_to', 'to_is_contract', 'on_batch_received_impl']])
    

    # Save filtered results to CSV
    false_rows.to_csv("false_contract_checks.csv", index=False)
    print("✅ False results saved to false_contract_checks.csv")





def augment_with_contract_checks(df: pd.DataFrame, api_key: str) -> pd.DataFrame:
    """
    For each row in a DataFrame of decoded safeBatchTransferFrom transactions,
    determine whether the 'to' address is a contract and whether it implements
    the ERC-1155 onERC1155BatchReceived interface.  Two new boolean columns
    are added: 'to_is_contract' and 'on_batch_received_impl'.

    This function uses the Etherscan API:
      * proxy.eth_getCode to check if there is bytecode at the address
      * contract.getabi to retrieve the contract's ABI and look for
        onERC1155BatchReceived.

    Args:
        df: A pandas DataFrame with at least a 'decoded_to' column (if present)
            and a 'to' column (the destination address).  It may also have other
            columns from analyse_transactions.
        api_key: Your Etherscan API key.

    Returns:
        The input DataFrame with two new columns populated.
    """
    # Prepare new columns
    df['to_is_contract'] = False
    df['on_batch_received_impl'] = False

    # Cache results per contract address to minimise API calls
    contract_cache: Dict[str, Tuple[bool, bool]] = {}

    for idx, row in df.iterrows():
        # Prefer the decoded 'to' address if present; fall back to raw 'to'
        to_addr = row.get('decoded_to') or row.get('to')
        if not isinstance(to_addr, str) or not to_addr.startswith('0x'):
            continue
        to_addr = to_addr.lower()

        # Skip the zero address
        if to_addr == '0x0000000000000000000000000000000000000000':
            continue

        # Use cached results if we've already inspected this address
        if to_addr in contract_cache:
            is_contract, has_receiver = contract_cache[to_addr]
        else:
            # 1. Check if there is bytecode at the address using eth_getCode
            code_url = (
                "https://api.etherscan.io/api"
                f"?module=proxy&action=eth_getCode"
                f"&address={to_addr}"
                f"&apikey={api_key}"
            )
            try:
                code_resp = requests.get(code_url, timeout=10).json()
                code_result = code_resp.get("result", "")
            except Exception:
                code_result = ""
            is_contract = (code_result and code_result != "0x")

            has_receiver = False
            if is_contract:
                # 2. Fetch the ABI and check for onERC1155BatchReceived
                abi_url = (
                    "https://api.etherscan.io/api"
                    f"?module=contract&action=getabi"
                    f"&address={to_addr}"
                    f"&apikey={api_key}"
                )
                try:
                    abi_resp = requests.get(abi_url, timeout=10).json()
                    if abi_resp.get("status") == "1":
                        abi_str = abi_resp.get("result")
                        abi = json.loads(abi_str)
                        for entry in abi:
                            if (
                                entry.get("type") == "function"
                                and entry.get("name") == "onERC1155BatchReceived"
                            ):
                                has_receiver = True
                                break
                except Exception:
                    has_receiver = False

            # Cache the result
            contract_cache[to_addr] = (is_contract, has_receiver)

        df.at[idx, 'to_is_contract'] = is_contract
        df.at[idx, 'on_batch_received_impl'] = has_receiver

    return df

def main():
    parser = argparse.ArgumentParser(
        description="Extract and analyse ERC‑1155 safeBatchTransferFrom transactions for possible exploits."
    )
    # parser.add_argument('--json', required=True,
    #                     help='Path to the JSON file containing contract metadata')
    parser.add_argument('--csv', required=True,
                        help='Path to the CSV file containing contract metadata')
    parser.add_argument('--num-addresses', type=int, default=10,
                        help='Number of addresses to process (default 10)')
    parser.add_argument('--raw-csv', default=None,
                        help='Optional file path to save raw transaction data')
    parser.add_argument('--annotated-csv', default=None,
                        help='Optional file path to save annotated results with flags')
    args = parser.parse_args()
    
    # fetch_and_analyse(args.json, args.num_addresses, args.raw_csv, args.annotated_csv)
    fetch_and_analyse(args.csv, args.num_addresses, args.raw_csv, args.annotated_csv)
    
    
    
    

if __name__ == "__main__":
    main()
