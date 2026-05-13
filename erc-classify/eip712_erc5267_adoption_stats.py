'''
Author: ashokkasthuri ashokraj.kasthuri@gmail.com
Date: 2026-05-13
Description:
Add Ethereum contract creation transaction, creation block, and block timestamp
to a CSV dataset using Etherscan API v2.

Input CSV columns expected:
    address, bytecode, function_sighashes, is_erc20, is_erc721, block_number

Output CSV will include:
    creation_tx_hash
    creation_block_number
    creation_timestamp
    creation_datetime_utc
    timestamp_status
'''

import os
import time
import json
import itertools
import requests
import pandas as pd

from pathlib import Path
from dotenv import load_dotenv
from tqdm import tqdm
from typing import Optional, Tuple


# ============================================================
# Config
# ============================================================

CSV_PATH = "/Users/ashokk/Downloads/evm_data/ethereum_deduplicated_results.csv"

OUT_PATH = "/Users/ashokk/Downloads/evm_data/ethereum_deduplicated_results_with_timestamps.csv"

CACHE_PATH = "/Users/ashokk/Downloads/evm_data/etherscan_contract_timestamp_cache.csv"

ETHERSCAN_URL = "https://api.etherscan.io/v2/api"
CHAIN_ID = 1

ADDRESS_COL = "address"

# Process in chunks so huge CSVs do not overload memory.
CHUNK_SIZE = 5000

# Etherscan supports comma-separated contract addresses for getcontractcreation.
# Keep this conservative.
CREATION_BATCH_SIZE = 5

# Sleep after each API call. Increase if you hit rate limits.
BASE_SLEEP_SECONDS = 0.20

MAX_RETRIES = 6


# ============================================================
# API key loading / rotation
# ============================================================

def load_api_keys() -> list[str]:
    """Load multiple Etherscan API keys from .env file."""
    load_dotenv()

    api_keys = []
    i = 1
    while True:
        key = os.getenv(f"ETHERSCAN_API_KEY{i}")
        if not key:
            break
        api_keys.append(key.strip())
        i += 1

    # Fallback: allow single ETHERSCAN_API_KEY too.
    single_key = os.getenv("ETHERSCAN_API_KEY")
    if single_key:
        api_keys.append(single_key.strip())

    # Remove duplicates / blanks.
    api_keys = list(dict.fromkeys([k for k in api_keys if k]))

    if not api_keys:
        raise ValueError(
            "No API keys found. Set ETHERSCAN_API_KEY1, ETHERSCAN_API_KEY2, etc. in .env"
        )

    print(f"Loaded {len(api_keys)} Etherscan API key(s).")
    return api_keys


API_KEYS = load_api_keys()
KEY_CYCLE = itertools.cycle(API_KEYS)


# ============================================================
# Helpers
# ============================================================

def normalize_address(addr: str) -> str:
    if pd.isna(addr):
        return ""
    addr = str(addr).strip()
    if not addr:
        return ""
    return addr.lower()


def is_probable_address(addr: str) -> bool:
    addr = normalize_address(addr)
    return addr.startswith("0x") and len(addr) == 42


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def is_rate_limited(data: dict) -> bool:
    text = json.dumps(data).lower()
    return (
        "rate limit" in text
        or "max rate" in text
        or "too many requests" in text
        or "temporarily unavailable" in text
    )


def etherscan_get(params: dict, max_retries: int = MAX_RETRIES) -> dict:
    """
    Round-robin API-key Etherscan GET with retry/backoff.
    """
    last_error = None

    for attempt in range(max_retries):
        api_key = next(KEY_CYCLE)

        query = dict(params)
        query["apikey"] = api_key

        try:
            r = requests.get(ETHERSCAN_URL, params=query, timeout=30)
            r.raise_for_status()
            data = r.json()

            if is_rate_limited(data):
                sleep_time = BASE_SLEEP_SECONDS + (attempt + 1) * 1.5
                time.sleep(sleep_time)
                continue

            # Some Etherscan responses use status=0 for valid "not found" cases.
            # Do not reject all status=0 responses here.
            return data

        except Exception as e:
            last_error = e
            sleep_time = BASE_SLEEP_SECONDS + (attempt + 1) * 1.5
            time.sleep(sleep_time)

    raise RuntimeError(f"Etherscan request failed after retries. params={params}, last_error={last_error}")


def load_cache() -> pd.DataFrame:
    if Path(CACHE_PATH).exists():
        cache = pd.read_csv(CACHE_PATH, low_memory=False)
        if "address" in cache.columns:
            cache["address"] = cache["address"].map(normalize_address)
        return cache

    return pd.DataFrame(columns=[
        "address",
        "creation_tx_hash",
        "creation_block_number",
        "creation_timestamp",
        "creation_datetime_utc",
        "timestamp_status",
    ])


def save_cache(cache: pd.DataFrame):
    cache = cache.drop_duplicates(subset=["address"], keep="last")
    cache.to_csv(CACHE_PATH, index=False)


# ============================================================
# Etherscan queries
# ============================================================

def fetch_creation_info_batch(addresses: list[str]) -> dict[str, dict]:
    """
    Fetch creation tx hash for a batch of contract addresses.

    Returns:
        {
          address: {
            "creation_tx_hash": "...",
            "timestamp_status": "creation_found" / "not_found" / ...
          }
        }
    """
    addresses = [normalize_address(a) for a in addresses if is_probable_address(a)]
    if not addresses:
        return {}

    data = etherscan_get({
        "chainid": CHAIN_ID,
        "module": "contract",
        "action": "getcontractcreation",
        "contractaddresses": ",".join(addresses),
    })

    result = data.get("result")

    out = {}

    if not isinstance(result, list):
        # Mark all as failed.
        for addr in addresses:
            out[addr] = {
                "creation_tx_hash": "",
                "timestamp_status": f"creation_lookup_failed:{data.get('message', '')}",
            }
        return out

    for item in result:
        addr = normalize_address(item.get("contractAddress", ""))
        tx_hash = item.get("txHash", "") or item.get("hash", "")

        if addr and tx_hash:
            out[addr] = {
                "creation_tx_hash": tx_hash,
                "timestamp_status": "creation_found",
            }

    # Fill missing addresses.
    for addr in addresses:
        if addr not in out:
            out[addr] = {
                "creation_tx_hash": "",
                "timestamp_status": "creation_not_found",
            }

    return out


def fetch_tx_block_number(tx_hash: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Fetch block number from transaction hash using Etherscan proxy.
    """
    if not tx_hash:
        return None, None

    data = etherscan_get({
        "chainid": CHAIN_ID,
        "module": "proxy",
        "action": "eth_getTransactionByHash",
        "txhash": tx_hash,
    })

    result = data.get("result")
    if not isinstance(result, dict):
        return None, "tx_not_found"

    block_hex = result.get("blockNumber")
    if not block_hex:
        return None, "tx_missing_block"

    return int(block_hex, 16), None


def fetch_block_timestamp(block_number: int) -> Tuple[Optional[int], Optional[str]]:
    """
    Fetch block timestamp from block number using Etherscan proxy.
    """
    if block_number is None:
        return None, "missing_block_number"

    block_hex = hex(int(block_number))

    data = etherscan_get({
        "chainid": CHAIN_ID,
        "module": "proxy",
        "action": "eth_getBlockByNumber",
        "tag": block_hex,
        "boolean": "false",
    })

    result = data.get("result")
    if not isinstance(result, dict):
        return None, "block_not_found"

    ts_hex = result.get("timestamp")
    if not ts_hex:
        return None, "block_missing_timestamp"

    return int(ts_hex, 16), None


def enrich_addresses(addresses: list[str], cache: pd.DataFrame) -> pd.DataFrame:
    """
    Add creation tx, block, and timestamp for addresses not already in cache.
    """
    addresses = [normalize_address(a) for a in addresses if is_probable_address(a)]
    addresses = sorted(set(addresses))

    cached_addresses = set(cache["address"].dropna().map(normalize_address).tolist())
    missing = [a for a in addresses if a not in cached_addresses]

    print(f"Unique addresses in input: {len(addresses)}")
    print(f"Already cached: {len(addresses) - len(missing)}")
    print(f"Need lookup: {len(missing)}")

    new_rows = []

    for batch in tqdm(list(chunks(missing, CREATION_BATCH_SIZE)), desc="Creation lookup"):
        batch_info = fetch_creation_info_batch(batch)

        for addr in batch:
            info = batch_info.get(addr, {})
            tx_hash = info.get("creation_tx_hash", "")
            status = info.get("timestamp_status", "unknown")

            block_number = None
            timestamp = None
            datetime_utc = ""

            if tx_hash:
                block_number, tx_err = fetch_tx_block_number(tx_hash)
                if tx_err:
                    status = tx_err

                if block_number is not None:
                    timestamp, block_err = fetch_block_timestamp(block_number)
                    if block_err:
                        status = block_err
                    else:
                        datetime_utc = str(pd.to_datetime(timestamp, unit="s", utc=True))
                        status = "ok"

            new_rows.append({
                "address": addr,
                "creation_tx_hash": tx_hash,
                "creation_block_number": block_number,
                "creation_timestamp": timestamp,
                "creation_datetime_utc": datetime_utc,
                "timestamp_status": status,
            })

            time.sleep(BASE_SLEEP_SECONDS)

        # Save incremental cache frequently.
        if new_rows:
            temp = pd.concat([cache, pd.DataFrame(new_rows)], ignore_index=True)
            save_cache(temp)

    if new_rows:
        cache = pd.concat([cache, pd.DataFrame(new_rows)], ignore_index=True)
        cache = cache.drop_duplicates(subset=["address"], keep="last")

    return cache


# ============================================================
# Main workflow
# ============================================================

def collect_unique_addresses_from_csv() -> list[str]:
    """
    Read only the address column in chunks and collect unique addresses.
    """
    unique_addresses = set()

    for chunk in pd.read_csv(CSV_PATH, usecols=[ADDRESS_COL], chunksize=CHUNK_SIZE, low_memory=False):
        chunk[ADDRESS_COL] = chunk[ADDRESS_COL].map(normalize_address)
        valid = chunk[chunk[ADDRESS_COL].map(is_probable_address)][ADDRESS_COL]
        unique_addresses.update(valid.tolist())

    return sorted(unique_addresses)


def merge_cache_back_to_csv():
    """
    Merge timestamp cache back into original CSV and write output CSV.
    """
    cache = load_cache()
    cache["address"] = cache["address"].map(normalize_address)

    first = True

    for chunk in tqdm(
        pd.read_csv(CSV_PATH, chunksize=CHUNK_SIZE, low_memory=False),
        desc="Merging output CSV"
    ):
        chunk[ADDRESS_COL] = chunk[ADDRESS_COL].map(normalize_address)

        merged = chunk.merge(cache, on="address", how="left")

        merged.to_csv(
            OUT_PATH,
            mode="w" if first else "a",
            index=False,
            header=first
        )

        first = False

    print(f"Wrote enriched CSV: {OUT_PATH}")


def main():
    print("Input CSV:", CSV_PATH)
    print("Output CSV:", OUT_PATH)
    print("Cache CSV:", CACHE_PATH)

    addresses = collect_unique_addresses_from_csv()[:20]

    print("Total unique valid addresses:", len(addresses))

    cache = load_cache()
    cache = enrich_addresses(addresses, cache)
    save_cache(cache)

    merge_cache_back_to_csv()

    print("Done.")


if __name__ == "__main__":
    main()