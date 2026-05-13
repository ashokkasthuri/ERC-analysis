import pandas as pd
import requests
import time
import os
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from collections import deque
from datetime import datetime
from dotenv import load_dotenv

def load_api_keys() -> list:
    """Load multiple Etherscan API keys from .env file"""
    # load_dotenv()
    load_dotenv("/home/ashok/ashokTests/ERC-analysis/.env")
    
    api_keys = []
    i = 1
    while True:
        key = os.getenv(f"ETHERSCAN_API_KEY{i}")
        if not key:
            break
        api_keys.append(key)
        i += 1
    
    if not api_keys:
        raise ValueError("❌ No API keys found. Please set ETHERSCAN_API_KEY1, ETHERSCAN_API_KEY2, etc. in .env")
    
    return api_keys

# Load API keys for rotation
API_KEYS = load_api_keys()

# Configuration
# CSV_PATH = "/Users/ashokk/Downloads/evm_data/ethereum_deduplicated_results.csv"
CSV_PATH = "/home/ashok/ashokTests/ERC-analysis/erc-classify/ERC-5267_eip712Domain_ethereum_deduplicated_results.csv"


# OUTPUT_DIR = "/Users/ashokk/Downloads/evm_data/erc20-transferFrom1"
# OUTPUT_DIR = "/Users/ashokk/Downloads/evm_data/erc2612-permit"
OUTPUT_DIR = "/home/ashok/ashokTests/ERC-analysis/erc-classify/erc5267"
LIMIT = None  # Set to None for all, or number for testing

CHAIN_ID = 1
# TARGET_SELECTOR = "23b872dd" # transferFrom
# TARGET_SELECTOR = "d505accf" # permit

TARGET_SELECTOR = "84b0196e" # ERC5267 eip712Domain() 

MAX_WORKERS = 20  # Adjust based on API keys
RATE_LIMIT_PER_KEY = 5  # Calls per second per API key
SAVE_INTERVAL = 100  # Save progress every N contracts

# ========== FIX: Set PROGRESS_FILE based on selector BEFORE creating tracker ==========
if TARGET_SELECTOR == "84b0196e":  # 
    PROGRESS_FILE = "/home/ashok/ashokTests/ERC-analysis/erc-classify/download_progress_ERC5267_eip712Domain.json"
elif TARGET_SELECTOR == "d505accf": #permit
    PROGRESS_FILE = "/Users/ashokk/Downloads/evm_data/download_progress_permit.json"
else:
    PROGRESS_FILE = "/Users/ashokk/Downloads/evm_data/download_progress_transferfrom.json"


class APIKeyManager:
    """Manages API key rotation for rate limiting"""
    def __init__(self, api_keys, calls_per_second_per_key=5):
        self.api_keys = deque(api_keys)
        self.key_locks = {key: Lock() for key in api_keys}
        self.key_last_call = {key: 0 for key in api_keys}
        self.min_interval = 1.0 / calls_per_second_per_key
        self.key_usage_count = {key: 0 for key in api_keys}
        self.lock = Lock()
    
    def get_key(self):
        with self.lock:
            self.api_keys.rotate(-1)
            return self.api_keys[0]
    
    def wait_if_needed(self, api_key):
        with self.key_locks[api_key]:
            current_time = time.time()
            time_since_last = current_time - self.key_last_call[api_key]
            if time_since_last < self.min_interval:
                time.sleep(self.min_interval - time_since_last)
            self.key_last_call[api_key] = time.time()
            self.key_usage_count[api_key] += 1

class ProgressTracker:
    """Track download progress and support resuming"""
    def __init__(self, progress_file):
        self.progress_file = progress_file
        self.completed_addresses = set()
        self.failed_addresses = set()
        self.load()
    
    def load(self):
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, 'r') as f:
                    data = json.load(f)
                    self.completed_addresses = set(data.get('completed', []))
                    self.failed_addresses = set(data.get('failed', []))
                print(f"📂 Resuming from previous session: {len(self.completed_addresses)} completed, {len(self.failed_addresses)} failed")
            except:
                pass
    
    def save(self):
        with open(self.progress_file, 'w') as f:
            json.dump({
                'completed': list(self.completed_addresses),
                'failed': list(self.failed_addresses),
                'last_updated': datetime.now().isoformat()
            }, f)
    
    def is_completed(self, address):
        return address in self.completed_addresses or address in self.failed_addresses
    
    def mark_completed(self, address):
        self.completed_addresses.add(address)
        if len(self.completed_addresses) % SAVE_INTERVAL == 0:
            self.save()
    
    def mark_failed(self, address):
        self.failed_addresses.add(address)
        if len(self.failed_addresses) % SAVE_INTERVAL == 0:
            self.save()

# Global managers
api_manager = APIKeyManager(API_KEYS, RATE_LIMIT_PER_KEY)
progress_tracker = ProgressTracker(PROGRESS_FILE)

def get_contract_source_code(address, chain_id=1):
    """Fetch contract source code with automatic API key rotation"""
    max_retries = 3
    for attempt in range(max_retries):
        api_key = api_manager.get_key()
        api_manager.wait_if_needed(api_key)
        
        url = (
            f"https://api.etherscan.io/v2/api"
            f"?chainid={chain_id}"
            f"&module=contract"
            f"&action=getsourcecode"
            f"&address={address}"
            f"&apikey={api_key}"
        )
        
        try:
            response = requests.get(url, timeout=30)
            data = response.json()
            
            # Rate limit hit
            if "rate limit" in str(data).lower() or "max rate limit" in str(data).lower():
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
            
            if data.get("status") == "1" and data.get("result"):
                contract_data = data["result"][0]
                source_code = contract_data.get("SourceCode", "")
                
                if source_code and len(source_code) > 100:
                    if source_code.startswith("{"):
                        try:
                            parsed = json.loads(source_code)
                            if "sources" in parsed:
                                first_source = next(iter(parsed["sources"].values()))
                                source_code = first_source.get("content", source_code)
                        except:
                            pass
                    
                    return source_code, contract_data.get("ContractName", "Unknown")
            
            # No source code found, don't retry
            return None, None
                
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
    
    return None, None

def bytecode_contains_selector(bytecode, selector):
    """Check if bytecode contains selector"""
    if not bytecode or not isinstance(bytecode, str):
        return False
    return selector.lower() in bytecode.lower().replace('0x', '')

def run_long_running_job(matching_addresses, output_dir, chain_id):
    """Run the download job with progress tracking and auto-resume"""
    print(f"\n{'='*60}")
    print(f"🚀 STARTING LONG-RUNNING DOWNLOAD JOB")
    print(f"{'='*60}")
    print(f"Total contracts to process: {len(matching_addresses)}")
    print(f"Already completed: {len(progress_tracker.completed_addresses)}")
    print(f"Already failed: {len(progress_tracker.failed_addresses)}")
    print(f"Remaining: {len(matching_addresses) - len(progress_tracker.completed_addresses) - len(progress_tracker.failed_addresses)}")
    print(f"Workers: {MAX_WORKERS}")
    print(f"API Keys: {len(API_KEYS)}")
    print(f"Progress file: {PROGRESS_FILE}")
    print(f"{'='*60}\n")
    
    start_time = time.time()
    successful = 0
    failed = 0
    skipped = 0
    
    # Filter out already processed addresses
    addresses_to_process = [
        addr for addr in matching_addresses 
        if not progress_tracker.is_completed(addr)
    ]
    
    print(f"Starting fresh downloads for {len(addresses_to_process)} contracts...\n")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                process_contract,
                address=address,
                output_dir=output_dir,
                chain_id=chain_id
            ): address for address in addresses_to_process
        }
        
        for i, future in enumerate(as_completed(futures), 1):
            address, status, size, contract_name = future.result()
            
            if status == "success":
                successful += 1
                print(f"[{i}/{len(addresses_to_process)}] ✓ {address[:10]}... - {contract_name} ({size} chars)")
            elif status == "skipped":
                skipped += 1
                print(f"[{i}/{len(addresses_to_process)}] ⏭ {address[:10]}... - Skipped (already processed)")
            else:
                failed += 1
                print(f"[{i}/{len(addresses_to_process)}] ✗ {address[:10]}... - {status.upper()}")
            
            # Estimate remaining time
            if i % 100 == 0:
                elapsed = time.time() - start_time
                rate = i / elapsed
                remaining = len(addresses_to_process) - i
                eta_seconds = remaining / rate
                eta_hours = eta_seconds / 3600
                print(f"  📊 Progress: {i}/{len(addresses_to_process)} ({rate:.1f} contracts/sec) | ETA: {eta_hours:.1f} hours")
                
                # Save progress
                progress_tracker.save()
    
    # Final save
    progress_tracker.save()
    
    elapsed = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"✅ JOB COMPLETE")
    print(f"{'='*60}")
    print(f"Successfully downloaded: {successful}")
    print(f"Failed: {failed}")
    print(f"Skipped (already done): {skipped}")
    print(f"Total processed: {len(addresses_to_process)}")
    print(f"Total time: {elapsed/3600:.2f} hours")
    print(f"Average rate: {len(addresses_to_process)/elapsed:.2f} contracts/sec")
    
    # Print API key usage
    print(f"\n📊 API Key Usage:")
    for key, count in api_manager.key_usage_count.items():
        print(f"  {key[:10]}...: {count} calls")

def flatten_solidity_sources(source_code: str, contract_name: str, address: str) -> str:
    """
    Flatten multi-file Solidity contract into a single file.
    Merges all source files with clear separators.
    """
    import re
    
    # Clean the source code (remove comments and fix double braces)
    if source_code.startswith('// SPDX-License-Identifier'):
        lines = source_code.split('\n')
        json_start = 0
        for i, line in enumerate(lines):
            if line.strip().startswith('{'):
                json_start = i
                break
        source_code = '\n'.join(lines[json_start:])
    
    # Fix double braces and quotes
    source_code = re.sub(r'{{', '{', source_code)
    source_code = re.sub(r'}}', '}', source_code)
    source_code = re.sub(r'""', '"', source_code)
    
    flattened_code = []
    flattened_code.append(f"// SPDX-License-Identifier: UNLICENSED")
    flattened_code.append(f"// Source: {address}")
    flattened_code.append(f"// Contract Name: {contract_name}")
    flattened_code.append(f"// This is a flattened version of all source files")
    flattened_code.append(f"// Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    flattened_code.append("")
    
    try:
        # Try to parse as JSON
        data = json.loads(source_code)
        
        if 'sources' in data:
            # Standard JSON Input format - extract all files
            for file_path, file_info in data['sources'].items():
                if 'content' in file_info:
                    content = file_info['content']
                    
                    # Add file separator with original path
                    flattened_code.append(f"\n{'='*80}")
                    flattened_code.append(f"// FILE: {file_path}")
                    flattened_code.append(f"{'='*80}\n")
                    flattened_code.append(content)
            return '\n'.join(flattened_code)
        
        elif isinstance(data, dict):
            # Alternative format: direct mapping of filenames to content
            for name, content in data.items():
                if isinstance(content, str) and ('pragma solidity' in content.lower() or 'contract' in content.lower()):
                    flattened_code.append(f"\n{'='*80}")
                    flattened_code.append(f"// FILE: {name}")
                    flattened_code.append(f"{'='*80}\n")
                    flattened_code.append(content)
            return '\n'.join(flattened_code)
            
    except json.JSONDecodeError:
        # Not JSON, treat as single file
        pass
    
    # Single file contract
    return source_code


def process_contract(address, output_dir, chain_id):
    """Process a single contract and save as flattened single file"""
    # Skip if already processed
    if progress_tracker.is_completed(address):
        return address, "skipped", 0, None
    
    try:
        source_code, contract_name = get_contract_source_code(address, chain_id)
        
        if source_code:
            # Create safe filename
            safe_name = contract_name.replace(" ", "_").replace("/", "_").replace(":", "_").replace("\\", "_")
            if safe_name == "Unknown" or not safe_name:
                filename = f"{address}.sol"
            else:
                filename = f"{address}_{safe_name}.sol"
            
            filepath = os.path.join(output_dir, filename)
            
            # Flatten all sources into one file
            flattened_source = flatten_solidity_sources(source_code, contract_name, address)
            
            # Write flattened file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(flattened_source)
            
            # Count lines for stats
            line_count = len(flattened_source.split('\n'))
            
            progress_tracker.mark_completed(address)
            return address, "success", len(source_code), f"{contract_name} ({line_count} lines)"
        else:
            progress_tracker.mark_failed(address)
            return address, "failed", 0, None
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)[:100]}")
        progress_tracker.mark_failed(address)
        return address, "error", 0, None

def main():
    
    
    # Create output directory
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    
    # Read CSV and find matching contracts
    print(f"Reading CSV: {CSV_PATH}")
    df = pd.read_csv(CSV_PATH)
    print(f"Loaded {len(df)} contracts")
    
    matching_addresses = []
    for idx, row in df.iterrows():
        if bytecode_contains_selector(row.get('bytecode', ''), TARGET_SELECTOR):
            matching_addresses.append(row['address'])
        
        if (idx + 1) % 10000 == 0:
            print(f"Processed {idx + 1}/{len(df)} - Found {len(matching_addresses)}")
    
    print(f"\n✅ Found {len(matching_addresses)} contracts with transferFrom selector")
    
    # Apply limit if specified
    if LIMIT is not None and LIMIT > 0:
        original_count = len(matching_addresses)
        matching_addresses = matching_addresses[:LIMIT]
        print(f"Limited to first {LIMIT} contracts (from {original_count})")
    
    if not matching_addresses:
        print("No matching contracts to process. Exiting.")
        return
    
    # Run the long-running job
    run_long_running_job(matching_addresses, OUTPUT_DIR, CHAIN_ID)

if __name__ == "__main__":
    print(f"⚠️  This will download contracts for {LIMIT if LIMIT else 'ALL'} matching addresses")
    
    # Reset progress if this is a new permit job and user confirms
    if TARGET_SELECTOR == "d505accf":
        print(f"\n📁 Progress file: {PROGRESS_FILE}")
        if os.path.exists(PROGRESS_FILE):
            reset = input("New permit job. Reset progress? (yes/no): ")
            if reset.lower() == 'yes':
                os.remove(PROGRESS_FILE)
                print("✓ Progress file reset")
            else:
                print("Continuing with existing progress file")
        else:
            print("✓ No existing progress file found. Starting fresh.")
    
    main()