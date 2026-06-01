#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Any, List, Optional

import requests
import pandas as pd
from tqdm import tqdm

ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"

CHAIN_IDS = {
    "ethereum": 1,
    "binance": 56,
    "bsc": 56,
    "polygon": 137,
    "avalanche": 43114,
}

ADDRESS_RE = re.compile(
    r"(0x[a-fA-F0-9]{40})\s*,\s*"
    r"(\d{4})\s*,\s*"
    r"(\d+)\s*,\s*"
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z)?)"
)


def load_env(path: Optional[str]) -> None:
    if not path:
        return
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def load_api_keys(env_path: Optional[str]) -> List[str]:
    load_env(env_path)
    keys = []

    i = 1
    while True:
        k = os.getenv(f"ETHERSCAN_API_KEY{i}")
        if not k:
            break
        keys.append(k.strip())
        i += 1

    single = os.getenv("ETHERSCAN_API_KEY")
    if single:
        keys.append(single.strip())

    keys = list(dict.fromkeys([k for k in keys if k]))
    if not keys:
        raise ValueError("No Etherscan keys found. Set ETHERSCAN_API_KEY1/2/3 or ETHERSCAN_API_KEY in .env")
    return keys


def normalize_address(x: str) -> str:
    x = str(x).strip().lower()
    return x if x.startswith("0x") else "0x" + x


def clean_rtf_text(text: str) -> str:
    # Enough for copied Allium RTF/text dumps: keep readable tokens and remove common RTF noise.
    text = text.replace("\\par", " ")
    text = text.replace("\\line", " ")
    text = re.sub(r"\\'[0-9a-fA-F]{2}", " ", text)
    text = re.sub(r"\\[a-zA-Z]+\d* ?", " ", text)
    text = text.replace("{", " ").replace("}", " ")
    text = text.replace("\n", " ")
    text = re.sub(r"\s+", " ", text)
    return text


def parse_allium_files(input_dir: str, chain_name: str) -> pd.DataFrame:
    input_path = Path(input_dir)
    files = sorted(list(input_path.glob("*.rtf")) + list(input_path.glob("*.txt")) + list(input_path.glob("*.csv")))
    if not files:
        raise FileNotFoundError(f"No .rtf/.txt/.csv files found in {input_dir}")

    rows = []
    for f in files:
        text = f.read_text(errors="ignore")
        text = clean_rtf_text(text)

        file_year_match = re.search(r"(20\d{2})", f.name)
        file_year = int(file_year_match.group(1)) if file_year_match else None

        found = 0
        for m in ADDRESS_RE.finditer(text):
            addr, year, block_number, block_timestamp = m.groups()
            rows.append({
                "chain_name": chain_name,
                "address": normalize_address(addr),
                "year": int(year),
                "block_number": int(block_number),
                "block_timestamp": block_timestamp.replace("T", " ").replace("Z", ""),
                "source_file": f.name,
            })
            found += 1

        if found == 0:
            # Fallback: at least collect addresses if timestamp parsing failed.
            for addr in re.findall(r"0x[a-fA-F0-9]{40}", text):
                rows.append({
                    "chain_name": chain_name,
                    "address": normalize_address(addr),
                    "year": file_year,
                    "block_number": None,
                    "block_timestamp": None,
                    "source_file": f.name,
                })

    df = pd.DataFrame(rows)
    if df.empty:
        raise ValueError(f"No addresses parsed from {input_dir}")

    df = df.drop_duplicates(subset=["address"]).copy()
    df = df.sort_values(["year", "block_number", "address"], na_position="last")
    return df


class APIKeyManager:
    def __init__(self, keys: List[str], calls_per_second_per_key: float):
        self.keys = keys
        self.idx = 0
        self.lock = threading.Lock()
        self.last_call = {k: 0.0 for k in keys}
        self.min_interval = 1.0 / max(calls_per_second_per_key, 0.1)

    def get_key(self) -> str:
        with self.lock:
            k = self.keys[self.idx % len(self.keys)]
            self.idx += 1
            return k

    def wait(self, key: str):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_call[key]
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_call[key] = time.time()


def etherscan_get(key_manager: APIKeyManager, chain_id: int, params: Dict[str, Any], retries: int = 5) -> Dict[str, Any]:
    last_err = None
    for attempt in range(retries):
        key = key_manager.get_key()
        key_manager.wait(key)

        p = dict(params)
        p["chainid"] = str(chain_id)
        p["apikey"] = key

        try:
            r = requests.get(ETHERSCAN_V2_URL, params=p, timeout=40)
            r.raise_for_status()
            data = r.json()
            txt = json.dumps(data).lower()

            if "rate limit" in txt or "too many requests" in txt or "temporarily unavailable" in txt:
                time.sleep(1.5 * (attempt + 1))
                continue

            return data

        except Exception as e:
            last_err = e
            time.sleep(1.5 * (attempt + 1))

    return {"status": "0", "message": "ERROR", "result": f"request_failed: {last_err}"}


def sanitize_filename(x: str) -> str:
    x = str(x or "").strip()
    x = re.sub(r"[^a-zA-Z0-9_.-]+", "_", x)
    return x[:120] if x else "Contract"


def normalize_source_code(source: str) -> str:
    source = source or ""
    source = source.strip()

    # Etherscan sometimes wraps standard JSON as {{...}}
    if source.startswith("{{") and source.endswith("}}"):
        source = source[1:-1]

    return source




def write_source_files(base: Path, address: str, result: Dict[str, Any]) -> Dict[str, Any]:
    contract_name = sanitize_filename(result.get("ContractName") or "Unknown")
    source_raw = normalize_source_code(result.get("SourceCode") or "")

    info = {
        "saved_files": [],
        "source_format": "none",
    }

    if not source_raw.strip():
        return info

    base.mkdir(parents=True, exist_ok=True)

    flattened = flatten_to_single_solidity(
        source_raw=source_raw,
        contract_name=contract_name,
        address=address,
    )

    out_sol = base / f"{address}_{contract_name}.sol"
    out_sol.write_text(flattened, encoding="utf-8", errors="ignore")

    info["saved_files"].append(str(out_sol))
    info["source_format"] = "flattened_single_solidity"

    return info

def flatten_to_single_solidity(source_raw: str, contract_name: str, address: str) -> str:
    source_raw = normalize_source_code(source_raw)

    header = [
        "// SPDX-License-Identifier: UNLICENSED",
        f"// Flattened source downloaded from Etherscan",
        f"// Address: {address}",
        f"// Contract Name: {contract_name}",
        "",
    ]

    # Case 1: Etherscan Standard JSON or multi-file JSON
    if source_raw.strip().startswith("{"):
        try:
            obj = json.loads(source_raw)

            # Standard JSON input: {"language": "...", "sources": {...}}
            if isinstance(obj, dict) and "sources" in obj:
                sources = obj["sources"]

            # Etherscan sometimes returns direct mapping:
            # {"contracts/A.sol": {"content": "..."}}
            elif isinstance(obj, dict):
                sources = obj

            else:
                return "\n".join(header) + source_raw

            flattened = header[:]
            for file_path, src_obj in sources.items():
                content = ""
                if isinstance(src_obj, dict):
                    content = src_obj.get("content", "") or ""
                elif isinstance(src_obj, str):
                    content = src_obj

                if content.strip():
                    flattened.append("\n")
                    flattened.append("// ============================================================")
                    flattened.append(f"// FILE: {file_path}")
                    flattened.append("// ============================================================")
                    flattened.append(content)

            return "\n".join(flattened)

        except Exception:
            pass

    # Case 2: already flattened Solidity
    return "\n".join(header) + source_raw

def fetch_one(row: Dict[str, Any], chain_id: int, key_manager: APIKeyManager, outdir: Path, fetch_impl: bool) -> Dict[str, Any]:
    address = row["address"]
    year = int(row["year"]) if pd.notna(row.get("year")) else "unknown"

    data = etherscan_get(
        key_manager,
        chain_id,
        {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        },
    )

    rec = dict(row)
    rec["chain_id"] = chain_id
    rec["api_status"] = data.get("status")
    rec["api_message"] = data.get("message")

    result = data.get("result")
    if not isinstance(result, list) or not result:
        rec["source_status"] = "api_no_result"
        rec["error"] = str(result)[:500]
        return rec

    r = result[0]
    source = normalize_source_code(r.get("SourceCode") or "")
    verified = bool(source.strip()) and "Contract source code not verified" not in source

    rec.update({
        "source_status": "verified" if verified else "not_verified",
        "contract_name": r.get("ContractName"),
        "compiler_version": r.get("CompilerVersion"),
        "optimization_used": r.get("OptimizationUsed"),
        "runs": r.get("Runs"),
        "license_type": r.get("LicenseType"),
        "proxy": r.get("Proxy"),
        "implementation": r.get("Implementation"),
        "evm_version": r.get("EVMVersion"),
        "constructor_arguments": r.get("ConstructorArguments"),
    })

    year_dir = outdir / "verified_sources" / str(year)
    meta_dir = outdir / "metadata" / str(year)
    meta_dir.mkdir(parents=True, exist_ok=True)

    # Always save metadata response for audit.
    (meta_dir / f"{address}.json").write_text(
        json.dumps(r, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    if verified:
        saved = write_source_files(year_dir, address, r)
        rec["source_format"] = saved["source_format"]
        rec["saved_files_count"] = len(saved["saved_files"])
        rec["source_dir"] = str(year_dir)
    else:
        rec["source_format"] = "none"
        rec["saved_files_count"] = 0
        rec["source_dir"] = ""

    # Optional: also fetch implementation if proxy.
    impl = str(r.get("Implementation") or "").strip().lower()
    if fetch_impl and impl.startswith("0x") and len(impl) == 42 and impl != address:
        impl_row = dict(row)
        impl_row["address"] = impl
        impl_row["year"] = year
        impl_data = etherscan_get(
            key_manager,
            chain_id,
            {
                "module": "contract",
                "action": "getsourcecode",
                "address": impl,
            },
        )
        impl_result = impl_data.get("result")
        if isinstance(impl_result, list) and impl_result:
            impl_r = impl_result[0]
            impl_source = normalize_source_code(impl_r.get("SourceCode") or "")
            impl_verified = bool(impl_source.strip()) and "Contract source code not verified" not in impl_source
            rec["implementation_source_status"] = "verified" if impl_verified else "not_verified"
            if impl_verified:
                impl_base = outdir / "verified_sources" / str(year) / f"{address}_implementation_{impl}"
                impl_base.mkdir(parents=True, exist_ok=True)
                write_source_files(outdir / "verified_sources" / str(year), impl, impl_r)
        else:
            rec["implementation_source_status"] = "api_no_result"

    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True, help="Folder containing Allium .rtf/.txt/.csv copied pages for one chain.")
    ap.add_argument("--outdir", required=True, help="Output folder.")
    ap.add_argument("--env", required=True, help=".env containing ETHERSCAN_API_KEY1/2/3.")
    ap.add_argument("--chain-name", required=True, choices=["ethereum", "polygon", "binance", "bsc", "avalanche"])
    ap.add_argument("--chain-id", type=int, default=None)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--calls-per-second-per-key", type=float, default=4.0)
    ap.add_argument("--fetch-implementation", action="store_true")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    chain_name = "binance" if args.chain_name == "bsc" else args.chain_name
    chain_id = args.chain_id or CHAIN_IDS[args.chain_name]

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    keys = load_api_keys(args.env)
    print(f"Loaded {len(keys)} Etherscan API key(s)")
    print(f"Chain: {chain_name}, chain_id={chain_id}")

    df = parse_allium_files(args.input_dir, chain_name=chain_name)
    if args.limit:
        df = df.head(args.limit).copy()

    parsed_csv = outdir / f"{chain_name}_parsed_allium_addresses.csv"
    df.to_csv(parsed_csv, index=False)
    print(f"Parsed unique addresses: {len(df)}")
    print(f"Saved parsed input: {parsed_csv}")
    print(df.groupby("year").size())

    done_csv = outdir / f"{chain_name}_source_enriched.csv"
    done_addresses = set()
    existing_rows = []

    if done_csv.exists():
        old = pd.read_csv(done_csv, low_memory=False)
        if "address" in old.columns:
            done_addresses = set(old["address"].astype(str).str.lower())
            existing_rows = old.to_dict("records")
        print(f"Resume mode: already completed {len(done_addresses)} addresses")

    pending = df[~df["address"].isin(done_addresses)].copy()
    print(f"Pending addresses: {len(pending)}")

    key_manager = APIKeyManager(keys, args.calls_per_second_per_key)
    results = list(existing_rows)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [
            ex.submit(
                fetch_one,
                row.to_dict(),
                chain_id,
                key_manager,
                outdir,
                args.fetch_implementation,
            )
            for _, row in pending.iterrows()
        ]

        for i, fut in enumerate(tqdm(as_completed(futs), total=len(futs), desc="Downloading source")):
            rec = fut.result()
            results.append(rec)

            if len(results) % 100 == 0:
                pd.DataFrame(results).to_csv(done_csv, index=False)

    final = pd.DataFrame(results)
    final.to_csv(done_csv, index=False)

    verified = final[final["source_status"] == "verified"].copy()
    verified_csv = outdir / f"{chain_name}_verified_source_only.csv"
    verified.to_csv(verified_csv, index=False)

    summary = final["source_status"].value_counts(dropna=False)
    summary_path = outdir / f"{chain_name}_source_status_summary.txt"
    summary_path.write_text(summary.to_string(), encoding="utf-8")

    print("\nDone.")
    print(f"All enriched rows: {done_csv}")
    print(f"Verified-only CSV: {verified_csv}")
    print(summary)


if __name__ == "__main__":
    main()