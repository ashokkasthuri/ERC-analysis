#!/usr/bin/env python3
"""
download_latest_eip_matched_contracts.py

Collect ONLY newly deployed contracts that match signature-related EIPs:
  - ERC-2612 permit():        d505accf
  - EIP-712 DOMAIN_SEPARATOR: 3644e515
  - EIP-712 domain typehash:  8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f
  - ERC-5267 eip712Domain():  84b0196e
  - ERC-1271 isValidSignature:1626ba7e, 20c13b0b

Workflow:
  1. Read old deployment_cache.json and find latest analyzed timestamp/block.
  2. Query an indexed contract table, preferably BigQuery, from cutoff -> end date.
  3. Pre-filter by function_sighashes / bytecode selectors/typehashes.
  4. Export matched contracts only.
  5. Optionally merge with old matched_contracts_with_deployment.csv.

Requirements:
  pip install pandas tqdm google-cloud-bigquery pyarrow

Google auth:
  gcloud auth application-default login
"""

from __future__ import annotations

import argparse
import ast
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
from tqdm import tqdm
import hashlib

EIP_PATTERNS = {
    "EIP2612": ["d505accf"],
    "EIP712": [
        "3644e515",
        "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f",
    ],
    "EIP5267": ["84b0196e"],
    "EIP1271": ["1626ba7e", "20c13b0b"],
}

ALL_PATTERNS = sorted({p.lower().replace("0x", "") for ps in EIP_PATTERNS.values() for p in ps})


def normalize_address(x: Any) -> str:
    if x is None or pd.isna(x):
        return ""
    s = str(x).strip().lower()
    if not s:
        return ""
    return s if s.startswith("0x") else "0x" + s


def normalize_hex(x: Any) -> str:
    if x is None or pd.isna(x):
        return ""
    s = str(x).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return "".join(c for c in s if c in "0123456789abcdef")


def add_code_hash_and_dedup(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)

    if "bytecode" not in df.columns:
        raise ValueError("Cannot deduplicate by bytecode: missing bytecode column.")

    df = df.copy()
    df["bytecode_norm"] = df["bytecode"].fillna("").astype(str).map(normalize_hex)
    df = df[df["bytecode_norm"].str.len() > 0].copy()

    df["code_hash"] = df["bytecode_norm"].map(
        lambda x: hashlib.sha256(x.encode("utf-8")).hexdigest()
    )

    # Keep the earliest deployment for each unique runtime bytecode.
    if "block_number" in df.columns:
        df["block_number"] = pd.to_numeric(df["block_number"], errors="coerce")
        df = df.sort_values(["block_number", "address"], na_position="last")
    elif "timestamp" in df.columns:
        df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
        df = df.sort_values(["timestamp", "address"], na_position="last")

    df = df.drop_duplicates(subset=["code_hash"], keep="first")

    print(f"Bytecode deduplication: {before} deployments -> {len(df)} unique bytecodes")
    return df

def parse_sighashes(x: Any) -> List[str]:
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return []
    if isinstance(x, list):
        vals = x
    else:
        s = str(x).strip()
        if not s or s.lower() == "nan":
            return []
        try:
            obj = ast.literal_eval(s)
            vals = obj if isinstance(obj, list) else [obj]
        except Exception:
            vals = re.split(r"[,\s;|]+", s)
    out = []
    for v in vals:
        h = normalize_hex(v)
        if h:
            out.append(h[:8] if len(h) >= 8 else h)
    return out




def detect_features(bytecode: Any = "", function_sighashes: Any = "") -> Dict[str, bool]:
    b = normalize_hex(bytecode)
    sighashes = set(parse_sighashes(function_sighashes))

    def has_dispatch_selector(sel: str) -> bool:
        sel = sel.lower().replace("0x", "")

        # Source/metadata selector if available.
        if sel in sighashes:
            return True

        # Runtime dispatcher pattern:
        # PUSH4 <selector> EQ PUSH1/2/3 <dest> JUMPI
        # 63 selector 14 60/61/62 ... 57
        head = b[:12000]  # dispatcher is normally near beginning
        pat = rf"63{sel}14(?:60[0-9a-f]{{2}}|61[0-9a-f]{{4}}|62[0-9a-f]{{6}})57"
        return re.search(pat, head) is not None

    eip712_typehash = "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"

    features = {
        "EIP2612": has_dispatch_selector("d505accf"),
        "EIP712": has_dispatch_selector("3644e515") or eip712_typehash in b,
        "EIP5267": has_dispatch_selector("84b0196e"),
        "EIP1271": has_dispatch_selector("1626ba7e") or has_dispatch_selector("20c13b0b"),
    }

    if features["EIP2612"]:
        features["EIP712"] = True

    return features

def make_combo(features: Dict[str, bool]) -> str:
    order = ["EIP2612", "EIP712", "EIP5267", "EIP1271"]
    active = [e for e in order if features.get(e, False)]
    return "_".join(active) if active else "None"


def classify_family(features: Dict[str, bool]) -> str:
    if features["EIP2612"] and features["EIP5267"]:
        return "EIP2612_EIP712_EIP5267"
    if features["EIP2612"]:
        return "EIP2612_EIP712"
    if features["EIP5267"]:
        return "EIP712_EIP5267"
    if features["EIP712"]:
        return "EIP712_only"
    if features["EIP1271"]:
        return "EIP1271_only"
    return "None"


def add_detection_columns(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Local EIP detection"):
        features = detect_features(
            bytecode=row.get("bytecode", ""),
            function_sighashes=row.get("function_sighashes", ""),
        )
        rec = dict(row)
        for k, v in features.items():
            rec[k] = bool(v)
        rec["eip_combo"] = make_combo(features)
        rec["eip_family"] = classify_family(features)
        rec["is_eip_matched"] = any(features.values())
        rows.append(rec)
    return pd.DataFrame(rows)


def find_cutoff_from_cache(cache_path: str) -> Dict[str, Any]:
    with open(cache_path, "r", encoding="utf-8") as f:
        cache = json.load(f)
    ok = []
    for v in cache.values():
        if (
            isinstance(v, dict)
            and v.get("creation_status") == "ok"
            and v.get("timestamp") is not None
            and v.get("block_number") is not None
        ):
            ok.append(v)
    if not ok:
        raise ValueError(f"No ok deployment records found in {cache_path}")
    latest = max(ok, key=lambda x: int(x["timestamp"]))
    return {
        "latest_address": normalize_address(latest.get("address")),
        "latest_block_number": int(latest["block_number"]),
        "latest_timestamp": int(latest["timestamp"]),
        "latest_datetime_utc": latest.get("datetime_utc"),
    }




def build_bq_query(
    table: str,
    start_ts: str,
    end_ts: str,
    start_block: Optional[int],
    address_col: str,
    bytecode_col: str,
    sighash_col: str,
    block_col: str,
    timestamp_col: str,
) -> str:
    # Strict rule:
    # 4-byte selectors must appear in function_sighashes.
    # Only the full EIP-712 domain typehash is searched inside bytecode.
    selector_list = "'d505accf', '3644e515', '84b0196e', '1626ba7e', '20c13b0b'"
    eip712_typehash = "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"

    block_filter = f"AND {block_col} > {int(start_block)}" if start_block is not None else ""

    return f"""
    SELECT
      LOWER({address_col}) AS address,
      CAST({bytecode_col} AS STRING) AS bytecode,
      {sighash_col} AS function_sighashes,
      CAST({block_col} AS INT64) AS block_number,
      TIMESTAMP({timestamp_col}) AS block_timestamp
    FROM `{table}`
    WHERE TIMESTAMP({timestamp_col}) > TIMESTAMP('{start_ts}')
      AND TIMESTAMP({timestamp_col}) <= TIMESTAMP('{end_ts}')
      {block_filter}
      AND (
        EXISTS (
            SELECT 1
            FROM UNNEST({sighash_col}) AS sig
            WHERE LOWER(REPLACE(CAST(sig AS STRING), '0x', '')) IN ({selector_list})
        )

        OR REGEXP_CONTAINS(
            SUBSTR(LOWER(COALESCE(CAST({bytecode_col} AS STRING), '')), 1, 12000),
            r'63d505accf14(60[0-9a-f]{{2}}|61[0-9a-f]{{4}}|62[0-9a-f]{{6}})57'
        )

        OR REGEXP_CONTAINS(
            SUBSTR(LOWER(COALESCE(CAST({bytecode_col} AS STRING), '')), 1, 12000),
            r'633644e51514(60[0-9a-f]{{2}}|61[0-9a-f]{{4}}|62[0-9a-f]{{6}})57'
        )

        OR REGEXP_CONTAINS(
            SUBSTR(LOWER(COALESCE(CAST({bytecode_col} AS STRING), '')), 1, 12000),
            r'6384b0196e14(60[0-9a-f]{{2}}|61[0-9a-f]{{4}}|62[0-9a-f]{{6}})57'
        )

        OR REGEXP_CONTAINS(
            SUBSTR(LOWER(COALESCE(CAST({bytecode_col} AS STRING), '')), 1, 12000),
            r'631626ba7e14(60[0-9a-f]{{2}}|61[0-9a-f]{{4}}|62[0-9a-f]{{6}})57'
        )

        OR REGEXP_CONTAINS(
            SUBSTR(LOWER(COALESCE(CAST({bytecode_col} AS STRING), '')), 1, 12000),
            r'6320c13b0b14(60[0-9a-f]{{2}}|61[0-9a-f]{{4}}|62[0-9a-f]{{6}})57'
        )

        OR STRPOS(
            LOWER(COALESCE(CAST({bytecode_col} AS STRING), '')),
            '{eip712_typehash}'
        ) > 0
        )
    """



def run_bigquery(args: argparse.Namespace, cutoff: Dict[str, Any]) -> pd.DataFrame:
    try:
        from google.cloud import bigquery
    except Exception as exc:
        raise RuntimeError(
            "google-cloud-bigquery not installed. Run: pip install google-cloud-bigquery pyarrow"
        ) from exc

    client = bigquery.Client(project=args.bq_project) if args.bq_project else bigquery.Client()

    start_ts = args.start_date or cutoff.get("latest_datetime_utc")
    if not start_ts:
        start_ts = datetime.fromtimestamp(cutoff["latest_timestamp"], tz=timezone.utc).isoformat()

    start_block = args.start_block if args.start_block is not None else cutoff.get("latest_block_number")

    end_ts = args.end_date
    if len(end_ts) == 10:
        end_ts = end_ts + "T23:59:59+00:00"

    query = build_bq_query(
        table=args.bq_table,
        start_ts=start_ts,
        end_ts=end_ts,
        start_block=start_block,
        address_col=args.address_col,
        bytecode_col=args.bytecode_col,
        sighash_col=args.sighash_col,
        block_col=args.block_col,
        timestamp_col=args.timestamp_col,
    )

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    sql_path = outdir / "bigquery_candidate_query.sql"
    sql_path.write_text(query, encoding="utf-8")
    print(f"Saved BigQuery SQL: {sql_path}")

    print("Running BigQuery candidate pre-filter query...")
    job = client.query(query)
    df = job.result().to_dataframe(create_bqstorage_client=True)
    print(f"BigQuery returned candidate rows: {len(df)}")

    if df.empty:
        return df

    df["address"] = df["address"].map(normalize_address)
    df["chain_id"] = int(args.chain_id)
    df["chain_name"] = args.chain_name
    df["datetime_utc"] = pd.to_datetime(df["block_timestamp"], utc=True).dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    df["timestamp"] = pd.to_datetime(df["block_timestamp"], utc=True).astype("int64") // 10**9
    df["year"] = pd.to_datetime(df["block_timestamp"], utc=True).dt.year
    df["creation_status"] = "ok_bigquery"

    # Match the original CSV logic: use unique bytecode-level contracts,
    # not raw deployment-level clones.
    df = add_code_hash_and_dedup(df)

    return df


def run_csv_candidates(args: argparse.Namespace) -> pd.DataFrame:
    df = pd.read_csv(args.candidate_csv, low_memory=False)
    print(f"Loaded candidate CSV rows: {len(df)}")
    print(f"Columns: {df.columns.tolist()}")

    if "address" not in df.columns:
        raise ValueError("candidate CSV must have an address column")

    df["address"] = df["address"].map(normalize_address)
    if "chain_id" not in df.columns:
        df["chain_id"] = int(args.chain_id)
    if "chain_name" not in df.columns:
        df["chain_name"] = args.chain_name

    if "bytecode" not in df.columns:
        df["bytecode"] = ""
    if "function_sighashes" not in df.columns:
        df["function_sighashes"] = ""

    if "datetime_utc" not in df.columns:
        if "timestamp" in df.columns:
            df["datetime_utc"] = pd.to_datetime(df["timestamp"], unit="s", utc=True).dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        elif "block_timestamp" in df.columns:
            df["datetime_utc"] = pd.to_datetime(df["block_timestamp"], utc=True).dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    if "timestamp" not in df.columns and "datetime_utc" in df.columns:
        df["timestamp"] = pd.to_datetime(df["datetime_utc"], utc=True).astype("int64") // 10**9

    if "year" not in df.columns and "datetime_utc" in df.columns:
        df["year"] = pd.to_datetime(df["datetime_utc"], utc=True).dt.year

    if "creation_status" not in df.columns:
        df["creation_status"] = "ok_candidate_csv"

    df = add_code_hash_and_dedup(df)
    return df


def merge_old_new(old_csv: str, new_df: pd.DataFrame, output_path: Path, chain_id: int, chain_name: str) -> pd.DataFrame:
    old = pd.read_csv(old_csv, low_memory=False)
    print(f"Old matched rows: {len(old)}")
    if "address" not in old.columns:
        raise ValueError("old matched CSV must have address column")

    old["address"] = old["address"].map(normalize_address)
    if "chain_id" not in old.columns:
        old["chain_id"] = int(chain_id)
    if "chain_name" not in old.columns:
        old["chain_name"] = chain_name

    for col in set(new_df.columns) - set(old.columns):
        old[col] = pd.NA
    for col in set(old.columns) - set(new_df.columns):
        new_df[col] = pd.NA

    cols = sorted(old.columns)

    old_aligned = old[cols].astype("object")
    new_aligned = new_df[cols].astype("object")

    combined = pd.concat([old_aligned, new_aligned], ignore_index=True)
    if "code_hash" in combined.columns:
        has_hash = combined["code_hash"].notna() & (combined["code_hash"].astype(str).str.len() > 0)

        with_hash = combined[has_hash].drop_duplicates(
            subset=["chain_id", "code_hash"],
            keep="first"
        )

        without_hash = combined[~has_hash].drop_duplicates(
            subset=["chain_id", "address"],
            keep="last"
        )

        combined = pd.concat([with_hash, without_hash], ignore_index=True)
    else:
        combined = combined.drop_duplicates(subset=["chain_id", "address"], keep="last")

    if "timestamp" in combined.columns:
        combined["timestamp"] = pd.to_numeric(combined["timestamp"], errors="coerce")
        combined = combined.sort_values(["chain_id", "timestamp", "address"], na_position="last")

    combined.to_csv(output_path, index=False)
    print(f"Saved merged master CSV: {output_path}")
    print(f"Merged rows: {len(combined)}")
    return combined


def write_yearly_outputs(df: pd.DataFrame, outdir: Path) -> None:
    ok = df.copy()

    if "year" not in ok.columns:
        if "timestamp" in ok.columns:
            ok["timestamp"] = pd.to_numeric(ok["timestamp"], errors="coerce")
            ok["year"] = pd.to_datetime(ok["timestamp"], unit="s", utc=True).dt.year
        else:
            print("Cannot write yearly outputs: no year/timestamp column")
            return

    for e in ["EIP2612", "EIP712", "EIP5267", "EIP1271"]:
        if e not in ok.columns:
            ok[e] = False
        ok[e] = ok[e].fillna(False).astype(bool)

    if "eip_combo" not in ok.columns:
        ok["eip_combo"] = ok.apply(
            lambda r: make_combo({e: bool(r[e]) for e in ["EIP2612", "EIP712", "EIP5267", "EIP1271"]}),
            axis=1,
        )

    yearly_rows = []
    group_cols = ["chain_id", "chain_name", "year"]
    for (chain_id, chain_name, year), subset in ok.groupby(group_cols, dropna=False):
        total = len(subset)
        row = {
            "chain_id": chain_id,
            "chain_name": chain_name,
            "year": int(year) if pd.notna(year) else None,
            "matched_contracts_with_timestamp": int(total),
        }
        for e in ["EIP2612", "EIP712", "EIP5267", "EIP1271"]:
            count = int(subset[e].sum())
            row[f"{e}_count"] = count
            row[f"{e}_pct_among_matched"] = round((count / total) * 100, 6) if total else 0.0
        yearly_rows.append(row)

    yearly = pd.DataFrame(yearly_rows).sort_values(["chain_id", "year"])
    yearly_path = outdir / "yearly_matched_eip_trend_merged.csv"
    yearly.to_csv(yearly_path, index=False)
    print(f"Saved yearly merged trend: {yearly_path}")

    combo = (
        ok.groupby(["chain_id", "chain_name", "year", "eip_combo"], dropna=False)
        .size()
        .reset_index(name="count")
        .sort_values(["chain_id", "year", "count"], ascending=[True, True, False])
    )
    combo_path = outdir / "yearly_combo_summary_merged.csv"
    combo.to_csv(combo_path, index=False)
    print(f"Saved yearly combo merged: {combo_path}")


def main() -> None:
    p = argparse.ArgumentParser(
        description="Collect latest matched EIP contracts only, from cutoff to end date, using BigQuery or candidate CSV."
    )
    p.add_argument("--mode", choices=["bigquery", "csv_candidates"], required=True)
    p.add_argument("--chain-id", type=int, required=True)
    p.add_argument("--chain-name", required=True)
    p.add_argument("--deployment-cache", required=True)
    p.add_argument("--old-matched-csv", default=None)
    p.add_argument("--outdir", required=True)
    p.add_argument("--start-date", default=None)
    p.add_argument("--start-block", type=int, default=None)
    p.add_argument("--end-date", required=True)

    p.add_argument("--bq-project", default=None)
    p.add_argument("--bq-table", default=None)
    p.add_argument("--address-col", default="address")
    p.add_argument("--bytecode-col", default="bytecode")
    p.add_argument("--sighash-col", default="function_sighashes")
    p.add_argument("--block-col", default="block_number")
    p.add_argument("--timestamp-col", default="block_timestamp")

    p.add_argument("--candidate-csv", default=None)
    p.add_argument("--merge-old", action="store_true")
    p.add_argument("--keep-bytecode", action="store_true")

    args = p.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    cutoff = find_cutoff_from_cache(args.deployment_cache)
    print("=== Cutoff from old deployment_cache ===")
    for k, v in cutoff.items():
        print(f"{k}: {v}")

    if args.mode == "bigquery":
        if not args.bq_table:
            raise ValueError("--bq-table is required in bigquery mode")
        df = run_bigquery(args, cutoff)
    else:
        if not args.candidate_csv:
            raise ValueError("--candidate-csv is required in csv_candidates mode")
        df = run_csv_candidates(args)

    if df.empty:
        print("No candidate rows found.")
        return

    detected = add_detection_columns(df)
    matched = detected[detected["is_eip_matched"]].copy()
    matched = matched[matched["address"].str.match(r"^0x[a-f0-9]{40}$", na=False)]
    if "code_hash" in matched.columns:
        matched = matched.drop_duplicates(subset=["chain_id", "code_hash"], keep="first")
    else:
        matched = matched.drop_duplicates(subset=["chain_id", "address"], keep="last")

    if not args.keep_bytecode and "bytecode" in matched.columns:
        matched = matched.drop(columns=["bytecode"])

    latest_csv = outdir / f"{args.chain_name}_new_matched_eip_contracts.csv"
    matched.to_csv(latest_csv, index=False)

    print("\n=== New matched contracts ===")
    print(f"Rows: {len(matched)}")
    print(f"Saved: {latest_csv}")
    print(matched[["EIP2612", "EIP712", "EIP5267", "EIP1271"]].sum())

    if "year" in matched.columns:
        print("\nYear preview:")
        print(matched.groupby("year").size().to_string())

    if args.merge_old:
        if not args.old_matched_csv:
            raise ValueError("--old-matched-csv is required with --merge-old")
        merged_path = outdir / f"{args.chain_name}_merged_old_new_matched_eip_contracts.csv"
        merged = merge_old_new(
            old_csv=args.old_matched_csv,
            new_df=matched,
            output_path=merged_path,
            chain_id=args.chain_id,
            chain_name=args.chain_name,
        )
        write_yearly_outputs(merged, outdir)
    else:
        write_yearly_outputs(matched, outdir)


if __name__ == "__main__":
    main()



# python3 download_latest_eip_matched_contracts.py \
#   --mode bigquery \
#   --chain-id 1 \
#   --chain-name ethereum \
#   --deployment-cache /home/ashok/ashokTests/smart-contract-data-source/eip_adoption_v2/deployment_cache.json \
#   --old-matched-csv /home/ashok/ashokTests/smart-contract-data-source/eip_adoption_v2/matched_contracts_with_deployment.csv \
#   --outdir /home/ashok/ashokTests/smart-contract-data-source/eip_adoption_2024_2026 \
#   --bq-table bigquery-public-data.crypto_ethereum.contracts \
#   --end-date 2026-05-31 \
#   --merge-old
  
  
#   python % python3 /Users/ashokk/Documents/ERC-analysis-master/erc-classify/python/download_latest_eip_matched_contracts.py \
#   --mode bigquery \
#   --chain-id 1 \
#   --chain-name ethereum \
#   --deployment-cache /Users/ashokk/Downloads/evm_data/eip_adoption_v2/deployment_cache.json \
#   --old-matched-csv /Users/ashokk/Downloads/evm_data/eip_adoption_v2/matched_contracts_with_deployment.csv \
#   --outdir /Users/ashokk/Downloads/evm_data/eip_adoption_2024_2026 \
#   --bq-table bigquery-public-data.crypto_ethereum.contracts \
#   --end-date 2026-05-31 \
#   --merge-old
  
  
  
  
  
# ashokk@ASHOKKMD6RM python % python3 /Users/ashokk/Documents/ERC-analysis-master/erc-classify/python/download_latest_eip_matched_contracts.py \
#   --mode bigquery \
#   --chain-id 137 \
#   --chain-name polygon \
#   --deployment-cache /Users/ashokk/Downloads/evm_data/eip_adoption_polygon_v2/deployment_cache.json \
#   --old-matched-csv /Users/ashokk/Downloads/evm_data/eip_adoption_polygon_v2/matched_contracts_with_deployment.csv \
#   --outdir /Users/ashokk/Downloads/evm_data/eip_adoption_polygon_2024_2026_test \
#   --bq-project api-project-659683831600 \
#   --bq-table bigquery-public-data.crypto_polygon.contracts \
#   --start-date 2024-01-01 \
#   --start-block 0 \
#   --end-date 2026-05-31 \
#   --merge-old