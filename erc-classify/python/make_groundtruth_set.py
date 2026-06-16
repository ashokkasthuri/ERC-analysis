#!/usr/bin/env python3
import json, csv, random, shutil
from pathlib import Path
from collections import defaultdict

BASE = Path("/home/ashok/ashokTests/smart-contract-data-source")
RESULTS_JSON = BASE / "domain_separator_analysis/domain_separator_results.json"
SRC_ROOT = BASE / "etherscan_verified_sources"
OUT_DIR = BASE / "domain_separator_analysis/groundtruth_review"
OUT_CSV = OUT_DIR / "groundtruth_candidates.csv"

TARGET_TOTAL = 180
PER_CATEGORY = 15
SAFE_LOW_INFO = 40

random.seed(42)

CATEGORIES = [
    "missing_chainId",
    "hardcoded_chainId",
    "missing_verifyingContract",
    "incorrect_verifyingContract",
    "hardcoded_verifier",
    "stale_cached_DOMAIN_SEPARATOR",
    "proxy_stale_domain",
    "missing_logical_domain_disambiguator",
    "hardcoded_salt",
    "zero_salt_used",
]

def infer_chain_year(path):
    p = str(path)
    chain = "unknown"
    year = "unknown"
    for c in ["ethereum", "binance", "polygon", "avalanche"]:
        if f"/{c}/" in p:
            chain = c
            break
    for y in ["2017","2018","2019","2020","2021","2022","2023","2024","2025","2026"]:
        if f"/{y}/" in p:
            year = y
            break
    return chain, year

def copy_for_review(src, label, idx):
    src = Path(src)
    if not src.exists():
        return ""
    chain, year = infer_chain_year(src)
    dst_dir = OUT_DIR / "files" / label / chain / str(year)
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / f"{idx:04d}_{src.name}"
    shutil.copy2(src, dst)
    return str(dst)

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    results = json.loads(RESULTS_JSON.read_text())

    by_cat = defaultdict(list)
    safe = []

    for r in results:
        cats = r.get("risk_category", [])
        risk = r.get("risk_level", "")
        f = r.get("file", "")

        if not f or not f.endswith(".sol"):
            continue

        if risk in {"Low", "Info"}:
            safe.append(r)

        for c in cats:
            if c in CATEGORIES:
                by_cat[c].append(r)

    selected = []
    seen_files = set()

    # 1. sample positives per category across chain/year
    for cat in CATEGORIES:
        bucket = by_cat.get(cat, [])
        random.shuffle(bucket)

        # spread by chain-year
        by_chain_year = defaultdict(list)
        for r in bucket:
            chain, year = infer_chain_year(r.get("file", ""))
            by_chain_year[(chain, year)].append(r)

        picked = []
        keys = list(by_chain_year.keys())
        random.shuffle(keys)

        while len(picked) < PER_CATEGORY and keys:
            for k in list(keys):
                if by_chain_year[k]:
                    r = by_chain_year[k].pop()
                    f = r.get("file")
                    if f not in seen_files:
                        picked.append((cat, r))
                        seen_files.add(f)
                    if len(picked) >= PER_CATEGORY:
                        break
                else:
                    keys.remove(k)

        selected.extend(picked)

    # 2. add negatives/safe examples
    random.shuffle(safe)
    safe_count = 0
    for r in safe:
        f = r.get("file")
        if f not in seen_files:
            selected.append(("SAFE_OR_NO_FINDING", r))
            seen_files.add(f)
            safe_count += 1
        if safe_count >= SAFE_LOW_INFO:
            break

    # 3. trim if needed
    selected = selected[:TARGET_TOTAL]

    rows = []
    for i, (label, r) in enumerate(selected, 1):
        src = r.get("file", "")
        chain, year = infer_chain_year(src)
        copied = copy_for_review(src, label, i)

        rows.append({
            "id": i,
            "chain": chain,
            "year": year,
            "source_file": src,
            "review_file": copied,
            "tool_label": label,
            "tool_risk_level": r.get("risk_level", ""),
            "tool_risk_category": "|".join(r.get("risk_category", [])),
            "tool_taxonomy": "|".join(r.get("taxonomy_ids", [])),
            "manual_label": "",
            "manual_is_true_positive": "",
            "manual_correct_category": "",
            "manual_notes": "",
        })

    with OUT_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Ground-truth candidates: {len(rows)}")
    print(f"[OK] CSV: {OUT_CSV}")
    print(f"[OK] Files copied under: {OUT_DIR / 'files'}")

if __name__ == "__main__":
    main()