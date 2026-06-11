#!/usr/bin/env python3
import argparse, csv, json, os, re, time, threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from tqdm import tqdm

ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"

CHAIN_IDS = {
    "ethereum": 1,
    "binance": 56,
    "bsc": 56,
    "polygon": 137,
    "avalanche": 43114,
}

ADDR_RE = re.compile(r"(0x[a-fA-F0-9]{40})")
YEAR_RE = re.compile(r"/(20\d{2})/")

def load_env(env_path):
    if not env_path:
        return
    p = Path(env_path)
    if not p.exists():
        return
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

def load_keys(env_path):
    load_env(env_path)
    keys = []
    for i in range(1, 9):
        k = os.getenv(f"ETHERSCAN_API_KEY{i}")
        if k:
            keys.append(k.strip())
    if os.getenv("ETHERSCAN_API_KEY"):
        keys.append(os.getenv("ETHERSCAN_API_KEY").strip())
    keys = list(dict.fromkeys(keys))
    if not keys:
        raise RuntimeError("No ETHERSCAN_API_KEY1-8 found")
    return keys

class KeyPool:
    def __init__(self, keys, cps):
        self.keys = keys
        self.cps = cps
        self.idx = 0
        self.idx_lock = threading.Lock()
        self.key_locks = {k: threading.Lock() for k in keys}
        self.last = {k: 0.0 for k in keys}
        self.interval = 1.0 / cps

    def acquire(self):
        with self.idx_lock:
            k = self.keys[self.idx % len(self.keys)]
            self.idx += 1
        with self.key_locks[k]:
            now = time.time()
            wait = self.interval - (now - self.last[k])
            if wait > 0:
                time.sleep(wait)
            self.last[k] = time.time()
        return k

def parse_high_risk(summary_json):
    data = json.loads(Path(summary_json).read_text())
    rows, seen = [], set()

    for f in data.get("high_risk_files", []):
        f = str(f)
        m_addr = ADDR_RE.search(f)
        if not m_addr:
            continue
        address = m_addr.group(1).lower()

        chain = None
        for c in CHAIN_IDS:
            if f"/{c}/" in f.lower():
                chain = "binance" if c == "bsc" else c
                break
        if chain is None:
            continue

        m_year = YEAR_RE.search(f)
        year = int(m_year.group(1)) if m_year else None

        key = (chain, address)
        if key in seen:
            continue
        seen.add(key)

        rows.append({
            "chain": chain,
            "chain_id": CHAIN_IDS[chain],
            "year": year,
            "address": address,
            "source_file": f,
        })

    return rows

def fetch_bytecode(row, keypool, retries=5):
    err = ''
    for attempt in range(retries):
        key = keypool.acquire()
        try:
            r = requests.get(ETHERSCAN_V2_URL, params={
                "chainid": row["chain_id"],
                "module": "proxy",
                "action": "eth_getCode",
                "address": row["address"],
                "tag": "latest",
                "apikey": key,
            }, timeout=30)

            data = r.json()
            result = data.get("result", "")

            if isinstance(result, str) and result.startswith("0x"):
                out = dict(row)
                out["bytecode"] = result
                out["bytecode_len"] = max(0, len(result) - 2) // 2
                out["status"] = "ok" if result != "0x" else "empty"
                out["error"] = ""
                return out

            txt = json.dumps(data).lower()
            if "rate limit" in txt or "too many requests" in txt:
                time.sleep(1.5 * (attempt + 1))
                continue

            err = str(data)[:500]

        except Exception as e:
            err = str(e)[:500]
            time.sleep(1.5 * (attempt + 1))

    out = dict(row)
    out["bytecode"] = ""
    out["bytecode_len"] = 0
    out["status"] = "error"
    out["error"] = err
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary-json", default="/Users/ashokk/Documents/ERC-analysis-master/erc-classify/DATA/domain_taxonomy_all_chains_summary.json")
    ap.add_argument("--env", default="/Users/ashokk/Documents/ERC-analysis-master/.env")
    ap.add_argument("--out", default="/Users/ashokk/Documents/ERC-analysis-master/erc-classify/DATA/high_risk_bytecode_all_chains.csv")
    ap.add_argument("--workers", type=int, default=64)
    ap.add_argument("--calls-per-second-per-key", type=float, default=4.0)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    keys = load_keys(args.env)
    rows = parse_high_risk(args.summary_json)
    if args.limit:
        rows = rows[:args.limit]

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    done = set()
    if out_path.exists():
        with out_path.open(newline="") as f:
            for r in csv.DictReader(f):
                done.add((r["chain"], r["address"].lower()))

    pending = [r for r in rows if (r["chain"], r["address"]) not in done]
    print(f"keys={len(keys)} total={len(rows)} done={len(done)} pending={len(pending)} workers={args.workers}")

    fields = ["chain", "chain_id", "year", "address", "bytecode_len", "status", "error", "bytecode", "source_file"]
    write_header = not out_path.exists()

    keypool = KeyPool(keys, args.calls_per_second_per_key)

    with out_path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if write_header:
            writer.writeheader()

        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(fetch_bytecode, r, keypool) for r in pending]
            for fut in tqdm(as_completed(futs), total=len(futs), desc="Downloading bytecode"):
                rec = fut.result()
                writer.writerow({k: rec.get(k, "") for k in fields})
                f.flush()

    print(f"saved: {out_path}")

if __name__ == "__main__":
    main()