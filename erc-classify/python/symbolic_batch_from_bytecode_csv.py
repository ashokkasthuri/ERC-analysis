'''
Author: ashokkasthuri ashokraj.kasthuri@gmail.com
Date: 2026-06-11 16:01:31
LastEditors: ashokkasthuri ashokraj.kasthuri@gmail.com
LastEditTime: 2026-06-11 16:01:41
FilePath: /ERC-analysis-master/erc-classify/python/symbolic_batch_from_bytecode_csv.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''
#!/usr/bin/env python3
import csv, json, subprocess
from pathlib import Path
from tqdm import tqdm

IN="/home/ashok/ashokTests/smart-contract-data-source/domain_separator_analysis/high_risk_bytecode_all_chains.csv"
OUT="/home/ashok/ashokTests/smart-contract-data-source/domain_separator_analysis/symbolic_results"
PROBE="/home/ashok/ashokTests/ERC-analysis/erc-classify/python/symbolic_probe_permit_domain.py"
GREED="/home/greed"

Path(OUT).mkdir(parents=True, exist_ok=True)

with open(IN, newline="") as f:
    rows=[r for r in csv.DictReader(f) if r.get("status")=="ok" and int(r.get("bytecode_len") or 0)>0]

import sys
limit=int(sys.argv[1]) if len(sys.argv)>1 else None
rows=rows[:limit] if limit else rows
for r in tqdm(rows, desc="symbolic"):
    chain, year, addr = r["chain"], r["year"], r["address"].lower()
    odir=Path(OUT)/chain/str(year)
    odir.mkdir(parents=True, exist_ok=True)
    out_json=odir/f"{addr}.json"
    if out_json.exists():
        continue

    bytecode=(r["bytecode"] or "").replace("0x","").strip()
    Path("/home/greed/bytecode.hex").write_text(bytecode)

    subprocess.run("cd /home/greed && rm -rf .temp/bytecode && /home/greed/gigahorse-toolchain/gigahorse.py -T 300 --reuse_datalog_bin --disable_inline -C /home/greed/gigahorse-toolchain/clients/greed_client.dl_compiled,/home/greed/gigahorse-toolchain/clients/visualizeout.py bytecode.hex", shell=True, check=False)
    subprocess.run(f"cp /home/greed/bytecode.hex /home/greed/.temp/bytecode/out/contract.hex", shell=True, check=False)

    subprocess.run(f"python3 {PROBE} --target-dir /home/greed/.temp/bytecode/out --contract-address {addr} --block-number 19000000 --max-paths 20 --output {out_json}", shell=True, check=False)