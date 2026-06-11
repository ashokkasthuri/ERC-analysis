
#!/usr/bin/env python3

import argparse, json, csv, os
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional

from greed import Project, options
from greed.solver.shortcuts import *  # noqa

try:
    from osprey.core.exploration import directed_search_exit
except Exception:
    directed_search_exit = None

PERMIT_SELECTOR_HEX = "d505accf"
PERMIT_SELECTOR_INT = 0xD505ACCF
PERMIT_CALLDATA_SIZE = 4 + 32 * 7

OWNER_OFFSET = 4 + 12
SPENDER_OFFSET = 4 + 32 + 12
VALUE_OFFSET = 4 + 32 * 2
DEADLINE_OFFSET = 4 + 32 * 3

@dataclass
class Finding:
    taxonomy_id: str
    category: str
    severity: str
    confidence: str
    reason: str

@dataclass
class Observation:
    mode: str
    sha3_count: int = 0
    sload_count: int = 0
    staticcall_count: int = 0
    chainid_seen: bool = False
    address_seen: bool = False
    ecrecover_seen: bool = False
    classification: str = "unknown"
    trace_sample: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

@dataclass
class Report:
    contract_address: str
    block_number: int
    target_dir: str
    is_candidate: bool
    reason: str
    paths_found: int = 0
    has_ecrecover_path: bool = False
    has_dynamic_domain_path: bool = False
    has_cached_domain_path: bool = False
    findings: List[Finding] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    static_bytecode_hints: Dict[str, Any] = field(default_factory=dict)

def setup():
    options.SOLVER_TIMEOUT = 360
    options.LAZY_SOLVES = False
    options.MAX_CALLDATA_SIZE = 1024
    options.MAX_SHA_SIZE = 512
    options.GREEDY_SHA = True
    options.OPTIMISTIC_CALL_RESULTS = True
    options.DEFAULT_CREATE_RESULT_ADDRESS = True
    options.DEFAULT_CREATE2_RESULT_ADDRESS = True
    options.DEFAULT_EXTCODESIZE = True

def hints(project: Project) -> Dict[str, Any]:
    code = getattr(project, "code", b"") or b""
    h = code.hex() if isinstance(code, bytes) else str(code).replace("0x", "").lower()
    return {
        "bytecode_len": len(h)//2,
        "has_permit_selector_d505accf": PERMIT_SELECTOR_HEX in h,
        "has_DOMAIN_SEPARATOR_selector_3644e515": "3644e515" in h,
        "has_eip712Domain_selector_84b0196e": "84b0196e" in h,
        "has_EIP712_full_typehash_8b73": "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f" in h,
        "has_PERMIT_typehash_6e71": "6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9" in h,
    }

def classify(obs: Observation, h: Dict[str, Any]) -> None:
    domain_hint = h.get("has_EIP712_full_typehash_8b73", False) or obs.sha3_count >= 2

    if h.get("has_permit_selector_d505accf") and not domain_hint:
        obs.findings.append(Finding("T1", "missing_domain_separator_candidate", "High", "Medium",
            "permit selector exists but no EIP712 domain typehash / multi-hash domain evidence was found."))

    if domain_hint and not obs.chainid_seen:
        obs.findings.append(Finding("T2", "missing_or_hardcoded_chainId_candidate", "High", "Medium",
            "EIP712 domain evidence exists, but CHAINID opcode was not observed in symbolic/static evidence."))

    if domain_hint and not obs.address_seen:
        obs.findings.append(Finding("T3", "missing_or_hardcoded_verifyingContract_candidate", "High", "Medium",
            "EIP712 domain evidence exists, but ADDRESS opcode was not observed in symbolic/static evidence."))

    if obs.sload_count > 0 and domain_hint and not obs.chainid_seen and not obs.address_seen:
        obs.findings.append(Finding("T4", "stale_cached_DOMAIN_SEPARATOR_candidate", "High", "Medium",
            "Domain appears storage/cached and no runtime CHAINID/ADDRESS rebuild evidence was found."))

    if obs.chainid_seen and obs.address_seen and domain_hint:
        obs.classification = "safe_dynamic_domain_evidence"
    elif any(f.taxonomy_id == "T4" for f in obs.findings):
        obs.classification = "stale_cached_domain_candidate"
    elif obs.findings:
        obs.classification = "domain_risk_candidate"
    else:
        obs.classification = "inconclusive"

def symbolic_try(target_dir, contract_address, block_number, max_paths, h) -> List[Observation]:
    if directed_search_exit is None:
        return []

    project = Project(target_dir=target_dir)
    calldata = "0x" + PERMIT_SELECTOR_HEX + ("SS" * (PERMIT_CALLDATA_SIZE - 4))
    state = project.factory.entry_state(xid=1, init_ctx={
        "ADDRESS": contract_address,
        "NUMBER": block_number,
        "CALLDATASIZE": PERMIT_CALLDATA_SIZE,
        "CALLDATA": calldata,
        "CALLVALUE": 0,
    })

    selector = state.calldata.readn(BVV(0, 256), BVV(4, 256))
    owner = state.calldata.readn(BVV(OWNER_OFFSET, 256), BVV(20, 256))
    spender = state.calldata.readn(BVV(SPENDER_OFFSET, 256), BVV(20, 256))
    value = state.calldata.readn(BVV(VALUE_OFFSET, 256), BVV(32, 256))
    deadline = state.calldata.readn(BVV(DEADLINE_OFFSET, 256), BVV(32, 256))

    state.solver.add_path_constraint(Equal(selector, BVV(PERMIT_SELECTOR_INT, 32)))
    state.solver.add_path_constraint(BV_UGE(state.calldatasize, BVV(PERMIT_CALLDATA_SIZE, 256)))
    try:
        ctx_or_symbolic("TIMESTAMP", state.ctx, state.xid, nbits=256)
        state.solver.add_path_constraint(BV_UGE(deadline, state.ctx["TIMESTAMP"]))
        state.solver.add_path_constraint(NotEqual(owner, BVV(0, 160)))
        state.solver.add_path_constraint(NotEqual(spender, BVV(0, 160)))
        state.solver.add_path_constraint(BV_UGT(value, BVV(0, 256)))
    except Exception:
        pass

    out = []
    try:
        for exit_state in directed_search_exit(project, state, with_monitor_call=True, with_monitor_sload=True):
            obs = Observation(mode="symbolic_success")
            for stmt in getattr(exit_state, "trace", []) or []:
                op = getattr(stmt, "__internal_name__", stmt.__class__.__name__).upper()
                sid = str(getattr(stmt, "id", getattr(stmt, "stmt_id", "unknown")))
                if op in {"SHA3", "KECCAK256"}: obs.sha3_count += 1
                if op == "SLOAD": obs.sload_count += 1
                if op == "STATICCALL": obs.staticcall_count += 1; obs.ecrecover_seen = True
                if op == "CHAINID": obs.chainid_seen = True
                if op == "ADDRESS": obs.address_seen = True
                if op in {"SHA3","KECCAK256","SLOAD","STATICCALL","CHAINID","ADDRESS","REVERT","RETURN","STOP"}:
                    obs.trace_sample.append({"id": sid, "op": op})
            classify(obs, h)
            out.append(obs)
            if len(out) >= max_paths: break
    except Exception:
        pass
    return out

def static_fact_fallback(target_dir, h) -> Observation:
    obs = Observation(mode="static_fact_fallback")

    for root, _, files in os.walk(target_dir):
        for fn in files:
            if not fn.endswith(".csv"):
                continue
            p = os.path.join(root, fn)
            try:
                with open(p, newline="", errors="ignore") as f:
                    text = f.read().upper()
                    obs.sha3_count += text.count("SHA3") + text.count("KECCAK256")
                    obs.sload_count += text.count("SLOAD")
                    obs.staticcall_count += text.count("STATICCALL")
                    obs.chainid_seen = obs.chainid_seen or ("CHAINID" in text)
                    obs.address_seen = obs.address_seen or ("ADDRESS" in text)
                    obs.ecrecover_seen = obs.ecrecover_seen or ("STATICCALL" in text and ("0X1" in text or ",1" in text))
            except Exception:
                pass

    classify(obs, h)
    return obs

def dedup(fs):
    seen, out = set(), []
    for f in fs:
        k = (f.taxonomy_id, f.category, f.reason)
        if k not in seen:
            seen.add(k); out.append(f)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-dir", required=True)
    ap.add_argument("--contract-address", required=True)
    ap.add_argument("--block-number", type=int, required=True)
    ap.add_argument("--max-paths", type=int, default=5)
    ap.add_argument("--output")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    setup()
    project = Project(target_dir=args.target_dir)
    h = hints(project)

    observations = symbolic_try(args.target_dir, args.contract_address, args.block_number, args.max_paths, h)

    if not observations:
        observations = [static_fact_fallback(args.target_dir, h)]

    findings = dedup([f for o in observations for f in o.findings])
    has_dynamic = any(o.classification == "safe_dynamic_domain_evidence" for o in observations)
    has_cached = any(o.classification == "stale_cached_domain_candidate" for o in observations)
    has_ecrecover = any(o.ecrecover_seen for o in observations)

    report = Report(
        contract_address=args.contract_address,
        block_number=args.block_number,
        target_dir=args.target_dir,
        is_candidate=bool(findings),
        reason="Symbolic success path if available; otherwise static fact fallback used.",
        paths_found=len([o for o in observations if o.mode == "symbolic_success"]),
        has_ecrecover_path=has_ecrecover,
        has_dynamic_domain_path=has_dynamic,
        has_cached_domain_path=has_cached,
        findings=findings,
        observations=observations,
        static_bytecode_hints=h,
    )

    text = json.dumps(asdict(report), indent=2)
    if args.output:
        open(args.output, "w").write(text)
    print(text)

if __name__ == "__main__":
    main()
