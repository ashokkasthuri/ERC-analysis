#!/usr/bin/env python3
"""
Minimal GREED/Osprey-style symbolic probe for ERC-2612 permit() and EIP-712 DOMAIN_SEPARATOR.

Goal
----
Start symbolic execution from permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
and inspect successful paths for:
  1. STATICCALL/ecrecover reachability.
  2. Runtime DOMAIN_SEPARATOR construction style:
       - dynamic: CHAINID + ADDRESS + SHA3 observed on the permit path.
       - cached/stale candidate: SLOAD-based domain separator, but no CHAINID/ADDRESS rebuild on the path.
  3. Permit path constraints and possible calldata model.

Important
---------
This is the first minimal one-file prototype. It is intentionally conservative.
It does NOT yet prove cross-contract/cross-chain replay. It identifies symbolic
path evidence that should be fed into the full specification checker.

Expected input
--------------
GREED/Gigahorse target directory, not raw bytecode directly.

Typical flow:
  1. Generate GREED/Gigahorse facts for one bytecode/contract.
  2. Run this script on the generated target-dir.

Example
-------
python3 permit_domain_symbolic_probe.py \
  --target-dir /path/to/gigahorse_output \
  --contract-address 0xYourToken \
  --block-number 19000000 \
  --max-paths 3 \
  --debug
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from greed import Project, options
from greed.solver.shortcuts import *  # noqa: F401,F403

try:
    from osprey.core.exploration import directed_search_exit
except Exception:
    directed_search_exit = None


LOGGING_FORMAT = "%(levelname)s | %(name)s | %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
log = logging.getLogger("permit-domain-probe")


# ERC-2612:
# permit(address owner,address spender,uint256 value,uint256 deadline,uint8 v,bytes32 r,bytes32 s)
PERMIT_SELECTOR_INT = 0xD505ACCF
PERMIT_SELECTOR_HEX = "d505accf"
PERMIT_CALLDATA_SIZE = 4 + 32 * 7

# ABI offsets.
OWNER_OFFSET = 4 + 12
SPENDER_OFFSET = 4 + 32 + 12
VALUE_OFFSET = 4 + 32 * 2
DEADLINE_OFFSET = 4 + 32 * 3
V_OFFSET = 4 + 32 * 4 + 31
R_OFFSET = 4 + 32 * 5
S_OFFSET = 4 + 32 * 6


@dataclass
class PathObservation:
    exit_stmt_id: Optional[str] = None
    calldata_hex: Optional[str] = None
    opcodes_seen: List[str] = field(default_factory=list)
    sha3_count: int = 0
    sload_count: int = 0
    sstore_count: int = 0
    staticcall_count: int = 0
    chainid_seen: bool = False
    address_seen: bool = False
    timestamp_seen: bool = False
    ecrecover_staticcall_candidate: bool = False
    staticcall_stmt_ids: List[str] = field(default_factory=list)
    sha3_stmt_ids: List[str] = field(default_factory=list)
    sload_stmt_ids: List[str] = field(default_factory=list)
    interesting_trace: List[Dict[str, Any]] = field(default_factory=list)
    classification: str = "unknown"
    warnings: List[str] = field(default_factory=list)


@dataclass
class PermitDomainProbeReport:
    contract_address: str
    block_number: int
    target_dir: str
    is_candidate: bool
    reason: str
    permit_selector_constrained: bool = True
    paths_found: int = 0
    has_dynamic_domain_path: bool = False
    has_cached_domain_candidate_path: bool = False
    has_ecrecover_path: bool = False
    observations: List[PathObservation] = field(default_factory=list)
    static_bytecode_hints: Dict[str, Any] = field(default_factory=dict)


def setup_greed_options() -> None:
    options.SOLVER_TIMEOUT = 360
    options.LAZY_SOLVES = False
    options.MAX_CALLDATA_SIZE = 1024
    options.MAX_SHA_SIZE = 512
    options.GREEDY_SHA = True
    options.OPTIMISTIC_CALL_RESULTS = True
    options.DEFAULT_CREATE_RESULT_ADDRESS = True
    options.DEFAULT_CREATE2_RESULT_ADDRESS = True
    options.DEFAULT_EXTCODESIZE = True


def mk_project(target_dir: str) -> Project:
    project = Project(target_dir=target_dir)

    # Best effort: if Osprey web3 globals are configured, attach w3 so partial storage can work later.
    try:
        from osprey.globals.extra import w3
        project._w3 = w3
    except Exception:
        pass

    return project


def symbolic_permit_calldata() -> str:
    """
    GREED supports 'SS' bytes in CALLDATA to denote symbolic bytes.
    We concretize only the first four selector bytes and leave all ABI args symbolic.
    """
    return "0x" + PERMIT_SELECTOR_HEX + ("SS" * (PERMIT_CALLDATA_SIZE - 4))


def init_permit_state(project: Project, contract_address: str, block_number: int, partial_concrete_storage: bool = False):
    init_ctx = {
        "ADDRESS": contract_address,
        "NUMBER": block_number,
        "CALLDATASIZE": PERMIT_CALLDATA_SIZE,
        "CALLDATA": symbolic_permit_calldata(),
        "CALLVALUE": 0,
    }

    state = project.factory.entry_state(
        xid=1,
        init_ctx=init_ctx,
        partial_concrete_storage=partial_concrete_storage,
    )

    # Ensure symbolic context exists.
    ctx_or_symbolic("ADDRESS", state.ctx, state.xid, nbits=160)
    ctx_or_symbolic("CALLER", state.ctx, state.xid, nbits=160)
    ctx_or_symbolic("TIMESTAMP", state.ctx, state.xid, nbits=256)

    return state


def read_permit_args(state):
    selector = state.calldata.readn(BVV(0, 256), BVV(4, 256))
    owner = state.calldata.readn(BVV(OWNER_OFFSET, 256), BVV(20, 256))
    spender = state.calldata.readn(BVV(SPENDER_OFFSET, 256), BVV(20, 256))
    value = state.calldata.readn(BVV(VALUE_OFFSET, 256), BVV(32, 256))
    deadline = state.calldata.readn(BVV(DEADLINE_OFFSET, 256), BVV(32, 256))
    v = state.calldata.readn(BVV(V_OFFSET, 256), BVV(1, 256))
    r = state.calldata.readn(BVV(R_OFFSET, 256), BVV(32, 256))
    s = state.calldata.readn(BVV(S_OFFSET, 256), BVV(32, 256))
    return selector, owner, spender, value, deadline, v, r, s


def add_permit_entry_constraints(state) -> None:
    selector, owner, spender, value, deadline, v, r, s = read_permit_args(state)

    state.solver.add_path_constraint(Equal(selector, BVV(PERMIT_SELECTOR_INT, 32)))
    state.solver.add_path_constraint(BV_UGE(state.calldatasize, BVV(PERMIT_CALLDATA_SIZE, 256)))

    # Deadline should be satisfiable for non-reverting permit path.
    try:
        timestamp = state.ctx["TIMESTAMP"]
        state.solver.add_path_constraint(BV_UGE(deadline, timestamp))
    except Exception:
        pass

    # Avoid degenerate owner/spender/value unless the path forces them.
    try:
        state.solver.add_path_constraint(NotEqual(owner, BVV(0, 160)))
        state.solver.add_path_constraint(NotEqual(spender, BVV(0, 160)))
        state.solver.add_path_constraint(BV_UGT(value, BVV(0, 256)))
    except Exception:
        pass


def stmt_name(stmt) -> str:
    return getattr(stmt, "__internal_name__", stmt.__class__.__name__).upper()


def stmt_id(stmt) -> str:
    return str(getattr(stmt, "id", getattr(stmt, "stmt_id", "unknown")))


def safe_term_int(state, term) -> Optional[int]:
    try:
        raw = state.solver.eval(term, raw=True)
        if hasattr(raw, "value"):
            return int(raw.value)
        if isinstance(raw, int):
            return int(raw)
        if isinstance(raw, str):
            return int(raw, 0)
    except Exception:
        return None
    return None


def collect_stmt_values(state, stmt) -> Dict[str, str]:
    """
    Best-effort extraction of concrete-ish statement values.
    GREED TAC statements expose different *_val fields depending on opcode.
    """
    out: Dict[str, str] = {}

    for attr in dir(stmt):
        if not attr.endswith("_val"):
            continue
        if attr.startswith("_"):
            continue
        try:
            val = getattr(stmt, attr)
            conc = safe_term_int(state, val)
            if conc is not None:
                out[attr] = hex(conc)
            else:
                out[attr] = str(val)
        except Exception:
            continue

    return out


def trace_observation(state) -> PathObservation:
    obs = PathObservation()
    obs.exit_stmt_id = stmt_id(state.curr_stmt)

    try:
        calldata = state.solver.eval_memory(state.calldata, BVV(PERMIT_CALLDATA_SIZE, 256))
        obs.calldata_hex = str(calldata)
    except Exception:
        pass

    trace = getattr(state, "trace", []) or []
    seen: List[str] = []

    for stmt in trace:
        name = stmt_name(stmt)
        sid = stmt_id(stmt)
        seen.append(name)

        if name in {"SHA3", "KECCAK256"}:
            obs.sha3_count += 1
            obs.sha3_stmt_ids.append(sid)

        if name == "SLOAD":
            obs.sload_count += 1
            obs.sload_stmt_ids.append(sid)

        if name == "SSTORE":
            obs.sstore_count += 1

        if name == "STATICCALL":
            obs.staticcall_count += 1
            obs.staticcall_stmt_ids.append(sid)

            vals = collect_stmt_values(state, stmt)
            # ecrecover precompile is address 0x01. Depending on TAC class,
            # the precompile target may show up as one of the *_val attributes.
            if any(v == "0x1" for v in vals.values()):
                obs.ecrecover_staticcall_candidate = True

        if name == "CHAINID":
            obs.chainid_seen = True

        if name == "ADDRESS":
            obs.address_seen = True

        if name == "TIMESTAMP":
            obs.timestamp_seen = True

        if name in {"STATICCALL", "SHA3", "KECCAK256", "SLOAD", "SSTORE", "CHAINID", "ADDRESS", "TIMESTAMP", "CALLDATALOAD", "MSTORE", "MLOAD", "EQ", "REVERT", "RETURN", "STOP"}:
            item = {
                "id": sid,
                "op": name,
            }
            vals = collect_stmt_values(state, stmt)
            if vals:
                item["values"] = vals
            obs.interesting_trace.append(item)

    # Keep compact unique opcode sequence.
    obs.opcodes_seen = sorted(set(seen))

    # Path classification.
    if obs.chainid_seen and obs.address_seen and obs.sha3_count > 0:
        obs.classification = "dynamic_domain_separator_path"
    elif obs.sload_count > 0 and not obs.chainid_seen and not obs.address_seen:
        obs.classification = "cached_domain_separator_candidate_path"
        obs.warnings.append(
            "Successful permit path uses storage reads but no CHAINID/ADDRESS rebuild; inspect whether DOMAIN_SEPARATOR is cached/stale."
        )
    elif obs.sha3_count > 0 and not obs.chainid_seen:
        obs.classification = "domain_hash_without_runtime_chainid_candidate"
        obs.warnings.append(
            "Successful permit path hashes data but no CHAINID observed; inspect for missing/hardcoded chainId."
        )
    else:
        obs.classification = "unclassified_permit_success_path"

    if obs.staticcall_count == 0:
        obs.warnings.append(
            "No STATICCALL observed on this successful path; implementation may use ECDSA library, ecrecover opcode modeling, or analysis missed the path."
        )
    elif not obs.ecrecover_staticcall_candidate:
        obs.warnings.append(
            "STATICCALL observed, but target precompile 0x01 was not concretely identified; inspect STATICCALL arguments."
        )

    return obs


def static_bytecode_hints(project: Project) -> Dict[str, Any]:
    code = getattr(project, "code", b"") or b""
    if isinstance(code, bytes):
        h = code.hex()
    else:
        h = str(code).replace("0x", "").lower()

    return {
        "bytecode_len": len(h) // 2,
        "has_permit_selector_d505accf": PERMIT_SELECTOR_HEX in h,
        "has_DOMAIN_SEPARATOR_selector_3644e515": "3644e515" in h,
        "has_eip712Domain_selector_84b0196e": "84b0196e" in h,
        "has_EIP712_domain_typehash_0x8b73": "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f" in h,
        "has_PERMIT_typehash_0x6e71": "6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9" in h,
    }

def find_evidence_statements(project: Project):
    evidence_ops = {"STATICCALL", "SHA3", "KECCAK256", "SLOAD", "CHAINID", "ADDRESS"}
    evidence = []

    for stmt_id, stmt in project.statement_at.items():
        name = stmt_name(stmt)
        if name in evidence_ops:
            evidence.append(stmt)

    return evidence

def check_permit_domain_paths(
    target_dir: str,
    contract_address: str,
    block_number: int,
    max_paths: int = 3,
    partial_concrete_storage: bool = False,
) -> PermitDomainProbeReport:
    setup_greed_options()
    project = mk_project(target_dir)
    state = init_permit_state(project, contract_address, block_number, partial_concrete_storage)
    add_permit_entry_constraints(state)

    hints = static_bytecode_hints(project)

    try:
        if not state.solver.is_sat():
            return PermitDomainProbeReport(
                contract_address=contract_address,
                block_number=block_number,
                target_dir=target_dir,
                is_candidate=False,
                reason="Initial permit selector / ABI / deadline constraints are UNSAT.",
                static_bytecode_hints=hints,
            )
    except Exception as exc:
        return PermitDomainProbeReport(
            contract_address=contract_address,
            block_number=block_number,
            target_dir=target_dir,
            is_candidate=False,
            reason=f"Initial satisfiability check failed: {exc}",
            static_bytecode_hints=hints,
        )

    observations: List[PathObservation] = []

    if directed_search_exit is None:
        return PermitDomainProbeReport(
            contract_address=contract_address,
            block_number=block_number,
            target_dir=target_dir,
            is_candidate=False,
            reason="Could not import osprey.core.exploration.directed_search_exit. Install/run inside Osprey environment.",
            static_bytecode_hints=hints,
        )

    # First search for reachable evidence points instead of requiring a full successful permit exit.
    evidence_stmts = find_evidence_statements(project)

    for target_stmt in evidence_stmts:
        try:
            from osprey.core.exploration import directed_search_find

            init_ctx = {
            "ADDRESS": contract_address,
            "NUMBER": block_number,
            "CALLDATASIZE": PERMIT_CALLDATA_SIZE,
            "CALLDATA": symbolic_permit_calldata(),
            "CALLVALUE": 0,
            }

            for found_state in directed_search_find(
                project,
                target_stmt,
                init_ctx=init_ctx,
                with_monitor_call=True,
                with_monitor_sload=True,
            ):
                obs = trace_observation(found_state)
                obs.classification = f"reachable_evidence_{stmt_name(target_stmt)}"
                obs.exit_stmt_id = stmt_id(target_stmt)
                observations.append(obs)

                if len(observations) >= max_paths:
                    break

        except TypeError as e:
            log.error(f"directed_search_find TypeError for {stmt_id(target_stmt)} {stmt_name(target_stmt)}: {e}")
        except Exception as e:
            log.debug(f"Evidence search failed for {stmt_id(target_stmt)} {stmt_name(target_stmt)}: {e}")

        if len(observations) >= max_paths:
            break

    if not observations:
        return PermitDomainProbeReport(
            contract_address=contract_address,
            block_number=block_number,
            target_dir=target_dir,
            is_candidate=False,
            reason="No reachable permit evidence point found under symbolic ABI constraints.",
            static_bytecode_hints=hints,
        )

    has_dynamic = any(o.classification == "dynamic_domain_separator_path" for o in observations)
    has_cached = any(o.classification == "cached_domain_separator_candidate_path" for o in observations)
    has_ecrecover = any(o.ecrecover_staticcall_candidate for o in observations)

    reason_bits = []
    if has_dynamic:
        reason_bits.append("dynamic DOMAIN_SEPARATOR evidence observed: CHAINID + ADDRESS + SHA3 on a permit success path")
    if has_cached:
        reason_bits.append("cached/stale DOMAIN_SEPARATOR candidate observed: SLOAD-based success path without CHAINID/ADDRESS rebuild")
    if has_ecrecover:
        reason_bits.append("STATICCALL to ecrecover precompile candidate observed")
    if not reason_bits:
        reason_bits.append("permit success path found, but domain-construction evidence is inconclusive")

    return PermitDomainProbeReport(
        contract_address=contract_address,
        block_number=block_number,
        target_dir=target_dir,
        is_candidate=True,
        reason="; ".join(reason_bits),
        paths_found=len(observations),
        has_dynamic_domain_path=has_dynamic,
        has_cached_domain_candidate_path=has_cached,
        has_ecrecover_path=has_ecrecover,
        observations=observations,
        static_bytecode_hints=hints,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal GREED/Osprey symbolic probe for permit() DOMAIN_SEPARATOR paths.")
    parser.add_argument("--target-dir", required=True, help="GREED/Gigahorse target directory.")
    parser.add_argument("--contract-address", required=True, help="Contract address used as ADDRESS context.")
    parser.add_argument("--block-number", required=True, type=int, help="Block number context.")
    parser.add_argument("--max-paths", type=int, default=3, help="Maximum successful paths to collect.")
    parser.add_argument("--partial-concrete-storage", action="store_true", help="Use GREED partial concrete storage if your environment supports it.")
    parser.add_argument("--output", default=None, help="Optional JSON output file.")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        logging.getLogger("greed").setLevel(logging.DEBUG)
        logging.getLogger("osprey").setLevel(logging.DEBUG)

    report = check_permit_domain_paths(
        target_dir=args.target_dir,
        contract_address=args.contract_address,
        block_number=args.block_number,
        max_paths=args.max_paths,
        partial_concrete_storage=args.partial_concrete_storage,
    )

    data = asdict(report)
    text = json.dumps(data, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)

    print(text)


if __name__ == "__main__":
    main()
