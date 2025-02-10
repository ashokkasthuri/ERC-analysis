#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
from typing import Sequence

import rattle
import re

# This might not be true, but I have a habit of running the wrong python version and this is to save me frustration
assert (sys.version_info.major >= 3 and sys.version_info.minor >= 6)

logger = logging.getLogger(__name__)




PERMIT_SIG_1 = int("0xd505accf", 16)
PERMIT_SIG_2 = int("0x8fcbaf0c", 16)
PERMIT_SIG_3 = int("0x2a6a40e2", 16)


# Required functions and storage variables
REQUIRED_FUNCTIONS = {
    "DOMAIN_SEPARATOR": "0x3644e515",
    "PERMIT_TYPEHASH": "0x30adf81f",
    "ecrecover": "0x61f56f16",
    "nonces": "0x7ecebe00",
}

def has_required_functions(cfg, function):
    """Check if the permit function contains necessary components for verification."""
    found_functions = set()

    for block in cfg:
        for instruction in block:
            insn_name = instruction.insn.name if hasattr(instruction.insn, 'name') else None

            # Check for required function calls
            if insn_name in ("MLOAD", "SLOAD", "SHA3", "CALLDATALOAD"):
                # print(f"insn_name 1: {insn_name}")
                for arg in instruction.arguments:
                    arg_str = str(arg)
                    # print(f"arg_str : {arg_str}")
                    if any(func in arg_str for func in REQUIRED_FUNCTIONS.values()):
                        found_functions.add(arg_str)

    return set(REQUIRED_FUNCTIONS.values()).issubset(found_functions)

def perform_data_flow_analysis(cfg, function):
    """Perform forward and backward data flow analysis to verify security conditions."""
    sv_check = False
    deadline_check = False
    nonce_check = False

    timestamp_variable = None  # Variable to store block.timestamp tracking
    potential_deadline_var = None  # Track potential deadline variable

    for block in cfg:
        for instruction in block:
            insn_name = instruction.insn.name if hasattr(instruction.insn, 'name') else None

            # Track block.timestamp
            if insn_name == "TIMESTAMP":
                timestamp_variable = instruction.return_value
                print(f"[DEBUG] Found block.timestamp stored in {timestamp_variable}")

            # Identify Signature Verification (SVCheck)
            if insn_name == "STATICCALL":
                print(f"[DEBUG] Found STATICCALL at {instruction.offset:#x}")
                sv_check = True

            # Deadline Enforcement (require(deadline >= block.timestamp))
            if insn_name in ("LT", "ISZERO"):
                for arg in instruction.arguments:
                    if arg == timestamp_variable:
                        potential_deadline_var = instruction.arguments[0]
                        deadline_check = True
                        print(f"[DEBUG] Found deadline enforcement with variable {potential_deadline_var}")

            # Nonce Security (SLOAD/SSTORE for `nonces`)
            if insn_name in ("SLOAD", "SSTORE"):
                for arg in instruction.arguments:
                    if "nonces" in str(arg):
                        nonce_check = True
                        print(f"[DEBUG] Found nonce storage operation at {instruction.offset:#x}")

    return sv_check, deadline_check, nonce_check

def analyze_bytecode(ssa):
    """Analyze bytecode for the permit function and verify its security conditions."""
    for function in sorted(ssa.functions, key=lambda f: f.offset):
        if function.hash == int(PERMIT_SIGNATURE, 16):
            print("[MATCH] Found permit function!")

            cfg = rattle.ControlFlowGraph(function)
            
        
            analyzer = DataFlowAnalyzer(cfg)
            analyzer.perform_analysis()
            
            if has_required_functions(cfg, function):
                print("[+] Permit function contains all required security components.")

                sv_check, deadline_check, nonce_check = perform_data_flow_analysis(cfg, function)

                print(f"[RESULT] Signature Verification Check: {'✔' if sv_check else '✘'}")
                print(f"[RESULT] Deadline Enforcement: {'✔' if deadline_check else '✘'}")
                print(f"[RESULT] Nonce Security: {'✔' if nonce_check else '✘'}")

            else:
                print("[WARNING] Permit function is missing required components!")



def main(argv: Sequence[str] = tuple(sys.argv)) -> None:  # run me with python3, fool
    parser = argparse.ArgumentParser(
        description='rattle ethereum evm binary analysis')
    parser.add_argument('--input', '-i', type=argparse.FileType('rb'), help='input evm file')
    parser.add_argument('--optimize', '-O', action='store_true', help='optimize resulting SSA form')
    parser.add_argument('--no-split-functions', '-nsf', action='store_false', help='split functions')
    parser.add_argument('--log', type=argparse.FileType('w'), default=sys.stdout,
                        help='log output file (default stdout)')
    parser.add_argument('--verbosity', '-v', type=str, default="None",
                        help='log output verbosity (None,  Critical, Error, Warning, Info, Debug)')
    parser.add_argument('--supplemental_cfg_file', type=argparse.FileType('rb'), default=None, help='optional cfg file')
    parser.add_argument('--stdout_to', type=argparse.FileType('wt'), default=None, help='redirect stdout to file')
    args = parser.parse_args(argv[1:])

    if args.input is None:
        parser.print_usage()
        sys.exit(1)

    orig_stdout = sys.stdout
    if args.stdout_to:
        sys.stdout = args.stdout_to

    edges = []
    if args.supplemental_cfg_file:
        edges = json.loads(args.supplemental_cfg_file.read())

    try:
        loglevel = getattr(logging, args.verbosity.upper())
    except AttributeError:
        loglevel = None

    logging.basicConfig(stream=args.log, level=loglevel)
    logger.info(f"Rattle running on input: {args.input.name}")

    ssa = rattle.Recover(args.input.read(), edges=edges, optimize=args.optimize,
                         split_functions=args.no_split_functions)

    print(ssa)

    print("Identified Functions:")
    for function in sorted(ssa.functions, key=lambda f: f.offset):
        print(f'\t{function.desc()} argument offsets:{function.arguments()}')

    print("")

    print("Storage Locations: " + repr(ssa.storage))
    print("Memory Locations: " + repr(ssa.memory))

    for location in [x for x in ssa.memory if x > 0x20]:
        print(f"Analyzing Memory Location: {location}\n")
        for insn in sorted(ssa.memory_at(location), key=lambda i: i.offset):
            print(f'\t{insn.offset:#x}: {insn}')
        print('\n\n')

    for function in sorted(ssa.functions, key=lambda f: f.offset):
        print(f"Function {function.desc()} storage:")
        for location in function.storage:
            print(f"\tAnalyzing Storage Location: {location}")
            for insn in sorted(ssa.storage_at(location), key=lambda i: i.offset):
                print(f'\t\t{insn.offset:#x}: {insn}')
            print('\n')

    '''
    print("Tracing SLOAD(0) (ignoring ANDs)")
    for insn in ssa.storage_at(0):
        print(insn)
        if insn.insn.name == 'SLOAD':
            g = rattle.DefUseGraph(insn.return_value)
            print(g.dot(lambda x: x.insn.name in ('AND', )))
        print('\n')
    '''

    can_send, functions_that_can_send = ssa.can_send_ether()
    if can_send:
        print("[+] Contract can send ether from following functions:")
        for function in functions_that_can_send:
            print(f"\t- {function.desc()}")

            _, insns = function.can_send_ether()
            for insn in insns:

                print(f"\t\t{insn}")

                if insn.insn.name == 'SELFDESTRUCT':
                    address = insn.arguments[0]
                    print(f'\t\t\t{address.writer}')

                elif insn.insn.name == 'CALL':
                    address = insn.arguments[1]
                    value = insn.arguments[2]
                    print(f'\t\t\tTo:\t{address.writer}')

                    try:
                        if value.writer:
                            print(f'\t\t\tValue:\t{value.writer}')
                        else:
                            value_in_eth = int(value) * 1.0 / 10 ** 18
                            print(f'\t\t\tValue:\t{value} {value_in_eth}ETH')
                    except Exception as e:
                        print(e)

                print("")
    else:
        print("[+] Contract can not send ether.")

    print("[+] Contract calls:")
    for call in ssa.calls():
        print(f"\t{call}")
        if call.insn.name == 'DELEGATECALL':
            gas, to, in_offset, in_size, out_offset, out_size = call.arguments
            value = None
        else:
            gas, to, value, in_offset, in_size, out_offset, out_size = call.arguments

        print(f"\t\tGas: {gas}", end='')
        if gas.writer:
            print(f'\t\t\t{gas.writer}')
        else:
            print("\n", end='')

        print(f"\t\tTo: {to} ", end='')
        if to.writer:
            print(f'\t\t\t{to.writer}')
        else:
            print("\n", end='')

        if value:
            print(f"\t\tValue: {value}", end='')
            if value.writer:
                print(f'\t\t\t{value.writer}')
            else:
                print("\n", end='')

        print(f"\t\tIn Data Offset: {in_offset}", end='')
        if in_offset.writer:
            print(f'\t\t{in_offset.writer}')
        else:
            print("\n", end='')

        print(f"\t\tIn Data Size: {in_size}", end='')
        if in_size.writer:
            print(f'\t\t{in_size.writer}')
        else:
            print("\n", end='')

        print(f"\t\tOut Data Offset: {out_offset}", end='')
        if out_offset.writer:
            print(f'\t\t{out_offset.writer}')
        else:
            print("\n", end='')

        print(f"\t\tOut Data Size: {out_size}", end='')
        if out_size.writer:
            print(f'\t\t{out_size.writer}')
        else:
            print("\n", end='')

        print("")

    
    # analyze_bytecode(ssa)

    for function in sorted(ssa.functions, key=lambda f: f.offset):
        
        # check_ecrecover_analysis(function)
        # check_permit_deadline(function)
        
        if function.hash == PERMIT_SIG_1 or function.hash == PERMIT_SIG_2 or function.hash == PERMIT_SIG_3:
            
            
            # for block in function.blocks:
            #     if len(block.function) > 0:
            #         print(f"insn_str block_ function HI: {block.function} and {len(block.function)}")
                
            
            print(f"match found : {hex(function.hash)}")
            print(f"function.blocks : {function.blocks}")
            
            check_ecrecover_analysis(function)
            check_permit_deadline(function)
            
            
            
            # g = rattle.ControlFlowGraph(function)
            # t = tempfile.NamedTemporaryFile(suffix='.dot', mode='w')
            # t.write(g.dot())
            # t.flush()

            # try:
            #     os.makedirs('output')
            # except:
            #     pass

            # out_file = f'output/{function.desc()}.png'

            # subprocess.call(['dot', '-Tpng', f'-o{out_file}', t.name])
            # print(f'[+] Wrote {function.desc()} to {out_file}')

            # try:
            #     # This is mac specific
            #     subprocess.call(['open', out_file])
            # except OSError as e:
            #     pass
    
        
        # print(f'function arguments  {function.arguments}')
        # print(f'function name  {function.name}')
        # print(f'function desc  {function.desc}')
        # print(f'function phis  {function.phis}')
        # Check if the function description matches any in the required list
        # if function.desc() in required_function_descriptions.values():
        #     g = rattle.ControlFlowGraph(function)
        #     t = tempfile.NamedTemporaryFile(suffix='.dot', mode='w')
        #     t.write(g.dot())
        #     t.flush()
            
        #     print(f'print  {function.calls}')

        #     # Ensure the output directory exists
        #     os.makedirs('output', exist_ok=True)

        #     out_file = f'output/{function.desc()}.png'

        #     subprocess.call(['dot', '-Tpng', f'-o{out_file}', t.name])
        #     print(f'[+] Wrote {function.desc()} to {out_file}')
            
        #     try:
        #         # This is mac specific
        #         subprocess.call(['open', out_file])
        #     except OSError as e:
        #         pass

        

    # Maybe a way to query the current value of a storage location out of some api (can infra do that?)
    # print(loc0.value.top())
    # print(loc0.value.attx(012323213))

    if args.stdout_to:
        sys.stdout = orig_stdout
        args.stdout_to.close()

    if args.input:
        args.input.close()
        
def check_permit_deadline(function):
    """
    Check that the 'permit' function correctly uses the deadline parameter.
    
    Steps:
      1. Find the block where CALLDATALOAD is used to load the permit parameters.
         - Look for instructions containing the following markers:
           - "CALLDATALOAD(#4)"    -> owner
           - "CALLDATALOAD(#24)"   -> spender
           - "CALLDATALOAD(#44)"   -> value
           - "CALLDATALOAD(#64)"   -> deadline
           - "CALLDATALOAD(#84)"   -> raw value for v (or intermediate result)
           - "CALLDATALOAD(#a4)"   -> r
           - "CALLDATALOAD(#c4)"   -> s
      2. Extract the left-hand side variable from each instruction.
      3. Then, iterate over subsequent blocks looking for:
         - A TIMESTAMP() instruction.
         - A condition (e.g. LT) that uses the deadline variable.
         - A JUMPI that uses the result of that condition.
    """
    permit_params = {}  # To store parameters by name.
    permit_block = None

    # Step 1: Find the block with the permit CALLDATALOAD instructions.
    for block in function.blocks:
        for insn in block.insns:
            insn_str = str(insn)
            # Check for the owner parameter.
            if "CALLDATALOAD(#4)" in insn_str and "ADDRESS" in insn_str:
                parts = insn_str.split("=")
                if len(parts) > 1:
                    # Left-hand side variable (e.g. "%435")
                    permit_params["owner"] = parts[0].strip()
            elif "CALLDATALOAD(#24)" in insn_str and "ADDRESS" in insn_str:
                parts = insn_str.split("=")
                if len(parts) > 1:
                    permit_params["spender"] = parts[0].strip()
            elif "CALLDATALOAD(#44)" in insn_str:
                parts = insn_str.split("=")
                if len(parts) > 1:
                    permit_params["value"] = parts[0].strip()
            elif "CALLDATALOAD(#64)" in insn_str:
                parts = insn_str.split("=")
                if len(parts) > 1:
                    permit_params["deadline"] = parts[0].strip()
            elif "CALLDATALOAD(#84)" in insn_str:
                parts = insn_str.split("=")
                if len(parts) > 1:
                    permit_params["raw_v"] = parts[0].strip()
            elif "CALLDATALOAD(#a4)" in insn_str.lower():
                parts = insn_str.split("=")
                if len(parts) > 1:
                    permit_params["r"] = parts[0].strip()
            elif "CALLDATALOAD(#c4)" in insn_str.lower():
                parts = insn_str.split("=")
                if len(parts) > 1:
                    permit_params["s"] = parts[0].strip()
        # If we found at least the deadline parameter, consider this the permit block.
        if "deadline" in permit_params:
            permit_block = block
            print(f"[permit] Permit block found at offset {block.offset:#x}")
            print(f"[permit] Extracted permit parameters: {permit_params}")
            break

    if not permit_block:
        print("[permit] Permit block not found!")
        return False

    # Step 2: Get the deadline variable.
    deadline_var = permit_params.get("deadline")
    if not deadline_var:
        print("[permit] Deadline parameter not extracted!")
        return False

    # Step 3: Look in subsequent blocks for the TIMESTAMP and require condition using the deadline.
    timestamp_found = False
    condition_found = False
    for block in function.blocks:
        # (Optionally, restrict to blocks coming after the permit block.)
        if block.offset <= permit_block.offset:
            continue

        for insn in block.insns:
            insn_str = str(insn)
            if "TIMESTAMP()" in insn_str:
                timestamp_found = True
                print(f"[permit] Found TIMESTAMP in block {block.offset:#x}: {insn_str}")
            # Look for a condition (e.g. LT) that compares the deadline variable.
            if "LT(" or "GT("in insn_str and deadline_var in insn_str:
                condition_found = True
                print(f"[permit] Found LT condition using deadline {deadline_var} in block {block.offset:#x}: {insn_str}")
            # Optionally check the JUMPI that uses the condition.
            if "JUMPI(" in insn_str and deadline_var in insn_str:
                print(f"[permit] Found JUMPI referencing deadline {deadline_var} in block {block.offset:#x}: {insn_str}")

        if timestamp_found and condition_found:
            break

    if not (timestamp_found and condition_found):
        print("[permit] Deadline usage condition not found (either TIMESTAMP or LT condition missing)!")
        return False

    print("[permit] Deadline is correctly used in a require-like condition with TIMESTAMP.")
    return True

def check_ecrecover_analysis(function):
    """
    Check that the function contains an ecrecover call and that later the recovered
    address is compared with the owner.
    
    Updated Behavior:
      - Instead of using the raw CALLDATALOAD(#4) result, we now look for the AND instruction 
        that masks it (e.g. "%848 = AND(%846, %847)") and use its LHS (e.g. "%848") as the owner.
      - Then, look for a STATICCALL (the ecrecover call) in any block.
      - In blocks after that, search for an MLOAD (to capture the recovered address)
        and then an EQ instruction that compares the recovered value with our owner variable.
    """
    # Step 1: Extract the owner value from the block that loads the permit input.
    owner_value = None
    for block in function.blocks:
        for insn in block.insns:
            insn_str = str(insn)
            # Look for the CALLDATALOAD(#4) that loads the owner.
            if "CALLDATALOAD(#4)" in insn_str:
                # Example: "<0x8e4: %847 = CALLDATALOAD(#4)>"
                parts = insn_str.split("=")
                if len(parts) > 1:
                    raw_owner = parts[0].strip()  # e.g. "%847"
                    print(f"[ecrecover] Found raw owner load: {raw_owner}")
                    # Now, in the same block, look for the AND instruction that uses this raw owner.
                    for insn2 in block.insns:
                        insn2_str = str(insn2)
                        if "AND(" in insn2_str and raw_owner in insn2_str:
                            # Example: "<0x8e6: %848 = AND(%846, %847)>"
                            parts2 = insn2_str.split("=")
                            if len(parts2) > 1:
                                owner_value = parts2[0].strip()  # e.g. "%848"
                                print(f"[ecrecover] Owner value updated after masking: {owner_value}")
                                break
                    if owner_value is not None:
                        break
                    if owner_value is None:
                        owner_value = raw_owner
        if owner_value is not None:
            break

    if owner_value is None:
        print("[ecrecover] Owner value not found (no masked value from CALLDATALOAD(#4))!")
        return False

    # Step 2: Find the STATICCALL corresponding to the ecrecover call.
    ecrecover_found = False
    staticcall_block_index = None

    for i, block in enumerate(function.blocks):
        for insn in block.insns:
            insn_str = str(insn)
            if "STATICCALL" in insn_str:
                ecrecover_found = True
                staticcall_block_index = i
                print(f"[ecrecover] Found STATICCALL in block {i}: {insn_str}")
                
                check_permit_nonce_update_general(function, owner_value)
                break
        if ecrecover_found:
            break

    if not ecrecover_found:
        print("[ecrecover] STATICCALL for ecrecover not found!")
        return False

    # Step 3: After the STATICCALL block, look for:
    #   - An MLOAD instruction that loads the recovered address (indicated by 'ADDRESS')
    #   - An EQ instruction that compares the recovered address with our owner_value.
    recovered_value = None
    mload_found = False
    eq_found = False
    
    candidate_and_var = None
    and_found = False


    for block in function.blocks[staticcall_block_index + 1:]:
        for insn in block.insns:
            insn_str = str(insn)
            # if "MLOAD" in insn_str:
            #     # For example: "<...: %1685 = MLOAD(%1684)    // ADDRESS>"
            #     parts = insn_str.split("=")
            #     if len(parts) > 1:
            #         recovered_value = parts[0].strip()  # e.g. "%1685"
            #         mload_found = True
            #         print(f"[ecrecover] Found recovered address via MLOAD: {insn_str}")
            # Look for an AND instruction that uses permit_owner.
            if not and_found and "AND(" in insn_str:
                # If the owner variable appears in the operands, we treat it as our candidate.
                if owner_value in insn_str:
                    # Extract the LHS variable (the result) by splitting on "=".
                    parts = insn_str.split("=")
                    if len(parts) > 1:
                        candidate_and_var = parts[0].strip()
                        and_found = True
                        print(f"[owner eq pattern] Found AND using owner in block {block.offset:#x}: {insn_str}")
                        print(f"    Candidate result variable: {candidate_and_var}")
            # Now look for an EQ instruction that uses the candidate AND result.
            if and_found and candidate_and_var and "EQ(" in insn_str:
                if candidate_and_var in insn_str:
                    eq_found = True
                    print(f"[owner eq pattern] Found EQ using candidate variable in block {block.offset:#x}: {insn_str}")
                    return True
            if "EQ(" in insn_str:
                # Instead of hardcoding a variable like %435, now compare with our owner_value.
                if owner_value in insn_str:
                    eq_found = True
                    print(f"[ecrecover] Found EQ comparing owner ({owner_value}): {insn_str}")
        if eq_found:
            break

    if not eq_found:
        print("[ecrecover] Missing MLOAD or EQ instruction after the ecrecover call!")
        return False

    return True


def check_permit_nonce_update_general(function, permit_owner):
    """
    Verify that nonces[owner]++ is implemented correctly in a permit function.
    
    This updated function now uses the masked owner value (e.g. "%848") instead of the raw CALLDATALOAD result.
    
    The pattern is:
      1. An MSTORE instruction that writes the owner value (permit_owner) into memory.
      2. A SHA3 instruction that computes a storage key from that memory.
      3. An SLOAD that loads the current nonce using that key.
      4. An ADD instruction that increments the nonce.
      5. An SSTORE that writes back the incremented nonce.
    """
    candidate = {
        "mstore_owner": None,
        "sha3": None,
        "computed_key": None,
        "sload": None,
        "nonce_loaded": None,
        "add": None,
        "nonce_new": None,
        "sstore": None
    }

    blocks = sorted(function.blocks, key=lambda b: b.offset)
    
    for block in blocks:
        for idx, insn in enumerate(block.insns):
            insn_str = str(insn)
            # (1) Find MSTORE that writes the masked owner (permit_owner).
            if candidate["mstore_owner"] is None and "MSTORE(" in insn_str and permit_owner in insn_str:
                candidate["mstore_owner"] = (block.offset, idx)
                print(f"[nonce check] Found MSTORE writing owner at block {block.offset:#x} idx {idx}: {insn_str}")
            
            # (2) Find a SHA3 that computes the storage key.
            if candidate["sha3"] is None and "SHA3(" in insn_str:
                parts = insn_str.split("=")
                if len(parts) > 1:
                    candidate["computed_key"] = parts[0].strip()
                    candidate["sha3"] = (block.offset, idx)
                    print(f"[nonce check] Found SHA3 computing key at block {block.offset:#x} idx {idx}: {insn_str}")
            
            # (3) Find an SLOAD that uses the computed key.
            if candidate["sha3"] is not None and candidate["computed_key"] is not None and candidate["sload"] is None and "SLOAD(" in insn_str:
                if candidate["computed_key"] in insn_str:
                    parts = insn_str.split("=")
                    if len(parts) > 1:
                        candidate["nonce_loaded"] = parts[0].strip()
                        candidate["sload"] = (block.offset, idx)
                        print(f"[nonce check] Found SLOAD using computed key at block {block.offset:#x} idx {idx}: {insn_str}")
            
            # (4) Find an ADD that increments the loaded nonce by 1.
            if candidate["nonce_loaded"] is not None and candidate["add"] is None and "ADD(" in insn_str:
                if candidate["nonce_loaded"] in insn_str and ("#1" in insn_str or " 1)" in insn_str):
                    parts = insn_str.split("=")
                    if len(parts) > 1:
                        candidate["nonce_new"] = parts[0].strip()
                        candidate["add"] = (block.offset, idx)
                        print(f"[nonce check] Found ADD incrementing nonce at block {block.offset:#x} idx {idx}: {insn_str}")
            
            # (5) Find an SSTORE that writes the new nonce at the computed key.
            if candidate["nonce_new"] is not None and candidate["computed_key"] is not None and candidate["sstore"] is None:
                if "SSTORE(" in insn_str and candidate["computed_key"] in insn_str and candidate["nonce_new"] in insn_str:
                    candidate["sstore"] = (block.offset, idx)
                    print(f"[nonce check] Found SSTORE storing new nonce at block {block.offset:#x} idx {idx}: {insn_str}")
            
        if (candidate["mstore_owner"] is not None and candidate["sha3"] is not None and
            candidate["sload"] is not None and candidate["add"] is not None and
            candidate["sstore"] is not None):
            print("[nonce check] Complete nonce update pattern (nonces[owner]++) found.")
            return True

    print("[nonce check] Nonce update pattern not found in function.")
    return False
