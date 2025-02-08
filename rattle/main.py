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
        
        if function.hash == PERMIT_SIG_1 or function.hash == PERMIT_SIG_2 or function.hash == PERMIT_SIG_3:
            
            
            for block in function.blocks:
                if len(block.function) > 0:
                    print(f"insn_str block_ function HI: {block.function} and {len(block.function)}")
                
            
            print(f"match found : {hex(function.hash)}")
            # print(f"function.blocks : {function.blocks}")
            
            check_ecrecover_analysis(function)
            check_permit_deadline(function)
            check_permit_nonce(function)
            
            
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

    Specifically:
      - Look for a STATICCALL in any block (this corresponds to the ecrecover call).
      - Verify that the STATICCALL instruction contains '#1' (or '0x01') and '#20' (or '0x20').
      - Extract the owner value from the permit input (e.g. from "CALLDATALOAD(#4)    // ADDRESS").
      - Extract the recovered address from the MLOAD (e.g. from "%1685 = MLOAD(%1684)    // ADDRESS").
      - Then, check that in a later block there is an EQ instruction comparing the recovered address with the owner.
    """
    # Step 1: Extract owner value from the block containing permit's first parameter.
    owner_value = None
    for block in function.blocks:
        for insn in block.insns:
            insn_str = str(insn)
            if "CALLDATALOAD(#4)" in insn_str in insn_str and "ADDRESS" in insn_str:
                # Example format: "<0x610: %435 = CALLDATALOAD(#4)    // ADDRESS>"
                
                print(f"insn_str : {insn_str}")
                parts = insn_str.split("=")
                print(f"parts : {parts}")
                if len(parts) > 1:
                    owner_value = parts[0].strip()
                    # Take the left-hand side of "="
                    # owner_value = rest.split("=")[0].strip()
                    # owner_value = rest
                    print(f"[ecrecover] Found owner value: {owner_value}")
                    break
        if owner_value is not None:
            break

    if owner_value is None:
        print("[ecrecover] Owner value not found!")
        return False

    # Step 2: Find the STATICCALL that corresponds to the ecrecover call.
    ecrecover_found = False
    staticcall_block_index = None

    for i, block in enumerate(function.blocks):
        for insn in block.insns:
            insn_str = str(insn)
            if "STATICCALL" in insn_str:
                # Find the first occurrence of '(' and the corresponding ')'
                start_index = insn_str.find('(')
                end_index = insn_str.find(')', start_index)
                if start_index != -1 and end_index != -1:
                    # Extract the arguments string, then split by commas and strip whitespace
                    args_str = insn_str[start_index+1:end_index]
                    args = [arg.strip() for arg in args_str.split(',')]
                    # Verify that we have exactly 6 arguments
                    if len(args) == 6:
                        print(f"len(args): {len(args)}")
                        second_arg = args[1]
                        sixth_arg = args[5]
                        
                        print(f"second_arg, sixth_arg: {second_arg, sixth_arg}")
                        # Check that the second argument is "#1" or "0x01"
                        # and that the sixth argument is "#20" or "0x20"
                        if (second_arg in ("#1", "0x01")) and (sixth_arg in ("#20", "0x20")):
                            ecrecover_found = True
                            staticcall_block_index = i
                            print(f"[ecrecover] Found STATICCALL in block {i}: {insn_str}")
                        else:
                            print(f"[ecrecover] STATICCALL found in block {i}, but arguments do not match: second_arg = {second_arg}, sixth_arg = {sixth_arg}")
                    else:
                        print(f"[ecrecover] STATICCALL found but expected 6 arguments, got {len(args)}: {args}")
        if ecrecover_found:
            break

    if not ecrecover_found:
        print("[ecrecover] STATICCALL for ecrecover not found!")
        return False

    # Step 3: After the STATICCALL block, look for an MLOAD instruction to capture the recovered address,
    # and then an EQ instruction that compares the recovered value with the owner.
    recovered_value = None
    mload_found = False
    eq_found = False

    for block in function.blocks[staticcall_block_index + 1:]:
        for insn in block.insns:
            insn_str = str(insn)
            if "MLOAD" in insn_str and "ADDRESS" in insn_str:
                # Example format: "<0xXXX: %1685 = MLOAD(%1684)    // ADDRESS>"
                parts = insn_str.split("=")
                print(f"parts : {parts}")
                if len(parts) > 1:
                    rest = parts[0].strip()
                    recovered_value = rest
                    print(f"recovered_value : {recovered_value}")
                    mload_found = True
                    print(f"[ecrecover] Found recovered address via MLOAD: {insn_str}")
            if "EQ(" in insn_str:
                # Instead of hardcoding, check that the EQ instruction contains both the owner and recovered variables.
                if owner_value in insn_str and recovered_value in insn_str:
                    eq_found = True
                    print(f"[ecrecover] Found EQ comparing recovered address to owner: {insn_str}")
        if mload_found and eq_found:
            break

    if not (mload_found and eq_found):
        print("[ecrecover] Missing MLOAD or EQ instruction after the ecrecover call!")
        return False

    return True


def check_permit_nonce(function):
    """
    Check that the nonce is correctly incremented in the permit function.
    
    We look for a pattern in one of the blocks similar to:
       - An SLOAD that loads the current nonce.
         Example: "<...: %1608 = SLOAD(#3)>"
       - An ADD that adds #1 to the loaded nonce.
         Example: "<...: %1618 = ADD(%1616, #1)>"
       - An SSTORE that stores the incremented nonce.
         Example: "<...: %1611 = SSTORE(%1615, %1618)>"
    
    The function returns True if such a pattern is found; otherwise, it returns False.
    """
    nonce_loaded = None
    nonce_load_block = None
    nonce_increment = None
    nonce_increment_block = None
    nonce_stored_found = False

    # Step 1: Find the SLOAD instruction for the nonce.
    for block in function.blocks:
        for insn in block.insns:
            insn_str = str(insn)
            # Look for SLOAD with a known slot (e.g., "#3")
            if "SLOAD" in insn_str and "#3" in insn_str:
                parts = insn_str.split("=")
                if len(parts) > 1:
                    nonce_loaded = parts[0].strip()  # e.g., "%1608"
                    nonce_load_block = block
                    print(f"[permit nonce] Found nonce load: {insn_str} => {nonce_loaded}")
                    break
        if nonce_loaded:
            break

    if not nonce_loaded:
        print("[permit nonce] Nonce SLOAD not found!")
        return False

    # Step 2: Look for an ADD instruction that adds "#1" to the loaded nonce.
    # We expect the loaded nonce variable to appear in the ADD operation.
    for block in function.blocks:
        # Optionally, only check blocks after the nonce load block.
        if block.offset < nonce_load_block.offset:
            continue
        for insn in block.insns:
            insn_str = str(insn)
            if "ADD(" in insn_str and "#1" in insn_str and nonce_loaded in insn_str:
                parts = insn_str.split("=")
                if len(parts) > 1:
                    nonce_increment = parts[0].strip()  # e.g., "%1618"
                    nonce_increment_block = block
                    print(f"[permit nonce] Found nonce increment: {insn_str} => {nonce_increment}")
                    break
        if nonce_increment:
            break

    if not nonce_increment:
        print("[permit nonce] Nonce increment (ADD) not found!")
        return False

    # Step 3: Look for an SSTORE instruction that stores the incremented nonce.
    for block in function.blocks:
        if block.offset < nonce_increment_block.offset:
            continue
        for insn in block.insns:
            insn_str = str(insn)
            if "SSTORE(" in insn_str and nonce_increment in insn_str:
                print(f"[permit nonce] Found SSTORE using nonce increment: {insn_str}")
                nonce_stored_found = True
                break
        if nonce_stored_found:
            break

    if not nonce_stored_found:
        print("[permit nonce] Nonce SSTORE not found!")
        return False

    print("[permit nonce] Nonce increment (nonces[owner]++) is implemented correctly.")
    return True
