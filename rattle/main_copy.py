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
import pandas as pd
import csv

# This might not be true, but I have a habit of running the wrong python version and this is to save me frustration
assert (sys.version_info.major >= 3 and sys.version_info.minor >= 6)

logger = logging.getLogger(__name__)




PERMIT_SIG_1 = int("0xd505accf", 16)
PERMIT_SIG_2 = int("0x8fcbaf0c", 16)
PERMIT_SIG_3 = int("0x2a6a40e2", 16)

# def main(argv: Sequence[str] = tuple(sys.argv)) -> None:
#     parser = argparse.ArgumentParser(
#         description='Rattle Ethereum EVM binary analysis from CSV file'
#     )
#     parser.add_argument('--input', '-i', type=argparse.FileType('rb'), help='input evm file')
#     # parser.add_argument('--input', '-i', type=argparse.FileType('r'),
#     #                     help='Input CSV file with a "bytecode" column')
#     parser.add_argument('--optimize', '-O', action='store_true',
#                         help='Optimize resulting SSA form')
#     parser.add_argument('--no-split-functions', '-nsf', action='store_false',
#                         help='Do not split functions')
#     parser.add_argument('--log', type=argparse.FileType('w'), default=sys.stdout,
#                         help='Log output file (default stdout)')
#     parser.add_argument('--verbosity', '-v', type=str, default="None",
#                         help='Log output verbosity (None, Critical, Error, Warning, Info, Debug)')
#     parser.add_argument('--supplemental_cfg_file', type=argparse.FileType('r'), default=None,
#                         help='Optional supplemental CFG file')
#     parser.add_argument('--stdout_to', type=argparse.FileType('wt'), default=None,
#                         help='Redirect stdout to file')
#     args = parser.parse_args(argv[1:])

#     if args.input is None:
#         parser.print_usage()
#         sys.exit(1)

#     if args.stdout_to:
#         sys.stdout = args.stdout_to

#     edges = []
#     if args.supplemental_cfg_file:
#         edges = json.loads(args.supplemental_cfg_file.read())

#     try:
#         loglevel = getattr(logging, args.verbosity.upper())
#     except AttributeError:
#         loglevel = None
#     logging.basicConfig(stream=args.log, level=loglevel)
#     logger = logging.getLogger(__name__)
#     logger.info(f"Rattle running on input: {args.input.name}")
    
#     ssa = rattle.Recover(args.input.read(), edges=edges, optimize=args.optimize,
#                          split_functions=args.no_split_functions)


import csv
import re
import sys
import argparse
import logging
from typing import Sequence, List, Tuple

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_valid_bytecode(bytecode: str) -> bool:
    """Check if the bytecode is valid (hexadecimal and even length)."""
    return bool(re.match(r'^[0-9a-fA-F]*$', bytecode)) and len(bytecode) % 2 == 0

def main(argv: Sequence[str] = tuple(sys.argv)) -> None:
    
    sys.setrecursionlimit(20000)
    parser = argparse.ArgumentParser(
        description='Rattle Ethereum EVM binary analysis from CSV file'
    )
    
    parser.add_argument('--input', '-i', type=argparse.FileType('rb'), help='input evm file')
    
    # parser.add_argument('--input', '-i', type=argparse.FileType('r'),
    #                     help='Input CSV file with a "bytecode" column')
    parser.add_argument('--optimize', '-O', action='store_true',
                        help='Optimize resulting SSA form')
    parser.add_argument('--no-split-functions', '-nsf', action='store_false',
                        help='Do not split functions')
    parser.add_argument('--log', type=argparse.FileType('w'), default=sys.stdout,
                        help='Log output file (default stdout)')
    parser.add_argument('--verbosity', '-v', type=str, default="None",
                        help='Log output verbosity (None, Critical, Error, Warning, Info, Debug)')
    parser.add_argument('--supplemental_cfg_file', type=argparse.FileType('r'), default=None,
                        help='Optional supplemental CFG file')
    parser.add_argument('--stdout_to', type=argparse.FileType('wt'), default=None,
                        help='Redirect stdout to file')
    args = parser.parse_args(argv[1:])

    if args.input is None:
        parser.print_usage()
        sys.exit(1)

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
    
    ssa = rattle.Recover(args.input.read(), edges=edges, optimize=args.optimize,
                         split_functions=args.no_split_functions)
    PermitMain(ssa)

    # with args.input as csvfile:
    #     reader = csv.DictReader(csvfile)
    #     for row_number, row in enumerate(reader, start=1):
    #         if row_number > 10:
    #             break  # Stop after processing 10 rows

    #         if 'bytecode' not in row:
    #             logger.error(f"Row {row_number}: No 'bytecode' column found.")
    #             continue

    #         bytecode = row['bytecode']

    #         # Remove the "0x" prefix if it exists
    #         if bytecode.startswith('0x'):
    #             bytecode = bytecode[2:]

    #         # Validate bytecode
    #         if not is_valid_bytecode(bytecode):
    #             logger.error(f"Row {row_number}: Invalid bytecode format.")
    #             continue

    #         logger.info(f"Processing row {row_number}: Bytecode length = {len(bytecode)}")

    #         try:
    #             # Pass the bytecode to the Recover class
    #             ssa = rattle.Recover(bytecode.encode(), edges=edges, optimize=args.optimize,
    #                                  split_functions=args.no_split_functions)
    #             logger.info(f"Successfully processed row {row_number}")
    #             PermitMain(ssa)
    #         except Exception as e:
    #             logger.error(f"Error processing row {row_number}: {e}")

    if args.stdout_to:
        sys.stdout = orig_stdout
        args.stdout_to.close()

    if args.input:
        args.input.close()
    # for function in sorted(ssa.functions, key=lambda f: f.offset):
    #     print(f'\t{function.desc()} argument offsets:{function.arguments()}')

    # print("")

    # print("Storage Locations: " + repr(ssa.storage))
    # print("Memory Locations: " + repr(ssa.memory))

    # for location in [x for x in ssa.memory if x > 0x20]:
    #     print(f"Analyzing Memory Location: {location}\n")
    #     for insn in sorted(ssa.memory_at(location), key=lambda i: i.offset):
    #         print(f'\t{insn.offset:#x}: {insn}')
    #     print('\n\n')

    # for function in sorted(ssa.functions, key=lambda f: f.offset):
    #     print(f"Function {function.desc()} storage:")
    #     for location in function.storage:
    #         print(f"\tAnalyzing Storage Location: {location}")
    #         for insn in sorted(ssa.storage_at(location), key=lambda i: i.offset):
    #             print(f'\t\t{insn.offset:#x}: {insn}')
    #         print('\n')

    '''
    print("Tracing SLOAD(0) (ignoring ANDs)")
    for insn in ssa.storage_at(0):
        print(insn)
        if insn.insn.name == 'SLOAD':
            g = rattle.DefUseGraph(insn.return_value)
            print(g.dot(lambda x: x.insn.name in ('AND', )))
        print('\n')
    '''
def canSendEther(ssa):
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


def contractCalls(ssa):
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



def PermitMain(ssa):
    for function in sorted(ssa.functions, key=lambda f: f.offset):
        # Check if the function matches any of the permit signatures
        if function.hash in (PERMIT_SIG_1, PERMIT_SIG_2, PERMIT_SIG_3):
            # Generate the Control Flow Graph (CFG) for the function
            
            print(f"match found : {hex(function.hash)}")
            check_check_ecrecover_analysis(function)
            
            
            g = rattle.ControlFlowGraph(function)
            
            # Create a temporary DOT file for the CFG
            with tempfile.NamedTemporaryFile(suffix='.dot', mode='w', delete=False) as t:
                t.write(g.dot())
                t.flush()
                dot_file = t.name  # Save the temporary file path

            # Ensure the output directory exists
            os.makedirs('output', exist_ok=True)

           # Define the base output PNG file name using the function descriptor.
            base_name = "permit"
            out_file = f'output/{base_name}.png'
            counter = 1
            # If the file already exists, append a counter to avoid override.
            while os.path.exists(out_file):
                out_file = f'output/{base_name}_{counter}.png'
                counter += 1

            # Use Graphviz to generate the PNG file from the DOT file
            subprocess.call(['dot', '-Tpng', f'-o{out_file}', dot_file])
            print(f'[+] Wrote {function.name} to {out_file}')

            # Attempt to open the PNG file (macOS specific)
            try:
                subprocess.call(['open', out_file])
            except OSError as e:
                print(f"[-] Could not open {out_file}: {e}")

            # Clean up the temporary DOT file
            os.unlink(dot_file)
    
    
        
        

    
def check_permit_deadline(function):
    """
    Object-level check that the permit function correctly uses the deadline parameter.
    
    This function scans the SSA function blocks for CALLDATALOAD instructions.
    It assumes that literal values are stored as ConcreteStackValue objects such that:
    
      int(literal.lstrip("#"), 16) == 4    --> owner
      int(literal.lstrip("#"), 16) == 24   --> spender
      int(literal.lstrip("#"), 16) == 44   --> value
      int(literal.lstrip("#"), 16) == 64   --> deadline
      int(literal.lstrip("#"), 16) == 84   --> raw_v
      int(literal.lstrip("#"), 16) == 0xa4  --> r  (164)
      int(literal.lstrip("#"), 16) == 0xc4  --> s  (196)
    
    Once the deadline parameter is identified, it searches subsequent blocks for:
      - A TIMESTAMP instruction.
      - A comparison (LT, GT, SLT, or SGT) that uses the deadline value.
    
    Returns True if both are found, otherwise False.
    """
    permit_params = {}  # To store parameters by name.
    permit_block = None

    # Step 1: Find the block with the permit CALLDATALOAD instructions.
    for block in function.blocks:
        for insn in block.insns:
            if insn.insn.name == "CALLDATALOAD":
                # print(f"insn.arguments : {insn.arguments}")
                for arg in insn.arguments:
                    # Convert argument string (e.g., "#4", "#24", etc.) using base 16.
                    try:
                        if isinstance(arg, str):
                            literal_val = int(arg.lstrip("#"), 16)
                        else:
                            literal_val = int(str(arg).lstrip("#"), 16)

                        print(f"Extracted literal (decimal): {literal_val}, (hex): {hex(literal_val)}")
                    except Exception:
                        continue
                    
                    if literal_val == 4:
                        
                        permit_params["owner"] = insn.return_value
                    elif literal_val == 36:
                        
                        permit_params["spender"] = insn.return_value
                    elif literal_val == 68:
                        
                        permit_params["value"] = insn.return_value
                    elif literal_val == 100:
                        
                        permit_params["deadline"] = insn.return_value
                    elif literal_val == 132:
                        
                        permit_params["raw_v"] = insn.return_value
                    elif literal_val == 0xa4:  # 164 in decimal.
                        
                        permit_params["r"] = insn.return_value
                    elif literal_val == 0xc4:  # 196 in decimal.
                        
                        permit_params["s"] = insn.return_value
        print(f"permit_params :{permit_params}")
        if "deadline" in permit_params:
            permit_block = block
            # Printing the permit parameters using a dictionary comprehension for string conversion.
            print(f"[permit] Found permit block at offset {block.offset:#x}")
            print(f"[permit] Extracted permit parameters: { {key: str(permit_params[key]) for key in permit_params} }")
            break

    if permit_block is None:
        print("[permit] Permit block not found!")
        return False

    deadline_val = permit_params.get("deadline")
    if deadline_val is None:
        print("[permit] Deadline parameter not extracted!")
        return False

    # Step 2: Search for a TIMESTAMP instruction and a condition using the deadline.
    timestamp_found = False
    condition_found = False

    # We assume that later blocks (with higher offset) contain the check.
    for block in function.blocks:
        if block.offset <= permit_block.offset:
            continue
        for insn in block.insns:
            # Check for TIMESTAMP opcode.
            if insn.insn.name == "TIMESTAMP":
                timestamp_found = True
                print(f"[permit] Found TIMESTAMP in block {block.offset:#x}")
            # Check for a comparison (e.g. LT, GT, SLT, or SGT) that uses the deadline.
            if insn.insn.name in ("LT", "GT", "SLT", "SGT"):
                for arg in insn.arguments:
                    try:
                        if int(arg.lstrip("#"), 16) == int(deadline_val.lstrip("#"), 16):
                            condition_found = True
                            print(f"[permit] Found {insn.insn.name} condition using deadline in block {block.offset:#x}")
                            break
                    except Exception:
                        if arg == deadline_val:
                            condition_found = True
                            print(f"[permit] Found {insn.insn.name} condition using deadline in block {block.offset:#x}")
                            break
            if timestamp_found and condition_found:
                break
        if timestamp_found and condition_found:
            break

    if not (timestamp_found and condition_found):
        print("[permit] Deadline usage condition not found!")
        return False

    print("[permit] Deadline is correctly used in a require-like condition with TIMESTAMP.")
    return True

def check_permit_nonce_update_general(function, permit_owner):
    """
    Object-level check that nonces[owner]++ is implemented correctly.
    
    Instead of hardcoding memory offsets or literal immediate values, this function uses the
    data in the SSAInstruction.arguments directly.
    
    It searches for:
      1. An MSTORE instruction that writes the permit owner (i.e. one of its arguments equals permit_owner).
      2. A SHA3 instruction whose return_value is the computed storage key.
      3. An SLOAD instruction that loads the nonce using that computed key.
      4. An ADD instruction that increments the nonce (by adding 1).
      5. An SSTORE instruction that writes the incremented nonce back using the computed key.
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
            # (1) Look for an MSTORE that writes permit_owner.
            if candidate["mstore_owner"] is None and insn.insn.name == "MSTORE":
                for arg in insn.arguments:
                    # Compare object-level; if permit_owner is a ConcreteStackValue, you can compare directly.
                    if arg == permit_owner:
                        candidate["mstore_owner"] = (block.offset, idx)
                        print(f"[nonce] Found MSTORE writing owner in block {block.offset} index {idx}")
                        break
            # (2) Look for a SHA3 instruction; use its return_value as computed_key.
            if candidate["sha3"] is None and insn.insn.name == "SHA3":
                if insn.return_value is not None:
                    candidate["computed_key"] = insn.return_value
                    candidate["sha3"] = (block.offset, idx)
                    print(f"[nonce] Found SHA3 computing key in block {block.offset} index {idx}")
            # (3) Look for an SLOAD that uses computed_key.
            if candidate["sha3"] is not None and candidate["computed_key"] is not None and candidate["sload"] is None:
                if insn.insn.name == "SLOAD":
                    # Check if any argument equals candidate["computed_key"].
                    for arg in insn.arguments:
                        try:
                            if int(arg) == int(candidate["computed_key"]):
                                candidate["sload"] = (block.offset, idx)
                                if insn.return_value is not None:
                                    candidate["nonce_loaded"] = insn.return_value
                                print(f"[nonce] Found SLOAD loading nonce in block {block.offset} index {idx}")
                                break
                        except Exception:
                            if arg == candidate["computed_key"]:
                                candidate["sload"] = (block.offset, idx)
                                if insn.return_value is not None:
                                    candidate["nonce_loaded"] = insn.return_value
                                print(f"[nonce] Found SLOAD loading nonce in block {block.offset} index {idx}")
                                break
            # (4) Look for an ADD instruction that increments the nonce.
            if candidate["nonce_loaded"] is not None and candidate["add"] is None:
                if insn.insn.name == "ADD":
                    # Check that one argument equals nonce_loaded and another is literal 1.
                    if candidate["nonce_loaded"] in insn.arguments:
                        for arg in insn.arguments:
                            try:
                                if int(arg) == 1:
                                    candidate["nonce_new"] = insn.return_value
                                    candidate["add"] = (block.offset, idx)
                                    print(f"[nonce] Found ADD incrementing nonce in block {block.offset} index {idx}")
                                    break
                            except Exception:
                                continue
            # (5) Look for an SSTORE that writes the new nonce using computed_key.
            if candidate["nonce_new"] is not None and candidate["computed_key"] is not None and candidate["sstore"] is None:
                if insn.insn.name == "SSTORE":
                    found_key = False
                    found_nonce = False
                    for arg in insn.arguments:
                        try:
                            if int(arg) == int(candidate["computed_key"]):
                                found_key = True
                        except Exception:
                            if arg == candidate["computed_key"]:
                                found_key = True
                    for arg in insn.arguments:
                        try:
                            if int(arg) == int(candidate["nonce_new"]):
                                found_nonce = True
                        except Exception:
                            if arg == candidate["nonce_new"]:
                                found_nonce = True
                    if found_key and found_nonce:
                        candidate["sstore"] = (block.offset, idx)
                        print(f"[nonce] Found SSTORE storing new nonce in block {block.offset} index {idx}")
        if (candidate["mstore_owner"] is not None and candidate["sha3"] is not None and
            candidate["sload"] is not None and candidate["add"] is not None and
            candidate["sstore"] is not None):
            print("[nonce] Complete nonce update pattern found.")
            return True

    print("[nonce] Nonce update pattern not found.")
    return False

def track_variable_reassignments(function, start_value):
    """
    Track reassignments of a variable in the SSA representation.
    Returns a set of all values that the start_value can propagate to.
    """
    visited = set()
    stack = [start_value]
    propagated_values = set()

    while stack:
        current_value = stack.pop()
        if current_value in visited:
            continue
        visited.add(current_value)
        propagated_values.add(current_value)

        # Find all instructions where current_value is used as an argument
        for block in function.blocks:
            for insn in block.insns:
                if current_value in insn.arguments:
                    # If the instruction has a return value, add it to the stack
                    if insn.return_value is not None:
                        stack.append(insn.return_value)
                    # Handle PHI instructions (common in SSA)
                    if insn.insn.name == "PHI":
                        for arg in insn.arguments:
                            stack.append(arg)

    return propagated_values

def forward_analysis(function, staticcall_block, ecrecover_return_value):
    """
    Perform forward analysis from the STATICCALL block to track the return value of ecrecover.
    Check if the return value (or its reassignments) is used in conditional checks (e.g., EQ, JUMPI).
    """
    # Track all propagated values of the ecrecover return value
    ecrecover_values = track_variable_reassignments(function, ecrecover_return_value)

    # Find the index of the staticcall_block in the function.blocks list
    staticcall_block_index = None
    for i, block in enumerate(function.blocks):
        if block == staticcall_block:
            staticcall_block_index = i
            break

    if staticcall_block_index is None:
        print("[Forward Analysis] STATICCALL block not found in function.blocks!")
        return False

    # Iterate over blocks starting from the staticcall_block
    for block in function.blocks[staticcall_block_index:]:
        for insn in block.insns:
            # Check if the return value of ecrecover (or its reassignments) is used in a conditional check
            if insn.insn.name in ("EQ", "JUMPI"):
                for arg in insn.arguments:
                    if arg in ecrecover_values:
                        print(f"[Forward Analysis] Found {insn.insn.name} using ecrecover return value (or reassignment) in block {block.offset:#x}")
                        return True
    return False

def backward_analysis(function, staticcall_block, owner_value, deadline_value):
    """
    Perform backward analysis from the STATICCALL block to track the owner and deadline variables.
    Check if the owner (or its reassignments) is used in nonce[owner]++ and if the deadline (or its reassignments) is used in conditional checks.
    """
    # Track all propagated values of the owner and deadline
    owner_values = track_variable_reassignments(function, owner_value)
    deadline_values = track_variable_reassignments(function, deadline_value)

    nonce_update_found = False
    deadline_check_found = False

    for block in reversed(function.blocks[:staticcall_block.offset]):
        for insn in block.insns:
            # Check if the owner (or its reassignments) is used in nonce[owner]++
            if insn.insn.name == "SSTORE":
                for arg in insn.arguments:
                    if arg in owner_values:
                        print(f"[Backward Analysis] Found SSTORE using owner (or reassignment) in block {block.offset:#x}")
                        nonce_update_found = True
                        break

            # Check if the deadline (or its reassignments) is used in a conditional check
            if insn.insn.name in ("LT", "GT", "SLT", "SGT", "JUMPI"):
                for arg in insn.arguments:
                    if arg in deadline_values:
                        print(f"[Backward Analysis] Found {insn.insn.name} using deadline (or reassignment) in block {block.offset:#x}")
                        deadline_check_found = True
                        break

        if nonce_update_found and deadline_check_found:
            break

    return nonce_update_found, deadline_check_found


def track_domain_separator(function):
    """
    Track the DOMAIN_SEPARATOR in the function.
    Returns the DOMAIN_SEPARATOR value if found, otherwise None.
    """
    domain_separator_value = None
    

    for block in function.blocks:
        for insn in block.insns:
            # Look for SHA3 or KECCAK256 instructions (used to compute DOMAIN_SEPARATOR)
            
            if insn.insn.name in ("SHA3", "KECCAK256"):
                
                # Check if the arguments include known DOMAIN_SEPARATOR components
                # (e.g., chain ID, contract address, etc.)
                # This is a heuristic and may need to be adjusted based on the specific implementation.
                if len(insn.arguments) >= 3:  # Adjust based on expected arguments
                    domain_separator_value = insn.return_value
                    print(f"[DOMAIN_SEPARATOR] Found DOMAIN_SEPARATOR computation in block {block.offset:#x}")
                    break
        if domain_separator_value is not None:
            break

    return domain_separator_value

def check_domain_separator_usage(function, domain_separator_value):
    """
    Check if the DOMAIN_SEPARATOR is used in the permit function.
    """
    if domain_separator_value is None:
        print("[DOMAIN_SEPARATOR] DOMAIN_SEPARATOR not found!")
        return False

    # Track all propagated values of the DOMAIN_SEPARATOR
    domain_separator_values = track_variable_reassignments(function, domain_separator_value)

    # Check if the DOMAIN_SEPARATOR is used in the ecrecover call or in a conditional check
    for block in function.blocks:
        for insn in block.insns:
            # Check if the DOMAIN_SEPARATOR is used in the ecrecover call
            if insn.insn.name == "STATICCALL":
                for arg in insn.arguments:
                    if arg in domain_separator_values:
                        print(f"[DOMAIN_SEPARATOR] Found DOMAIN_SEPARATOR used in ecrecover call in block {block.offset:#x}")
                        return True

            # Check if the DOMAIN_SEPARATOR is used in a conditional check (e.g., EQ, JUMPI)
            if insn.insn.name in ("EQ", "JUMPI"):
                for arg in insn.arguments:
                    if arg in domain_separator_values:
                        print(f"[DOMAIN_SEPARATOR] Found DOMAIN_SEPARATOR used in conditional check in block {block.offset:#x}")
                        return True

    print("[DOMAIN_SEPARATOR] DOMAIN_SEPARATOR not used in ecrecover or conditional checks!")
    return False

def check_check_ecrecover_analysis(function):
    """
    Object-level check that the permit function calls ecrecover and compares the recovered
    address with the owner.
    """
    owner_value = None
    deadline_value = None
    ecrecover_return_value = None
    staticcall_block = None

    # Step 1: Find the owner and deadline values
    for block in function.blocks:
        for insn in block.insns:
            if insn.insn.name == "CALLDATALOAD":
                for arg in insn.arguments:
                    try:
                        if isinstance(arg, str):
                            literal_val = int(arg.lstrip("#"), 16)
                        else:
                            literal_val = int(str(arg).lstrip("#"), 16)
                        print(f"Extracted literal (decimal): {literal_val}, (hex): {hex(literal_val)}")
                    except Exception:
                        continue
                    
                    if literal_val == 4:
                        owner_value = insn.return_value
                    elif literal_val == 100:
                        deadline_value = insn.return_value

    if owner_value is None and deadline_value is None:
        print("[ecrecover] Owner or deadline value not found!")
        return False

    # Step 2: Locate the STATICCALL instruction (ecrecover)
    for block in function.blocks:
        for insn in block.insns:
            if insn.insn.name == "STATICCALL":
                if len(insn.arguments) >= 6:
                    second_arg = insn.arguments[1]
                    sixth_arg = insn.arguments[5]
                    try:
                        if int(second_arg) == 1 and int(sixth_arg) == 32:
                            ecrecover_return_value = insn.return_value
                            staticcall_block = block
                            print(f"[ecrecover] Found STATICCALL in block at offset :{second_arg}, {sixth_arg}, {block.offset:#x}")
                            break
                    except Exception:
                        ecrecover_return_value = insn.return_value
                        staticcall_block = block
                        print(f"[ecrecover] Found STATICCALL in block at offset {block.offset:#x} (conversion failed)")
                        break
        if staticcall_block is not None:
            break

    if staticcall_block is None:
        print("[ecrecover] STATICCALL not found!")
        return False

    # Step 3: Perform forward analysis to check ecrecover return value usage
    if not forward_analysis(function, staticcall_block, ecrecover_return_value):
        print("[ecrecover] Ecrecover return value not used in conditional checks!")
        return False

    # Step 4: Perform backward analysis to check owner and deadline usage
    nonce_update_found, deadline_check_found = backward_analysis(function, staticcall_block, owner_value, deadline_value)
    
    
    
    # Step 5: Check DOMAIN_SEPARATOR usage
    domain_separator_value = track_domain_separator(function)
    print(f"domain_separator_value : {domain_separator_value}")
    if not check_domain_separator_usage(function, domain_separator_value):
        print("[ecrecover] DOMAIN_SEPARATOR not used correctly!")
        return False
    
    if not nonce_update_found:
        print("[ecrecover] Nonce update not found!")
        return False
    if not deadline_check_found:
        print("[ecrecover] Deadline check not found!")
        return False
    

    print("[ecrecover] All checks passed: ecrecover, nonce update, deadline check, and DOMAIN_SEPARATOR usage.")
    return True
