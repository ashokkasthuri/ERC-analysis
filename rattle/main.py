#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
import re
import csv
import pandas as pd
from typing import Sequence, List, Tuple
import rattle  

# This might not be true, but I have a habit of running the wrong python version
# and this is to save me frustration.
assert (sys.version_info.major >= 3 and sys.version_info.minor >= 6)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Permit signature constants
PERMIT_SIG_1 = int("0xd505accf", 16)
PERMIT_SIG_2 = int("0x8fcbaf0c", 16)
PERMIT_SIG_3 = int("0x2a6a40e2", 16)
SAFE_TRANSFER = int("0xeb795549", 16)
SAFE_BATCH_TRANSFER_FROM = int("0x2eb2c2d6", 16)

TRANSFER = int("0xddf252ad", 16)
TRANSFER1 = int("0x850a6919", 16)
ONERC20RECIEVED = int("0x4fc35859", 16)

ON_TRANSFER_RECEIVED = int("0x88a7ca5c", 16)
# 0x30e0789e



def is_valid_bytecode(bytecode: str) -> bool:
    """Check if the bytecode is valid (hexadecimal and even length)."""
    return bool(re.match(r'^[0-9a-fA-F]*$', bytecode)) and len(bytecode) % 2 == 0


def main(argv: Sequence[str] = tuple(sys.argv)) -> None:
    sys.setrecursionlimit(20000)
    parser = argparse.ArgumentParser(
        description='Rattle Ethereum EVM binary analysis from CSV file'
    )
    
    parser.add_argument('--input', '-i', type=argparse.FileType('rb'), help='input evm file')
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

    orig_stdout = sys.stdout
    if args.stdout_to:
        sys.stdout = args.stdout_to

    # If a supplemental CFG file is provided, load the edges from it.
    edges = []
    if args.supplemental_cfg_file:
        edges = json.loads(args.supplemental_cfg_file.read())

    try:
        loglevel = getattr(logging, args.verbosity.upper())
    except AttributeError:
        loglevel = None
    logging.basicConfig(stream=args.log, level=loglevel)
    
    # Recover the SSA representation from the input bytecode (and optional CFG edges)
    
    ssa = rattle.Recover(args.input.read(), edges=edges, optimize=args.optimize,
                         split_functions=args.no_split_functions)
    # Run the permit check analysis on all functions that match the permit signature.
    PermitMain(ssa)
    # analyze_received_implementation(ssa)
    
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
    #             # PermitMain(ssa)
    #             # analyze_received_implementation(ssa)
    #         except Exception as e:
    #             logger.error(f"Error processing row {row_number}: {e}")
    
    

    if args.stdout_to:
        sys.stdout = orig_stdout
        args.stdout_to.close()

    if args.input:
        args.input.close()


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
                    if insn.return_value is not None:
                        stack.append(insn.return_value)
                    if insn.insn.name == "PHI":
                        for arg in insn.arguments:
                            stack.append(arg)

    return propagated_values


def forward_analysis(function, staticcall_block, ecrecover_return_value):
    """
    Perform forward analysis from the STATICCALL block to track the return value of ecrecover.
    Check if the return value (or its reassignments) is used in conditional checks (e.g., EQ, JUMPI).
    """
    ecrecover_values = track_variable_reassignments(function, ecrecover_return_value)
    staticcall_block_index = None
    for i, block in enumerate(function.blocks):
        if block == staticcall_block:
            staticcall_block_index = i
            break

    if staticcall_block_index is None:
        print("[Forward Analysis] STATICCALL block not found in function.blocks!")
        return False
    
    for block in function.blocks[staticcall_block_index:]:
        # Get the fallthrough edge of the current block.
        ft_block = block.fallthrough_edge
        
        if ft_block is not None:
            revert_found = False
            for ft_insn in ft_block.insns:
                # print(f"  In fallthrough block {ft_block.offset:#x}, found instruction: {ft_insn.insn.name}")
                if ft_insn.insn.name == "REVERT":
                    print(f"  [Check] Found REVERT in fallthrough block at offset {ft_block.offset:#x}")
                    revert_found = True
                    break  # Found the REVERT, no need to check further in this fallthrough.
            if not revert_found:
                print(f"  [Check] No REVERT found in the fallthrough branch of block {block.offset:#x}!")

        # Now check the instructions in the current block.
        for insn in block.insns:
            if insn.insn.name in ("EQ", "JUMPI"):
                print(f"Block at offset {block.offset:#x} contains {insn.insn.name}.")
                # Check the arguments of the instruction for any propagated ecrecover value.
                for arg in insn.arguments:
                    if arg in ecrecover_values:
                        if(insn.insn.name in ("JUMPI")) and revert_found:
                            print(f"REVERT found with JUMPI")
                        print(f"[Forward Analysis] Found {insn.insn.name} using ecrecover return value (or its reassignment) in block {block.offset:#x}")
                        # Optionally, return True if you consider this a complete match:
                        return True

    # If no matching block was found, return False.
    return False



def backward_analysis(function, staticcall_block, owner_value, deadline_value):
    """
    Perform backward analysis from the STATICCALL block to track the owner and deadline variables.
    Check if the owner (or its reassignments) is used in a nonce update (e.g., SSTORE for nonces[owner])
    and if the deadline (or its reassignments) is used in conditional checks.
    """
    owner_values = track_variable_reassignments(function, owner_value)
    deadline_values = track_variable_reassignments(function, deadline_value)

    nonce_update_found = False
    deadline_check_found = False

    for block in reversed(function.blocks[:staticcall_block.offset]):
        for insn in block.insns:
            if insn.insn.name == "SSTORE":
                for arg in insn.arguments:
                    if arg in owner_values:
                        print(f"[Backward Analysis] Found SSTORE using owner (or reassignment) in block {block.offset:#x}")
                        nonce_update_found = True
                        break

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
            if insn.insn.name in ("SHA3", "KECCAK256"):
                if len(insn.arguments) >= 3:  # Heuristic: expecting multiple arguments
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

    domain_separator_values = track_variable_reassignments(function, domain_separator_value)

    for block in function.blocks:
        for insn in block.insns:
            if insn.insn.name == "STATICCALL":
                for arg in insn.arguments:
                    if arg in domain_separator_values:
                        print(f"[DOMAIN_SEPARATOR] Found DOMAIN_SEPARATOR used in STATICCALL in block {block.offset:#x}")
                        return True
            if insn.insn.name in ("EQ", "JUMPI"):
                for arg in insn.arguments:
                    if arg in domain_separator_values:
                        print(f"[DOMAIN_SEPARATOR] Found DOMAIN_SEPARATOR used in conditional check in block {block.offset:#x}")
                        return True

    print("[DOMAIN_SEPARATOR] DOMAIN_SEPARATOR not used in ecrecover or conditional checks!")
    return False


def branch_contains_revert(block, visited=None) -> bool:
    """
    Recursively traverse from a given block (via its fallthrough and jump edges)
    to determine if a REVERT opcode appears in any reachable block.
    """
    if visited is None:
        visited = set()
    if block.offset in visited:
        return False
    visited.add(block.offset)
    for insn in block.insns:
        if insn.insn.name == "REVERT":
            return True
    # Check fallthrough edge
    if block.fallthrough_edge and branch_contains_revert(block.fallthrough_edge, visited):
        return True
    # Check jump edges
    for target in block.jump_edges:
        if branch_contains_revert(target, visited):
            return True
    return False


def check_jumppi_false_branch(function) -> bool:
    """
    For each block that contains a JUMPI (conditional jump), check that its false branch
    (assumed to be the fallthrough edge) eventually contains a REVERT opcode.
    """
    for block in function.blocks:
        for insn in block.insns:
            if insn.insn.name == "JUMPI":
                false_branch = block.fallthrough_edge
                if false_branch is None:
                    print(f"[JUMPI Check] Block {block.offset:#x} has JUMPI but no fallthrough edge!")
                    return False
                if not branch_contains_revert(false_branch):
                    print(f"[JUMPI Check] False branch of block {block.offset:#x} does not contain a REVERT!")
                    return False
    return True


def check_require_false_branch(function) -> bool:
    """
    Wrapper function (if needed) to ensure that at least one REVERT is present in a require-false branch.
    Here we rely on the jump-branch check.
    """
    return check_jumppi_false_branch(function)


def analyze_branch_for_permit(function, target_offset, visited=None) -> bool:
    """
    Recursively examine a branch starting at target_offset for permit-related operations.
    Avoid revisiting blocks via the visited set.
    """
    if visited is None:
        visited = set()

    for block in function.blocks:
        if block.offset == target_offset and block.offset not in visited:
            visited.add(block.offset)
            # Look for a STATICCALL in this block (as a proxy for an ecrecover call)
            for insn in block.insns:
                if insn.insn.name == "STATICCALL":
                    print(f"[Branch Analysis] Found STATICCALL in block {block.offset:#x}")
                    return True
            # If not found, follow any jumps from this block
            for insn in block.insns:
                if insn.insn.name in ("JUMP", "JUMPI"):
                    try:
                        new_target = int(insn.arguments[0])
                        if analyze_branch_for_permit(function, new_target, visited):
                            return True
                    except Exception:
                        continue
    return False


def check_jump_branches(function) -> bool:
    """
    Examine blocks with jump instructions. For each jump instruction, attempt to follow its branch target
    to see if permit-related operations appear (e.g. STATICCALL, nonce update, deadline check,
    DOMAIN_SEPARATOR usage). Also, check that false branches (require failure) contain REVERT opcodes.
    """
    for block in function.blocks:
        for insn in block.insns:
            if insn.insn.name in ("JUMP", "JUMPI"):
                try:
                    target_offset = int(insn.arguments[0])
                    if analyze_branch_for_permit(function, target_offset):
                        print(f"[Jump Branch] Permit checks found in branch starting at block {hex(target_offset)}")
                        return True
                except Exception:
                    continue
    print("[Jump Branch] No permit checks found in jump branches.")
    return False


def is_ecrecover_staticcall(function, staticcall_insn) -> bool:
    
    # The second parameter (index 1) is the target address.
    target = staticcall_insn.arguments[1]
    target1 = staticcall_insn.arguments[5]
    try:
        target_val = int(target)
        target_val1 = int(target1)
    except Exception:
        target_val = 0
        target_val1 = 0    
    
    if target_val == 1 and target_val1 == 32:
        print(f"staticcall_insn :  {staticcall_insn}")
        return True
    print(f"target and target1 : {target}, {target1}")
    
    # Track all possible values of the target through PHI nodes, etc.
    possible_values = track_variable_reassignments(function, target)
    
    # print(f"possible_values,  : {possible_values}")
    # print(f"staticcall_insn :  {staticcall_insn}")
    
    for val in possible_values:
        try:
            # Attempt to convert the value to an integer.
            # This assumes that literal values can be converted directly.
            numeric_val = int(val)
            numeric_val1 = int(target1)
            if numeric_val == 1 and numeric_val1 == 32:
                print(f"Staticcall target value {val} equals 1 (ecrecover call).")
                return True
        except Exception:
            # If conversion fails, skip this value.
            continue
    
    print("No possible target value equals 1; not an ecrecover call.")
    return False

def search_jump_blocks_for_staticcall(function, block, visited=None):
   
    if visited is None:
        visited = set()
    
    # Use block offset as unique identifier
    if block.offset in visited:
        return None
    visited.add(block.offset)
    
    # Check if current block contains a STATICCALL instruction.
    for insn in block.insns:
        if insn.insn.name == "STATICCALL":
            
            if is_ecrecover_staticcall(function, insn):
                print("This STATICCALL is likely an ecrecover call.")
            else:
                print("This STATICCALL does not appear to be an ecrecover call.")
            return block  # Found a block with STATICCALL.
            
    
    # Otherwise, iterate over jump edges.
    for jump_block in block.jump_edges:
        # Only add if the jump block has non-empty instructions.
        if jump_block.insns:
            # Add the jump block to the function if not already added.
            # function.add_block(jump_block)
            print(f"Added jump block: {jump_block}")
            
            result = search_jump_blocks_for_staticcall(jump_block, visited)
            if result is not None:
                return result  # Found a block with STATICCALL further down.
    
    return None  # No STATICCALL found along this branch.

def check_check_ecrecover_analysis(function) -> bool:
    """
    Check that the permit function calls ecrecover (via STATICCALL) and compares the recovered
    address with the owner. If no STATICCALL is directly found in the function blocks,
    follow jump branches to continue the analysis. Also verify that:
      - The ecrecover return value is used in conditional checks (forward analysis),
      - Owner and deadline values are used (backward analysis),
      - A REVERT opcode is present in the false branch of any require (JUMPI) condition,
      - DOMAIN_SEPARATOR is computed and used.
    """
    owner_value = None
    deadline_value = None
    ecrecover_return_value = None
    staticcall_block = None

    # Step 1: Locate the STATICCALL (used for ecrecover) in the function blocks.
    for block in function.blocks:  
        for insn in block.insns:
            if insn.insn.name == "STATICCALL" and len(insn.arguments) == 6 and is_ecrecover_staticcall(function, insn):
                # int(insn.arguments[1]) == 1 and int(insn.arguments[5]) == 32
                ecrecover_return_value = insn.return_value
                staticcall_block = block
                print(f"[ecrecover] Found STATICCALL in block {block.offset:#x}")
                break
        if staticcall_block is not None:
            break
    # Step 2: Identify owner and deadline values from CALLDATALOAD instructions.    
    for block in function.blocks:
        for insn in block.insns:
            if insn.insn.name == "CALLDATALOAD" and staticcall_block is not None:
                for arg in insn.arguments:
                    try:
                        # Heuristic: interpret literal arguments (adjust these values as needed)
                        literal_val = int(str(arg).lstrip("#"), 16)
                        print(f"Extracted literal: {literal_val} ({hex(literal_val)})")
                    except Exception:
                        continue
                    
                    if literal_val == 4:
                        owner_value = insn.return_value
                    elif literal_val == 100:
                        deadline_value = insn.return_value

    if owner_value is None or deadline_value is None:
        print("[ecrecover] Owner or deadline value not found!")
        return False
    
    
    # # If no STATICCALL is found in the current blocks, try to follow jump branches.
    # if staticcall_block is None:
    #     print("[ecrecover] STATICCALL not found in direct blocks; checking jump branches...")
    #     if check_jump_branches(function):
    #         print("[ecrecover] Permit checks found in jump branch. Analysis passed.")
    #         return True
    #     else:
    #         print("[ecrecover] No STATICCALL or valid jump branch with permit checks found!")
    #         return False

    # Step 3: Forward analysis to ensure the ecrecover return value is used in conditional checks.
    if not forward_analysis(function, staticcall_block, ecrecover_return_value):
        print("[ecrecover] Ecrecover return value not used in conditional checks!")
        return False

    # Step 4: Backward analysis to check that owner and deadline are used appropriately.
    nonce_update_found, deadline_check_found = backward_analysis(function, staticcall_block, owner_value, deadline_value)
    if not nonce_update_found:
        print("[ecrecover] Nonce update not found!")
        return False
    if not deadline_check_found:
        print("[ecrecover] Deadline check not found!")
        return False

    # Step 5: Check that each JUMPI false branch (require false case) eventually contains a REVERT.
    if not check_jumppi_false_branch(function):
        print("[ecrecover] One or more JUMPI false branches do not contain a REVERT!")
        return False

    # Step 6: Check DOMAIN_SEPARATOR usage.
    domain_separator_value = track_domain_separator(function)
    print(f"DOMAIN_SEPARATOR value: {domain_separator_value}")
    if not check_domain_separator_usage(function, domain_separator_value):
        print("[ecrecover] DOMAIN_SEPARATOR not used correctly!")
        return False

    print("[ecrecover] All checks passed: ecrecover call, nonce update, deadline check, and DOMAIN_SEPARATOR usage.")
    return True

def check_safe_transfer_analysis(function) -> bool:
    """
    Analyze the safeTransfer function in the given SSAFunction and verify that:
      1. It calls _transfer with exactly three parameters.
      2. If 'to' is a contract then there is a require (or conditional check)
         that calls onERC20Received (or tokenReceived) and compares its return value
         to the expected interface identifier.
    
    Returns True if both conditions are met, otherwise False.
    """
    transfer_call_found = False
    token_receiver_check_found = False

    # Iterate over each block in the function.
    for block in function.blocks:
        for insn in block.insns:
            # Check for _transfer call.
            if insn.insn.name == "_transfer":
                if len(insn.arguments) == 3:
                    print(f"Found _transfer call in block {block.offset:#x} with three parameters.")
                    transfer_call_found = True

            # Check for token receiver call: we look for onERC20Received or tokenReceived.
            if insn.insn.name in ("onERC20Received", "tokenReceived"):
                # Heuristic: we expect a require (or EQ/JUMPI) following this call that compares
                # its return value to an expected interface id.
                # Here we check in the same block for a subsequent instruction that uses the
                # return value of the token receiver call.
                if insn.return_value is None:
                    continue  # No return value to check.
                for later_insn in block.insns:
                    if later_insn.insn.name in ("EQ", "JUMPI", "REQUIRE"):
                        if insn.return_value in later_insn.arguments:
                            print(f"Found token receiver check in block {block.offset:#x} using {insn.insn.name}.")
                            token_receiver_check_found = True
                            break

    if not transfer_call_found:
        print("No _transfer call with three parameters found in safeTransfer function.")
    if not token_receiver_check_found:
        print("No token receiver check (onERC20Received/tokenReceived) found when 'to' is a contract.")
    
    return transfer_call_found and token_receiver_check_found


def SafeTransferMain(ssa):
    """
    Iterate over the SSA functions, and for any function named 'safeTransfer'
    run the safeTransfer analysis.
    """
    for function in ssa.functions:
        if function.name == "safeTransfer":
            print(f"Analyzing safeTransfer function {function.name} at offset {function.offset:#x}...")
            if check_safe_transfer_analysis(function):
                print(f"[+] Function {function.name} satisfies safeTransfer checks.")
            else:
                print(f"[-] Function {function.name} does not satisfy safeTransfer checks.")


def print_cfg(function):
    # Generate the Control Flow Graph (CFG) for visualization
    
    g = rattle.ControlFlowGraph(function)
    with tempfile.NamedTemporaryFile(suffix='.dot', mode='w', delete=False) as t:
        t.write(g.dot())
        t.flush()
        dot_file = t.name

    os.makedirs('output', exist_ok=True)
    base_name = "permit"
    out_file = f'output/{base_name}.png'
    counter = 1
    while os.path.exists(out_file):
        out_file = f'output/{base_name}_{counter}.png'
        counter += 1

    subprocess.call(['dot', '-Tpng', f'-o{out_file}', dot_file])
    print(f"[+] Wrote CFG of {function.name} to {out_file}")

    try:
        subprocess.call(['open', out_file])
    except OSError as e:
        print(f"[-] Could not open {out_file}: {e}")

    os.unlink(dot_file)

def trace_jump_chain(block, visited=None):
   
    if visited is None:
        visited = []
    if block in visited:
        return visited
    visited.append(block)
    if not block.jump_edges:
        return visited
    # For this example, follow the first jump edge.
    next_block = next(iter(block.jump_edges))
    return trace_jump_chain(next_block, visited)

def find_and_print_jump_chains(ssa, target_function):
   
    terminal_blocks = []
    length = len(target_function.blocks)
    block_with_valid_jumps = target_function.blocks[length-2]
    
    print(f"target_function block len : {length}")
    print(f"target_function block last : {block_with_valid_jumps}")
    
    chain = trace_jump_chain(block_with_valid_jumps)
    terminal_blocks.append(chain[-1])
    print(f"chain : {chain}")
    # for block in chain:
    #     target_function.add_block(block)
   
    

    # Finally, print the CFG for the target function.
    print_cfg(target_function)

# def PermitMain(ssa):
   
#     for function in sorted(ssa.functions, key=lambda f: f.offset):
        
#         # print_cfg(function)
        
#         # if check_check_ecrecover_analysis(function):
#         #         print(f"[+] Function {function.name} (offset {function.offset:#x}) satisfies permit checks.")
        
#         # if function.hash in (SAFE_TRANSFER, TRANSFER, TRANSFER1, ONERC20RECIEVED):
        
#         if function.hash == SAFE_BATCH_TRANSFER_FROM:
#             print(f"function.hash : {function.hash}")
#             # print(f"function.blockmap : {function.blockmap}")
#             print(f"function.blocks : {function.blocks}")
            
#             find_and_print_jump_chains(ssa, function)
#             print_cfg(function)
#         # if function.hash in (PERMIT_SIG_1, PERMIT_SIG_2, PERMIT_SIG_3):
#         #     # print_cfg(function)
#         #     print(f"Match found for permit signature: {hex(function.hash)} in function {function.name}")
#         #     matched_function = function
#         #     if check_check_ecrecover_analysis(matched_function):
#         #         print(f"[+] Function {function.name} (offset {function.offset:#x}) satisfies permit checks.")









# def verify_erc1155_bytecode(ssa):
#     # Find the function with the safeBatchTransferFrom selector
#     target = next((f for f in ssa.functions if f.hash == SAFE_BATCH_TRANSFER_FROM), None)
#     if target is None:
#         raise RuntimeError("safeBatchTransferFrom not found")

#     requirements = {
#         'sender_check': False,
#         'approval_check': False,
#         'zero_address_check': False,
#         'length_matching_check': False,
#         'transfer_batch_event_found': False,
#         'to_isContract_check': False,
#         'on_received_check': False,
#     }

#     # Use blockmap and trace_blocks to explore only the reachable CFG
#     entry_block = target.blockmap.get(target.offset)
#     if entry_block is None:
#         raise RuntimeError(f"Entry block at offset {target.offset:#x} not found")
#     reachable_blocks = target.trace_blocks(entry_block)

#     for block in reachable_blocks:
#         for insn in block.insns:
#             name = insn.insn.name

#             # Check for calls and extract the selector
#             if name in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):
#                 selector = None
#                 for arg in insn.arguments:
#                     if hasattr(arg, 'concrete_value'):
#                         selector = arg.concrete_value >> 224
#                         print(f"selector:{selector}")
#                         break
#                 if selector == IS_APPROVED_FOR_ALL:
#                     requirements['approval_check'] = True
#                 elif selector == ON_BATCH_RECEIVED:
#                     requirements['on_received_check'] = True

#             # Detect inlined Address.isContract via EXTCODESIZE
#             if name == 'EXTCODESIZE':
#                 requirements['to_isContract_check'] = True

#             # Detect the TransferBatch event emission (LOGx with event hash)
#             if name.startswith('LOG'):
#                 for arg in insn.arguments:
#                     if hasattr(arg, 'concrete_value') and arg.concrete_value == TRANSFER_BATCH_EVENT:
#                         requirements['transfer_batch_event_found'] = True

#             # TODO: deeper data-flow checks for sender_check, zero_address_check, length_matching_check

#     return requirements

# def PermitMain(ssa):
#     for func in sorted(ssa.functions, key=lambda f: f.offset):
#         if func.hash == SAFE_BATCH_TRANSFER_FROM:
#             result = verify_erc1155_bytecode(ssa)
#             print(json.dumps(result, indent=2))
#             break






# def verify_erc1155_bytecode(ssa):
#     # Find the safeBatchTransferFrom function by its selector/hash
#     entry_func = next((f for f in ssa.functions
#                        if f.hash == SAFE_BATCH_TRANSFER_FROM), None)
#     if entry_func is None:
#         raise RuntimeError("safeBatchTransferFrom not found")

#     # Prepare flags for each ERC‑1155 requirement
#     requirements = {
#         'sender_check': False,
#         'approval_check': False,
#         'zero_address_check': False,
#         'length_matching_check': False,
#         'transfer_batch_event_found': False,
#         'to_isContract_check': False,
#         'on_received_check': False,
#     }

#     # Worklist for functions (to follow internal calls)
#     todo = [entry_func]
#     seen_funcs = set()

#     while todo:
#         func = todo.pop()
#         if func.offset in seen_funcs:
#             continue
#         seen_funcs.add(func.offset)

#         # Trace reachable blocks from the entry point
#         entry_block = func.blockmap.get(func.offset)
        
#         # print(f"entry_block:{entry_block}")
#         if entry_block is None:
#             continue
#         blocks = func.trace_blocks(entry_block)
#         # print(f"entry_block_blocks:{blocks}")

#         # Map from SSA value -> role (from_param, to_param, ids_offset, amounts_offset, caller)
#         role_of_value = {}

#         for block in blocks:
#             for insn in block.insns:
#                 op = insn.insn.name

#                 # Parameter capture
#                 if op == 'CALLDATALOAD' and len(insn.arguments) == 1:
#                     arg0 = insn.arguments[0]
                    
#                     # print(f"DEBUG_arg0:{arg0.concrete_value}")
#                     # print(f"DEBUG_insn:{insn}")
                    
#                     # Resolve the argument to its concrete value (if possible)
#                     # arg0.resolve() returns (resolved_value, updated_flag)
#                     try:
#                         resolved_value, _ = arg0.resolve()
#                         print(f"DEBUG_resolved_value:{resolved_value}")
#                     except Exception:
#                         resolved_value = arg0  # fall back if resolve() raises
                        
#                     if hasattr(resolved_value, 'concrete_value'):
#                         off = resolved_value.concrete_value
#                         # off = arg0.concrete_value
#                         print(f"DEBUG_off:{off}")
#                         if off == 4:    # first 32 bytes after selector
#                             role_of_value[insn.return_value] = 'from'
#                         elif off == 36: # second param
#                             role_of_value[insn.return_value] = 'to'
#                         elif off == 68: # third param (ids offset)
#                             role_of_value[insn.return_value] = 'ids_offset'
#                         elif off == 100:# fourth param (amounts offset)
#                             role_of_value[insn.return_value] = 'amounts_offset'

#                 # Capture CALLER (msg.sender)
#                 elif op == 'CALLER':
#                     role_of_value[insn.return_value] = 'caller'

#         # Second pass: look for comparisons, calls, events, and reverts
#         for block in blocks:
#             for insn in block.insns:
#                 op = insn.insn.name

#                 # Internal calls (ICALL / ICONDCALL) to identify helpers and isApprovedForAll
#                 if op in ('ICALL', 'CONDICALL'):
#                     callee = insn.insn.target  # SSAFunction for the callee
#                     # Follow internal calls
#                     if callee and callee.offset not in seen_funcs:
#                         todo.append(callee)
#                     # Check if the callee is isApprovedForAll
#                     if callee and callee.hash == IS_APPROVED_FOR_ALL:
#                         requirements['approval_check'] = True

#                 # External call opcodes: look for selectors in constants
#                 if op in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):
#                     for arg in insn.arguments:
#                         if hasattr(arg, 'concrete_value'):
#                             val  = arg.concrete_value
#                             high = (val >> 224) & 0xffffffff
#                             low  = val & 0xffffffff
#                             if high == IS_APPROVED_FOR_ALL or low == IS_APPROVED_FOR_ALL:
#                                 requirements['approval_check'] = True
#                             if high == ON_BATCH_RECEIVED or low == ON_BATCH_RECEIVED:
#                                 requirements['on_received_check'] = True

#                 # EXTCODESIZE is used in Address.isContract
#                 if op == 'EXTCODESIZE':
#                     requirements['to_isContract_check'] = True

#                 # LOG opcodes for the TransferBatch event
#                 if op.startswith('LOG'):
#                     for arg in insn.arguments:
#                         if hasattr(arg, 'concrete_value') and arg.concrete_value == TRANSFER_BATCH_EVENT:
#                             requirements['transfer_batch_event_found'] = True

#                 # sender_check: look for EQ comparing caller and from
#                 if op == 'EQ':
#                     a, b = insn.arguments
#                     role_a = role_of_value.get(a)
#                     role_b = role_of_value.get(b)
#                     if ((role_a == 'caller' and role_b == 'from') or
#                         (role_a == 'from'   and role_b == 'caller')):
#                         requirements['sender_check'] = True

#                     # zero_address_check via EQ(to, 0)
#                     if ((role_a == 'to' and hasattr(b, 'concrete_value') and b.concrete_value == 0) or
#                         (role_b == 'to' and hasattr(a, 'concrete_value') and a.concrete_value == 0)):
#                         requirements['zero_address_check'] = True

#                 # zero_address_check via ISZERO(to)
#                 if op == 'ISZERO' and insn.arguments:
#                     arg = insn.arguments[0]
#                     if role_of_value.get(arg) == 'to':
#                         requirements['zero_address_check'] = True

#                 # length_matching_check: detect revert messages
#                 if op.startswith('PUSH') and insn.arguments:
#                     # Many constants (strings) are pushed onto the stack in 32‑byte chunks.
#                     # We compare the hex representation of the constant’s high 32 bytes
#                     # to our known segments.
#                     const = insn.insn.immediate if hasattr(insn.insn, 'immediate') else None
#                     if isinstance(const, int):
#                         hex_const = f"{const:064x}"
#                         if hex_const.startswith(REVERT_LEN_MISMATCH):
#                             requirements['length_matching_check'] = True
#                         elif hex_const.startswith(REVERT_ZERO_ADDRESS):
#                             requirements['zero_address_check'] = True
#                         elif hex_const.startswith(REVERT_CALLER_NOT_OWNER):
#                             # We consider this implies both sender check and approval check
#                             requirements['sender_check'] = True
#                             requirements['approval_check'] = True

#     return requirements

# def PermitMain(ssa):
#     for func in sorted(ssa.functions, key=lambda f: f.offset):
#         if func.hash == SAFE_BATCH_TRANSFER_FROM:
#             result = verify_erc1155_bytecode(ssa)
#             print(json.dumps(result, indent=2))
#             break




SAFE_BATCH_TRANSFER_FROM = 0x2eb2c2d6
IS_APPROVED_FOR_ALL      = 0xe985e9c5
ON_BATCH_RECEIVED        = 0xbc197c81

TRANSFER_BATCH_EVENT     = 0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb




# def verify_erc1155_bytecode(ssa):
#     target = next((f for f in ssa.functions if f.hash == SAFE_BATCH_TRANSFER_FROM), None)
#     if target is None:
#         raise RuntimeError("safeBatchTransferFrom not found")

#     requirements = {
#         'sender_check': False,
#         'approval_check': False,
#         'zero_address_check': False,
#         'length_matching_check': False,
#         'transfer_batch_event_found': False,
#         'to_isContract_check': False,
#         'on_received_check': False,
#     }

#     worklist = [target]
#     visited_funcs = set()

#     while worklist:
#         func = worklist.pop()
#         if func.offset in visited_funcs:
#             continue
#         visited_funcs.add(func.offset)

#         entry_block = func.blockmap.get(func.offset)
#         blocks = func.trace_blocks(entry_block) if entry_block else []

#         caller_vals   = set()
#         calldata_vals = set()

#         for block in blocks:
#             for insn in block.insns:
#                 op = insn.insn.name
#                 if op == 'CALLER':
#                     caller_vals.add(insn.return_value)
#                     print(f"DEBUG: CALLER return_value={insn.return_value}")
#                 if op == 'CALLDATALOAD' and len(insn.arguments) == 1:
#                     calldata_vals.add(insn.return_value)
#                     print(f"DEBUG: CALLDATALOAD return_value={insn.return_value} arg={insn.arguments[0]}")

#         for block in blocks:
#             for insn in block.insns:
#                 op = insn.insn.name

#                 # Internal calls
#                 if op in ('ICALL', 'CONDICALL'):
#                     callee = insn.insn.target
#                     print(f"DEBUG: internal call to {callee.desc()} offset={callee.offset:#x} hash={callee.hash:#x}")
#                     if callee and callee.offset not in visited_funcs:
#                         worklist.append(callee)
#                     if callee and callee.hash == IS_APPROVED_FOR_ALL:
#                         requirements['approval_check'] = True
#                         print("DEBUG: approval_check via internal call")

#                 # External calls
#                 if op in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):
#                     for arg in insn.arguments:
#                         if hasattr(arg, 'concrete_value'):
#                             val  = arg.concrete_value
#                             high = (val >> 224) & 0xffffffff
#                             low  = val & 0xffffffff
#                             if high == IS_APPROVED_FOR_ALL or low == IS_APPROVED_FOR_ALL:
#                                 requirements['approval_check'] = True
#                                 print(f"DEBUG: approval_check via selector {val:#x}")
#                             if high == ON_BATCH_RECEIVED or low == ON_BATCH_RECEIVED:
#                                 requirements['on_received_check'] = True
#                                 print(f"DEBUG: on_received_check via selector {val:#x}")

#                 # Address.isContract
#                 if op == 'EXTCODESIZE':
#                     requirements['to_isContract_check'] = True
#                     print(f"DEBUG: to_isContract_check via EXTCODESIZE at {insn.offset:#x}")

#                 # TransferBatch event
#                 if op.startswith('LOG'):
#                     for arg in insn.arguments:
#                         if hasattr(arg, 'concrete_value') and arg.concrete_value == TRANSFER_BATCH_EVENT:
#                             requirements['transfer_batch_event_found'] = True
#                             print(f"DEBUG: transfer_batch_event_found via LOG at {insn.offset:#x}")

#                 # Sender and zero‑address checks via comparisons
#                 if op == 'EQ' and len(insn.arguments) == 2:
#                     a, b = insn.arguments
#                     role_a = ("caller" if a in caller_vals else "calldata" if a in calldata_vals else "other")
#                     role_b = ("caller" if b in caller_vals else "calldata" if b in calldata_vals else "other")
#                     print(f"DEBUG: EQ at {insn.offset:#x} args roles=({role_a}, {role_b})")
#                     if ((a in caller_vals and b in calldata_vals) or
#                         (b in caller_vals and a in calldata_vals)):
#                         requirements['sender_check'] = True
#                         print("DEBUG: sender_check detected via EQ")
#                     if ((a in calldata_vals and hasattr(b, 'concrete_value') and b.concrete_value == 0) or
#                         (b in calldata_vals and hasattr(a, 'concrete_value') and a.concrete_value == 0)):
#                         requirements['zero_address_check'] = True
#                         print("DEBUG: zero_address_check detected via EQ(calldata,0)")

#                 if op == 'ISZERO' and len(insn.arguments) == 1:
#                     arg = insn.arguments[0]
#                     if arg in calldata_vals:
#                         requirements['zero_address_check'] = True
#                         print(f"DEBUG: zero_address_check via ISZERO at {insn.offset:#x}")

#                 # Revert strings: search for segments in any 32‑byte constant
#                 if op.startswith('PUSH') and hasattr(insn.insn, 'immediate'):
#                     const = insn.insn.immediate
#                     if isinstance(const, int):
#                         hex_const = f"{const:064x}"
#                         if (CALLER_NOT_OWNER_SEG1 in hex_const or CALLER_NOT_OWNER_SEG2 in hex_const):
#                             requirements['sender_check']   = True
#                             requirements['approval_check'] = True
#                             print(f"DEBUG: found caller-not-owner segment in {hex_const} at {insn.offset:#x}")
#                         if (ZERO_ADDRESS_SEG1 in hex_const or ZERO_ADDRESS_SEG2 in hex_const):
#                             requirements['zero_address_check'] = True
#                             print(f"DEBUG: found zero-address segment in {hex_const} at {insn.offset:#x}")
#                         if (LEN_MISMATCH_SEG1 in hex_const or LEN_MISMATCH_SEG2 in hex_const):
#                             requirements['length_matching_check'] = True
#                             print(f"DEBUG: found length-mismatch segment in {hex_const} at {insn.offset:#x}")

#     return requirements

# def PermitMain(ssa):
#     for func in sorted(ssa.functions, key=lambda f: f.offset):
#         if func.hash == SAFE_BATCH_TRANSFER_FROM:
#             result = verify_erc1155_bytecode(ssa)
#             print(json.dumps(result, indent=2))
#             break




# Revert string segments
CALLER_NOT_OWNER_SEG1 = "455243313135353a207472616e736665722063616c6c6572206973206e6f7420"
CALLER_NOT_OWNER_SEG2 = "6f776e6572206e6f7220617070726f766564"
ZERO_ADDRESS_SEG1     = "455243313135353a207472616e7366657220746f20746865207a65726f206164"
ZERO_ADDRESS_SEG2     = "6472657373"
LEN_MISMATCH_SEG1     = "455243313135353a2069647320616e6420616d6f756e7473206c656e67746820"
LEN_MISMATCH_SEG2     = "6d69736d61746368"

from .ssa import InternalCall, ConditionalInternalCall

def verify_erc1155_contract(ssa):
    requirements = {
        'sender_check': False,
        'approval_check': False,
        'zero_address_check': False,
        'length_matching_check': False,
        'transfer_batch_event_found': False,
        'to_isContract_check': False,
        'on_received_check': False,
    }

    for func in ssa.functions:
        print(f"DEBUG: scanning function {func.desc()} (offset {func.offset:#x})")
        entry_block = func.blockmap.get(func.offset)
        print(f"entry_block:{entry_block}")
        blocks = func.trace_blocks(entry_block) if entry_block else []

        caller_vals   = set()
        calldata_vals = set()

        # Collect CALLER and CALLDATALOAD
        for block in blocks:
            for insn in block.insns:
                if insn.insn.name == 'CALLER':
                    caller_vals.add(insn.return_value)
                if insn.insn.name == 'CALLDATALOAD' and len(insn.arguments) == 1:
                    calldata_vals.add(insn.return_value)

        for block in blocks:
            for insn in block.insns:
                name = insn.insn.name

                # Internal calls
                if isinstance(insn, (InternalCall, ConditionalInternalCall)):
                    callee = insn.target
                    if callee and callee.hash == IS_APPROVED_FOR_ALL:
                        if not requirements['approval_check']:
                            print(f"DEBUG: approval_check via internal call to {callee.desc()} in {func.desc()}")
                        requirements['approval_check'] = True
                    continue

                # External call selectors
                if name in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):
                    for arg in insn.arguments:
                        if hasattr(arg, 'concrete_value'):
                            val  = arg.concrete_value
                            high = (val >> 224) & 0xffffffff
                            low  = val & 0xffffffff
                            if high == IS_APPROVED_FOR_ALL or low == IS_APPROVED_FOR_ALL:
                                if not requirements['approval_check']:
                                    print(f"DEBUG: approval_check via external call constant {val:#x} in {func.desc()}")
                                requirements['approval_check'] = True
                            if high == ON_BATCH_RECEIVED or low == ON_BATCH_RECEIVED:
                                if not requirements['on_received_check']:
                                    print(f"DEBUG: on_received_check via selector {val:#x} in {func.desc()}")
                                requirements['on_received_check'] = True

                # to.isContract()
                if name == 'EXTCODESIZE':
                    if not requirements['to_isContract_check']:
                        print(f"DEBUG: to_isContract_check via EXTCODESIZE at {insn.offset:#x} in {func.desc()}")
                    requirements['to_isContract_check'] = True

                # TransferBatch event
                if name.startswith('LOG'):
                    for arg in insn.arguments:
                        if hasattr(arg, 'concrete_value') and arg.concrete_value == TRANSFER_BATCH_EVENT:
                            if not requirements['transfer_batch_event_found']:
                                print(f"DEBUG: transfer_batch_event_found via LOG at {insn.offset:#x} in {func.desc()}")
                            requirements['transfer_batch_event_found'] = True

                # sender and zero address checks
                if name == 'EQ' and len(insn.arguments) == 2:
                    a, b = insn.arguments
                    role_a = ("caller" if a in caller_vals else "calldata" if a in calldata_vals else "other")
                    role_b = ("caller" if b in caller_vals else "calldata" if b in calldata_vals else "other")
                    print(f"DEBUG: EQ at {insn.offset:#x} in {func.desc()} roles=({role_a},{role_b})")
                    if ((a in caller_vals and b in calldata_vals) or
                        (b in caller_vals and a in calldata_vals)):
                        if not requirements['sender_check']:
                            print(f"DEBUG: sender_check via EQ in {func.desc()} at {insn.offset:#x}")
                        requirements['sender_check'] = True
                    if ((a in calldata_vals and hasattr(b, 'concrete_value') and b.concrete_value == 0) or
                        (b in calldata_vals and hasattr(a, 'concrete_value') and a.concrete_value == 0)):
                        if not requirements['zero_address_check']:
                            print(f"DEBUG: zero_address_check via EQ(calldata,0) in {func.desc()} at {insn.offset:#x}")
                        requirements['zero_address_check'] = True

                if name == 'ISZERO' and len(insn.arguments) == 1:
                    arg = insn.arguments[0]
                    if arg in calldata_vals:
                        if not requirements['zero_address_check']:
                            print(f"DEBUG: zero_address_check via ISZERO in {func.desc()} at {insn.offset:#x}")
                        requirements['zero_address_check'] = True

                # Revert message segments
                if name.startswith('PUSH') and hasattr(insn.insn, 'immediate'):
                    const = insn.insn.immediate
                    if isinstance(const, int):
                        hex_const = f"{const:064x}"
                        if (CALLER_NOT_OWNER_SEG1 in hex_const or CALLER_NOT_OWNER_SEG2 in hex_const):
                            if not requirements['sender_check'] or not requirements['approval_check']:
                                print(f"DEBUG: found caller-not-owner message in const {hex_const} at {insn.offset:#x} in {func.desc()}")
                            requirements['sender_check']   = True
                            requirements['approval_check'] = True
                        if (ZERO_ADDRESS_SEG1 in hex_const or ZERO_ADDRESS_SEG2 in hex_const):
                            if not requirements['zero_address_check']:
                                print(f"DEBUG: found zero-address message in const {hex_const} at {insn.offset:#x} in {func.desc()}")
                            requirements['zero_address_check'] = True
                        if (LEN_MISMATCH_SEG1 in hex_const or LEN_MISMATCH_SEG2 in hex_const):
                            if not requirements['length_matching_check']:
                                print(f"DEBUG: found length-mismatch message in const {hex_const} at {insn.offset:#x} in {func.desc()}")
                            requirements['length_matching_check'] = True

    return requirements

def PermitMain(ssa):
    result = verify_erc1155_contract(ssa)
    print(json.dumps(result, indent=2))






def get_fallthrough_branch(block, insn):
    return block.fallthrough_edge

def contains_opcode(block, opcode):
    
    if block is None:
        return False
    for insn in block.insns:
        if insn.insn.name == opcode:
            return True
    return contains_opcode(block.fallthrough_edge, opcode)

def detect_onlycentralAccount(function) -> bool:
   
    for block in function.blocks:
        caller_insn = None
        sload_insn = None
        eq_found = False
        for insn in block.insns:
            if insn.insn.name == "CALLER":
                caller_insn = insn
            elif insn.insn.name == "SLOAD":
                sload_insn = insn
            elif insn.insn.name == "EQ":
                # Check if both caller and sload appear as arguments
                if caller_insn and sload_insn and (caller_insn in insn.arguments and sload_insn in insn.arguments):
                    eq_found = True
            elif insn.insn.name == "JUMPI" and eq_found:
                # Get the fallthrough branch (false branch)
                false_branch = get_fallthrough_branch(block, insn)
                if false_branch and contains_opcode(false_branch, "REVERT"):
                    print(f"[onlycentralAccount] Detected in function {function.name} at block {hex(block.offset)}")
                    return True
    return False

def detect_transfer(function) -> bool:
    for block in function.blocks:
        for insn in block.insns:
            # For our example, assume the event emission or call is labeled "Transfer"
            if insn.insn.name == "Transfer" and len(insn.arguments) == 3:
                print(f"[Transfer] Found Transfer pattern in block {hex(block.offset)}")
                return True
    return False

def detect_no_approval(function) -> bool:
    for block in function.blocks:
        for insn in block.insns:
            if "approve" in insn.insn.name.lower():
                print(f"[Approval] Found approval opcode '{insn.insn.name}' in block {hex(block.offset)}")
                return False
    return True

def check_zero_fee_transaction(function) -> bool:
    
    if not detect_onlycentralAccount(function):
        print(f"Function {function.name} missing onlycentralAccount check.")
        return False
    if not detect_transfer(function):
        print(f"Function {function.name} missing Transfer pattern.")
        return False
    if not detect_no_approval(function):
        print(f"Function {function.name} contains approval operation.")
        return False
    print(f"Function {function.name} passes all checks.")
    return True

# Example usage: iterate over all SSA functions in a recovered contract.
def analyze_contract(ssa):
    for function in ssa.functions:
        print(f"Analyzing function {function.name} (offset {hex(function.offset)})")
        if check_zero_fee_transaction(function):
            print(f"[+] Function {function.name} (hash {function.hash:#x}) appears to implement zero_fee_transaction.")
        else:
            print(f"[-] Function {function.name} does not match zero_fee_transaction pattern.")


def check_on_transfer_received_implementation(function):
    """
    Check if the function implements the onTransferReceived logic as required by ERC1363.
    """
    # Constants
    ERC1363_RECEIVED_SELECTOR = "0x88a7ca5c"  # Example selector for onTransferReceived

    # Track variables
    is_contract_check_found = False
    on_transfer_received_call_found = False
    return_value_check_found = False

    # Step 1: Identify the isContract check
    for block in function.blocks:
        for insn in block.insns:
            # Look for EXTCODESIZE or ISCONTRACT check
            if insn.insn.name == "EXTCODESIZE":
                is_contract_check_found = True
                print(f"[onTransferReceived] Found EXTCODESIZE check in block {block.offset:#x}")
                
                break
        if is_contract_check_found:
            break

    if not is_contract_check_found:
        print("[onTransferReceived] isContract check not found!")
        return False

    # Step 2: Identify the onTransferReceived call
    for block in function.blocks:
        for insn in block.insns:
            # Look for CALL or STATICCALL with the onTransferReceived selector
            if insn.insn.name in ("CALL", "STATICCALL"):
                if len(insn.arguments) >= 4:  # Ensure there are enough arguments
                    # Check if the selector matches onTransferReceived
                    selector = insn.arguments[3]  # Assuming selector is the 4th argument
                    if selector == ERC1363_RECEIVED_SELECTOR:
                        on_transfer_received_call_found = True
                        print(f"[onTransferReceived] Found onTransferReceived call in block {block.offset:#x}")
                        break
        if on_transfer_received_call_found:
            break

    if not on_transfer_received_call_found:
        print("[onTransferReceived] onTransferReceived call not found!")
        return False

    # Step 3: Check the return value comparison
    for block in function.blocks:
        for insn in block.insns:
            # Look for EQ or JUMPI to compare the return value
            if insn.insn.name in ("EQ", "JUMPI"):
                for arg in insn.arguments:
                    # Check if the argument is the return value of onTransferReceived
                    if arg == ERC1363_RECEIVED_SELECTOR:
                        return_value_check_found = True
                        print(f"[onTransferReceived] Found return value check in block {block.offset:#x}")
                        break
        if return_value_check_found:
            break

    if not return_value_check_found:
        print("[onTransferReceived] Return value check not found!")
        return False

    # Step 4: Verify that _msgSender(), from, value, and data are passed correctly
    # This is a heuristic and may need to be adjusted based on the specific implementation.
    # For simplicity, we assume that these parameters are passed in the correct order.
    print("[onTransferReceived] All checks passed: isContract check, onTransferReceived call, and return value check.")
    return True

def analyze_received_implementation(ssa):
    """
    Analyze all functions in the SSA representation to check for onTransferReceived implementation.
    """
    for function in sorted(ssa.functions, key=lambda f: f.offset):
        print_cfg(function)
        print(f"Analyzing function: {function.name} at offset {function.offset:#x}")
        if check_on_transfer_received_implementation(function):
            print(f"[+] Function {function.name} implements onTransferReceived correctly.")
        else:
            print(f"[-] Function {function.name} does not implement onTransferReceived correctly.")



if __name__ == '__main__':
    main(sys.argv)
