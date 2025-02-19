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
    import rattle  # Assumes rattle is installed and in the PYTHONPATH
    ssa = rattle.Recover(args.input.read(), edges=edges, optimize=args.optimize,
                         split_functions=args.no_split_functions)
    
    # Run the permit check analysis on all functions that match the permit signature.
    PermitMain(ssa)

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
    # static_block = function.blocks[staticcall_block_index:]
    # for static_block.insns in static_block:
    #     if insn.insn.name in ("EQ", "JUMPI"):
    #         for insn in static_block.fallthrough_edge.insns:
    #             if insn.insn.name in ("REVERT"):
    #                 print(f"block fallthrough_edge : {block.fallthrough_edge}")
    #                 # return True
        
    # Assume:
    # - staticcall_block_index: index of the block where STATICCALL was found.
    # - ecrecover_values: a set of values that propagate from the ecrecover call.
    for block in function.blocks[staticcall_block_index:]:
        # Get the fallthrough edge of the current block.
        ft_block = block.fallthrough_edge
        # print(f"Block at offset {block.offset:#x} fallthrough_edge: {ft_block}")

        # If there is a fallthrough block, check if it contains a REVERT opcode.
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
                # Depending on your policy you may want to return False or continue checking.
                # For example, you might:
                # return False

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

    # Step 1: Identify owner and deadline values from CALLDATALOAD instructions.
    for block in function.blocks:
        for insn in block.insns:
            if insn.insn.name == "CALLDATALOAD":
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

    # Step 2: Locate the STATICCALL (used for ecrecover) in the function blocks.
    for block in function.blocks:
        for insn in block.insns:
            if insn.insn.name == "STATICCALL" and len(insn.arguments) == 6 :
                
                # print(f"function hash : {function.hash}, {PERMIT_SIG_1}, {PERMIT_SIG_2}, {PERMIT_SIG_3}")
                if function.hash in (PERMIT_SIG_1, PERMIT_SIG_2, PERMIT_SIG_3):
                # if len(insn.arguments) >= 6:
                    second_arg = insn.arguments[1]
                    sixth_arg = insn.arguments[5]
                    try:
                        if int(second_arg) == 1 and int(sixth_arg) == 32:
                            ecrecover_return_value = insn.return_value
                            staticcall_block = block
                            print(f"[ecrecover] Found STATICCALL in block {block.offset:#x}")
                            break
                    except Exception:
                        ecrecover_return_value = insn.return_value
                        staticcall_block = block
                        print(f"[ecrecover] Found STATICCALL in block {block.offset:#x} (conversion failed)")
                        break
                else:
                    print(f"CUSTOM STATICCALL")
        if staticcall_block is not None:
            break

    # If no STATICCALL is found in the current blocks, try to follow jump branches.
    if staticcall_block is None:
        print("[ecrecover] STATICCALL not found in direct blocks; checking jump branches...")
        if check_jump_branches(function):
            print("[ecrecover] Permit checks found in jump branch. Analysis passed.")
            return True
        else:
            print("[ecrecover] No STATICCALL or valid jump branch with permit checks found!")
            return False

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


def PermitMain(ssa):
    """
    For each function in the recovered SSA, if the function’s signature matches one of the permit signatures,
    perform the comprehensive permit analysis.
    """
    for function in sorted(ssa.functions, key=lambda f: f.offset):
        
        if check_check_ecrecover_analysis(function):
                print(f"[+] Function {function.name} (offset {function.offset:#x}) satisfies permit checks.")
        else:
                print(f"[-] Function {function.name} (offset {function.offset:#x}) does not satisfy permit checks.")
        
        # if function.hash in (PERMIT_SIG_1, PERMIT_SIG_2, PERMIT_SIG_3):
            
            
        #     print(f"Match found for permit signature: {hex(function.hash)} in function {function.name}")
        #     if check_check_ecrecover_analysis(function):
        #         print(f"[+] Function {function.name} (offset {function.offset:#x}) satisfies permit checks.")
        #     else:
        #         print(f"[-] Function {function.name} (offset {function.offset:#x}) does not satisfy permit checks.")

            # # Generate the Control Flow Graph (CFG) for visualization
            # import rattle  # Assumes rattle includes a ControlFlowGraph class
            # g = rattle.ControlFlowGraph(function)
            # with tempfile.NamedTemporaryFile(suffix='.dot', mode='w', delete=False) as t:
            #     t.write(g.dot())
            #     t.flush()
            #     dot_file = t.name

            # os.makedirs('output', exist_ok=True)
            # base_name = "permit"
            # out_file = f'output/{base_name}.png'
            # counter = 1
            # while os.path.exists(out_file):
            #     out_file = f'output/{base_name}_{counter}.png'
            #     counter += 1

            # subprocess.call(['dot', '-Tpng', f'-o{out_file}', dot_file])
            # print(f"[+] Wrote CFG of {function.name} to {out_file}")

            # try:
            #     subprocess.call(['open', out_file])
            # except OSError as e:
            #     print(f"[-] Could not open {out_file}: {e}")

            # os.unlink(dot_file)


if __name__ == '__main__':
    main(sys.argv)
