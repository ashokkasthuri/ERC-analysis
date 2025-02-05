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




# Constants for function signatures
PERMIT_SIGNATURE = "0xd505accf"

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
        
        
        
        if function.hash == int(PERMIT_SIGNATURE, 16):  # Match permit() function
            print(f"match found : {function.hash}")
            # print(f"function.blocks : {function.blocks}")
            # print(f"function.arguments : {function.arguments}")
            # print(f"function.optimize : {function.optimize}")
            # print(f"function.trace_blocks : {function.trace_blocks}")
            
            check_require(function)
            check_ecrecover_analysis(function)


            
            
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
        
        
class DataFlowAnalyzer:
    def __init__(self, cfg):
        self.cfg = cfg
        self.recovered_address = None
        self.sink = None
        self.source = None

    def find_ecrecover_call(self):
        """Find the ecrecover call and track its return value."""
        for block in self.cfg:
            # print(f"block len : {block.size()}")
            for insn in block:
                # print(f"insn.insn.name : {insn.insn.name}")
                if insn.insn.name == "STATICCALL":  # ecrecover is typically called via STATICCALL
                    print(f"[INFO] ecrecover found at {insn.offset:#x}")
                    self.recovered_address = insn.return_value
                    
                    print(f"return_value : {insn.return_value}")
                    return True
        return False

    def forward_data_flow_analysis(self):
        """Check if the recovered address is validated properly using a require statement."""
        for block in self.cfg:
            for insn in block:
                if insn.insn.name == "EQ" and self.recovered_address in insn.arguments:
                    print(f"[INFO] Condition check found at {insn.offset:#x}")
                    self.sink = insn.return_value
                    return True
        return False

    def backward_data_flow_analysis(self):
        """Ensure the owner parameter is the original source."""
        for block in self.cfg:
            for insn in block:
                if insn.insn.name == "CALLDATALOAD" and self.sink in insn.return_value.readers():
                    print(f"[INFO] Owner parameter verified at {insn.offset:#x}")
                    self.source = insn.return_value
                    return True
        return False

    def perform_analysis(self):
        """Perform full data flow analysis on the permit function."""
        if not self.find_ecrecover_call():
            print("[ERROR] ecrecover call not found!")
            return False
        
        if not self.forward_data_flow_analysis():
            print("[ERROR] No proper verification of recovered address!")
            return False
        
        if not self.backward_data_flow_analysis():
            print("[ERROR] Permit owner parameter not verified!")
            return False
        
        print("[SUCCESS] Signature verification check passed!")
        return True

def check_require(function):
    """
    Check that the function's first "logical" block (or the following block)
    contains a require–like check. We look for:
       - A JUMPI instruction (implying a conditional check)
       - A REVERT instruction (the failure path)
    """
    if not function.blocks:
        print("Function has no blocks!")
        return False

    if len(function.blocks) < 2:
        print("Function does not have at least 2 blocks to check!")
        return False

    first_block = function.blocks[0]
    second_block = function.blocks[1]
    
    print(f"first_block : {first_block}")
    print(f"second_block : {second_block}")
    print(f"first_block.insns : {first_block.insns}")
    print(f"second_block.insns : {second_block.insns}")
    
    for insn in first_block.insns:
        print(f"JUMPI first_block.insns : {str(insn)}")
    
    # Cast each instruction to a string before checking.
    jumpi_found = any("JUMPI" in str(insn) for insn in first_block.insns)
    revert_found = any("REVERT" in str(insn) for insn in second_block.insns)

    print(f"[Require Check] First block: JUMPI found? {jumpi_found}, REVERT found? {revert_found}")
    return jumpi_found and revert_found

def check_ecrecover_analysis(function):
    """
    Check that the function contains an ecrecover call and that later the recovered
    address is compared with the owner.
    
    Specifically:
      - Look for a STATICCALL in any block (this corresponds to the ecrecover call).
      - Then, check that in a later block there is an MLOAD instruction (loading the address)
        and an EQ instruction comparing that value with %435.
    """
    ecrecover_found = False
    staticcall_block_index = None

    # Search through all blocks for the STATICCALL.
    for i, block in enumerate(function.blocks):
        for insn in block.insns:
            # Convert instruction to string in case it's not already.
            insn_str = str(insn)
            if "STATICCALL" in insn_str:
                ecrecover_found = True
                staticcall_block_index = i
                print(f"[ecrecover] Found STATICCALL in block {i}: {insn_str}")
                break
        if ecrecover_found:
            break

    if not ecrecover_found:
        print("[ecrecover] STATICCALL not found!")
        return False

    # After the block containing the STATICCALL, look for:
    #   - An MLOAD that loads the recovered address (we assume it contains the keyword 'ADDRESS')
    #   - An EQ instruction comparing the recovered address with '%435'
    mload_found = False
    eq_found = False
    for block in function.blocks[staticcall_block_index + 1:]:
        for insn in block.insns:
            insn_str = str(insn)
            if "MLOAD" in insn_str and "ADDRESS" in insn_str:
                mload_found = True
                print(f"[ecrecover] Found MLOAD for recovered address: {insn_str}")
            if "EQ(" in insn_str and "%435" in insn_str and "%1685" in insn_str:
                eq_found = True
                print(f"[ecrecover] Found EQ comparing recovered address to owner: {insn_str}")
        if mload_found and eq_found:
            break

    if not (mload_found and eq_found):
        print("[ecrecover] Missing MLOAD or EQ instruction after the ecrecover call!")
        return False

    return True
