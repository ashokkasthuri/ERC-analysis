import re

# Example CFG string (usually you would load this from a file or generate it)
cfg = r"""<SSAFunction name: hash:0xd505accf offset:0x5e2 num_blocks:11 blocks:<SSABasicBlock offset:0x5e2 num_insns:5 in: [] insns:[
        <0x5e9: %427 = CALLDATASIZE()>
        <0x5ea: %428 = SUB(%427, #4)>
        <0x5ee: %430 = LT(%428, #e0)>
        <0x5ef: %431 = ISZERO(%430)>
        <0x5f3: JUMPI(#5f8, %431)>
] fallthrough:0x5f4 jumps:[0x5f8]>
<SSABasicBlock offset:0x5f4 num_insns:1 in: [0x5e2] insns:[
        <0x5f7: REVERT(#0, #0)>
] fallthrough:None jumps:None>
<SSABasicBlock offset:0x5f8 num_insns:9 in: [0x5e2] insns:[
        <0x610: %435 = CALLDATALOAD(#4)    // ADDRESS>
        <0x618: %439 = CALLDATALOAD(#24)    // ADDRESS>
        <0x621: %443 = CALLDATALOAD(#44)>
        <0x627: %446 = CALLDATALOAD(#64)>
        <0x62f: %450 = CALLDATALOAD(#84)>
        <0x630: %451 = AND(%450, #ff)>
        <0x636: %454 = CALLDATALOAD(#a4)>
        <0x63b: %457 = CALLDATALOAD(#c4)>
        <0x63f: JUMP(#1b0c)>
] fallthrough:None jumps:[0x1b0c]>
<SSABasicBlock offset:0x1b0c num_insns:4 in: [0x5f8] insns:[
        <0x1b0d: %1587 = TIMESTAMP()>
        <0x1b0f: %1588 = LT(%446, %1587)>
        <0x1b10: %1589 = ISZERO(%1588)>
        <0x1b14: JUMPI(#1b7b, %1589)>
] fallthrough:0x1b15 jumps:[0x1b7b]>
<!-- Additional blocks omitted for brevity -->
<SSABasicBlock offset:0x1cdc num_insns:6 in: [0x1b7b] insns:[
        <0x1ce1: %1682 = MLOAD(#40)>
        <0x1d03: %1684 = ADD(#ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0, %1682)>
        <0x1d04: %1685 = MLOAD(%1684)    // ADDRESS>
        <0x1d1f: %1688 = ISZERO(%1685)>
        <0x1d21: %1689 = ISZERO(%1688)>
        <0x1d26: JUMPI(#1d57, %1688)>
] fallthrough:0x1d27 jumps:[0x1d57]>
<SSABasicBlock offset:0x1d27 num_insns:1 in: [0x1cdc] insns:[
        <0x1d56: %1695 = EQ(%1685, %435)>
] fallthrough:0x1d57 jumps:None>
<!-- ... -->
<SSABasicBlock offset:0x1d5c num_insns:12 in: [0x1d57] insns:[
        <0x1d5f: %1698 = MLOAD(#40)>
        <0x1d82: MSTORE(%1698, #8c379a000000000000000000000000000000000000000000000000000000000)>
        <0x1d88: %1702 = ADD(%1698, #4)>
        <0x1d89: MSTORE(%1702, #20)>
        <0x1d8f: %1705 = ADD(%1698, #24)>
        <0x1d90: MSTORE(%1705, #1c)>
        <0x1db5: %1708 = ADD(%1698, #44)>
        <0x1db6: MSTORE(%1708, #556e697377617056323a20494e56414c49445f5349474e415455524500000000)>
        <0x1db8: %1709 = MLOAD(#40)>
        <0x1dbc: %1710 = SUB(%1698, %1709)>
        <0x1dbf: %1712 = ADD(#64, %1710)>
        <0x1dc1: REVERT(%1709, %1712)>
]"""

class PermitAnalyse:
    @staticmethod
    def check_timestamp_require(cfg_text):
        """
        Check that the permit method performs a require check on the deadline against TIMESTAMP.
        We look for a TIMESTAMP instruction followed by a LT and then a JUMPI that uses the inverted result.
        """
        # Find all TIMESTAMP instructions
        ts_pattern = re.compile(r"<0x[\da-f]+:\s+%[\d]+ = TIMESTAMP\(\)>")
        ts_matches = list(ts_pattern.finditer(cfg_text))
        if not ts_matches:
            print("No TIMESTAMP instruction found!")
            return False

        # For each TIMESTAMP, try to find a subsequent LT and JUMPI that use its result.
        # In our CFG, after TIMESTAMP we expect:
        #    %1588 = LT(%446, %1587)
        #    %1589 = ISZERO(%1588)
        #    JUMPI(..., %1589)
        #
        # We use a simple pattern that spans across lines.
        require_pattern = re.compile(
            r"TIMESTAMP\(\)[^<]+?LT\([^,]+,\s*(%[\d]+)\)[^<]+?ISZERO\([^,]+\)[^<]+?JUMPI\([^,]+,\s*%[\d]+\)",
            re.DOTALL
        )
        if require_pattern.search(cfg_text):
            print("✅ Found require-style timestamp check (deadline vs. TIMESTAMP).")
            return True
        else:
            print("❌ Did not find the expected require check using TIMESTAMP.")
            return False

    @staticmethod
    def check_ecrecover_analysis(cfg_text):
        """
        Check that ecrecover is called with four arguments and its return value is compared against the owner.
        For our CFG, we assume that:
          - A STATICCALL with second argument '#1' corresponds to the ecrecover call.
          - The call's return value is later loaded and compared with the owner (here assumed to be %435).
        """
        # Find a STATICCALL instruction where the second parameter is "#1".
        staticcall_pattern = re.compile(
            r"<0x[\da-f]+:\s+%[\d]+ = STATICCALL\([^,]+,\s*#1,\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*([^,\)]+)\)"
        )
        staticcall_match = staticcall_pattern.search(cfg_text)
        if not staticcall_match:
            print("❌ No STATICCALL with second argument '#1' found. (ecrecover call not detected)")
            return False

        # If found, print the four arguments (for illustration purposes)
        arg1, arg2, arg3, arg4 = staticcall_match.groups()
        print("✅ Found ecrecover call (STATICCALL to address #1) with parameters:")
        print(f"    Arg1 (gas): {arg1.strip()}")
        print(f"    Arg2 (address): #1")
        print(f"    Arg3 (input offset & size): {arg2.strip()}, {arg3.strip()}")
        print(f"    Arg4 (output size): {arg4.strip()}")

        # --- Forward Data Analysis ---
        # In the CFG, after the STATICCALL the returned value is written to memory and then later loaded.
        # We look for a MLOAD that appears to retrieve the ecrecover output.
        mload_pattern = re.compile(r"MLOAD\(%[\d]+\)\s*//\s*ADDRESS")
        if mload_pattern.search(cfg_text):
            print("✅ Forward analysis: ecrecover return value is loaded from memory.")
        else:
            print("❌ Forward analysis: ecrecover return value load not found.")

        # --- Backward Data Analysis ---
        # Now check for an equality comparison (EQ) that compares the loaded address with the 'owner' value.
        # In our CFG, the owner is loaded early on as '%435 = CALLDATALOAD(#4)' and later we see an EQ.
        eq_pattern = re.compile(r"EQ\((%[\d]+),\s*(%435)\)")
        eq_match = eq_pattern.search(cfg_text)
        if eq_match:
            recovered_val = eq_match.group(1)
            print(f"✅ Backward analysis: The recovered address ({recovered_val}) is compared to the owner (%435).")
            return True
        else:
            print("❌ Backward analysis: No equality check found comparing recovered address and owner.")
            return False

    def runAnalysis(self):
        # --- Run the analyses ---
        print("Analyzing CFG for 'permit' method ...\n")

        # Task 1: Check for require (timestamp) check
        timestamp_check = self.check_timestamp_require(cfg)

        # Task 2: Check for ecrecover usage and data-flow verification
        ecrecover_check = self.check_ecrecover_analysis(cfg)

        if timestamp_check and ecrecover_check:
            print("\n✅ CFG analysis passed both tasks.")
        else:
            print("\n❌ CFG analysis did not pass all checks.")


if __name__ == '__main__':
    PermitAnalyse().runAnalysis()
