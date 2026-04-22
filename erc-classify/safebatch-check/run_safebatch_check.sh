#!/usr/bin/env bash
###
 # @Author: ashokkasthuri ashokraj.kasthuri@gmail.com
 # @Date: 2025-09-23 17:08:25
 # @LastEditors: ashokkasthuri ashokraj.kasthuri@gmail.com
 # @LastEditTime: 2026-02-24 20:23:43
 # @FilePath: /ERC-analysis-master/erc-classify/safebatch-check/run_safebatch_check.sh
 # @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
### 
set -euo pipefail

#########################################
# EDIT THIS ONE VALUE (or export it before running)
ARCHIVE_RPC="${ARCHIVE_RPC:-https://eth-mainnet.alchemyapi.io/v2/ljX-nE-U9P0_qjChJSjVp4LDaQuMH_AD}"   # e.g. https://eth-mainnet.alchemyapi.io/v2/YOUR_ARCHIVE_KEY
#########################################


# === Fixed values from your CSV ===
TX_BLOCK=17068681
FORK_BLOCK=$((TX_BLOCK - 1))  # pre-tx state
TX_HASH="0xb2e88203a51f47f19ade10d8d8f346f4c3704944e36345e67cfae58e129a8dc7"

# ERC-1155 contract (the callee)
CONTRACT="0xab9aee8a32e4a0594dd908b2f9f29e3c126f5146"

# tx.from (the caller on-chain)
OPERATOR="0x63605e53d422c4f1ac0e01390ac59aaf84c44a51"

# decoded params
OWNER="0x7de8b9905d584b264602ab8b548ccc362bef9f82"      # _from

RECIPIENT="0x9fa7bb759641fcd37fe4ae41f725e0f653f2c726"  # _to
IDS='[1]'
AMOUNTS='[1]'

# Your exact calldata (input) from the CSV:
TXDATA="0x2eb2c2d60000000000000000000000007de8b9905d584b264602ab8b548ccc362bef9f820000000000000000000000009fa7bb759641fcd37fe4ae41f725e0f653f2c72600000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"

if [ "$ARCHIVE_RPC" = "REPLACE_ME" ]; then
  echo "❌ Please set ARCHIVE_RPC (export ARCHIVE_RPC=... or edit run_safebatch_check.sh)."
  exit 1
fi

echo "=== Config ==="
echo "ARCHIVE_RPC      : $ARCHIVE_RPC"
echo "TX_BLOCK         : $TX_BLOCK"
echo "FORK_BLOCK       : $FORK_BLOCK (pre-tx state)"
echo "TX_HASH          : $TX_HASH"
echo "CONTRACT         : $CONTRACT"
echo "OPERATOR (tx.from): $OPERATOR"
echo "OWNER (param _from): $OWNER"
echo "RECIPIENT (param _to): $RECIPIENT"
echo "IDS / AMOUNTS    : $IDS / $AMOUNTS"
echo

# 1) Start Anvil at pre-tx block
echo "▶ Starting Anvil fork at block $FORK_BLOCK ..."
anvil --fork-url "$ARCHIVE_RPC" --fork-block-number "$FORK_BLOCK" --chain-id 1 > anvil.log 2>&1 &
ANVIL_PID=$!
sleep 1
ANVIL_RPC="http://127.0.0.1:8545"
echo "Anvil RPC: $ANVIL_RPC (pid $ANVIL_PID). Logs -> anvil.log"

# Wait briefly for readiness
for i in {1..10}; do
  if curl -sS "$ANVIL_RPC" >/dev/null 2>&1; then break; fi
  sleep 0.3
done

# 2) Decode calldata (informational)
echo
echo "▶ Decoding calldata (safeBatchTransferFrom):"
if command -v cast >/dev/null 2>&1; then
  cast calldata "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)" "$TXDATA" --rpc-url "$ANVIL_RPC" || true
else
  echo "cast not found; skipping decode. (Install Foundry if needed.)"
fi

# 3) Check approval & balance
echo
echo "▶ Checking isApprovedForAll(owner, operator):"
cast call "$CONTRACT" "isApprovedForAll(address,address)(bool)" "$OWNER" "$OPERATOR" --rpc-url "$ANVIL_RPC" || true

echo
echo "▶ Checking balanceOf(owner, id=1):"
cast call "$CONTRACT" "balanceOf(address,uint256)(uint256)" "$OWNER" 1 --rpc-url "$ANVIL_RPC" || true

# 4) Run Node script for impersonation + callStatic + local tx
echo
echo "▶ Running Node test (impersonate -> callStatic -> attempt local tx)..."
node test_safebatch.js "$ANVIL_RPC" "$CONTRACT" "$OPERATOR" "$OWNER" "$RECIPIENT" "$IDS" "$AMOUNTS" "$TXDATA" || true

# 5) Stop Anvil
echo
echo "▶ Stopping Anvil (pid $ANVIL_PID)..."
kill "$ANVIL_PID" || true
echo "✅ Done. Check anvil.log for low-level RPC traces if needed."
