const { ethers } = require("ethers");

async function main() {
  if (process.argv.length < 10) {
    console.error("Usage: node test_safebatch.js <ANVIL_RPC> <CONTRACT> <OPERATOR> <OWNER> <RECIPIENT> <IDS_JSON> <AMOUNTS_JSON> <TXDATA>");
    process.exit(1);
  }
  const [
    , , ANVIL_RPC, CONTRACT, OPERATOR, OWNER, RECIPIENT, IDS_ARG, AMOUNTS_ARG, TXDATA
  ] = process.argv;

  const IDS = JSON.parse(IDS_ARG);
  const AMOUNTS = JSON.parse(AMOUNTS_ARG);

  const provider = new ethers.providers.JsonRpcProvider(ANVIL_RPC);

  console.log("RPC       :", ANVIL_RPC);
  console.log("CONTRACT  :", CONTRACT);
  console.log("OPERATOR  :", OPERATOR, "(impersonated)");
  console.log("OWNER     :", OWNER);
  console.log("RECIPIENT :", RECIPIENT);
  console.log("IDS       :", IDS);
  console.log("AMOUNTS   :", AMOUNTS);

  // Impersonate operator and fund with 10 ETH
  await provider.send("anvil_impersonateAccount", [OPERATOR]);
  await provider.send("anvil_setBalance", [OPERATOR, "0x8ac7230489e80000"]); // 10 ETH
  const signer = provider.getSigner(OPERATOR);

  const abi = [
    "function isApprovedForAll(address,address) view returns (bool)",
    "function balanceOf(address,uint256) view returns (uint256)",
    "function safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)"
  ];
  const contract = new ethers.Contract(CONTRACT, abi, signer);

  try {
    const approved = await contract.isApprovedForAll(OWNER, OPERATOR);
    console.log("isApprovedForAll(owner, operator):", approved);
  } catch (e) {
    console.error("isApprovedForAll failed:", e.message || e);
  }

  try {
    const bal = await contract.balanceOf(OWNER, IDS[0]);
    console.log(`balanceOf(owner, id=${IDS[0]}):`, bal.toString());
  } catch (e) {
    console.error("balanceOf failed:", e.message || e);
  }

  console.log("\n→ callStatic (eth_call) of safeBatchTransferFrom ...");
  try {
    await contract.callStatic.safeBatchTransferFrom(OWNER, RECIPIENT, IDS, AMOUNTS, "0x");
    console.log("callStatic: WOULD succeed (no revert).");
  } catch (err) {
    console.error("callStatic reverted:", err.error?.message || err.reason || err.message || err);
  }

  console.log("\n→ Attempting local transaction (on fork) ...");
  try {
    const tx = await contract.safeBatchTransferFrom(OWNER, RECIPIENT, IDS, AMOUNTS, "0x", { gasLimit: 800000 });
    const receipt = await tx.wait();
    console.log("Local tx receipt:", {
      txHash: receipt.transactionHash,
      status: receipt.status,
      gasUsed: receipt.gasUsed.toString()
    });
  } catch (err) {
    console.error("Local tx failed/reverted:", err.error?.message || err.reason || err.message || err);
  }

  await provider.send("anvil_stopImpersonatingAccount", [OPERATOR]);
  console.log("\nStopped impersonation.");
}

main().catch(e => { console.error(e); process.exit(1); });
