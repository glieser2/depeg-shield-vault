import { readFileSync } from "fs";
import { resolve } from "path";
import { createClient, createAccount } from "genlayer-js";
import { testnetBradbury, studionet } from "genlayer-js/chains";
import { TransactionStatus } from "genlayer-js/types";

// 读取环境变量并部署 DepegShieldVault 智能合约至 Bradbury 测试网或 Studionet，等待共识确认并输出合约地址
async function main() {
  const targetNet =
    process.env.GENLAYER_NETWORK === "bradbury" ? testnetBradbury : studionet;
  const account = process.env.PRIVATE_KEY
    ? createAccount(process.env.PRIVATE_KEY as `0x${string}`)
    : createAccount();

  const client = createClient({
    chain: targetNet,
    account,
  });

  const contractCode = readFileSync(
    resolve(__dirname, "../contracts/depeg_shield_vault.py"),
    "utf-8"
  );

  // 初始化验证者价格容差为 30 bps (0.30%)，防突击投保等待期为 900 秒
  const txHash = await client.deployContract({
    code: contractCode,
    args: [30, 900],
  });

  console.log(`Deployment tx submitted on ${targetNet.name}: ${txHash}`);
  const receipt = await client.waitForTransactionReceipt({
    hash: txHash,
    status: TransactionStatus.ACCEPTED,
  });
  console.log("Deployed contract receipt:", receipt);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
