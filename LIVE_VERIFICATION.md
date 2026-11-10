# Live Verification & Provenance Record (`DepegShieldVault`)

## 1. Source Integrity

- **Contract file:** `contracts/depeg_shield_vault.py`
- **GenVM dependency header:** `# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }`
- **Source SHA-256:** `c23d8c6b85e949bd7557313f7c1ad9c8ba41b8cf9cf23cfb5627b303b7415934`

## 2. Live GenLayer Studionet Deployment & Consensus Verification (Chain ID `61999`)

- **Deployed Contract Address:** [`0x1A1f1bC129147FAc83922dD6B936807e96D2D0B9`](https://explorer-studio.genlayer.com/address/0x1A1f1bC129147FAc83922dD6B936807e96D2D0B9)
- **GenLayer Studio Interactive Import:** [`https://studio.genlayer.com/?import-contract=0x1A1f1bC129147FAc83922dD6B936807e96D2D0B9`](https://studio.genlayer.com/?import-contract=0x1A1f1bC129147FAc83922dD6B936807e96D2D0B9)
- **Constructor arguments:** `price_tolerance_bps = 30`, `activation_delay_seconds = 900`

### Verified Consensus Transactions

| Step | Action | Transaction Hash | Consensus Outcome |
|---|---|---|---|
| 1 | `deploy_contract(args=[30, 900])` | [`0x8cac18267cb00902b79eff2dcc0ecc59dbab662a8615989b4f8f93533ca9c024`](https://explorer-studio.genlayer.com/tx/0x8cac18267cb00902b79eff2dcc0ecc59dbab662a8615989b4f8f93533ca9c024) | `ACCEPTED` (`MAJORITY_AGREE`) |
| 2 | `register_asset("USDC", 9750, 9000, 300, ...)` | [`0x4d5089e38195224e48a952f6feb79b14c4d7ae2c6c4f8a35abc66b2e7ad5a288`](https://explorer-studio.genlayer.com/tx/0x4d5089e38195224e48a952f6feb79b14c4d7ae2c6c4f8a35abc66b2e7ad5a288) | `ACCEPTED` (`MAJORITY_AGREE`) |
| 3 | `provide_liquidity("USDC", value=50000)` | [`0x154c73bf66c90400ad47e3d1df3493b9104d1d5c45bcc687e526f850f2ce92dd`](https://explorer-studio.genlayer.com/tx/0x154c73bf66c90400ad47e3d1df3493b9104d1d5c45bcc687e526f850f2ce92dd) | `ACCEPTED` (`MAJORITY_AGREE`) |

### Verified On-Chain View Snapshot (`get_asset_risk_state("USDC")`)

```json
{
  "symbol": "USDC",
  "peg_target_bps": 10000,
  "trigger_depeg_bps": 9750,
  "severe_depeg_bps": 9000,
  "premium_rate_bps": 300,
  "total_pool_wei": 50000,
  "total_lp_shares": 50000,
  "locked_coverage_wei": 0,
  "available_capacity_wei": 50000,
  "last_price_bps": 10000,
  "last_incident_class": "NORMAL",
  "redemption_halted": false,
  "circuit_breaker_active": false,
  "is_active": true
}
```
