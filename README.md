# DepegShieldVault — Multi-Source Depeg Protection & Proof-of-Reserve Circuit-Breaker Primitive

A standalone, composable **GenLayer Intelligent Contract** (`py-genlayer`) that resolves stablecoin and liquid-staking token (LST/LRT) depeg coverage claims and exposes an on-chain circuit-breaker signal by combining **live market price feeds** with **official issuer reserve/redemption disclosures** under Optimistic Democracy.

---

## 1. Real Trust Problem Solved

Conventional EVM depeg insurance and lending-market circuit breakers fail in two opposite failure modes:

1. **False-positive liquidations/payouts on transient DEX flash wicks:** Pure numeric price feeds trigger payouts or pause protocols during 60-second single-venue liquidity wicks where backing reserves remain 100% intact.
2. **Delayed response during banking/custodian reserve freezes:** When an issuer halts primary redemptions or discloses custodian impairment (e.g., weekend banking receivership or bridge exploit), human committees take days to adjudicate claims.

`DepegShieldVault` solves this directly inside GenVM:
- **NAV Share-Based Underwriting & 100% Solvency Locking:** Liquidity providers supply `GEN` into per-asset pools (`provide_liquidity`) and receive proportional LP shares (`total_lp_shares` / `lp_shares`). Policy premiums accrue fairly to all LP shares (`redeem_lp_shares`), losses are socialized pro-rata across shares (preventing bank-run front-running), and `locked_coverage_wei <= total_pool_wei` guarantees full collateralization of active policies.
- **Anti-Backrunning Activation Delay & Duration-Scaled Premiums:** Policies enforce a configurable `activation_delay_seconds` (default `900s`) so attackers cannot buy coverage *after* a depeg begins, and scale minimum premiums proportionally by coverage duration (`quote_premium`).
- **Multi-Source Qualitative + Quantitative Consensus:** `adjudicate_depeg_claim` and permissionless `sync_asset_risk_state` use `gl.vm.run_nondet_unsafe(leader_fn, validator_fn)` to fetch **both** the live market price endpoint and the issuer's official transparency/redemption status page, classifying events into `"NORMAL"`, `"FLASH_WICK"`, `"SUSTAINED_DEPEG"` (50% payout), or `"RESERVE_IMPAIRMENT"` / `redemption_halted` (100% payout).
- **Composable DeFi Circuit Breaker:** External GenLayer lending vaults, DEX pools, or treasuries can query `is_circuit_breaker_active(symbol)` and `get_asset_risk_state(symbol)` in real time.

---

## 2. Consensus & Security Architecture

Instead of a naive format-only check, `DepegShieldVault` implements **Byzantine-resilient independent multi-source verification** in `validator_fn`:

1. **Strict Byzantine Leader Payload Verification:** Before running external calls, `validator_fn` enforces exact key-set matching, non-boolean integer bounds (`1 <= observed_price_bps <= 25000`), bounded `evidence_summary` (`1..240` chars to block storage-bloat poisoning), and deterministic payout-tier consistency.
2. **Independent Re-Execution & Error Classification:** Validators independently fetch `market_feed_url` and `reserve_attestation_url` via `gl.nondet.web.get` and run independent LLM analysis, matching deterministic `gl.vm.UserError` messages while rotating leaders on malformed LLM responses.
3. **Hard Qualitative Gates + Numeric Basis-Point Tolerance:**
   - `incident_class`, `redemption_halted`, and derived `payout_tier_bps` (`0`, `5000`, or `10000`) must match **strictly** across leader and validators.
   - `observed_price_bps` allows a configurable **`±price_tolerance_bps` (default `±30 bps` / `0.30%`)** window for minor timestamp drift.
4. **SSRF & Prompt Injection Hardening:** Public HTTPS URLs are validated with `urllib.parse.urlsplit` (blocking credentials, custom ports, fragments, IP literals, and local hosts), HTML scripts/tags are stripped, and async transfer refunds to `__on_errored_message__` are isolated in `refunded_transfer_pool`.

---

## 3. Public Interface & Composability

| Method | Decorator | Purpose |
|---|---|---|
| `register_asset(symbol, trigger_depeg_bps, severe_depeg_bps, premium_rate_bps, market_feed_url, reserve_attestation_url)` | `@gl.public.write` | Register a pegged asset (`USDC`, `USDE`, `STETH`, etc.) with dual HTTPS endpoints |
| `provide_liquidity(symbol)` | `@gl.public.write.payable` | Deposit `GEN` underwriting capital and mint proportional LP shares |
| `withdraw_liquidity(symbol, amount_wei, use_eoa_transfer)` | `@gl.public.write` | Withdraw unlocked `GEN` by burning ceiling-rounded LP shares |
| `redeem_lp_shares(symbol, share_amount, use_eoa_transfer)` | `@gl.public.write` | Redeem exact LP shares for underlying principal + earned policy premiums |
| `quote_premium(symbol, coverage_wei, duration_seconds)` | `@gl.public.view` | Compute exact duration-scaled minimum `GEN` premium (30-day base rate) |
| `purchase_policy(symbol, coverage_wei, duration_seconds)` | `@gl.public.write.payable` | Lock 100%-backed depeg protection subject to `activation_delay_seconds` |
| `sync_asset_risk_state(symbol)` | `@gl.public.write` | Permissionless consensus probe to refresh risk state & trip circuit breaker |
| `adjudicate_depeg_claim(policy_id)` | `@gl.public.write` | Adjudicate an active policy via multi-validator consensus and credit payout |
| `reset_circuit_breaker(symbol)` | `@gl.public.write` | Verify peg & active redemptions via consensus to clear an active circuit breaker |
| `expire_policy(policy_id)` | `@gl.public.write` | Unlock collateral reserve after an unclaimed policy expires |
| `claim_payout(use_eoa_transfer)` | `@gl.public.write` | Pull-pattern (`CEI`) `GEN` payout supporting Studio/GenVM and Bradbury EOA transfers |
| `is_circuit_breaker_active(symbol)` / `get_asset_risk_state(symbol)` / `get_lp_position(symbol, lp)` | `@gl.public.view` | Composable read-only guards and accounting views |

### Example Cross-Contract Integration (DeFi Lending Guard)

```python
vault = gl.get_contract_at(Address(depeg_shield_address))
if vault.view().is_circuit_breaker_active("USDC"):
    raise gl.vm.UserError("USDC borrowing paused: DepegShield circuit breaker active")
```

---

## 4. Quickstart: Local Testing & Deployment

```bash
pip install genlayer-test cloudpickle
pytest tests/ -v
```

- **GenLayer Studio (`https://studio.genlayer.com`):** Upload `contracts/depeg_shield_vault.py`, set `price_tolerance_bps = 30`, `activation_delay_seconds = 900`, and click **Deploy**.
- **GenLayer CLI:** `genlayer deploy --contract contracts/depeg_shield_vault.py --args 30 900`
