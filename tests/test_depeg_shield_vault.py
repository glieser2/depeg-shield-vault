import cloudpickle
import json
from pathlib import Path

CONTRACT_FILE = str(
    Path(__file__).resolve().parent.parent / "contracts" / "depeg_shield_vault.py"
)


def _addr_hex(addr_obj) -> str:
    # 将测试账户地址转换为标准 EIP-55 校验和十六进制字符串
    if hasattr(addr_obj, "as_hex"):
        return addr_obj.as_hex
    from genlayer.py.types import Address

    return Address(addr_obj).as_hex


def _assert_latest_validator_picklable(direct_vm) -> None:
    # 显式验证捕获的 leader_fn 与 validator_fn 可通过 cloudpickle 跨 GenVM WASM 沙箱序列化
    _, leader_fn, validator_fn = direct_vm._captured_validators[-1]
    cloudpickle.dumps(leader_fn)
    cloudpickle.dumps(validator_fn)


def _register_usdc_and_fund_pool(direct_vm, contract, owner_addr, lp_addr, deposit=10000):
    # 辅助函数：注册 USDC 监控配置并注入初始承保流动性
    direct_vm.sender = owner_addr
    contract.register_asset(
        "USDC",
        9750,
        9000,
        300,
        "https://api.coingecko.com/api/v3/simple/price?ids=usd-coin&vs_currencies=usd",
        "https://www.circle.com/transparency",
    )

    direct_vm.sender = lp_addr
    direct_vm.value = deposit
    contract.provide_liquidity("USDC")
    direct_vm.value = 0


def test_lp_share_accounting_prevents_bank_run_and_distributes_premiums(
    direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob, direct_charlie
):
    # 回归测试 [C-01]：验证净值份额（Share）模型确保多 LP 按比例均摊亏损（无挤兑套利）并能完整提取未出险保单保费收益
    direct_vm.warp("2026-11-10T00:00:00Z")
    contract = direct_deploy(CONTRACT_FILE, 30, 900)

    # Alice 与 Bob 各存入 10,000 wei，各获 10,000 shares（总池 20,000 wei，总份额 20,000）
    _register_usdc_and_fund_pool(direct_vm, contract, direct_owner, direct_alice, 10000)
    direct_vm.sender = direct_bob
    direct_vm.value = 10000
    assert contract.provide_liquidity("USDC") == 10000
    direct_vm.value = 0

    # Charlie 购买 10,000 wei 保额、30 天期保单（300 bps 费率 -> 保费 300 wei）
    req_prem = contract.quote_premium("USDC", 10000, 86400 * 30)
    assert req_prem == 300
    direct_vm.sender = direct_charlie
    direct_vm.value = 300
    policy_id = contract.purchase_policy("USDC", 10000, 86400 * 30)
    direct_vm.value = 0

    # 发生 100% 储备受损理赔后，池内剩余 20,300 - 10,000 = 10,300 wei，Alice 与 Bob 净值应各为 5,150 wei
    direct_vm.warp("2026-11-10T01:00:00Z")
    direct_vm.mock_web(
        r"coingecko\.com/api/v3/simple/price",
        {"status": 200, "body": '{"usd-coin": {"usd": 0.8500}}'},
    )
    direct_vm.mock_web(
        r"circle\.com/transparency",
        {"status": 200, "body": "Primary redemptions suspended."},
    )
    direct_vm.mock_llm(
        r".*pegged asset USDC.*",
        json.dumps(
            {
                "observed_price_bps": 8500,
                "incident_class": "RESERVE_IMPAIRMENT",
                "redemption_halted": True,
                "evidence_summary": "Custodian freeze at 8500 bps.",
            }
        ),
    )
    contract.adjudicate_depeg_claim(policy_id)
    _assert_latest_validator_picklable(direct_vm)

    alice_pos = contract.get_lp_position("USDC", _addr_hex(direct_alice))
    bob_pos = contract.get_lp_position("USDC", _addr_hex(direct_bob))
    assert alice_pos["underlying_wei"] == 5150
    assert bob_pos["underlying_wei"] == 5150

    # Alice 试图按旧本金抢跑提走 10,000 wei 必须被 Share 净值校验拒绝
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("Insufficient LP share value"):
        contract.withdraw_liquidity("USDC", 10000, False)

    # Alice 与 Bob 各自赎回全部 10,000 shares，精准各得 5,150 wei（含保费分润且零锁死）
    assert contract.redeem_lp_shares("USDC", 10000, False) == 5150
    direct_vm.sender = direct_bob
    assert contract.redeem_lp_shares("USDC", 10000, False) == 5150
    assert contract.get_asset_risk_state("USDC")["total_pool_wei"] == 0


def test_activation_delay_and_ssrf_url_validation(
    direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob
):
    # 回归测试 [H-03] & [C-02]：验证保单生效等待期拦截突击骗保，且非法/内网/带凭证 URL 被拦截
    direct_vm.warp("2026-11-10T00:00:00Z")
    contract = direct_deploy(CONTRACT_FILE, 30, 900)

    direct_vm.sender = direct_owner
    for bad_url in (
        "http://api.example.com/price",
        "https://user:pass@api.example.com/price",
        "https://127.0.0.1/price",
        "https://localhost/price",
        "https://api.example.com:8443/price",
        "https://api.example.com/price#frag",
    ):
        with direct_vm.expect_revert():
            contract.register_asset(
                "USDT", 9750, 9000, 300, bad_url, "https://tether.to/transparency"
            )

    _register_usdc_and_fund_pool(direct_vm, contract, direct_owner, direct_alice, 10000)

    # 验证时长定价：180 天保费严格等于 30 天保费的 6 倍
    prem_30d = contract.quote_premium("USDC", 5000, 86400 * 30)
    prem_180d = contract.quote_premium("USDC", 5000, 86400 * 180)
    assert prem_180d == prem_30d * 6

    direct_vm.sender = direct_bob
    direct_vm.value = prem_30d
    policy_id = contract.purchase_policy("USDC", 5000, 86400 * 30)
    direct_vm.value = 0

    # 购买后仅过 60 秒（未满 900 秒等待期）尝试理赔必须被拦截
    direct_vm.warp("2026-11-10T00:01:00Z")
    with direct_vm.expect_revert("activation waiting period"):
        contract.adjudicate_depeg_claim(policy_id)


def test_flash_wick_rejected_and_redemption_halt_priority(
    direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob
):
    # 回归测试 [M-02]：正常插针不赔付；但若一级兑付已暂停（redemption_halted=True），即使归类为 FLASH_WICK 也优先按 100% 赔付
    direct_vm.strict_mocks = True
    direct_vm.warp("2026-11-10T00:00:00Z")
    contract = direct_deploy(CONTRACT_FILE, 30, 60)
    _register_usdc_and_fund_pool(direct_vm, contract, direct_owner, direct_alice, 10000)

    direct_vm.sender = direct_bob
    direct_vm.value = contract.quote_premium("USDC", 4000, 86400)
    policy_id = contract.purchase_policy("USDC", 4000, 86400)
    direct_vm.value = 0

    direct_vm.warp("2026-11-10T00:05:00Z")
    direct_vm.mock_web(
        r"coingecko\.com/api/v3/simple/price",
        {"status": 200, "body": '{"usd-coin": {"usd": 0.9992}}'},
    )
    direct_vm.mock_web(
        r"circle\.com/transparency",
        {"status": 200, "body": "100% backed; redemptions operational."},
    )
    direct_vm.mock_llm(
        r".*pegged asset USDC.*",
        json.dumps(
            {
                "observed_price_bps": 9992,
                "incident_class": "FLASH_WICK",
                "redemption_halted": False,
                "evidence_summary": "Brief single-venue wick recovered.",
            }
        ),
    )

    outcome = contract.adjudicate_depeg_claim(policy_id)
    assert outcome["payout_tier_bps"] == 0
    assert contract.is_circuit_breaker_active("USDC") is False


def test_byzantine_leader_payload_rejected_by_validator(
    direct_vm, direct_deploy, direct_owner, direct_alice
):
    # 回归测试 [H-02] & [H-03]：测试无保单主动巡检 sync_asset_risk_state，且验证节点拦截恶意 Leader 注入的超长垃圾文本/布尔伪造整数/档位篡改
    direct_vm.warp("2026-11-10T02:00:00Z")
    contract = direct_deploy(CONTRACT_FILE, 30, 60)
    _register_usdc_and_fund_pool(direct_vm, contract, direct_owner, direct_alice, 10000)

    direct_vm.mock_web(
        r"coingecko\.com/api/v3/simple/price",
        {"status": 200, "body": '{"usd-coin": {"usd": 0.9600}}'},
    )
    direct_vm.mock_web(
        r"circle\.com/transparency",
        {"status": 200, "body": "Reserves intact; market discount."},
    )
    direct_vm.mock_llm(
        r".*pegged asset USDC.*",
        json.dumps(
            {
                "observed_price_bps": 9600,
                "incident_class": "SUSTAINED_DEPEG",
                "redemption_halted": False,
                "evidence_summary": "Sustained discount at 9600 bps.",
            }
        ),
    )

    res = contract.sync_asset_risk_state("USDC")
    assert res["circuit_breaker_active"] is True
    assert contract.is_circuit_breaker_active("USDC") is True
    _assert_latest_validator_picklable(direct_vm)

    # 诚实容差漂移（9618 vs 9600 <= 30 bps）应通过
    assert (
        direct_vm.run_validator(
            leader_result={
                "observed_price_bps": 9618,
                "incident_class": "SUSTAINED_DEPEG",
                "redemption_halted": False,
                "payout_tier_bps": 5000,
                "evidence_summary": "Honest leader slightly different bps.",
            }
        )
        is True
    )

    # 恶意 Leader 1：塞入超过 240 字符的超大存储投毒摘要 -> 必须返回 False
    assert (
        direct_vm.run_validator(
            leader_result={
                "observed_price_bps": 9600,
                "incident_class": "SUSTAINED_DEPEG",
                "redemption_halted": False,
                "payout_tier_bps": 5000,
                "evidence_summary": "X" * 500,
            }
        )
        is False
    )

    # 恶意 Leader 2：使用 bool 冒充整数或伪造不一致的 payout_tier_bps -> 必须返回 False
    assert (
        direct_vm.run_validator(
            leader_result={
                "observed_price_bps": True,
                "incident_class": "SUSTAINED_DEPEG",
                "redemption_halted": False,
                "payout_tier_bps": 5000,
                "evidence_summary": "Bool attack",
            }
        )
        is False
    )
    assert (
        direct_vm.run_validator(
            leader_result={
                "observed_price_bps": 9600,
                "incident_class": "SUSTAINED_DEPEG",
                "redemption_halted": False,
                "payout_tier_bps": 10000,
                "evidence_summary": "Inflated payout tier attack",
            }
        )
        is False
    )


def test_circuit_breaker_recovery_and_refund_buffer_recovery(
    direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob
):
    # 回归测试 [M-01] & [M-02]：验证熔断恢复需同时满足锚定与兑付开启，且异步退款缓冲池可安全恢复而不侵占 LP 资产
    direct_vm.warp("2026-11-10T03:00:00Z")
    contract = direct_deploy(CONTRACT_FILE, 30, 0)
    _register_usdc_and_fund_pool(direct_vm, contract, direct_owner, direct_alice, 10000)

    # 模拟异步失败退回 500 wei 进入 refunded_transfer_pool
    direct_vm.sender = direct_bob
    direct_vm.value = 500
    contract.__on_errored_message__()
    direct_vm.value = 0
    assert contract.get_refunded_transfer_pool() == 500

    # 管理员仅能提取不超过 500 wei 的退回资金，试图提取 501 wei（触碰 LP 资金池）立即报错
    direct_vm.sender = direct_owner
    with direct_vm.expect_revert("exceeds refunded_transfer_pool"):
        contract.recover_refunded_funds(_addr_hex(direct_bob), 501, False)

    contract.recover_refunded_funds(_addr_hex(direct_bob), 500, False)
    assert contract.get_refunded_transfer_pool() == 0
    assert contract.get_asset_risk_state("USDC")["total_pool_wei"] == 10000

    # 触发熔断后再通过双源验证恢复
    direct_vm.mock_web(
        r"coingecko\.com/api/v3/simple/price",
        {"status": 200, "body": '{"usd-coin": {"usd": 0.9620}}'},
    )
    direct_vm.mock_web(
        r"circle\.com/transparency",
        {"status": 200, "body": "Market discount."},
    )
    direct_vm.mock_llm(
        r".*pegged asset USDC.*",
        json.dumps(
            {
                "observed_price_bps": 9620,
                "incident_class": "SUSTAINED_DEPEG",
                "redemption_halted": False,
                "evidence_summary": "Sustained discount.",
            }
        ),
    )
    contract.sync_asset_risk_state("USDC")
    assert contract.is_circuit_breaker_active("USDC") is True

    direct_vm.clear_mocks()
    direct_vm.mock_web(
        r"coingecko\.com/api/v3/simple/price",
        {"status": 200, "body": '{"usd-coin": {"usd": 0.9996}}'},
    )
    direct_vm.mock_web(
        r"circle\.com/transparency",
        {"status": 200, "body": "Redemptions active and 100% backed."},
    )
    direct_vm.mock_llm(
        r".*verifying whether pegged asset USDC.*",
        json.dumps(
            {
                "observed_price_bps": 9996,
                "redemptions_active": True,
                "summary": "Healthy peg and active redemptions.",
            }
        ),
    )
    contract.reset_circuit_breaker("USDC")
    _assert_latest_validator_picklable(direct_vm)
    assert contract.is_circuit_breaker_active("USDC") is False


def test_policy_expiry_and_studio_abi_schema_and_http_error_consensus(
    direct_vm, direct_deploy, direct_owner, direct_alice, direct_bob
):
    # 验证保单到期释放、Studio ABI Schema 完整性以及上游 HTTP 503 确定性错误共识
    direct_vm.warp("2026-11-10T05:00:00Z")
    contract = direct_deploy(CONTRACT_FILE, 30, 60)
    cls = type(object.__getattribute__(contract, "_instance"))
    schema = json.loads(cls.__get_schema__())
    for expected_fn in (
        "adjudicate_depeg_claim",
        "sync_asset_risk_state",
        "redeem_lp_shares",
        "quote_premium",
        "recover_refunded_funds",
    ):
        assert expected_fn in schema["methods"]

    _register_usdc_and_fund_pool(direct_vm, contract, direct_owner, direct_alice, 10000)

    direct_vm.sender = direct_bob
    direct_vm.value = contract.quote_premium("USDC", 5000, 7200)
    policy_id = contract.purchase_policy("USDC", 5000, 7200)
    direct_vm.value = 0

    direct_vm.warp("2026-11-10T05:05:00Z")
    direct_vm.mock_web(
        r"coingecko\.com/api/v3/simple/price",
        {"status": 200, "body": '{"usd-coin": {"usd": 0.9999}}'},
    )
    direct_vm.mock_web(
        r"circle\.com/transparency",
        {"status": 200, "body": "All reserves healthy."},
    )
    direct_vm.mock_llm(
        r".*pegged asset USDC.*",
        "```json\n{\"price_bps\": 9999, \"incident_class\": \"NORMAL\", \"redemption_halted\": false, \"evidence_summary\": \"Healthy peg\"}\n```",
    )
    res = contract.adjudicate_depeg_claim(policy_id)
    assert res["observed_price_bps"] == 9999

    assert direct_vm.run_validator(leader_error=Exception("Market feed HTTP error 503")) is False
    direct_vm.clear_mocks()
    direct_vm.mock_web(
        r"coingecko\.com/api/v3/simple/price",
        {"status": 503, "body": "Service Unavailable"},
    )
    assert direct_vm.run_validator(leader_error=Exception("Market feed HTTP error 503")) is True

    direct_vm.warp("2026-11-10T08:00:00Z")
    contract.expire_policy(policy_id)
    assert contract.get_policy(policy_id)["status"] == "EXPIRED"
