use super::*;

/// Anvil's first pre-funded account address
/// The tests' anvil runs with network_mode: host, so the wallet under test
/// reaches it at the same address the in-container tooling uses.
pub(crate) const ANVIL_RPC_URL: &str = "http://localhost:8545";

const ANVIL_ACCOUNT_0: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
/// Anvil's first pre-funded account private key
const ANVIL_PRIVATE_KEY_0: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

pub(crate) struct EthContract {
    pub address: String,
    pub deployer: String,
}

fn anvil_exec() -> Vec<String> {
    let compose_file = ["tests", "compose.yaml"].join(MAIN_SEPARATOR_STR);
    vec![s!("-f"), compose_file, s!("exec"), s!("-T"), s!("anvil")]
}

/// Deploy the TestERC20 contract on anvil and return contract info.
///
/// Uses `forge create` via docker compose exec inside the anvil container.
pub(crate) fn deploy_test_erc20(
    name: &str,
    symbol: &str,
    decimals: u8,
    initial_supply: u64,
) -> EthContract {
    ensure_openzeppelin_installed();

    let mut args = anvil_exec();
    args.extend([
        s!("forge"),
        s!("create"),
        s!("/contracts/TestERC20.sol:TestERC20"),
        s!("--rpc-url"),
        s!("http://localhost:8545"),
        s!("--private-key"),
        ANVIL_PRIVATE_KEY_0.to_string(),
        s!("--cache-path"),
        s!("/tmp/forge-cache"),
        s!("--out"),
        s!("/tmp/forge-out"),
        s!("--root"),
        s!("/tmp"),
        s!("--contracts"),
        s!("/contracts"),
        s!("--remappings=@openzeppelin/=/tmp/lib/openzeppelin-contracts/"),
        s!("--broadcast"),
        s!("--constructor-args"),
        name.to_string(),
        symbol.to_string(),
        decimals.to_string(),
        initial_supply.to_string(),
    ]);

    let output = Command::new("docker")
        .stdin(Stdio::null())
        .arg("compose")
        .args(&args)
        .output()
        .expect("failed to deploy ERC-20");

    assert!(
        output.status.success(),
        "forge create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("invalid utf8 from forge create");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // forge may print to either stdout or stderr; search both
    let all_output = format!("{stdout}\n{stderr}");
    let address = all_output
        .lines()
        .find(|l| l.contains("Deployed to:"))
        .unwrap_or_else(|| panic!("could not find contract address in forge output:\n{all_output}"))
        .split("Deployed to:")
        .nth(1)
        .unwrap()
        .trim()
        .to_string();

    EthContract {
        address,
        deployer: ANVIL_ACCOUNT_0.to_string(),
    }
}

/// Install OpenZeppelin contracts in the anvil container (idempotent).
fn ensure_openzeppelin_installed() {
    let mut args = anvil_exec();
    args.extend([
        s!("sh"),
        s!("-c"),
        s!("test -d /tmp/lib/openzeppelin-contracts || forge install OpenZeppelin/openzeppelin-contracts --root /tmp --no-git"),
    ]);

    let output = Command::new("docker")
        .stdin(Stdio::null())
        .arg("compose")
        .args(&args)
        .output()
        .expect("failed to install OpenZeppelin");

    assert!(
        output.status.success(),
        "OpenZeppelin install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Deploy the BaseBridge contract on anvil and return contract info.
///
/// Installs OpenZeppelin deps (if needed), then uses `forge create` via docker compose exec.
/// `token` is the ERC-20 address the bridge will accept.
pub(crate) fn deploy_bridge(token: &str) -> EthContract {
    ensure_openzeppelin_installed();

    let mut args = anvil_exec();
    args.extend([
        s!("forge"),
        s!("create"),
        s!("/contracts/BaseBridge.sol:BaseBridge"),
        s!("--rpc-url"),
        s!("http://localhost:8545"),
        s!("--private-key"),
        ANVIL_PRIVATE_KEY_0.to_string(),
        s!("--cache-path"),
        s!("/tmp/forge-cache"),
        s!("--out"),
        s!("/tmp/forge-out"),
        s!("--root"),
        s!("/tmp"),
        s!("--contracts"),
        s!("/contracts"),
        s!("--remappings=@openzeppelin/=/tmp/lib/openzeppelin-contracts/"),
        s!("--broadcast"),
        s!("--constructor-args"),
        token.to_string(),
    ]);

    let output = Command::new("docker")
        .stdin(Stdio::null())
        .arg("compose")
        .args(&args)
        .output()
        .expect("failed to deploy BaseBridge");

    assert!(
        output.status.success(),
        "forge create BaseBridge failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("invalid utf8 from forge create");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let all_output = format!("{stdout}\n{stderr}");
    let address = all_output
        .lines()
        .find(|l| l.contains("Deployed to:"))
        .unwrap_or_else(|| panic!("could not find contract address in forge output:\n{all_output}"))
        .split("Deployed to:")
        .nth(1)
        .unwrap()
        .trim()
        .to_string();

    EthContract {
        address,
        deployer: ANVIL_ACCOUNT_0.to_string(),
    }
}

/// Query the ERC-20 balance of an account via `cast call`.
pub(crate) fn erc20_balance_of(contract: &str, account: &str) -> u64 {
    let mut args = anvil_exec();
    args.extend([
        s!("cast"),
        s!("call"),
        contract.to_string(),
        s!("balanceOf(address)(uint256)"),
        account.to_string(),
        s!("--rpc-url"),
        s!("http://localhost:8545"),
    ]);

    let output = Command::new("docker")
        .stdin(Stdio::null())
        .arg("compose")
        .args(&args)
        .output()
        .expect("failed to call balanceOf");

    assert!(
        output.status.success(),
        "cast call balanceOf failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let raw = String::from_utf8(output.stdout).unwrap();
    // cast may append a human-readable suffix like "1000000 [1e6]"
    let value = raw.split_whitespace().next().unwrap_or("");
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse::<u64>()
    }
    .unwrap_or_else(|e| panic!("could not parse balance from {value:?}: {e}"))
}

/// Approve `spender` to transfer `amount` of an ERC-20 token via `cast send`.
pub(crate) fn erc20_approve(token: &str, spender: &str, amount: u64) {
    let mut args = anvil_exec();
    args.extend([
        s!("cast"),
        s!("send"),
        token.to_string(),
        s!("approve(address,uint256)"),
        spender.to_string(),
        amount.to_string(),
        s!("--rpc-url"),
        s!("http://localhost:8545"),
        s!("--private-key"),
        ANVIL_PRIVATE_KEY_0.to_string(),
    ]);

    let output = Command::new("docker")
        .stdin(Stdio::null())
        .arg("compose")
        .args(&args)
        .output()
        .expect("failed to approve ERC-20");

    assert!(
        output.status.success(),
        "cast send approve failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Call `fundsIn` on the BaseBridge contract to lock ERC-20 tokens.
///
/// `opid` is the 64-char hex RGB operation ID (used as `operationId`).
pub(crate) fn bridge_funds_in(bridge: &str, amount: u64, opid: &str) {
    let operation_id = format!("0x{opid}");

    let mut args = anvil_exec();
    args.extend([
        s!("cast"),
        s!("send"),
        bridge.to_string(),
        s!("fundsIn(uint256,uint256)"),
        amount.to_string(),
        operation_id,
        s!("--rpc-url"),
        s!("http://localhost:8545"),
        s!("--private-key"),
        ANVIL_PRIVATE_KEY_0.to_string(),
    ]);

    let output = Command::new("docker")
        .stdin(Stdio::null())
        .arg("compose")
        .args(&args)
        .output()
        .expect("failed to call fundsIn");

    assert!(
        output.status.success(),
        "cast send fundsIn failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
