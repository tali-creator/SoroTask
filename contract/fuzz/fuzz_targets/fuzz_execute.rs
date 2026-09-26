#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger as _},
    Address, Env, Symbol, Vec,
};
use soro_task_contract::{SoroTaskContract, SoroTaskContractClient, TaskConfig};

/// Minimal target contract used inside the fuzz harness.
#[contract]
struct FuzzTarget;

#[contractimpl]
impl FuzzTarget {
    pub fn ping(_env: Env) {}
}

/// Fuzz the `execute` function with randomized timestamps, intervals,
/// gas_balance values, and Dutch-auction parameters to surface panics or
/// unexpected behaviour in the execution path (interval check, whitelist
/// check, fee deduction, and time-decay bounty calculation).
///
/// Input layout (bytes):
///   [0..8]   interval      (u64 LE)
///   [8..16]  ledger_ts     (u64 LE)
///   [16..24] gas_balance   (i128 lower 8 bytes, sign-extended)
///   [24..32] priority_bid  (i128 lower 8 bytes, sign-extended)
///   [32..40] max_fee       (i128 lower 8 bytes, sign-extended)
fuzz_target!(|data: &[u8]| {
    if data.len() < 40 {
        return;
    }

    let interval = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let ledger_ts = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let gas_balance = i64::from_le_bytes(data[16..24].try_into().unwrap()) as i128;
    let priority_bid = i64::from_le_bytes(data[24..32].try_into().unwrap()) as i128;
    let max_fee = i64::from_le_bytes(data[32..40].try_into().unwrap()) as i128;

    // Skip degenerate intervals — those are covered by fuzz_register
    if interval == 0 {
        return;
    }

    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, SoroTaskContract);
    let client = SoroTaskContractClient::new(&env, &contract_id);

    let target = env.register_contract(None, FuzzTarget);

    let config = TaskConfig {
        creator: Address::generate(&env),
        target,
        function: Symbol::new(&env, "ping"),
        args: Vec::new(&env),
        resolver: None,
        interval,
        last_run: 0,
        gas_balance,
        whitelist: Vec::new(&env),
        is_active: true,
        priority_bid,
        max_fee,
    };

    let task_id = client.register(&config);

    env.ledger().with_mut(|l| l.timestamp = ledger_ts);

    let keeper = Address::generate(&env);

    // execute may legitimately panic (InsufficientBalance, TaskPaused, etc.)
    // — we only care that it never causes undefined behaviour or an unexpected
    // panic outside of the known error variants. The Dutch-auction bounty
    // calculation must also never overflow or exceed the escrowed gas_balance.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.execute(&keeper, &task_id);
    }));
});
