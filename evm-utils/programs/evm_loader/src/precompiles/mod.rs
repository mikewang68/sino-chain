use evm_state::{
    executor::{LogEntry, OwnedPrecompile, PrecompileFailure, PrecompileOutput},
    CallScheme, Context, ExitError, Log, H256,
};
use once_cell::sync::Lazy;
use primitive_types::H160;
use std::collections::{BTreeMap, HashMap};

mod abi_parse;
mod builtins;
mod compatibility;
mod errors;
pub use abi_parse::*;
pub use builtins::{ETH_TO_SOR_ADDR, ETH_TO_SOR_CODE};
pub use compatibility::build_precompile_map;
pub use errors::PrecompileErrors;

use crate::account_structure::AccountStructure;
use sdk::keyed_account::KeyedAccount;

pub type Result<T, Err = PrecompileErrors> = std::result::Result<T, Err>;
type CallResult = Result<(PrecompileOutput, u64, LogEntry)>;

pub struct NativeContext<'a, 'b> {
    accounts: AccountStructure<'a>,
    keep_old_errors: bool,
    precompile_context: PrecompileContext<'b>,
}

impl<'a, 'b> NativeContext<'a, 'b> {
    fn new(
        keep_old_errors: bool,
        accounts: AccountStructure<'a>,
        gas_limit: Option<u64>,
        evm_context: &'b Context,
        call_scheme: Option<CallScheme>,
    ) -> Self {
        Self {
            keep_old_errors,
            accounts,
            precompile_context: PrecompileContext::new(gas_limit, evm_context, call_scheme),
        }
    }
}

pub struct PrecompileContext<'b> {
    #[allow(unused)]
    gas_limit: Option<u64>,
    evm_context: &'b Context,
    call_scheme: Option<CallScheme>,
}
impl<'b> PrecompileContext<'b> {
    fn new(
        gas_limit: Option<u64>,
        evm_context: &'b Context,
        call_scheme: Option<CallScheme>,
    ) -> Self {
        Self {
            gas_limit,
            evm_context,
            call_scheme,
        }
    }
}

// Currently only static is allowed (but it can be closure).
type BuiltinEval =
    &'static (dyn for<'a, 'c> Fn(&'a [u8], PrecompileContext<'c>) -> CallResult + Sync);

type NativeBuiltinEval =
    &'static (dyn for<'a, 'b, 'c> Fn(&'a [u8], NativeContext<'b, 'c>) -> CallResult + Sync);

type NativePromiseHandler =
    &'static (dyn for<'a, 'b, 'c> Fn(AccountStructure, Vec<H256>, Vec<u8>) -> Result<()> + Sync);

pub static NATIVE_CONTRACTS: Lazy<HashMap<H160, (NativeBuiltinEval, NativePromiseHandler)>> =
    Lazy::new(|| {
        let mut native_contracts = HashMap::new();

        let eth_to_sol: NativeBuiltinEval =
            &|function_abi_input, cx| (*ETH_TO_SOR_CODE).eval(function_abi_input, cx);

        let handle_log: NativePromiseHandler = &|accounts, _topics: Vec<H256>, data| {
            (*ETH_TO_SOR_CODE).process_promise(accounts, data)
        };
        assert!(native_contracts
            .insert(*ETH_TO_SOR_ADDR, (eth_to_sol, handle_log))
            .is_none());
        native_contracts
    });

pub static PRECOMPILES_MAP_DEPRECATED: Lazy<HashMap<H160, BuiltinEval>> =
    Lazy::new(|| build_precompile_map(false));

pub static PRECOMPILES_MAP: Lazy<HashMap<H160, BuiltinEval>> =
    Lazy::new(|| build_precompile_map(true));

pub static NO_PRECOMPILES: Lazy<HashMap<H160, BuiltinEval>> = Lazy::new(|| HashMap::new());

// Simulation does not have access to real account structure, so only process immutable entrypoints
pub fn simulation_entrypoint<'a>(
    activate_precompile: PrecompileSet,
    evm_account: &'a KeyedAccount,
    users_accounts: &'a [KeyedAccount],
) -> OwnedPrecompile<'a> {
    let accounts = AccountStructure::new(evm_account, users_accounts);
    entrypoint(accounts, activate_precompile, true)
}

#[derive(Debug, PartialEq)]
pub enum PrecompileSet {
    No,
    SinoClassic,
    SinoNext,
}

pub fn entrypoint(
    accounts: AccountStructure,
    activate_precompile: PrecompileSet,
    keep_old_errors: bool,
) -> OwnedPrecompile {
    let mut map = BTreeMap::new();

    let precompiles = match activate_precompile {
        PrecompileSet::SinoClassic => &PRECOMPILES_MAP_DEPRECATED,
        PrecompileSet::SinoNext => &PRECOMPILES_MAP,
        PrecompileSet::No => &NO_PRECOMPILES,
    };

    map.extend(precompiles.iter().map(|(k, method)| {
        (
            *k,
            Box::new(
                move |function_abi_input: &[u8],
                      gas_left,
                      call_scheme,
                      cx: &Context,
                      _is_static| {
                    let cx = PrecompileContext::new(gas_left, cx, call_scheme);
                    method(function_abi_input, cx).map_err(|err| {
                        let exit_err: ExitError = Into::into(err);
                        PrecompileFailure::Error {
                            exit_status: exit_err,
                        }
                    })
                },
            )
                as Box<
                    dyn for<'a, 'b> Fn(
                        &'a [u8],
                        Option<u64>,
                        Option<CallScheme>,
                        &'b Context,
                        bool,
                    ) -> Result<
                        (PrecompileOutput, u64, LogEntry),
                        PrecompileFailure,
                    >,
                >,
        )
    }));

    map.extend(NATIVE_CONTRACTS.iter().map(|(k, (method, _))| {
        (
            *k,
            Box::new(
                move |function_abi_input: &[u8],
                      gas_left,
                      call_scheme,
                      cx: &Context,
                      _is_static| {
                    let cx =
                        NativeContext::new(keep_old_errors, accounts, gas_left, cx, call_scheme);
                    method(function_abi_input, cx).map_err(|err| {
                        let exit_err: ExitError = Into::into(err);
                        PrecompileFailure::Error {
                            exit_status: exit_err,
                        }
                    })
                },
            )
                as Box<
                    dyn for<'a, 'b> Fn(
                        &[u8],
                        Option<u64>,
                        Option<CallScheme>,
                        &Context,
                        bool,
                    ) -> Result<
                        (PrecompileOutput, u64, LogEntry),
                        PrecompileFailure,
                    >,
                >,
        )
    }));
    OwnedPrecompile { precompiles: map }
}

pub fn filter_native_logs(accounts: AccountStructure<'_>, logs: &mut Vec<Log>) -> Result<()> {
    let tmp_logs = std::mem::take(logs);
    for log in tmp_logs {
        if let Some(c) = NATIVE_CONTRACTS.get(&log.address) {
            let handle_promise = c.1;
            (*handle_promise)(accounts, log.topics, log.data)?
        } else {
            logs.push(log)
        }
    }
    Ok(())
}

