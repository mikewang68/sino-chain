pub use evm::{
    backend::{Apply, ApplyBackend, Backend, Log, MemoryAccount, MemoryVicinity},
    executor::stack::{MemoryStackState, StackExecutor, StackState, StackSubstateMetadata},
    executor::traces::*,
    Config, Context, Handler, Transfer,
    {ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed},
};
use std::collections::BTreeMap;
use std::fmt;

use log::*;
pub use primitive_types::{H256, U256};
pub use secp256k1::rand;
use snafu::ensure;

use crate::types::H160;
use crate::{
    context::{ChainContext, EvmConfig, ExecutorContext, TransactionContext},
    state::{AccountProvider, EvmBackend, Incomming},
    transactions::{
        Transaction, TransactionAction, TransactionInReceipt, TransactionReceipt,
        UnsignedTransaction, UnsignedTransactionWithCaller,
    },
};
use crate::{error::*, BlockVersion, CallScheme};
pub use evm::executor::stack::{Precompile, PrecompileFailure, PrecompileOutput, PrecompileResult};
pub use triedb::empty_trie_hash;

pub const MAX_TX_LEN: u64 = 3 * 1024 * 1024; // Limit size to 3 MB
pub const TX_MTU: usize = 908;

// NOTE: value must not overflow i32::MAX at least
pub const TEST_CHAIN_ID: u64 = 0xDEAD;

/// Exit result, if succeed, returns `ExitSucceed` - info about execution, Vec<u8> - output data, u64 - gas cost
pub type PrecompileCallResult = Result<(ExitSucceed, Vec<u8>, u64), ExitError>;

pub type LogEntry = Vec<(Vec<H256>, Vec<u8>)>;
#[derive(Default)]
#[allow(clippy::type_complexity)]
pub struct OwnedPrecompile<'precompile> {
    pub precompiles: BTreeMap<
        H160,
        Box<
            dyn Fn(
                    &[u8],
                    Option<u64>,
                    Option<CallScheme>,
                    &Context,
                    bool,
                ) -> Result<(PrecompileOutput, u64, LogEntry), PrecompileFailure>
                + 'precompile,
        >,
    >,
}

use evm::executor::stack::{PrecompileHandle, PrecompileSet};

impl<'precompile> PrecompileSet for OwnedPrecompile<'precompile> {
    fn execute(&self, handle: &mut impl PrecompileHandle) -> Option<PrecompileResult> {
        let address = handle.code_address();

        self.get(&address).map(|precompile| {
            let input = handle.input();
            let gas_limit = handle.gas_limit();
            let call_scheme = handle.call_scheme();
            let context = handle.context();
            let is_static = handle.is_static();

            match (*precompile)(input, gas_limit, call_scheme, context, is_static) {
                Ok((output, cost, logs)) => {
                    handle.record_cost(cost)?;
                    for (log_topics, log_data) in logs {
                        handle.log(address, log_topics, log_data)?;
                    }
                    Ok(output)
                }
                Err(err) => Err(err),
            }
        })
    }
    fn is_precompile(&self, address: H160) -> bool {
        self.contains_key(&address)
    }
}

impl<'precompile> std::ops::Deref for OwnedPrecompile<'precompile> {
    type Target = BTreeMap<
    H160,
    Box<
        dyn Fn(
                &[u8],
                Option<u64>,
                Option<CallScheme>,
                &Context,
                bool,
            ) -> Result<(PrecompileOutput, u64, LogEntry), PrecompileFailure>
            + 'precompile,
    >,
>;
    
    fn deref(&self) -> &Self::Target {
        &self.precompiles
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionResult {
    pub exit_reason: evm::ExitReason,
    pub exit_data: Vec<u8>,
    pub used_gas: u64,
    pub tx_logs: Vec<Log>,
    pub tx_id: H256,
    pub traces: Vec<Trace>,
}

impl fmt::Display for ExecutionResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Execution result:")?;
        writeln!(f, "->Used gas: {}", self.used_gas)?;
        if !self.exit_data.is_empty() {
            writeln!(f, "->Output data: {}", hex::encode(&self.exit_data))?;
        }
        writeln!(f, "->Status: {:?}", self.exit_reason)?;
        if !self.tx_logs.is_empty() {
            writeln!(f, "->Logs:")?;
            for (id, l) in self.tx_logs.iter().enumerate() {
                writeln!(f, "-{}>Address: {:?}", id, l.address)?;
                writeln!(f, "-{}>Data: {:?}", id, l.data)?;
                writeln!(f, "-{}>Topics:", id,)?;
                for (id, topic) in l.topics.iter().enumerate() {
                    writeln!(f, "--{}>{:?}", id, topic)?;
                }
                writeln!(f)?;
            }
        }
        if !self.traces.is_empty() {
            writeln!(f, "->Traces:")?;
            for (id, trace) in self.traces.iter().enumerate() {
                writeln!(f, "-{}>Action: {:?}", id, trace.action)?;
                writeln!(f, "-{}>Result: {:?}", id, trace.result)?;
                writeln!(f, "-{}>Subtraces: {}", id, trace.subtraces)?;
                writeln!(f, "-{}>TraceAddress: {:?}", id, trace.trace_address)?;
            }
        }

        writeln!(f, "->Native EVM TXID: {:?}", self.tx_id)
    }
}

#[derive(Debug, Clone, Default)]
pub struct FeatureSet {
    unsigned_tx_fix: bool,
    clear_logs_on_error: bool,
    accept_zero_gas_price_with_native_fee: bool,
}

impl FeatureSet {
    pub fn new(
        unsigned_tx_fix: bool,
        clear_logs_on_error: bool,
        accept_zero_gas_price_with_native_fee: bool,
    ) -> Self {
        FeatureSet {
            unsigned_tx_fix,
            clear_logs_on_error,
            accept_zero_gas_price_with_native_fee,
        }
    }

    pub fn new_with_all_enabled() -> Self {
        FeatureSet {
            unsigned_tx_fix: true,
            clear_logs_on_error: true,
            accept_zero_gas_price_with_native_fee: true,
        }
    }

    pub fn is_unsigned_tx_fix_enabled(&self) -> bool {
        self.unsigned_tx_fix
    }

    pub fn is_clear_logs_on_error_enabled(&self) -> bool {
        self.clear_logs_on_error
    }

    pub fn is_accept_zero_gas_price_with_native_fee_enabled(&self) -> bool {
        self.accept_zero_gas_price_with_native_fee
    }
}

#[derive(Debug, Clone)]
pub struct Executor {
    pub evm_backend: EvmBackend<Incomming>,
    chain_context: ChainContext,
    config: EvmConfig,

    pub feature_set: FeatureSet,
}

impl Executor {
    //Return new default executor, with empty state stored in temporary dirrectory
    pub fn testing() -> Self {
        Self::with_config(
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        )
    }
    pub fn default_configs(state: EvmBackend<Incomming>) -> Self {
        Self::with_config(
            state,
            Default::default(),
            Default::default(),
            Default::default(),
        )
    }

    pub fn with_config(
        evm_backend: EvmBackend<Incomming>,
        chain_context: ChainContext,
        config: EvmConfig,
        feature_set: FeatureSet,
    ) -> Self {
        Executor {
            evm_backend,
            chain_context,
            config,
            feature_set,
        }
    }

    pub fn support_precompile(&self) -> bool {
        self.evm_backend.state.block_version >= BlockVersion::VersionConsistentHashes
    }

    pub fn config(&self) -> &EvmConfig {
        &self.config
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transaction_execute_raw(
        &mut self,
        caller: H160,
        nonce: U256,
        mut gas_price: U256,
        gas_limit: U256,
        action: TransactionAction,
        input: Vec<u8>,
        value: U256,
        tx_chain_id: Option<u64>,
        tx_hash: H256,
        withdraw_fee: bool,
        precompiles: OwnedPrecompile,
    ) -> Result<ExecutionResult, Error> {
        let state_account = self
            .evm_backend
            .get_account_state(caller)
            .unwrap_or_default();

        let chain_id = self.config.chain_id;

        ensure!(
            tx_chain_id == Some(chain_id),
            WrongChainId {
                chain_id,
                tx_chain_id,
            }
        );

        ensure!(
            self.evm_backend.find_transaction_receipt(tx_hash).is_none(),
            DuplicateTx { tx_hash }
        );

        ensure!(
            nonce == state_account.nonce,
            NonceNotEqual {
                tx_nonce: nonce,
                state_nonce: state_account.nonce,
            }
        );

        ensure!(
            gas_price <= U256::from(u64::MAX),
            GasPriceOutOfBounds { gas_price }
        );

        if self
            .feature_set
            .is_accept_zero_gas_price_with_native_fee_enabled()
            && !withdraw_fee
            && gas_price.is_zero()
        {
            gas_price = self.config.burn_gas_price;
        } else {
            ensure!(
                gas_price >= self.config.burn_gas_price,
                GasPriceOutOfBounds { gas_price }
            );
        }

        ensure!(
            gas_limit <= U256::from(u64::MAX),
            GasLimitOutOfBounds { gas_limit }
        );

        ensure!(
            self.config.gas_limit >= self.evm_backend.state.used_gas,
            GasLimitConfigAssert {
                gas_limit: self.config.gas_limit,
                gas_used: self.evm_backend.state.used_gas
            }
        );

        let max_fee = gas_limit * gas_price;
        if withdraw_fee {
            ensure!(
                max_fee + value <= state_account.balance,
                CantPayTheBills {
                    value,
                    max_fee,
                    state_balance: state_account.balance,
                }
            );
        }

        let clear_logs_on_error_enabled = self.feature_set.is_clear_logs_on_error_enabled();
        let config = self.config.to_evm_params();
        let transaction_context = TransactionContext::new(gas_price.as_u64(), caller);
        let execution_context = ExecutorContext::new(
            &mut self.evm_backend,
            self.chain_context,
            transaction_context,
            self.config,
        );

        let block_gas_limit_left = execution_context.gas_left();
        let metadata = StackSubstateMetadata::new(block_gas_limit_left, &config);
        let state =
            MemoryStackState::new(metadata, &execution_context, clear_logs_on_error_enabled);
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &precompiles);
        let (exit_reason, exit_data) = match action {
            TransactionAction::Call(addr) => {
                debug!(
                    "TransactionAction::Call caller  = {}, to = {}.",
                    caller, addr
                );
                executor.transact_call(caller, addr, value, input, gas_limit.as_u64(), vec![])
            }
            TransactionAction::Create => {
                let addr = TransactionAction::Create.address(caller, nonce);
                debug!(
                    "TransactionAction::Create caller  = {}, to = {:?}.",
                    caller, addr
                );
                executor.transact_create(caller, value, input, gas_limit.as_u64(), vec![])
            }
        };
        let traces = executor.take_traces();
        let used_gas = executor.used_gas();
        let fee = executor.fee(gas_price);
        let mut executor_state = executor.into_state();

        if withdraw_fee && matches!(exit_reason, ExitReason::Succeed(_)) {
            // Burn the fee, if transaction executed correctly
            executor_state
                .withdraw(caller, fee)
                .map_err(|_| Error::CantPayTheBills {
                    value,
                    max_fee: fee,
                    state_balance: state_account.balance,
                })?;
        }

        // This was assert before, but at some point evm executor waste more gas than exist (on solidty assert opcode).
        ensure!(
            used_gas < block_gas_limit_left,
            GasUsedOutOfBounds {
                used_gas,
                gas_limit: block_gas_limit_left
            }
        );
        let (updates, logs) = executor_state.deconstruct();

        let tx_logs = match clear_logs_on_error_enabled && !exit_reason.is_succeed() {
            true => vec![],
            false => logs.into_iter().collect(),
        };
        execution_context.apply(updates, used_gas);

        Ok(ExecutionResult {
            exit_reason,
            exit_data,
            used_gas,
            tx_logs,
            tx_id: tx_hash,
            traces,
        })
    }

    /// Perform transaction execution without verify signature.
    pub fn transaction_execute_unsinged(
        &mut self,
        caller: H160,
        tx: UnsignedTransaction,
        withdraw_fee: bool,
        precompiles: OwnedPrecompile,
    ) -> Result<ExecutionResult, Error> {
        let chain_id = self.config.chain_id;

        let unsigned_tx = UnsignedTransactionWithCaller {
            unsigned_tx: tx.clone(),
            caller,
            chain_id,
            signed_compatible: self.feature_set.is_unsigned_tx_fix_enabled(),
        };
        let tx_hash = unsigned_tx.tx_id_hash();
        let result = self.transaction_execute_raw(
            caller,
            tx.nonce,
            tx.gas_price,
            tx.gas_limit,
            tx.action,
            tx.input.clone(),
            tx.value,
            Some(chain_id),
            tx_hash,
            withdraw_fee,
            precompiles,
        )?;

        self.register_tx_with_receipt(TransactionInReceipt::Unsigned(unsigned_tx), result.clone());
        Ok(result)
    }

    pub fn transaction_execute(
        &mut self,
        evm_tx: Transaction,
        withdraw_fee: bool,
        precompiles: OwnedPrecompile,
    ) -> Result<ExecutionResult, Error> {
        let caller = evm_tx.caller()?; // This method verify signature.

        let nonce = evm_tx.nonce;
        let gas_price = evm_tx.gas_price;
        let gas_limit = evm_tx.gas_limit;
        let action = evm_tx.action;
        let input = evm_tx.input.clone();
        let value = evm_tx.value;

        let tx_hash = evm_tx.tx_id_hash();
        let result = self.transaction_execute_raw(
            caller,
            nonce,
            gas_price,
            gas_limit,
            action,
            input,
            value,
            evm_tx.signature.chain_id(),
            tx_hash,
            withdraw_fee,
            precompiles,
        )?;

        self.register_tx_with_receipt(TransactionInReceipt::Signed(evm_tx), result.clone());

        Ok(result)
    }

    /// Do lowlevel operation with executor, without storing transaction into logs.
    /// Usefull for testing and transfering tokens from evm to sino and back.
    // Used for:
    // 1. deposit
    // 2. withdrawal? - currently unused
    // 3. executing transaction without commit
    pub fn with_executor<'a, F, U>(&'a mut self, precompiles: OwnedPrecompile, func: F) -> U
    where
        F: for<'r> FnOnce(
            &mut StackExecutor<
                'r,
                'r,
                MemoryStackState<'r, 'r, ExecutorContext<'a, Incomming>>,
                OwnedPrecompile,
            >,
        ) -> U,
    {
        let transaction_context = TransactionContext::default();
        let config = self.config.to_evm_params();
        let execution_context = ExecutorContext::new(
            &mut self.evm_backend,
            self.chain_context,
            transaction_context,
            self.config,
        );

        let gas_limit = execution_context.gas_left();
        let metadata = StackSubstateMetadata::new(gas_limit, &config);
        let state = MemoryStackState::new(
            metadata,
            &execution_context,
            self.feature_set.is_clear_logs_on_error_enabled(),
        );
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &precompiles);
        let result = func(&mut executor);
        let used_gas = executor.used_gas();
        let (updates, _logs) = executor.into_state().deconstruct();

        execution_context.apply(updates, used_gas);

        result
    }

    // TODO: Handle duplicates, statuses.
    fn register_tx_with_receipt(&mut self, tx: TransactionInReceipt, result: ExecutionResult) {
        let tx_hash = match &tx {
            TransactionInReceipt::Signed(tx) => tx.tx_id_hash(),
            TransactionInReceipt::Unsigned(tx) => tx.tx_id_hash(),
        };

        debug!(
            "Register tx = {} in EVM block = {}",
            tx_hash,
            self.evm_backend.block_number()
        );

        let tx_hashes = self.evm_backend.get_executed_transactions();

        assert!(!tx_hashes.contains(&tx_hash));

        let receipt = TransactionReceipt::new(
            tx,
            result.used_gas,
            self.evm_backend.block_number(),
            tx_hashes.len() as u64 + 1,
            result.tx_logs,
            (result.exit_reason, result.exit_data),
        );

        self.evm_backend.push_transaction_receipt(tx_hash, receipt);
    }

    // TODO: Make it cleaner - don't modify logs after storing, handle callback before push_transaction_receipt.
    pub fn modify_tx_logs<F, R>(&mut self, txid: H256, func: F) -> R
    where
        F: Fn(Option<&mut Vec<Log>>) -> R,
    {
        let mut tx = self
            .evm_backend
            .state
            .executed_transactions
            .iter_mut()
            .find(|(h, _)| *h == txid)
            .map(|(_, tx)| tx);
        let result = func(tx.as_mut().map(|tx| &mut tx.logs));
        if let Some(tx) = tx {
            tx.recalculate_bloom()
        };
        result
    }

    /// Mint evm tokens to some address.
    ///
    /// Internally just mint token, and create system transaction (not implemented):
    /// 1. Type: Call
    /// 2. from: EVM_MINT_ADDRESS
    /// 3. to: recipient (some address specified by method caller)
    /// 4. data: empty,
    /// 5. value: amount (specified by method caller)
    ///
    pub fn deposit(&mut self, recipient: H160, amount: U256) {
        self.with_executor(OwnedPrecompile::default(), |e| {
            e.state_mut().deposit(recipient, amount)
        });
    }

    pub fn register_swap_tx_in_evm(&mut self, mint_address: H160, recipient: H160, amount: U256) {
        let nonce = self.with_executor(OwnedPrecompile::default(), |e| {
            let nonce = e.nonce(mint_address);
            e.state_mut().inc_nonce(mint_address);
            nonce
        });
        let tx = UnsignedTransaction {
            nonce,
            gas_limit: 0.into(),
            gas_price: 0.into(),
            value: amount,
            input: Vec::new(),
            action: TransactionAction::Call(recipient),
        };
        let unsigned_tx = UnsignedTransactionWithCaller {
            unsigned_tx: tx,
            caller: mint_address,
            chain_id: self.config.chain_id,
            signed_compatible: self.feature_set.is_unsigned_tx_fix_enabled(),
        };
        let result = ExecutionResult {
            tx_logs: Vec::new(),
            used_gas: 0,
            exit_data: Vec::new(),
            exit_reason: ExitReason::Succeed(ExitSucceed::Returned),
            tx_id: unsigned_tx.tx_id_hash(),
            traces: Vec::new(),
        };
        self.register_tx_with_receipt(TransactionInReceipt::Unsigned(unsigned_tx), result)
    }

    /// After "swap from evm" transaction EVM_MINT_ADDRESS will cleanup. Using this method.
    pub fn reset_balance(&mut self, swap_addr: H160, ignore_reset_on_cleared: bool) {
        self.with_executor(OwnedPrecompile::default(), |e| {
            if !ignore_reset_on_cleared || e.state().basic(swap_addr).balance != U256::zero() {
                e.state_mut().reset_balance(swap_addr)
            }
        });
    }

    //  /// Burn some tokens on address:
    //  ///
    //  ///
    //  /// Internally just burn address, and create system transaction (not implemented):
    //  /// 1. Type: Call
    //  /// 2. from: from (some address specified by method caller)
    //  /// 3. to: EVM_MINT_ADDRESS
    //  /// 4. data: empty,
    //  /// 5. value: amount (specified by method caller)
    //  ///
    //  /// Note: This operation is failable, and can return error in case, when user has no enough tokens on his account.
    // pub fn burn(&mut self, from: H160, amount: U256) -> ExecutionResult {
    //     match self.with_executor(|e| e.state_mut().withdraw(evm_address, gweis)) {
    //         Ok(_) => {},
    //         Err(e) => return ExecutionResult {
    //             exit_reason: ExitReason::Error(e), // Error - should be rollbacked.
    //             exit_data: vec![],
    //             used_gas: 0,
    //             tx_logs: vec![]
    //         }
    //     }

    //     let unsigned_tx = UnsignedTransactionWithCaller {
    //         unsigned_tx: tx,
    //         caller,
    //         chain_id,
    //     };

    //     self.register_tx_with_receipt(TransactionInReceipt::Unsigned(unsigned_tx), result.clone());

    // }

    // pub fn get_tx_receipt_by_hash(&mut self, tx: H256) -> Option<&TransactionReceipt> {
    //     self.evm_backend.find_transaction_receipt(tx)
    // }
    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    pub fn balance(&self, addr: H160) -> U256 {
        self.evm_backend
            .get_account_state(addr)
            .unwrap_or_default()
            .balance
    }

    pub fn nonce(&self, addr: H160) -> U256 {
        self.evm_backend
            .get_account_state(addr)
            .unwrap_or_default()
            .nonce
    }

    pub fn deconstruct(self) -> EvmBackend<Incomming> {
        self.evm_backend
    }
}

// TODO: move out these blobs to test files
pub const HELLO_WORLD_CODE:&str = "608060405234801561001057600080fd5b5061011e806100206000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063942ae0a714602d575b600080fd5b603360ab565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101560715780820151818401526020810190506058565b50505050905090810190601f168015609d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60606040518060400160405280600a81526020017f68656c6c6f576f726c640000000000000000000000000000000000000000000081525090509056fea2646970667358221220fa787b95ca91ffe90fdb780b8ee8cb11c474bc63cb8217112c88bc465f7ea7d364736f6c63430007020033";
pub const HELLO_WORLD_ABI: &str = "942ae0a7";
pub const HELLO_WORLD_RESULT:&str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000a68656c6c6f576f726c6400000000000000000000000000000000000000000000";
pub const HELLO_WORLD_CODE_SAVED:&str = "6080604052348015600f57600080fd5b506004361060285760003560e01c8063942ae0a714602d575b600080fd5b603360ab565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101560715780820151818401526020810190506058565b50505050905090810190601f168015609d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60606040518060400160405280600a81526020017f68656c6c6f576f726c640000000000000000000000000000000000000000000081525090509056fea2646970667358221220fa787b95ca91ffe90fdb780b8ee8cb11c474bc63cb8217112c88bc465f7ea7d364736f6c63430007020033";


    