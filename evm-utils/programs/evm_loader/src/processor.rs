use std::cell::RefMut;
use std::fmt::Write;
use std::ops::DerefMut;

use super::account_structure::AccountStructure;
use super::instructions::{
    EvmBigTransaction, EvmInstruction, ExecuteTransaction, FeePayerType,
    EVM_INSTRUCTION_BORSH_PREFIX,
};
use super::precompiles;
use super::scope::*;
use evm_state::U256;
use log::*;

use borsh::BorshDeserialize;
use evm::{gweis_to_lamports, Executor, ExitReason};
use evm_state::ExecutionResult;
use serde::de::DeserializeOwned;
use program_runtime::ic_msg;
use program_runtime::invoke_context::InvokeContext;
use sdk::account::{AccountSharedData, ReadableAccount, WritableAccount};
use sdk::instruction::InstructionError;
use sdk::{keyed_account::KeyedAccount, program_utils::limited_deserialize};

use super::error::EvmError;
use super::tx_chunks::TxChunks;

pub const BURN_ADDR: evm_state::H160 = evm_state::H160::zero();

/// Return the next AccountInfo or a NotEnoughAccountKeys error
pub fn next_account_info<'a, 'b, I: Iterator<Item = &'a KeyedAccount<'b>>>(
    iter: &mut I,
) -> Result<I::Item, InstructionError> {
    iter.next().ok_or(InstructionError::NotEnoughAccountKeys)
}

#[derive(Default, Debug, Clone)]
pub struct EvmProcessor {}

impl EvmProcessor {
    pub fn process_instruction(
        &self,
        first_keyed_account: usize,
        data: &[u8],
        invoke_context: &mut InvokeContext,
    ) -> Result<(), InstructionError> {
        let (evm_state_account, keyed_accounts) =
            Self::check_evm_account(first_keyed_account, invoke_context)?;

        let cross_execution_enabled = invoke_context
            .feature_set
            .is_active(&sdk::feature_set::sino::evm_cross_execution::id());
        let register_swap_tx_in_evm = invoke_context
            .feature_set
            .is_active(&sdk::feature_set::sino::native_swap_in_evm_history::id());
        let new_error_handling = invoke_context
            .feature_set
            .is_active(&sdk::feature_set::sino::evm_new_error_handling::id());
        let ignore_reset_on_cleared = invoke_context
            .feature_set
            .is_active(&sdk::feature_set::sino::ignore_reset_on_cleared::id());
        let free_ownership_require_signer = invoke_context
            .feature_set
            .is_active(&sdk::feature_set::sino::free_ownership_require_signer::id());
        let borsh_serialization_enabled = invoke_context
            .feature_set
            .is_active(&sdk::feature_set::sino::evm_instruction_borsh_serialization::id());

        let cross_execution = invoke_context.get_stack_height() != 1;

        if cross_execution && !cross_execution_enabled {
            ic_msg!(invoke_context, "Cross-Program evm execution not enabled.");
            return Err(EvmError::CrossExecutionNotEnabled.into());
        }

        let evm_executor = if let Some(evm_executor) = invoke_context.get_evm_executor() {
            evm_executor
        } else {
            ic_msg!(
                invoke_context,
                "Invoke context didn't provide evm executor."
            );
            return Err(EvmError::EvmExecutorNotFound.into());
        };
        // bind variable to increase lifetime of temporary RefCell borrow.
        let mut evm_executor_borrow;
        // evm executor cannot be borrowed, because it not exist in invoke context, or borrowing failed.
        let executor = if let Ok(evm_executor) = evm_executor.try_borrow_mut() {
            evm_executor_borrow = evm_executor;
            evm_executor_borrow.deref_mut()
        } else {
            ic_msg!(
                invoke_context,
                "Recursive cross-program evm execution not enabled."
            );
            return Err(EvmError::RecursiveCrossExecution.into());
        };

        let accounts = AccountStructure::new(evm_state_account, keyed_accounts);

        let mut borsh_serialization_used = false;
        let ix = match (borsh_serialization_enabled, data.split_first()) {
            (true, Some((&prefix, borsh_data))) if prefix == EVM_INSTRUCTION_BORSH_PREFIX => {
                borsh_serialization_used = true;
                BorshDeserialize::deserialize(&mut &*borsh_data)
                    .map_err(|_| InstructionError::InvalidInstructionData)?
            }
            _ => limited_deserialize(data)?,
        };
        trace!("Run evm exec with ix = {:?}.", ix);
        let result = match ix {
            EvmInstruction::EvmBigTransaction(big_tx) => {
                self.process_big_tx(invoke_context, accounts, big_tx)
            }
            EvmInstruction::FreeOwnership {} => self.process_free_ownership(
                executor,
                invoke_context,
                accounts,
                free_ownership_require_signer,
            ),
            EvmInstruction::SwapNativeToEther {
                lamports,
                evm_address,
            } => self.process_swap_to_evm(
                executor,
                invoke_context,
                accounts,
                lamports,
                evm_address,
                register_swap_tx_in_evm,
            ),
            EvmInstruction::ExecuteTransaction { tx, fee_type } => self.process_execute_tx(
                executor,
                invoke_context,
                accounts,
                tx,
                fee_type,
                borsh_serialization_used,
            ),
        };

        if register_swap_tx_in_evm {
            executor.reset_balance(*precompiles::ETH_TO_SOR_ADDR, ignore_reset_on_cleared)
        }

        // When old error handling, manually convert EvmError to InstructionError
        result.or_else(|error| {
            ic_msg!(invoke_context, "Execution error: {}", error);

            let err = if !new_error_handling {
                use EvmError::*;
                match error {
                    CrossExecutionNotEnabled
                    | EvmExecutorNotFound
                    | RecursiveCrossExecution
                    | FreeNotEvmAccount
                    | InternalTransactionError => InstructionError::InvalidError,

                    InternalExecutorError
                    | AuthorizedTransactionIncorrectAddress
                    | AllocateStorageFailed
                    | WriteStorageFailed
                    | DeserializationError => InstructionError::InvalidArgument,

                    MissingAccount => InstructionError::MissingAccount,
                    MissingRequiredSignature => InstructionError::MissingRequiredSignature,
                    SwapInsufficient => InstructionError::InsufficientFunds,
                    BorrowingFailed => InstructionError::AccountBorrowFailed,
                    RevertTransaction => return Ok(()), // originally revert was not an error
                    // future error would be just invalid errors.
                    _ => InstructionError::InvalidError,
                }
            } else {
                error.into()
            };

            Err(err)
        })
    }

    fn process_execute_tx(
        &self,
        executor: &mut Executor,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        tx: ExecuteTransaction,
        fee_type: FeePayerType,
        borsh_used: bool,
    ) -> Result<(), EvmError> {
        let is_big = tx.is_big();
        let keep_old_errors = true;
        // TODO: Add logic for fee collector
        let (sender, _fee_collector) = if is_big {
            (accounts.users.get(1), accounts.users.get(2))
        } else {
            (accounts.first(), accounts.users.get(1))
        };

        // FeePayerType::Native is possible only in new serialization format
        if fee_type.is_native() && sender.is_none() {
            ic_msg!(invoke_context, "Fee payer is native but no sender providen",);
            return Err(EvmError::MissingRequiredSignature);
        }

        fn precompile_set(
            support_precompile: bool,
            evm_new_precompiles: bool,
        ) -> precompiles::PrecompileSet {
            match (support_precompile, evm_new_precompiles) {
                (false, _) => precompiles::PrecompileSet::No,
                (true, false) => precompiles::PrecompileSet::SinoClassic,
                (true, true) => precompiles::PrecompileSet::SinoNext,
            }
        }

        let withdraw_fee_from_evm = fee_type.is_evm();
        let mut tx_gas_price;
        let result = match tx {
            ExecuteTransaction::Signed { tx } => {
                let tx = match tx {
                    Some(tx) => tx,
                    None => Self::get_tx_from_storage(invoke_context, accounts, borsh_used)?,
                };
                ic_msg!(
                    invoke_context,
                    "Executing transaction: gas_limit:{}, gas_price:{}, value:{}, action:{:?},",
                    tx.gas_limit,
                    tx.gas_price,
                    tx.value,
                    tx.action
                );
                tx_gas_price = tx.gas_price;
                let activate_precompile = precompile_set(
                    executor.support_precompile(),
                    invoke_context
                        .feature_set
                        .is_active(&sdk::feature_set::sino::evm_new_precompiles::id()),
                );
                executor.transaction_execute(
                    tx,
                    withdraw_fee_from_evm,
                    precompiles::entrypoint(accounts, activate_precompile, keep_old_errors),
                )
            }
            ExecuteTransaction::ProgramAuthorized { tx, from } => {
                let program_account = sender.ok_or_else(|| {
                    ic_msg!(
                        invoke_context,
                        "Not enough accounts, expected signer address as second account."
                    );
                    EvmError::MissingAccount
                })?;
                Self::check_program_account(
                    invoke_context,
                    program_account,
                    from,
                    executor.feature_set.is_unsigned_tx_fix_enabled(),
                )?;
                let tx = match tx {
                    Some(tx) => tx,
                    None => Self::get_tx_from_storage(invoke_context, accounts, borsh_used)?,
                };
                ic_msg!(
                    invoke_context,
                    "Executing authorized transaction: gas_limit:{}, gas_price:{}, value:{}, action:{:?},",
                    tx.gas_limit,
                    tx.gas_price,
                    tx.value,
                    tx.action
                );
                tx_gas_price = tx.gas_price;
                let activate_precompile = precompile_set(
                    executor.support_precompile(),
                    invoke_context
                        .feature_set
                        .is_active(&sdk::feature_set::sino::evm_new_precompiles::id()),
                );
                executor.transaction_execute_unsinged(
                    from,
                    tx,
                    withdraw_fee_from_evm,
                    precompiles::entrypoint(accounts, activate_precompile, keep_old_errors),
                )
            }
        };

        if executor.feature_set.is_unsigned_tx_fix_enabled() && is_big {
            let storage = Self::get_big_transaction_storage(invoke_context, &accounts)?;
            self.cleanup_storage(invoke_context, storage, sender.unwrap_or(accounts.evm))?;
        }
        if executor
            .feature_set
            .is_accept_zero_gas_price_with_native_fee_enabled()
            && fee_type.is_native()
            && tx_gas_price.is_zero()
        {
            tx_gas_price = executor.config().burn_gas_price;
        }
        self.handle_transaction_result(
            executor,
            invoke_context,
            accounts,
            sender,
            tx_gas_price,
            result,
            withdraw_fee_from_evm,
        )
    }

    fn process_free_ownership(
        &self,
        _executor: &mut Executor,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        free_ownership_require_signer: bool,
    ) -> Result<(), EvmError> {
        let user = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "FreeOwnership: expected account as argument."
            );
            EvmError::MissingAccount
        })?;
        if free_ownership_require_signer && user.signer_key().is_none() {
            ic_msg!(invoke_context, "FreeOwnership: Missing signer key.");
            return Err(EvmError::MissingRequiredSignature);
        }

        let user_pk = user.unsigned_key();
        let mut user = user
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;

        if *user.owner() != crate::ID || *user_pk == solana::evm_state::ID {
            ic_msg!(
                invoke_context,
                "FreeOwnership: Incorrect account provided, maybe this account is not owned by evm."
            );
            return Err(EvmError::FreeNotEvmAccount);
        }
        user.set_owner(sdk::system_program::id());
        Ok(())
    }

    fn process_swap_to_evm(
        &self,
        executor: &mut Executor,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        lamports: u64,
        evm_address: evm::Address,
        register_swap_tx_in_evm: bool,
    ) -> Result<(), EvmError> {
        let gweis = evm::lamports_to_gwei(lamports);
        let user = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "SwapNativeToEther: No sender account found in swap to evm."
            );
            EvmError::MissingAccount
        })?;

        ic_msg!(
            invoke_context,
            "SwapNativeToEther: Sending tokens from native to evm chain from={},to={:?}",
            user.unsigned_key(),
            evm_address
        );

        if lamports == 0 {
            return Ok(());
        }

        if user.signer_key().is_none() {
            ic_msg!(invoke_context, "SwapNativeToEther: from must sign");
            return Err(EvmError::MissingRequiredSignature);
        }

        let mut user_account = user
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;
        if lamports > user_account.lamports() {
            ic_msg!(
                invoke_context,
                "SwapNativeToEther: insufficient lamports ({}, need {})",
                user_account.lamports(),
                lamports
            );
            return Err(EvmError::SwapInsufficient);
        }

        let user_account_lamports = user_account.lamports().saturating_sub(lamports);
        user_account.set_lamports(user_account_lamports);
        let mut evm_account = accounts
            .evm
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;

        let evm_account_lamports = evm_account.lamports().saturating_add(lamports);
        evm_account.set_lamports(evm_account_lamports);
        executor.deposit(evm_address, gweis);
        if register_swap_tx_in_evm {
            executor.register_swap_tx_in_evm(*precompiles::ETH_TO_SOR_ADDR, evm_address, gweis)
        }
        Ok(())
    }

    fn process_big_tx(
        &self,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        big_tx: EvmBigTransaction,
    ) -> Result<(), EvmError> {
        debug!("executing big_tx = {:?}", big_tx);

        let mut storage = Self::get_big_transaction_storage(invoke_context, &accounts)?;
        let mut tx_chunks = TxChunks::new(storage.data_as_mut_slice());

        match big_tx {
            EvmBigTransaction::EvmTransactionAllocate { size } => {
                tx_chunks.init(size as usize).map_err(|e| {
                    ic_msg!(
                        invoke_context,
                        "EvmTransactionAllocate: allocate error: {:?}",
                        e
                    );
                    EvmError::AllocateStorageFailed
                })?;

                Ok(())
            }

            EvmBigTransaction::EvmTransactionWrite { offset, data } => {
                ic_msg!(
                    invoke_context,
                    "EvmTransactionWrite: Writing at offset = {}, data = {:?}",
                    offset,
                    data
                );
                tx_chunks.push(offset as usize, data).map_err(|e| {
                    ic_msg!(
                        invoke_context,
                        "EvmTransactionWrite: Tx write error: {:?}",
                        e
                    );
                    EvmError::WriteStorageFailed
                })?;

                Ok(())
            }
        }
    }

    pub fn cleanup_storage<'a>(
        &self,
        invoke_context: &InvokeContext,
        mut storage_ref: RefMut<AccountSharedData>,
        user: &'a KeyedAccount<'a>,
    ) -> Result<(), EvmError> {
        let balance = storage_ref.lamports();

        storage_ref.set_lamports(0);

        let mut user_acc = user
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?;
        let user_acc_lamports = user_acc.lamports().saturating_add(balance);
        user_acc.set_lamports(user_acc_lamports);

        ic_msg!(
            invoke_context,
            "Refunding storage rent fee to transaction sender fee:{:?}, sender:{}",
            balance,
            user.unsigned_key()
        );
        Ok(())
    }

    fn check_program_account(
        invoke_context: &InvokeContext,
        program_account: &KeyedAccount,
        from: evm::Address,
        unsigned_tx_fix: bool,
    ) -> Result<(), EvmError> {
        let key = program_account.signer_key().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "Second account is not a signer, cannot execute transaction."
            );
            EvmError::MissingRequiredSignature
        })?;
        let from_expected = crate::evm_address_for_program(*key);
        if from_expected != from {
            ic_msg!(
                invoke_context,
                "From is not calculated with evm_address_for_program."
            );
            return Err(EvmError::AuthorizedTransactionIncorrectAddress);
        }

        if unsigned_tx_fix {
            let program_caller = invoke_context
                .get_parent_caller()
                .copied()
                .unwrap_or_default();
            let program_owner = *program_account
                .try_account_ref()
                .map_err(|_| EvmError::BorrowingFailed)?
                .owner();
            if program_owner != program_caller {
                ic_msg!(
                    invoke_context,
                    "Incorrect caller program_caller:{}, program_owner:{}",
                    program_caller,
                    program_owner,
                );
                return Err(EvmError::AuthorizedTransactionIncorrectOwner);
            }
        }
        Ok(())
    }

    fn get_tx_from_storage<T>(
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        deserialize_chunks_with_borsh: bool,
    ) -> Result<T, EvmError>
    where
        T: BorshDeserialize + DeserializeOwned,
    {
        let mut storage = Self::get_big_transaction_storage(invoke_context, &accounts)?;
        let tx_chunks = TxChunks::new(storage.data_mut().as_mut_slice());
        debug!("Tx chunks crc = {:#x}", tx_chunks.crc());

        let bytes = tx_chunks.take();
        debug!("Trying to deserialize tx chunks byte = {:?}", bytes);
        if deserialize_chunks_with_borsh {
            BorshDeserialize::deserialize(&mut bytes.as_slice()).map_err(|e| {
                ic_msg!(invoke_context, "Tx chunks deserialize error: {:?}", e);
                EvmError::DeserializationError
            })
        } else {
            bincode::deserialize(&bytes).map_err(|e| {
                ic_msg!(invoke_context, "Tx chunks deserialize error: {:?}", e);
                EvmError::DeserializationError
            })
        }
    }

    fn get_big_transaction_storage<'a>(
        invoke_context: &InvokeContext,
        accounts: &'a AccountStructure,
    ) -> Result<RefMut<'a, AccountSharedData>, EvmError> {
        let storage_account = accounts.first().ok_or_else(|| {
            ic_msg!(
                invoke_context,
                "EvmBigTransaction: No storage account found."
            );
            EvmError::MissingAccount
        })?;

        if storage_account.signer_key().is_none() {
            ic_msg!(
                invoke_context,
                "EvmBigTransaction: Storage should sign instruction."
            );
            return Err(EvmError::MissingRequiredSignature);
        }
        storage_account
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)
    }

    /// Calculate fee based on transaction result and charge native account
    pub fn charge_native_account(
        tx_result: &ExecutionResult,
        fee: U256,
        native_account: &KeyedAccount,
        evm_account: &KeyedAccount,
    ) -> Result<(), EvmError> {
        // Charge only when transaction succeeded
        if matches!(tx_result.exit_reason, ExitReason::Succeed(_)) {
            let (fee, _) = gweis_to_lamports(fee);

            trace!("Charging account for fee {}", fee);
            let mut account_data = native_account
                .try_account_ref_mut()
                .map_err(|_| EvmError::BorrowingFailed)?;
            let new_lamports = account_data
                .lamports()
                .checked_sub(fee)
                .ok_or(EvmError::NativeAccountInsufficientFunds)?;
            account_data.set_lamports(new_lamports);

            let mut evm_account = evm_account
                .try_account_ref_mut()
                .map_err(|_| EvmError::BorrowingFailed)?;
            let new_evm_lamports = evm_account
                .lamports()
                .checked_add(fee)
                .ok_or(EvmError::OverflowInRefund)?;
            evm_account.set_lamports(new_evm_lamports);
        }
        Ok(())
    }

    // Handle executor errors.
    // refund fee
    pub fn handle_transaction_result(
        &self,
        executor: &mut Executor,
        invoke_context: &InvokeContext,
        accounts: AccountStructure,
        sender: Option<&KeyedAccount>,
        tx_gas_price: evm_state::U256,
        result: Result<evm_state::ExecutionResult, evm_state::error::Error>,
        withdraw_fee_from_evm: bool,
    ) -> Result<(), EvmError> {
        let remove_native_logs_after_swap = true;
        let mut result = result.map_err(|e| {
            ic_msg!(invoke_context, "Transaction execution error: {}", e);
            EvmError::InternalExecutorError
        })?;

        if remove_native_logs_after_swap {
            executor.modify_tx_logs(result.tx_id, |logs| {
                if let Some(logs) = logs {
                    precompiles::filter_native_logs(accounts, logs).map_err(|e| {
                        ic_msg!(invoke_context, "Filter native logs error: {}", e);
                        EvmError::PrecompileError
                    })?;
                } else {
                    ic_msg!(invoke_context, "Unable to find tx by txid");
                    return Err(EvmError::PrecompileError);
                }
                Ok(())
            })?;
        } else {
            // same logic, but don't save result to block
            precompiles::filter_native_logs(accounts, &mut result.tx_logs).map_err(|e| {
                ic_msg!(invoke_context, "Filter native logs error: {}", e);
                EvmError::PrecompileError
            })?;
        }

        write!(
            crate::extension::MultilineLogger::new(invoke_context.get_log_collector()),
            "{}",
            result
        )
        .expect("no error during writes");
        if matches!(
            result.exit_reason,
            ExitReason::Fatal(_) | ExitReason::Error(_)
        ) {
            return Err(EvmError::InternalTransactionError);
        }
        // Fee refund will not work with revert, because transaction will be reverted from native chain too.
        if let ExitReason::Revert(_) = result.exit_reason {
            return Err(EvmError::RevertTransaction);
        }

        let full_fee = tx_gas_price * result.used_gas;

        let burn_fee = executor.config().burn_gas_price * result.used_gas;

        if full_fee < burn_fee {
            ic_msg!(
                invoke_context,
                "Transaction execution error: fee less than need to burn (burn_gas_price = {})",
                executor.config().burn_gas_price
            );
            return Err(EvmError::OverflowInRefund);
        }

        // refund only remaining part
        let refund_fee = full_fee - burn_fee;
        let (refund_native_fee, _) = gweis_to_lamports(refund_fee);

        // 1. Fee can be charged from evm account or native. (evm part is done in Executor::transaction_execute* methods.)
        if !withdraw_fee_from_evm {
            let sender = sender.as_ref().ok_or(EvmError::MissingRequiredSignature)?;
            Self::charge_native_account(&result, full_fee, sender, accounts.evm)?;
        }

        // 2. Then we should burn some part of it.
        // This if only register burn to the deposit address, withdrawal is done in 1.
        if burn_fee > U256::zero() {
            trace!("Burning fee {}", burn_fee);
            // we already withdraw gas_price during transaction_execute,
            // if burn_fixed_fee is activated, we should deposit to burn addr (0x00..00)
            executor.deposit(BURN_ADDR, burn_fee);
        };

        // 3. And transfer back remaining fee to the bridge as refund of native fee that was used to wrap this transaction.
        if let Some(payer) = sender {
            ic_msg!(
                invoke_context,
                "Refunding transaction fee to transaction sender fee:{:?}, sender:{}",
                refund_native_fee,
                payer.unsigned_key()
            );
            accounts.refund_fee(payer, refund_native_fee)?;
        } else {
            ic_msg!(
                invoke_context,
                "Sender didnt give his account, ignoring fee refund.",
            );
        }

        Ok(())
    }

    /// Ensure that first account is program itself, and it's locked for writes.
    fn check_evm_account<'a>(
        first_keyed_account: usize,
        invoke_context: &'a InvokeContext,
    ) -> Result<(&'a KeyedAccount<'a>, &'a [KeyedAccount<'a>]), InstructionError> {
        let keyed_accounts = invoke_context.get_keyed_accounts()?;
        let first = keyed_accounts
            .get(first_keyed_account)
            .ok_or(InstructionError::NotEnoughAccountKeys)?;

        trace!("first = {:?}", first);
        trace!("all = {:?}", keyed_accounts);
        if first.unsigned_key() != &solana::evm_state::id() || !first.is_writable() {
            debug!("First account is not evm, or not writable");
            return Err(InstructionError::MissingAccount);
        }

        let keyed_accounts = &keyed_accounts[(first_keyed_account + 1)..];
        Ok((first, keyed_accounts))
    }
}

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

const TEST_CHAIN_ID: u64 = 0xdead;
#[doc(hidden)]
pub fn dummy_call(nonce: usize) -> (evm::Transaction, evm::UnsignedTransaction) {
    let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
    let dummy_address = evm::addr_from_public_key(&evm::PublicKey::from_secret_key(
        evm::SECP256K1,
        &secret_key,
    ));

    let tx_call = evm::UnsignedTransaction {
        nonce: nonce.into(),
        gas_price: 1u32.into(),
        gas_limit: 300000u32.into(),
        action: evm::TransactionAction::Call(dummy_address),
        value: 0u32.into(),
        input: vec![],
    };

    (
        tx_call.clone().sign(&secret_key, Some(TEST_CHAIN_ID)),
        tx_call,
    )
}

