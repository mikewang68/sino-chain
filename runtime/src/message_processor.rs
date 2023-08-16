use {
    serde::{Deserialize, Serialize},
    measure::measure::Measure,
    program_runtime::{
        compute_budget::ComputeBudget,
        instruction_recorder::InstructionRecorder,
        invoke_context::{
            BuiltinProgram, Executors, InvokeContext, ProcessInstructionResult,
            TransactionAccountRefCell,
        },
        log_collector::LogCollector,
        sysvar_cache::SysvarCache,
        timings::{ExecuteDetailsTimings, ExecuteTimings},
    },
    sdk::{
        account::WritableAccount,
        feature_set::{prevent_calling_precompiles_as_programs, FeatureSet},
        hash::Hash,
        message::SanitizedMessage,
        precompiles::is_precompile,
        rent::Rent,
        saturating_add_assign,
        sysvar::instructions,
        transaction::TransactionError,
    },
    std::{borrow::Cow, cell::RefCell, rc::Rc, sync::Arc},
};

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct MessageProcessor {}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl ::frozen_abi::abi_example::AbiExample for MessageProcessor {
    fn example() -> Self {
        // MessageProcessor's fields are #[serde(skip)]-ed and not Serialize
        // so, just rely on Default anyway.
        MessageProcessor::default()
    }
}

/// Trace of all instructions attempted
pub type InstructionTrace = Vec<InstructionRecorder>;

/// Resultant information gathered from calling process_message()
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProcessedMessageInfo {
    /// The change in accounts data len
    pub accounts_data_len_delta: i64,
}

impl MessageProcessor {
    /// Process a message.
    /// This method calls each instruction in the message over the set of loaded accounts.
    /// For each instruction it calls the program entrypoint method and verifies that the result of
    /// the call does not violate the bank's accounting rules.
    /// The accounts are committed back to the bank only if every instruction succeeds.
    #[allow(clippy::too_many_arguments)]
    pub fn process_message(
        builtin_programs: &[BuiltinProgram],
        message: &SanitizedMessage,
        program_indices: &[Vec<usize>],
        accounts: &[TransactionAccountRefCell],
        rent: Rent,
        log_collector: Option<Rc<RefCell<LogCollector>>>,
        executors: Rc<RefCell<Executors>>,
        instruction_trace: &mut InstructionTrace,
        feature_set: Arc<FeatureSet>,
        compute_budget: ComputeBudget,
        timings: &mut ExecuteTimings,
        sysvar_cache: &SysvarCache,
        blockhash: Hash,
        wens_per_signature: u64,
        current_accounts_data_len: u64,
        accumulated_consumed_units: &mut u64,
        evm_executor: Option<Rc<RefCell<evm_state::Executor>>>,
    ) -> Result<ProcessedMessageInfo, TransactionError> {
        let mut invoke_context = InvokeContext::new(
            rent,
            accounts,
            builtin_programs,
            Cow::Borrowed(sysvar_cache),
            log_collector,
            compute_budget,
            executors,
            feature_set,
            blockhash,
            wens_per_signature,
            current_accounts_data_len,
            evm_executor,
        );

        debug_assert_eq!(program_indices.len(), message.instructions().len());
        for (instruction_index, ((program_id, instruction), program_indices)) in message
            .program_instructions_iter()
            .zip(program_indices.iter())
            .enumerate()
        {
            invoke_context.record_top_level_instruction(
                instruction.decompile(message).map_err(|err| {
                    TransactionError::InstructionError(instruction_index as u8, err)
                })?,
            );

            if invoke_context
                .feature_set
                .is_active(&prevent_calling_precompiles_as_programs::id())
                && is_precompile(program_id, |id| invoke_context.feature_set.is_active(id))
            {
                // Precompiled programs don't have an instruction processor
                continue;
            }

            // Fixup the special instructions key if present
            // before the account pre-values are taken care of
            for (pubkey, account) in accounts.iter().take(message.account_keys_len()) {
                if instructions::check_id(pubkey) {
                    let mut mut_account_ref = account.borrow_mut();
                    instructions::store_current_index(
                        mut_account_ref.data_as_mut_slice(),
                        instruction_index as u16,
                    );
                    break;
                }
            }

            let mut time = Measure::start("execute_instruction");
            let ProcessInstructionResult {
                compute_units_consumed,
                result,
            } = invoke_context.process_instruction(
                message,
                instruction,
                program_indices,
                &[],
                &[],
                timings,
            );
            time.stop();
            *accumulated_consumed_units =
                accumulated_consumed_units.saturating_add(compute_units_consumed);
            timings.details.accumulate_program(
                program_id,
                time.as_us(),
                compute_units_consumed,
                result.is_err(),
            );
            invoke_context.timings = {
                timings.details.accumulate(&invoke_context.timings);
                ExecuteDetailsTimings::default()
            };
            saturating_add_assign!(
                timings.execute_accessories.process_instructions.total_us,
                time.as_us()
            );

            result.map_err(|err| {
                instruction_trace.append(invoke_context.get_instruction_trace_mut());
                TransactionError::InstructionError(instruction_index as u8, err)
            })?;
        }
        instruction_trace.append(invoke_context.get_instruction_trace_mut());
        Ok(ProcessedMessageInfo {
            accounts_data_len_delta: invoke_context.get_accounts_data_meter().delta(),
        })
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::rent_collector::RentCollector,
        sdk::{
            account::{AccountSharedData, ReadableAccount},
            instruction::{AccountMeta, Instruction, InstructionError},
            keyed_account::keyed_account_at_index,
            message::Message,
            native_loader::{self, create_loadable_account_for_test},
            pubkey::Pubkey,
            secp256k1_instruction::new_secp256k1_instruction,
            secp256k1_program,
        },
    };

    #[derive(Debug, Serialize, Deserialize)]
    enum MockInstruction {
        NoopSuccess,
        NoopFail,
        ModifyOwned,
        ModifyNotOwned,
        ModifyReadonly,
    }

    #[test]
    fn test_process_message_readonly_handling() {
        #[derive(Serialize, Deserialize)]
        enum MockSystemInstruction {
            Correct,
            AttemptCredit { wens: u64 },
            AttemptDataChange { data: u8 },
        }

        fn mock_system_process_instruction(
            first_instruction_account: usize,
            data: &[u8],
            invoke_context: &mut InvokeContext,
        ) -> Result<(), InstructionError> {
            let keyed_accounts = invoke_context.get_keyed_accounts()?;
            if let Ok(instruction) = bincode::deserialize(data) {
                match instruction {
                    MockSystemInstruction::Correct => Ok(()),
                    MockSystemInstruction::AttemptCredit { wens } => {
                        keyed_account_at_index(keyed_accounts, first_instruction_account)?
                            .account
                            .borrow_mut()
                            .checked_sub_wens(wens)?;
                        keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?
                            .account
                            .borrow_mut()
                            .checked_add_wens(wens)?;
                        Ok(())
                    }
                    // Change data in a read-only account
                    MockSystemInstruction::AttemptDataChange { data } => {
                        keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?
                            .account
                            .borrow_mut()
                            .set_data(vec![data]);
                        Ok(())
                    }
                }
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }

        let mock_system_program_id = Pubkey::new(&[2u8; 32]);
        let rent_collector = RentCollector::default();
        let builtin_programs = &[BuiltinProgram {
            program_id: mock_system_program_id,
            process_instruction: mock_system_process_instruction,
        }];

        let program_account = Rc::new(RefCell::new(create_loadable_account_for_test(
            "mock_system_program",
        )));
        let accounts = vec![
            (
                sdk::pubkey::new_rand(),
                AccountSharedData::new_ref(100, 1, &mock_system_program_id),
            ),
            (
                sdk::pubkey::new_rand(),
                AccountSharedData::new_ref(0, 1, &mock_system_program_id),
            ),
            (mock_system_program_id, program_account),
        ];
        let program_indices = vec![vec![2]];

        let executors = Rc::new(RefCell::new(Executors::default()));

        let account_metas = vec![
            AccountMeta::new(accounts[0].0, true),
            AccountMeta::new_readonly(accounts[1].0, false),
        ];
        let message = SanitizedMessage::Legacy(Message::new(
            &[Instruction::new_with_bincode(
                mock_system_program_id,
                &MockSystemInstruction::Correct,
                account_metas.clone(),
            )],
            Some(&accounts[0].0),
        ));
        let sysvar_cache = SysvarCache::default();
        let result = MessageProcessor::process_message(
            builtin_programs,
            &message,
            &program_indices,
            &accounts,
            rent_collector.rent,
            None,
            executors.clone(),
            &mut Vec::new(),
            Arc::new(FeatureSet::all_enabled()),
            ComputeBudget::default(),
            &mut ExecuteTimings::default(),
            &sysvar_cache,
            Hash::default(),
            0,
            0,
            &mut 0,
            None,
        );
        assert!(result.is_ok());
        assert_eq!(accounts[0].1.borrow().wens(), 100);
        assert_eq!(accounts[1].1.borrow().wens(), 0);

        let message = SanitizedMessage::Legacy(Message::new(
            &[Instruction::new_with_bincode(
                mock_system_program_id,
                &MockSystemInstruction::AttemptCredit { wens: 50 },
                account_metas.clone(),
            )],
            Some(&accounts[0].0),
        ));

        let result = MessageProcessor::process_message(
            builtin_programs,
            &message,
            &program_indices,
            &accounts,
            rent_collector.rent,
            None,
            executors.clone(),
            &mut Vec::new(),
            Arc::new(FeatureSet::all_enabled()),
            ComputeBudget::default(),
            &mut ExecuteTimings::default(),
            &sysvar_cache,
            Hash::default(),
            0,
            0,
            &mut 0,
            None,
        );
        assert_eq!(
            result,
            Err(TransactionError::InstructionError(
                0,
                InstructionError::ReadonlyWenChange
            ))
        );

        let message = SanitizedMessage::Legacy(Message::new(
            &[Instruction::new_with_bincode(
                mock_system_program_id,
                &MockSystemInstruction::AttemptDataChange { data: 50 },
                account_metas,
            )],
            Some(&accounts[0].0),
        ));

        let result = MessageProcessor::process_message(
            builtin_programs,
            &message,
            &program_indices,
            &accounts,
            rent_collector.rent,
            None,
            executors,
            &mut Vec::new(),
            Arc::new(FeatureSet::all_enabled()),
            ComputeBudget::default(),
            &mut ExecuteTimings::default(),
            &sysvar_cache,
            Hash::default(),
            0,
            0,
            &mut 0,
            None,
        );
        assert_eq!(
            result,
            Err(TransactionError::InstructionError(
                0,
                InstructionError::ReadonlyDataModified
            ))
        );
    }

    #[test]
    fn test_process_message_duplicate_accounts() {
        #[derive(Serialize, Deserialize)]
        enum MockSystemInstruction {
            BorrowFail,
            MultiBorrowMut,
            DoWork { wens: u64, data: u8 },
        }

        fn mock_system_process_instruction(
            first_instruction_account: usize,
            data: &[u8],
            invoke_context: &mut InvokeContext,
        ) -> Result<(), InstructionError> {
            let keyed_accounts = invoke_context.get_keyed_accounts()?;
            if let Ok(instruction) = bincode::deserialize(data) {
                match instruction {
                    MockSystemInstruction::BorrowFail => {
                        let from_account =
                            keyed_account_at_index(keyed_accounts, first_instruction_account)?
                                .try_account_ref_mut()?;
                        let dup_account =
                            keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?
                                .try_account_ref_mut()?;
                        if from_account.wens() != dup_account.wens() {
                            return Err(InstructionError::InvalidArgument);
                        }
                        Ok(())
                    }
                    MockSystemInstruction::MultiBorrowMut => {
                        let from_wens = {
                            let from_account =
                                keyed_account_at_index(keyed_accounts, first_instruction_account)?
                                    .try_account_ref_mut()?;
                            from_account.wens()
                        };
                        let dup_wens = {
                            let dup_account = keyed_account_at_index(
                                keyed_accounts,
                                first_instruction_account + 2,
                            )?
                            .try_account_ref_mut()?;
                            dup_account.wens()
                        };
                        if from_wens != dup_wens {
                            return Err(InstructionError::InvalidArgument);
                        }
                        Ok(())
                    }
                    MockSystemInstruction::DoWork { wens, data } => {
                        {
                            let mut to_account = keyed_account_at_index(
                                keyed_accounts,
                                first_instruction_account + 1,
                            )?
                            .try_account_ref_mut()?;
                            let mut dup_account = keyed_account_at_index(
                                keyed_accounts,
                                first_instruction_account + 2,
                            )?
                            .try_account_ref_mut()?;
                            dup_account.checked_sub_wens(wens)?;
                            to_account.checked_add_wens(wens)?;
                            dup_account.set_data(vec![data]);
                        }
                        keyed_account_at_index(keyed_accounts, first_instruction_account)?
                            .try_account_ref_mut()?
                            .checked_sub_wens(wens)?;
                        keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?
                            .try_account_ref_mut()?
                            .checked_add_wens(wens)?;
                        Ok(())
                    }
                }
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }

        let mock_program_id = Pubkey::new(&[2u8; 32]);
        let rent_collector = RentCollector::default();
        let builtin_programs = &[BuiltinProgram {
            program_id: mock_program_id,
            process_instruction: mock_system_process_instruction,
        }];

        let program_account = Rc::new(RefCell::new(create_loadable_account_for_test(
            "mock_system_program",
        )));
        let accounts = vec![
            (
                sdk::pubkey::new_rand(),
                AccountSharedData::new_ref(100, 1, &mock_program_id),
            ),
            (
                sdk::pubkey::new_rand(),
                AccountSharedData::new_ref(0, 1, &mock_program_id),
            ),
            (mock_program_id, program_account),
        ];
        let program_indices = vec![vec![2]];

        let executors = Rc::new(RefCell::new(Executors::default()));

        let account_metas = vec![
            AccountMeta::new(accounts[0].0, true),
            AccountMeta::new(accounts[1].0, false),
            AccountMeta::new(accounts[0].0, false),
        ];

        // Try to borrow mut the same account
        let message = SanitizedMessage::Legacy(Message::new(
            &[Instruction::new_with_bincode(
                mock_program_id,
                &MockSystemInstruction::BorrowFail,
                account_metas.clone(),
            )],
            Some(&accounts[0].0),
        ));
        let sysvar_cache = SysvarCache::default();
        let result = MessageProcessor::process_message(
            builtin_programs,
            &message,
            &program_indices,
            &accounts,
            rent_collector.rent,
            None,
            executors.clone(),
            &mut Vec::new(),
            Arc::new(FeatureSet::all_enabled()),
            ComputeBudget::default(),
            &mut ExecuteTimings::default(),
            &sysvar_cache,
            Hash::default(),
            0,
            0,
            &mut 0,
            None,
        );
        assert_eq!(
            result,
            Err(TransactionError::InstructionError(
                0,
                InstructionError::AccountBorrowFailed
            ))
        );

        // Try to borrow mut the same account in a safe way
        let message = SanitizedMessage::Legacy(Message::new(
            &[Instruction::new_with_bincode(
                mock_program_id,
                &MockSystemInstruction::MultiBorrowMut,
                account_metas.clone(),
            )],
            Some(&accounts[0].0),
        ));
        let result = MessageProcessor::process_message(
            builtin_programs,
            &message,
            &program_indices,
            &accounts,
            rent_collector.rent,
            None,
            executors.clone(),
            &mut Vec::new(),
            Arc::new(FeatureSet::all_enabled()),
            ComputeBudget::default(),
            &mut ExecuteTimings::default(),
            &sysvar_cache,
            Hash::default(),
            0,
            0,
            &mut 0,
            None,
        );
        assert!(result.is_ok());

        // Do work on the same account but at different location in keyed_accounts[]
        let message = SanitizedMessage::Legacy(Message::new(
            &[Instruction::new_with_bincode(
                mock_program_id,
                &MockSystemInstruction::DoWork {
                    wens: 10,
                    data: 42,
                },
                account_metas,
            )],
            Some(&accounts[0].0),
        ));
        let result = MessageProcessor::process_message(
            builtin_programs,
            &message,
            &program_indices,
            &accounts,
            rent_collector.rent,
            None,
            executors,
            &mut Vec::new(),
            Arc::new(FeatureSet::all_enabled()),
            ComputeBudget::default(),
            &mut ExecuteTimings::default(),
            &sysvar_cache,
            Hash::default(),
            0,
            0,
            &mut 0,
            None,
        );
        assert!(result.is_ok());
        assert_eq!(accounts[0].1.borrow().wens(), 80);
        assert_eq!(accounts[1].1.borrow().wens(), 20);
        assert_eq!(accounts[0].1.borrow().data(), &vec![42]);
    }

    #[test]
    fn test_precompile() {
        let mock_program_id = Pubkey::new_unique();
        fn mock_process_instruction(
            _first_instruction_account: usize,
            _data: &[u8],
            _invoke_context: &mut InvokeContext,
        ) -> Result<(), InstructionError> {
            Err(InstructionError::Custom(0xbabb1e))
        }
        let builtin_programs = &[BuiltinProgram {
            program_id: mock_program_id,
            process_instruction: mock_process_instruction,
        }];

        let secp256k1_account = AccountSharedData::new_ref(1, 0, &native_loader::id());
        secp256k1_account.borrow_mut().set_executable(true);
        let mock_program_account = AccountSharedData::new_ref(1, 0, &native_loader::id());
        mock_program_account.borrow_mut().set_executable(true);
        let accounts = vec![
            (secp256k1_program::id(), secp256k1_account),
            (mock_program_id, mock_program_account),
        ];

        let message = SanitizedMessage::Legacy(Message::new(
            &[
                new_secp256k1_instruction(
                    &libsecp256k1::SecretKey::random(&mut rand::thread_rng()),
                    b"hello",
                ),
                Instruction::new_with_bytes(mock_program_id, &[], vec![]),
            ],
            None,
        ));
        let sysvar_cache = SysvarCache::default();
        let result = MessageProcessor::process_message(
            builtin_programs,
            &message,
            &[vec![0], vec![1]],
            &accounts,
            RentCollector::default().rent,
            None,
            Rc::new(RefCell::new(Executors::default())),
            &mut Vec::new(),
            Arc::new(FeatureSet::all_enabled()),
            ComputeBudget::default(),
            &mut ExecuteTimings::default(),
            &sysvar_cache,
            Hash::default(),
            0,
            0,
            &mut 0,
            None,
        );

        assert_eq!(
            result,
            Err(TransactionError::InstructionError(
                1,
                InstructionError::Custom(0xbabb1e)
            ))
        );
    }
}
