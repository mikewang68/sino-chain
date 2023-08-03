use {
    crate::{StoredExtendedRewards, StoredTransactionStatusMeta},
    account_decoder::parse_token::{real_number_string_trimmed, UiTokenAmount},
    sdk::{
        hash::Hash,
        instruction::{CompiledInstruction, InstructionError},
        message::{Message, MessageHeader},
        pubkey::Pubkey,
        signature::Signature,
        transaction::{Transaction, TransactionError},
    },
    transaction_status::{
        ConfirmedBlock, ConfirmedBlockWithOptionalMetadata, 
        InnerInstructions, Reward, RewardType,
        TransactionByAddrInfo, 
        TransactionStatusMeta, TransactionTokenBalance,
        TransactionWithMetadata, 
        TransactionWithOptionalMetadata,
    },
    std::{
        convert::{TryFrom, TryInto},
        str::FromStr,
    },
};

pub mod generated {
    include!(concat!(
        env!("OUT_DIR"),
        "/solana.storage.confirmed_block.rs"
    ));
}

pub mod tx_by_addr {
    include!(concat!(
        env!("OUT_DIR"),
        "/solana.storage.transaction_by_addr.rs"
    ));
}

pub mod generated_evm {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        concat!("/proto/solana.storage.evm_compatibility.rs")
    ));
}

impl From<Vec<Reward>> for generated::Rewards {
    fn from(rewards: Vec<Reward>) -> Self {
        Self {
            rewards: rewards.into_iter().map(|r| r.into()).collect(),
        }
    }
}

impl From<generated::Rewards> for Vec<Reward> {
    fn from(rewards: generated::Rewards) -> Self {
        rewards.rewards.into_iter().map(|r| r.into()).collect()
    }
}

impl From<StoredExtendedRewards> for generated::Rewards {
    fn from(rewards: StoredExtendedRewards) -> Self {
        Self {
            rewards: rewards
                .into_iter()
                .map(|r| {
                    let r: Reward = r.into();
                    r.into()
                })
                .collect(),
        }
    }
}

impl From<generated::Rewards> for StoredExtendedRewards {
    fn from(rewards: generated::Rewards) -> Self {
        rewards
            .rewards
            .into_iter()
            .map(|r| {
                let r: Reward = r.into();
                r.into()
            })
            .collect()
    }
}

impl From<Reward> for generated::Reward {
    fn from(reward: Reward) -> Self {
        Self {
            pubkey: reward.pubkey,
            lamports: reward.lamports,
            post_balance: reward.post_balance,
            reward_type: match reward.reward_type {
                None => generated::RewardType::Unspecified,
                Some(RewardType::Fee) => generated::RewardType::Fee,
                Some(RewardType::Rent) => generated::RewardType::Rent,
                Some(RewardType::Staking) => generated::RewardType::Staking,
                Some(RewardType::Voting) => generated::RewardType::Voting,
            } as i32,
            commission: reward.commission.map(|c| c.to_string()).unwrap_or_default(),
        }
    }
}

impl From<generated::Reward> for Reward {
    fn from(reward: generated::Reward) -> Self {
        Self {
            pubkey: reward.pubkey,
            lamports: reward.lamports,
            post_balance: reward.post_balance,
            reward_type: match reward.reward_type {
                0 => None,
                1 => Some(RewardType::Fee),
                2 => Some(RewardType::Rent),
                3 => Some(RewardType::Staking),
                4 => Some(RewardType::Voting),
                _ => None,
            },
            commission: reward.commission.parse::<u8>().ok(),
        }
    }
}

impl From<ConfirmedBlock> for generated::ConfirmedBlock {
    fn from(confirmed_block: ConfirmedBlock) -> Self {
        let ConfirmedBlock {
            previous_blockhash,
            blockhash,
            parent_slot,
            transactions,
            rewards,
            block_time,
            block_height,
        } = confirmed_block;

        Self {
            previous_blockhash,
            blockhash,
            parent_slot,
            transactions: transactions.into_iter().map(|tx| tx.into()).collect(),
            rewards: rewards.into_iter().map(|r| r.into()).collect(),
            block_time: block_time.map(|timestamp| generated::UnixTimestamp { timestamp }),
            block_height: block_height.map(|block_height| generated::BlockHeight { block_height }),
        }
    }
}

impl TryFrom<generated::ConfirmedBlock> for ConfirmedBlockWithOptionalMetadata {
    type Error = bincode::Error;
    fn try_from(
        confirmed_block: generated::ConfirmedBlock,
    ) -> std::result::Result<Self, Self::Error> {
        let generated::ConfirmedBlock {
            previous_blockhash,
            blockhash,
            parent_slot,
            transactions,
            rewards,
            block_time,
            block_height,
        } = confirmed_block;

        Ok(Self {
            previous_blockhash,
            blockhash,
            parent_slot,
            transactions: transactions
                .into_iter()
                .map(|tx| tx.try_into())
                .collect::<std::result::Result<Vec<TransactionWithOptionalMetadata>, Self::Error>>(
                )?,
            rewards: rewards.into_iter().map(|r| r.into()).collect(),
            block_time: block_time.map(|generated::UnixTimestamp { timestamp }| timestamp),
            block_height: block_height.map(|generated::BlockHeight { block_height }| block_height),
        })
    }
}

impl From<TransactionWithMetadata> for generated::ConfirmedTransaction {
    fn from(value: TransactionWithMetadata) -> Self {
        Self {
            transaction: Some(value.transaction.into()),
            meta: Some(value.meta.into()),
        }
    }
}

impl TryFrom<generated::ConfirmedTransaction> for TransactionWithOptionalMetadata {
    type Error = bincode::Error;
    fn try_from(value: generated::ConfirmedTransaction) -> std::result::Result<Self, Self::Error> {
        let meta = value.meta.map(|meta| meta.try_into()).transpose()?;
        Ok(Self {
            transaction: value.transaction.expect("transaction is required").into(),
            meta,
        })
    }
}

impl From<Transaction> for generated::Transaction {
    fn from(value: Transaction) -> Self {
        Self {
            signatures: value
                .signatures
                .into_iter()
                .map(|signature| <Signature as AsRef<[u8]>>::as_ref(&signature).into())
                .collect(),
            message: Some(value.message.into()),
        }
    }
}

impl From<generated::Transaction> for Transaction {
    fn from(value: generated::Transaction) -> Self {
        Self {
            signatures: value
                .signatures
                .into_iter()
                .map(|x| Signature::new(&x))
                .collect(),
            message: value.message.expect("message is required").into(),
        }
    }
}

impl From<Message> for generated::Message {
    fn from(value: Message) -> Self {
        Self {
            header: Some(value.header.into()),
            account_keys: value
                .account_keys
                .into_iter()
                .map(|key| <Pubkey as AsRef<[u8]>>::as_ref(&key).into())
                .collect(),
            recent_blockhash: value.recent_blockhash.to_bytes().into(),
            instructions: value.instructions.into_iter().map(|ix| ix.into()).collect(),
        }
    }
}

impl From<generated::Message> for Message {
    fn from(value: generated::Message) -> Self {
        Self {
            header: value.header.expect("header is required").into(),
            account_keys: value
                .account_keys
                .into_iter()
                .map(|key| Pubkey::new(&key))
                .collect(),
            recent_blockhash: Hash::new(&value.recent_blockhash),
            instructions: value.instructions.into_iter().map(|ix| ix.into()).collect(),
        }
    }
}

impl From<MessageHeader> for generated::MessageHeader {
    fn from(value: MessageHeader) -> Self {
        Self {
            num_required_signatures: value.num_required_signatures as u32,
            num_readonly_signed_accounts: value.num_readonly_signed_accounts as u32,
            num_readonly_unsigned_accounts: value.num_readonly_unsigned_accounts as u32,
        }
    }
}

impl From<generated::MessageHeader> for MessageHeader {
    fn from(value: generated::MessageHeader) -> Self {
        Self {
            num_required_signatures: value.num_required_signatures as u8,
            num_readonly_signed_accounts: value.num_readonly_signed_accounts as u8,
            num_readonly_unsigned_accounts: value.num_readonly_unsigned_accounts as u8,
        }
    }
}

impl From<TransactionStatusMeta> for generated::TransactionStatusMeta {
    fn from(value: TransactionStatusMeta) -> Self {
        let TransactionStatusMeta {
            status,
            fee,
            pre_balances,
            post_balances,
            inner_instructions,
            log_messages,
            pre_token_balances,
            post_token_balances,
            rewards,
        } = value;
        let err = match status {
            Ok(()) => None,
            Err(err) => Some(generated::TransactionError {
                err: bincode::serialize(&err).expect("transaction error to serialize to bytes"),
            }),
        };
        let inner_instructions_none = inner_instructions.is_none();
        let inner_instructions = inner_instructions
            .unwrap_or_default()
            .into_iter()
            .map(|ii| ii.into())
            .collect();
        let log_messages_none = log_messages.is_none();
        let log_messages = log_messages.unwrap_or_default();
        let pre_token_balances = pre_token_balances
            .unwrap_or_default()
            .into_iter()
            .map(|balance| balance.into())
            .collect();
        let post_token_balances = post_token_balances
            .unwrap_or_default()
            .into_iter()
            .map(|balance| balance.into())
            .collect();
        let rewards = rewards
            .unwrap_or_default()
            .into_iter()
            .map(|reward| reward.into())
            .collect();

        Self {
            err,
            fee,
            pre_balances,
            post_balances,
            inner_instructions,
            inner_instructions_none,
            log_messages,
            log_messages_none,
            pre_token_balances,
            post_token_balances,
            rewards,
        }
    }
}

impl From<StoredTransactionStatusMeta> for generated::TransactionStatusMeta {
    fn from(meta: StoredTransactionStatusMeta) -> Self {
        let meta: TransactionStatusMeta = meta.into();
        meta.into()
    }
}

impl TryFrom<generated::TransactionStatusMeta> for TransactionStatusMeta {
    type Error = bincode::Error;

    fn try_from(value: generated::TransactionStatusMeta) -> std::result::Result<Self, Self::Error> {
        let generated::TransactionStatusMeta {
            err,
            fee,
            pre_balances,
            post_balances,
            inner_instructions,
            inner_instructions_none,
            log_messages,
            log_messages_none,
            pre_token_balances,
            post_token_balances,
            rewards,
        } = value;
        let status = match &err {
            None => Ok(()),
            Some(tx_error) => Err(bincode::deserialize(&tx_error.err)?),
        };
        let inner_instructions = if inner_instructions_none {
            None
        } else {
            Some(
                inner_instructions
                    .into_iter()
                    .map(|inner| inner.into())
                    .collect(),
            )
        };
        let log_messages = if log_messages_none {
            None
        } else {
            Some(log_messages)
        };
        let pre_token_balances = Some(
            pre_token_balances
                .into_iter()
                .map(|balance| balance.into())
                .collect(),
        );
        let post_token_balances = Some(
            post_token_balances
                .into_iter()
                .map(|balance| balance.into())
                .collect(),
        );
        let rewards = Some(rewards.into_iter().map(|reward| reward.into()).collect());
        Ok(Self {
            status,
            fee,
            pre_balances,
            post_balances,
            inner_instructions,
            log_messages,
            pre_token_balances,
            post_token_balances,
            rewards,
        })
    }
}

impl From<InnerInstructions> for generated::InnerInstructions {
    fn from(value: InnerInstructions) -> Self {
        Self {
            index: value.index as u32,
            instructions: value.instructions.into_iter().map(|i| i.into()).collect(),
        }
    }
}

impl From<generated::InnerInstructions> for InnerInstructions {
    fn from(value: generated::InnerInstructions) -> Self {
        Self {
            index: value.index as u8,
            instructions: value.instructions.into_iter().map(|i| i.into()).collect(),
        }
    }
}

impl From<TransactionTokenBalance> for generated::TokenBalance {
    fn from(value: TransactionTokenBalance) -> Self {
        Self {
            account_index: value.account_index as u32,
            mint: value.mint,
            ui_token_amount: Some(generated::UiTokenAmount {
                ui_amount: value.ui_token_amount.ui_amount.unwrap_or_default(),
                decimals: value.ui_token_amount.decimals as u32,
                amount: value.ui_token_amount.amount,
                ui_amount_string: value.ui_token_amount.ui_amount_string,
            }),
            owner: value.owner,
        }
    }
}

impl From<generated::TokenBalance> for TransactionTokenBalance {
    fn from(value: generated::TokenBalance) -> Self {
        let ui_token_amount = value.ui_token_amount.unwrap_or_default();
        Self {
            account_index: value.account_index as u8,
            mint: value.mint,
            ui_token_amount: UiTokenAmount {
                ui_amount: if (ui_token_amount.ui_amount - f64::default()).abs() > f64::EPSILON {
                    Some(ui_token_amount.ui_amount)
                } else {
                    None
                },
                decimals: ui_token_amount.decimals as u8,
                amount: ui_token_amount.amount.clone(),
                ui_amount_string: if !ui_token_amount.ui_amount_string.is_empty() {
                    ui_token_amount.ui_amount_string
                } else {
                    real_number_string_trimmed(
                        u64::from_str(&ui_token_amount.amount).unwrap_or_default(),
                        ui_token_amount.decimals as u8,
                    )
                },
            },
            owner: value.owner,
        }
    }
}

impl From<CompiledInstruction> for generated::CompiledInstruction {
    fn from(value: CompiledInstruction) -> Self {
        Self {
            program_id_index: value.program_id_index as u32,
            accounts: value.accounts,
            data: value.data,
        }
    }
}

impl From<generated::CompiledInstruction> for CompiledInstruction {
    fn from(value: generated::CompiledInstruction) -> Self {
        Self {
            program_id_index: value.program_id_index as u8,
            accounts: value.accounts,
            data: value.data,
        }
    }
}

impl TryFrom<tx_by_addr::TransactionError> for TransactionError {
    type Error = &'static str;

    fn try_from(transaction_error: tx_by_addr::TransactionError) -> Result<Self, Self::Error> {
        if transaction_error.transaction_error == 8 {
            if let Some(instruction_error) = transaction_error.instruction_error {
                if let Some(custom) = instruction_error.custom {
                    return Ok(TransactionError::InstructionError(
                        instruction_error.index as u8,
                        InstructionError::Custom(custom.custom),
                    ));
                }

                let ie = match instruction_error.error {
                    0 => InstructionError::GenericError,
                    1 => InstructionError::InvalidArgument,
                    2 => InstructionError::InvalidInstructionData,
                    3 => InstructionError::InvalidAccountData,
                    4 => InstructionError::AccountDataTooSmall,
                    5 => InstructionError::InsufficientFunds,
                    6 => InstructionError::IncorrectProgramId,
                    7 => InstructionError::MissingRequiredSignature,
                    8 => InstructionError::AccountAlreadyInitialized,
                    9 => InstructionError::UninitializedAccount,
                    10 => InstructionError::UnbalancedInstruction,
                    11 => InstructionError::ModifiedProgramId,
                    12 => InstructionError::ExternalAccountLamportSpend,
                    13 => InstructionError::ExternalAccountDataModified,
                    14 => InstructionError::ReadonlyLamportChange,
                    15 => InstructionError::ReadonlyDataModified,
                    16 => InstructionError::DuplicateAccountIndex,
                    17 => InstructionError::ExecutableModified,
                    18 => InstructionError::RentEpochModified,
                    19 => InstructionError::NotEnoughAccountKeys,
                    20 => InstructionError::AccountDataSizeChanged,
                    21 => InstructionError::AccountNotExecutable,
                    22 => InstructionError::AccountBorrowFailed,
                    23 => InstructionError::AccountBorrowOutstanding,
                    24 => InstructionError::DuplicateAccountOutOfSync,
                    26 => InstructionError::InvalidError,
                    27 => InstructionError::ExecutableDataModified,
                    28 => InstructionError::ExecutableLamportChange,
                    29 => InstructionError::ExecutableAccountNotRentExempt,
                    30 => InstructionError::UnsupportedProgramId,
                    31 => InstructionError::CallDepth,
                    32 => InstructionError::MissingAccount,
                    33 => InstructionError::ReentrancyNotAllowed,
                    34 => InstructionError::MaxSeedLengthExceeded,
                    35 => InstructionError::InvalidSeeds,
                    36 => InstructionError::InvalidRealloc,
                    37 => InstructionError::ComputationalBudgetExceeded,
                    38 => InstructionError::PrivilegeEscalation,
                    39 => InstructionError::ProgramEnvironmentSetupFailure,
                    40 => InstructionError::ProgramFailedToComplete,
                    41 => InstructionError::ProgramFailedToCompile,
                    42 => InstructionError::Immutable,
                    43 => InstructionError::IncorrectAuthority,
                    44 => InstructionError::BorshIoError(String::new()),
                    45 => InstructionError::AccountNotRentExempt,
                    46 => InstructionError::InvalidAccountOwner,
                    47 => InstructionError::ArithmeticOverflow,
                    48 => InstructionError::UnsupportedSysvar,
                    49 => InstructionError::IllegalOwner,
                    50 => InstructionError::MaxAccountsDataSizeExceeded,
                    51 => InstructionError::ActiveVoteAccountClose,
                    _ => return Err("Invalid InstructionError"),
                };

                return Ok(TransactionError::InstructionError(
                    instruction_error.index as u8,
                    ie,
                ));
            }
        }

        Ok(match transaction_error.transaction_error {
            0 => TransactionError::AccountInUse,
            1 => TransactionError::AccountLoadedTwice,
            2 => TransactionError::AccountNotFound,
            3 => TransactionError::ProgramAccountNotFound,
            4 => TransactionError::InsufficientFundsForFee,
            5 => TransactionError::InvalidAccountForFee,
            6 => TransactionError::AlreadyProcessed,
            7 => TransactionError::BlockhashNotFound,
            9 => TransactionError::CallChainTooDeep,
            10 => TransactionError::MissingSignatureForFee,
            11 => TransactionError::InvalidAccountIndex,
            12 => TransactionError::SignatureFailure,
            13 => TransactionError::InvalidProgramForExecution,
            14 => TransactionError::SanitizeFailure,
            15 => TransactionError::ClusterMaintenance,
            16 => TransactionError::AccountBorrowOutstanding,
            17 => TransactionError::WouldExceedMaxBlockCostLimit,
            18 => TransactionError::UnsupportedVersion,
            19 => TransactionError::InvalidWritableAccount,
            20 => TransactionError::WouldExceedMaxAccountCostLimit,
            21 => TransactionError::WouldExceedMaxAccountDataCostLimit,
            22 => TransactionError::TooManyAccountLocks,
            23 => TransactionError::AddressLookupTableNotFound,
            24 => TransactionError::InvalidAddressLookupTableOwner,
            25 => TransactionError::InvalidAddressLookupTableData,
            26 => TransactionError::InvalidAddressLookupTableIndex,
            27 => TransactionError::InvalidRentPayingAccount,
            28 => TransactionError::WouldExceedMaxVoteCostLimit,
            _ => return Err("Invalid TransactionError"),
        })
    }
}

impl From<TransactionError> for tx_by_addr::TransactionError {
    fn from(transaction_error: TransactionError) -> Self {
        Self {
            transaction_error: match transaction_error {
                TransactionError::AccountInUse => tx_by_addr::TransactionErrorType::AccountInUse,
                TransactionError::AccountLoadedTwice => {
                    tx_by_addr::TransactionErrorType::AccountLoadedTwice
                }
                TransactionError::AccountNotFound => {
                    tx_by_addr::TransactionErrorType::AccountNotFound
                }
                TransactionError::ProgramAccountNotFound => {
                    tx_by_addr::TransactionErrorType::ProgramAccountNotFound
                }
                TransactionError::InsufficientFundsForFee => {
                    tx_by_addr::TransactionErrorType::InsufficientFundsForFee
                }
                TransactionError::InvalidAccountForFee => {
                    tx_by_addr::TransactionErrorType::InvalidAccountForFee
                }
                TransactionError::AlreadyProcessed => {
                    tx_by_addr::TransactionErrorType::AlreadyProcessed
                }
                TransactionError::BlockhashNotFound => {
                    tx_by_addr::TransactionErrorType::BlockhashNotFound
                }
                TransactionError::CallChainTooDeep => {
                    tx_by_addr::TransactionErrorType::CallChainTooDeep
                }
                TransactionError::MissingSignatureForFee => {
                    tx_by_addr::TransactionErrorType::MissingSignatureForFee
                }
                TransactionError::InvalidAccountIndex => {
                    tx_by_addr::TransactionErrorType::InvalidAccountIndex
                }
                TransactionError::SignatureFailure => {
                    tx_by_addr::TransactionErrorType::SignatureFailure
                }
                TransactionError::InvalidProgramForExecution => {
                    tx_by_addr::TransactionErrorType::InvalidProgramForExecution
                }
                TransactionError::SanitizeFailure => {
                    tx_by_addr::TransactionErrorType::SanitizeFailure
                }
                TransactionError::ClusterMaintenance => {
                    tx_by_addr::TransactionErrorType::ClusterMaintenance
                }
                TransactionError::InstructionError(_, _) => {
                    tx_by_addr::TransactionErrorType::InstructionError
                }
                TransactionError::AccountBorrowOutstanding => {
                    tx_by_addr::TransactionErrorType::AccountBorrowOutstandingTx
                }
                TransactionError::WouldExceedMaxBlockCostLimit => {
                    tx_by_addr::TransactionErrorType::WouldExceedMaxBlockCostLimit
                }
                TransactionError::UnsupportedVersion => {
                    tx_by_addr::TransactionErrorType::UnsupportedVersion
                }
                TransactionError::InvalidWritableAccount => {
                    tx_by_addr::TransactionErrorType::InvalidWritableAccount
                }
                TransactionError::WouldExceedMaxAccountCostLimit => {
                    tx_by_addr::TransactionErrorType::WouldExceedMaxAccountCostLimit
                }
                TransactionError::WouldExceedMaxAccountDataCostLimit => {
                    tx_by_addr::TransactionErrorType::WouldExceedMaxAccountDataCostLimit
                }
                TransactionError::TooManyAccountLocks => {
                    tx_by_addr::TransactionErrorType::TooManyAccountLocks
                }
                TransactionError::AddressLookupTableNotFound => {
                    tx_by_addr::TransactionErrorType::AddressLookupTableNotFound
                }
                TransactionError::InvalidAddressLookupTableOwner => {
                    tx_by_addr::TransactionErrorType::InvalidAddressLookupTableOwner
                }
                TransactionError::InvalidAddressLookupTableData => {
                    tx_by_addr::TransactionErrorType::InvalidAddressLookupTableData
                }
                TransactionError::InvalidAddressLookupTableIndex => {
                    tx_by_addr::TransactionErrorType::InvalidAddressLookupTableIndex
                }
                TransactionError::InvalidRentPayingAccount => {
                    tx_by_addr::TransactionErrorType::InvalidRentPayingAccount
                }
                TransactionError::WouldExceedMaxVoteCostLimit => {
                    tx_by_addr::TransactionErrorType::WouldExceedMaxVoteCostLimit
                }
            } as i32,
            instruction_error: match transaction_error {
                TransactionError::InstructionError(index, ref instruction_error) => {
                    Some(tx_by_addr::InstructionError {
                        index: index as u32,
                        error: match instruction_error {
                            InstructionError::GenericError => {
                                tx_by_addr::InstructionErrorType::GenericError
                            }
                            InstructionError::InvalidArgument => {
                                tx_by_addr::InstructionErrorType::InvalidArgument
                            }
                            InstructionError::InvalidInstructionData => {
                                tx_by_addr::InstructionErrorType::InvalidInstructionData
                            }
                            InstructionError::InvalidAccountData => {
                                tx_by_addr::InstructionErrorType::InvalidAccountData
                            }
                            InstructionError::AccountDataTooSmall => {
                                tx_by_addr::InstructionErrorType::AccountDataTooSmall
                            }
                            InstructionError::InsufficientFunds => {
                                tx_by_addr::InstructionErrorType::InsufficientFunds
                            }
                            InstructionError::IncorrectProgramId => {
                                tx_by_addr::InstructionErrorType::IncorrectProgramId
                            }
                            InstructionError::MissingRequiredSignature => {
                                tx_by_addr::InstructionErrorType::MissingRequiredSignature
                            }
                            InstructionError::AccountAlreadyInitialized => {
                                tx_by_addr::InstructionErrorType::AccountAlreadyInitialized
                            }
                            InstructionError::UninitializedAccount => {
                                tx_by_addr::InstructionErrorType::UninitializedAccount
                            }
                            InstructionError::UnbalancedInstruction => {
                                tx_by_addr::InstructionErrorType::UnbalancedInstruction
                            }
                            InstructionError::ModifiedProgramId => {
                                tx_by_addr::InstructionErrorType::ModifiedProgramId
                            }
                            InstructionError::ExternalAccountLamportSpend => {
                                tx_by_addr::InstructionErrorType::ExternalAccountLamportSpend
                            }
                            InstructionError::ExternalAccountDataModified => {
                                tx_by_addr::InstructionErrorType::ExternalAccountDataModified
                            }
                            InstructionError::ReadonlyLamportChange => {
                                tx_by_addr::InstructionErrorType::ReadonlyLamportChange
                            }
                            InstructionError::ReadonlyDataModified => {
                                tx_by_addr::InstructionErrorType::ReadonlyDataModified
                            }
                            InstructionError::DuplicateAccountIndex => {
                                tx_by_addr::InstructionErrorType::DuplicateAccountIndex
                            }
                            InstructionError::ExecutableModified => {
                                tx_by_addr::InstructionErrorType::ExecutableModified
                            }
                            InstructionError::RentEpochModified => {
                                tx_by_addr::InstructionErrorType::RentEpochModified
                            }
                            InstructionError::NotEnoughAccountKeys => {
                                tx_by_addr::InstructionErrorType::NotEnoughAccountKeys
                            }
                            InstructionError::AccountDataSizeChanged => {
                                tx_by_addr::InstructionErrorType::AccountDataSizeChanged
                            }
                            InstructionError::AccountNotExecutable => {
                                tx_by_addr::InstructionErrorType::AccountNotExecutable
                            }
                            InstructionError::AccountBorrowFailed => {
                                tx_by_addr::InstructionErrorType::AccountBorrowFailed
                            }
                            InstructionError::AccountBorrowOutstanding => {
                                tx_by_addr::InstructionErrorType::AccountBorrowOutstanding
                            }
                            InstructionError::DuplicateAccountOutOfSync => {
                                tx_by_addr::InstructionErrorType::DuplicateAccountOutOfSync
                            }
                            InstructionError::Custom(_) => tx_by_addr::InstructionErrorType::Custom,
                            InstructionError::InvalidError => {
                                tx_by_addr::InstructionErrorType::InvalidError
                            }
                            InstructionError::ExecutableDataModified => {
                                tx_by_addr::InstructionErrorType::ExecutableDataModified
                            }
                            InstructionError::ExecutableLamportChange => {
                                tx_by_addr::InstructionErrorType::ExecutableLamportChange
                            }
                            InstructionError::ExecutableAccountNotRentExempt => {
                                tx_by_addr::InstructionErrorType::ExecutableAccountNotRentExempt
                            }
                            InstructionError::UnsupportedProgramId => {
                                tx_by_addr::InstructionErrorType::UnsupportedProgramId
                            }
                            InstructionError::CallDepth => {
                                tx_by_addr::InstructionErrorType::CallDepth
                            }
                            InstructionError::MissingAccount => {
                                tx_by_addr::InstructionErrorType::MissingAccount
                            }
                            InstructionError::ReentrancyNotAllowed => {
                                tx_by_addr::InstructionErrorType::ReentrancyNotAllowed
                            }
                            InstructionError::MaxSeedLengthExceeded => {
                                tx_by_addr::InstructionErrorType::MaxSeedLengthExceeded
                            }
                            InstructionError::InvalidSeeds => {
                                tx_by_addr::InstructionErrorType::InvalidSeeds
                            }
                            InstructionError::InvalidRealloc => {
                                tx_by_addr::InstructionErrorType::InvalidRealloc
                            }
                            InstructionError::ComputationalBudgetExceeded => {
                                tx_by_addr::InstructionErrorType::ComputationalBudgetExceeded
                            }
                            InstructionError::PrivilegeEscalation => {
                                tx_by_addr::InstructionErrorType::PrivilegeEscalation
                            }
                            InstructionError::ProgramEnvironmentSetupFailure => {
                                tx_by_addr::InstructionErrorType::ProgramEnvironmentSetupFailure
                            }
                            InstructionError::ProgramFailedToComplete => {
                                tx_by_addr::InstructionErrorType::ProgramFailedToComplete
                            }
                            InstructionError::ProgramFailedToCompile => {
                                tx_by_addr::InstructionErrorType::ProgramFailedToCompile
                            }
                            InstructionError::Immutable => {
                                tx_by_addr::InstructionErrorType::Immutable
                            }
                            InstructionError::IncorrectAuthority => {
                                tx_by_addr::InstructionErrorType::IncorrectAuthority
                            }
                            InstructionError::BorshIoError(_) => {
                                tx_by_addr::InstructionErrorType::BorshIoError
                            }
                            InstructionError::AccountNotRentExempt => {
                                tx_by_addr::InstructionErrorType::AccountNotRentExempt
                            }
                            InstructionError::InvalidAccountOwner => {
                                tx_by_addr::InstructionErrorType::InvalidAccountOwner
                            }
                            InstructionError::ArithmeticOverflow => {
                                tx_by_addr::InstructionErrorType::ArithmeticOverflow
                            }
                            InstructionError::UnsupportedSysvar => {
                                tx_by_addr::InstructionErrorType::UnsupportedSysvar
                            }
                            InstructionError::IllegalOwner => {
                                tx_by_addr::InstructionErrorType::IllegalOwner
                            }
                            InstructionError::MaxAccountsDataSizeExceeded => {
                                tx_by_addr::InstructionErrorType::MaxAccountsDataSizeExceeded
                            }
                            InstructionError::ActiveVoteAccountClose => {
                                tx_by_addr::InstructionErrorType::ActiveVoteAccountClose
                            }
                        } as i32,
                        custom: match instruction_error {
                            InstructionError::Custom(custom) => {
                                Some(tx_by_addr::CustomError { custom: *custom })
                            }
                            _ => None,
                        },
                    })
                }
                _ => None,
            },
        }
    }
}

impl From<TransactionByAddrInfo> for tx_by_addr::TransactionByAddrInfo {
    fn from(by_addr: TransactionByAddrInfo) -> Self {
        let TransactionByAddrInfo {
            signature,
            err,
            index,
            memo,
            block_time,
        } = by_addr;

        Self {
            signature: <Signature as AsRef<[u8]>>::as_ref(&signature).into(),
            err: err.map(|e| e.into()),
            index,
            memo: memo.map(|memo| tx_by_addr::Memo { memo }),
            block_time: block_time.map(|timestamp| tx_by_addr::UnixTimestamp { timestamp }),
        }
    }
}

impl TryFrom<tx_by_addr::TransactionByAddrInfo> for TransactionByAddrInfo {
    type Error = &'static str;

    fn try_from(
        transaction_by_addr: tx_by_addr::TransactionByAddrInfo,
    ) -> Result<Self, Self::Error> {
        let err = transaction_by_addr
            .err
            .map(|err| err.try_into())
            .transpose()?;

        Ok(Self {
            signature: Signature::new(&transaction_by_addr.signature),
            err,
            index: transaction_by_addr.index,
            memo: transaction_by_addr
                .memo
                .map(|tx_by_addr::Memo { memo }| memo),
            block_time: transaction_by_addr
                .block_time
                .map(|tx_by_addr::UnixTimestamp { timestamp }| timestamp),
        })
    }
}

impl TryFrom<tx_by_addr::TransactionByAddr> for Vec<TransactionByAddrInfo> {
    type Error = &'static str;

    fn try_from(collection: tx_by_addr::TransactionByAddr) -> Result<Self, Self::Error> {
        collection
            .tx_by_addrs
            .into_iter()
            .map(|tx_by_addr| tx_by_addr.try_into())
            .collect::<Result<Vec<TransactionByAddrInfo>, Self::Error>>()
    }
}

//
// Evm compatibility layer
//

trait ConvertFromBytes {
    fn len_bytes() -> usize;

    fn from_slice(bytes: &[u8]) -> Self;

    fn into_vec(self) -> Vec<u8>;
}

impl ConvertFromBytes for evm_state::H256 {
    fn len_bytes() -> usize {
        Self::len_bytes()
    }

    fn from_slice(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
    }

    fn into_vec(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ConvertFromBytes for evm_state::H160 {
    fn len_bytes() -> usize {
        Self::len_bytes()
    }

    fn from_slice(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
    }

    fn into_vec(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ConvertFromBytes for evm_state::Bloom {
    fn len_bytes() -> usize {
        Self::len_bytes()
    }

    fn from_slice(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
    }
    fn into_vec(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// This function is consuming on purpose, it is used only in TryFrom, and consuming allows staticly check if all fields was taken.
fn convert_from_bytes<T: ConvertFromBytes>(slice: Vec<u8>) -> Result<T, &'static str> {
    if slice.len() != T::len_bytes() {
        return Err("Incorrect size of some field in protobuf structures");
    }
    Ok(T::from_slice(&slice))
}

impl From<evm_state::BlockHeader> for generated_evm::EvmBlockHeader {
    fn from(header: evm_state::BlockHeader) -> Self {
        let transactions: Vec<_> = header
            .transactions
            .into_iter()
            .map(ConvertFromBytes::into_vec)
            .collect();
        Self {
            parent_hash: header.parent_hash.into_vec(),
            state_root: header.state_root.into_vec(),
            native_chain_hash: header.native_chain_hash.into_vec(),
            transactions,
            transactions_root: header.transactions_root.into_vec(),
            receipts_root: header.receipts_root.into_vec(),
            logs_bloom: header.logs_bloom.into_vec(),
            block_number: header.block_number,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            timestamp: header.timestamp,
            native_chain_slot: header.native_chain_slot,
            version: header.version.into(),
        }
    }
}

impl TryFrom<generated_evm::EvmBlockHeader> for evm_state::BlockHeader {
    type Error = &'static str;
    fn try_from(header: generated_evm::EvmBlockHeader) -> Result<Self, Self::Error> {
        let transactions: Result<Vec<_>, _> = header
            .transactions
            .into_iter()
            .map(convert_from_bytes)
            .collect();
        Ok(Self {
            parent_hash: convert_from_bytes(header.parent_hash)?,
            state_root: convert_from_bytes(header.state_root)?,
            native_chain_hash: convert_from_bytes(header.native_chain_hash)?,
            transactions: transactions?,
            transactions_root: convert_from_bytes(header.transactions_root)?,
            receipts_root: convert_from_bytes(header.receipts_root)?,
            logs_bloom: convert_from_bytes(header.logs_bloom)?,
            block_number: header.block_number,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            timestamp: header.timestamp,
            native_chain_slot: header.native_chain_slot,
            version: header.version.try_into()?,
        })
    }
}

impl From<evm_state::TransactionReceipt> for generated_evm::TransactionReceipt {
    fn from(tx: evm_state::TransactionReceipt) -> Self {
        Self {
            transaction: Some(tx.transaction.into()),
            status: Some(tx.status.into()),
            logs: tx.logs.into_iter().map(From::from).collect(),
            logs_bloom: tx.logs_bloom.into_vec(),

            used_gas: tx.used_gas,
            index: tx.index,
            block_number: tx.block_number,
        }
    }
}

impl TryFrom<generated_evm::TransactionReceipt> for evm_state::TransactionReceipt {
    type Error = &'static str;

    fn try_from(tx: generated_evm::TransactionReceipt) -> Result<Self, Self::Error> {
        let logs: Result<Vec<_>, _> = tx.logs.into_iter().map(TryFrom::try_from).collect();
        Ok(Self {
            transaction: tx
                .transaction
                .ok_or("Transaction body is missing")?
                .try_into()?,
            status: tx
                .status
                .ok_or("Transaction status is missing")?
                .try_into()?,
            logs: logs?,
            logs_bloom: convert_from_bytes(tx.logs_bloom)?,
            block_number: tx.block_number,
            used_gas: tx.used_gas,
            index: tx.index,
        })
    }
}

impl From<evm_state::TransactionInReceipt> for generated_evm::TransactionInReceipt {
    fn from(tx: evm_state::TransactionInReceipt) -> Self {
        generated_evm::TransactionInReceipt {
            transaction: Some(match tx {
                evm_state::TransactionInReceipt::Signed(tx) => {
                    generated_evm::transaction_in_receipt::Transaction::Signed(tx.into())
                }
                evm_state::TransactionInReceipt::Unsigned(unsigned) => {
                    generated_evm::transaction_in_receipt::Transaction::Unsigned(unsigned.into())
                }
            }),
        }
    }
}

impl TryFrom<generated_evm::TransactionInReceipt> for evm_state::TransactionInReceipt {
    type Error = &'static str;
    fn try_from(tx: generated_evm::TransactionInReceipt) -> Result<Self, Self::Error> {
        Ok(
            match tx
                .transaction
                .ok_or("Empty transaction body in transaction receipt")?
            {
                generated_evm::transaction_in_receipt::Transaction::Unsigned(unsigned) => {
                    evm_state::TransactionInReceipt::Unsigned(unsigned.try_into()?)
                }
                generated_evm::transaction_in_receipt::Transaction::Signed(tx) => {
                    evm_state::TransactionInReceipt::Signed(tx.try_into()?)
                }
            },
        )
    }
}

impl From<evm_state::Transaction> for generated_evm::Transaction {
    fn from(tx: evm_state::Transaction) -> Self {
        let bytes = rlp::encode(&tx);
        Self {
            rlp_encoded_body: bytes.to_vec(),
        }
    }
}

impl TryFrom<generated_evm::Transaction> for evm_state::Transaction {
    type Error = &'static str;
    fn try_from(tx: generated_evm::Transaction) -> Result<Self, Self::Error> {
        rlp::decode(&tx.rlp_encoded_body).map_err(|_| "Failed to deserialize rlp tx body")
    }
}

impl From<evm_state::UnsignedTransactionWithCaller>
    for generated_evm::UnsignedTransactionWithCaller
{
    fn from(unsigned: evm_state::UnsignedTransactionWithCaller) -> Self {
        let bytes = rlp::encode(&unsigned.unsigned_tx);
        Self {
            rlp_encoded_body: bytes.to_vec(),
            chain_id: unsigned.chain_id,
            caller: unsigned.caller.into_vec(),
            signed_compatible: unsigned.signed_compatible,
        }
    }
}

impl TryFrom<generated_evm::UnsignedTransactionWithCaller>
    for evm_state::UnsignedTransactionWithCaller
{
    type Error = &'static str;
    fn try_from(
        unsigned: generated_evm::UnsignedTransactionWithCaller,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            chain_id: unsigned.chain_id,
            signed_compatible: unsigned.signed_compatible,
            caller: convert_from_bytes(unsigned.caller)?,
            unsigned_tx: rlp::decode(&unsigned.rlp_encoded_body)
                .map_err(|_| "Failed to deserialize rlp tx body")?,
        })
    }
}

impl From<evm_state::Log> for generated_evm::Log {
    fn from(logs: evm_state::Log) -> Self {
        let topics: Vec<_> = logs
            .topics
            .into_iter()
            .map(ConvertFromBytes::into_vec)
            .collect();
        Self {
            topics,
            address: logs.address.into_vec(),
            data: logs.data,
        }
    }
}

impl TryFrom<generated_evm::Log> for evm_state::Log {
    type Error = &'static str;
    fn try_from(logs: generated_evm::Log) -> Result<Self, Self::Error> {
        let topics: Result<Vec<_>, _> = logs.topics.into_iter().map(convert_from_bytes).collect();
        Ok(Self {
            data: logs.data,
            address: convert_from_bytes(logs.address)?,
            topics: topics?,
        })
    }
}

impl From<evm_state::ExitReason> for generated_evm::ExitReason {
    fn from(reason: evm_state::ExitReason) -> Self {
        use evm_state::{ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed};
        use generated_evm::exit_reason::ExitVariant;

        fn error_to_generated(error: ExitError) -> generated_evm::ExitReason {
            match error {
                ExitError::CallTooDeep => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::CallTooDeep.into(),
                },
                ExitError::CreateCollision => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::CreateCollision.into(),
                },
                ExitError::CreateContractLimit => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::CreateContractLimit.into(),
                },
                ExitError::CreateEmpty => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::CreateEmpty.into(),
                },
                ExitError::DesignatedInvalid => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::DesignatedInvalid.into(),
                },
                ExitError::InvalidCode(opcode) => generated_evm::ExitReason {
                    fatal: false,
                    other: opcode.as_u8().to_string(),
                    variant: ExitVariant::InvalidCode.into(),
                },
                ExitError::InvalidJump => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::InvalidJump.into(),
                },
                ExitError::InvalidRange => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::InvalidRange.into(),
                },
                ExitError::OutOfFund => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::OutOfFund.into(),
                },
                ExitError::OutOfGas => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::OutOfGas.into(),
                },
                ExitError::OutOfOffset => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::OutOfOffset.into(),
                },
                ExitError::PCUnderflow => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::PcUnderflow.into(),
                },
                ExitError::StackOverflow => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::StackOverflow.into(),
                },
                ExitError::StackUnderflow => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::StackUnderflow.into(),
                },
                ExitError::Other(s) => generated_evm::ExitReason {
                    fatal: false,
                    other: String::from(&*s),
                    variant: ExitVariant::Other.into(),
                },
            }
        }
        match reason {
            ExitReason::Revert(ExitRevert::Reverted) => Self {
                fatal: false,
                other: String::new(),
                variant: ExitVariant::Reverted.into(),
            },
            ExitReason::Succeed(ExitSucceed::Returned) => Self {
                fatal: false,
                other: String::new(),
                variant: ExitVariant::Returned.into(),
            },
            ExitReason::Succeed(ExitSucceed::Stopped) => Self {
                fatal: false,
                other: String::new(),
                variant: ExitVariant::Stopped.into(),
            },
            ExitReason::Succeed(ExitSucceed::Suicided) => Self {
                fatal: false,
                other: String::new(),
                variant: ExitVariant::Suicided.into(),
            },
            ExitReason::Fatal(ExitFatal::NotSupported) => Self {
                fatal: true,
                other: String::new(),
                variant: ExitVariant::NotSupported.into(),
            },
            ExitReason::Fatal(ExitFatal::UnhandledInterrupt) => Self {
                fatal: true,
                other: String::new(),
                variant: ExitVariant::UnhandledInterrupt.into(),
            },
            ExitReason::Fatal(ExitFatal::Other(s)) => Self {
                fatal: true,
                other: String::from(&*s),
                variant: ExitVariant::OtherFatal.into(),
            },
            ExitReason::Error(e) => error_to_generated(e),
            ExitReason::Fatal(ExitFatal::CallErrorAsFatal(e)) => Self {
                fatal: true,
                ..error_to_generated(e)
            },
        }
    }
}

impl TryFrom<generated_evm::ExitReason> for evm_state::ExitReason {
    type Error = &'static str;
    fn try_from(
        header: generated_evm::ExitReason,
    ) -> Result<Self, <Self as TryFrom<generated_evm::ExitReason>>::Error> {
        use evm_state::{ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed, Opcode};
        use generated_evm::exit_reason::ExitVariant;
        let error_or_fatal = match ExitVariant::from_i32(header.variant)
            .ok_or("Enum error variant out of bounds")?
        {
            ExitVariant::Returned => return Ok(ExitReason::Succeed(ExitSucceed::Returned)),
            ExitVariant::Stopped => return Ok(ExitReason::Succeed(ExitSucceed::Stopped)),
            ExitVariant::Suicided => return Ok(ExitReason::Succeed(ExitSucceed::Suicided)),
            ExitVariant::Reverted => return Ok(ExitReason::Revert(ExitRevert::Reverted)),
            ExitVariant::NotSupported => return Ok(ExitReason::Fatal(ExitFatal::NotSupported)),
            ExitVariant::UnhandledInterrupt => {
                return Ok(ExitReason::Fatal(ExitFatal::UnhandledInterrupt))
            }
            ExitVariant::OtherFatal => {
                return Ok(ExitReason::Fatal(ExitFatal::Other(header.other.into())))
            }
            ExitVariant::Other => ExitError::Other(header.other.into()),
            ExitVariant::CallTooDeep => ExitError::CallTooDeep,
            ExitVariant::CreateCollision => ExitError::CreateCollision,
            ExitVariant::CreateContractLimit => ExitError::CreateContractLimit,
            ExitVariant::CreateEmpty => ExitError::CreateEmpty,
            ExitVariant::DesignatedInvalid => ExitError::DesignatedInvalid,
            ExitVariant::InvalidCode => ExitError::InvalidCode(Opcode(
                u8::from_str(&header.other).map_err(|_| "Failed to decode opcode")?,
            )),
            ExitVariant::InvalidJump => ExitError::InvalidJump,
            ExitVariant::InvalidRange => ExitError::InvalidRange,
            ExitVariant::StackOverflow => ExitError::StackOverflow,
            ExitVariant::StackUnderflow => ExitError::StackUnderflow,
            ExitVariant::OutOfFund => ExitError::OutOfFund,
            ExitVariant::OutOfGas => ExitError::OutOfGas,
            ExitVariant::OutOfOffset => ExitError::OutOfOffset,
            ExitVariant::PcUnderflow => ExitError::PCUnderflow,
        };
        if header.fatal {
            Ok(ExitReason::Fatal(ExitFatal::CallErrorAsFatal(
                error_or_fatal,
            )))
        } else {
            Ok(ExitReason::Error(error_or_fatal))
        }
    }
}

impl From<(evm_state::H256, evm_state::TransactionReceipt)> for generated_evm::ReceiptWithHash {
    fn from(tx_with_hash: (evm_state::H256, evm_state::TransactionReceipt)) -> Self {
        Self {
            hash: tx_with_hash.0.into_vec(),
            transaction: Some(tx_with_hash.1.into()),
        }
    }
}

impl TryFrom<generated_evm::ReceiptWithHash> for (evm_state::H256, evm_state::TransactionReceipt) {
    type Error = &'static str;
    fn try_from(tx_with_hash: generated_evm::ReceiptWithHash) -> Result<Self, Self::Error> {
        Ok((
            convert_from_bytes(tx_with_hash.hash)?,
            tx_with_hash
                .transaction
                .ok_or("Transaction is missing in receipt with hash")?
                .try_into()?,
        ))
    }
}

impl From<evm_state::Block> for generated_evm::EvmFullBlock {
    fn from(block: evm_state::Block) -> Self {
        let transactions: Vec<_> = block.transactions.into_iter().map(Into::into).collect();
        Self {
            transactions,
            header: Some(block.header.into()),
        }
    }
}

impl TryFrom<generated_evm::EvmFullBlock> for evm_state::Block {
    type Error = &'static str;
    fn try_from(block: generated_evm::EvmFullBlock) -> Result<Self, Self::Error> {
        let transactions: Result<Vec<_>, _> = block
            .transactions
            .into_iter()
            .map(TryInto::try_into)
            .collect();
        Ok(Self {
            transactions: transactions?,
            header: block
                .header
                .ok_or("Block header is missing in full block")?
                .try_into()?,
        })
    }
}
