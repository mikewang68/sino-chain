use {
    crate::transaction_notifier_interface::TransactionNotifierLock,
    crossbeam_channel::{Receiver, RecvTimeoutError},
    itertools::izip,
    ledger::{
        blockstore::Blockstore,
        blockstore_processor::{TransactionStatusBatch, TransactionStatusMessage},
    },
    runtime::bank::{DurableNonceFee, TransactionExecutionDetails},
    transaction_status::{
        extract_and_fmt_memos, InnerInstructions, Reward, TransactionStatusMeta,
    },
    std::{
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub struct TransactionStatusService {
    thread_hdl: JoinHandle<()>,
}

impl TransactionStatusService {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        write_transaction_status_receiver: Receiver<TransactionStatusMessage>,
        max_complete_transaction_status_slot: Arc<AtomicU64>,
        enable_rpc_transaction_history: bool,
        transaction_notifier: Option<TransactionNotifierLock>,
        blockstore: Arc<Blockstore>,
        exit: &Arc<AtomicBool>,
    ) -> Self {
        let exit = exit.clone();
        let thread_hdl = Builder::new()
            .name("sino-transaction-status-writer".to_string())
            .spawn(move || loop {
                if exit.load(Ordering::Relaxed) {
                    break;
                }

                if let Err(RecvTimeoutError::Disconnected) = Self::write_transaction_status_batch(
                    &write_transaction_status_receiver,
                    &max_complete_transaction_status_slot,
                    enable_rpc_transaction_history,
                    transaction_notifier.clone(),
                    &blockstore,
                ) {
                    break;
                }
            })
            .unwrap();
        Self { thread_hdl }
    }

    fn write_transaction_status_batch(
        write_transaction_status_receiver: &Receiver<TransactionStatusMessage>,
        max_complete_transaction_status_slot: &Arc<AtomicU64>,
        enable_rpc_transaction_history: bool,
        transaction_notifier: Option<TransactionNotifierLock>,
        blockstore: &Arc<Blockstore>,
    ) -> Result<(), RecvTimeoutError> {
        match write_transaction_status_receiver.recv_timeout(Duration::from_secs(1))? {
            TransactionStatusMessage::Batch(TransactionStatusBatch {
                bank,
                transactions,
                execution_results,
                balances,
                token_balances,
                rent_debits,
            }) => {
                let slot = bank.slot();
                for (
                    transaction,
                    execution_result,
                    pre_balances,
                    post_balances,
                    pre_token_balances,
                    post_token_balances,
                    rent_debits,
                ) in izip!(
                    transactions,
                    execution_results,
                    balances.pre_balances,
                    balances.post_balances,
                    token_balances.pre_token_balances,
                    token_balances.post_token_balances,
                    rent_debits,
                ) {
                    if let Some(details) = execution_result {
                        let TransactionExecutionDetails {
                            status,
                            log_messages,
                            inner_instructions,
                            durable_nonce_fee,
                            ..
                        } = details;
                        let wens_per_signature = match durable_nonce_fee {
                            Some(DurableNonceFee::Valid(wens_per_signature)) => {
                                Some(wens_per_signature)
                            }
                            Some(DurableNonceFee::Invalid) => None,
                            None => bank.get_wens_per_signature_for_blockhash(
                                transaction.message().recent_blockhash(),
                            ),
                        }
                        .expect("wens_per_signature must be available");
                        let fee = bank.get_fee_for_message_with_wens_per_signature(
                            transaction.message(),
                            wens_per_signature,
                        );
                        let tx_account_locks = transaction.get_account_locks_unchecked();

                        let inner_instructions = inner_instructions.map(|inner_instructions| {
                            inner_instructions
                                .into_iter()
                                .enumerate()
                                .map(|(index, instructions)| InnerInstructions {
                                    index: index as u8,
                                    instructions,
                                })
                                .filter(|i| !i.instructions.is_empty())
                                .collect()
                        });

                        let pre_token_balances = Some(pre_token_balances);
                        let post_token_balances = Some(post_token_balances);
                        let rewards = Some(
                            rent_debits
                                .into_unordered_rewards_iter()
                                .map(|(pubkey, reward_info)| Reward {
                                    pubkey: pubkey.to_string(),
                                    wens: reward_info.wens,
                                    post_balance: reward_info.post_balance,
                                    reward_type: Some(reward_info.reward_type),
                                    commission: reward_info.commission,
                                })
                                .collect(),
                        );

                        let transaction_status_meta = TransactionStatusMeta {
                            status,
                            fee,
                            pre_balances,
                            post_balances,
                            inner_instructions,
                            log_messages,
                            pre_token_balances,
                            post_token_balances,
                            rewards,
                        };

                        if let Some(transaction_notifier) = transaction_notifier.as_ref() {
                            transaction_notifier.write().unwrap().notify_transaction(
                                slot,
                                transaction.signature(),
                                &transaction_status_meta,
                                &transaction,
                            );
                        }
                        if enable_rpc_transaction_history {
                            if let Some(memos) = extract_and_fmt_memos(transaction.message()) {
                                blockstore
                                    .write_transaction_memos(transaction.signature(), memos)
                                    .expect("Expect database write to succeed: TransactionMemos");
                            }

                            blockstore
                                .write_transaction_status(
                                    slot,
                                    *transaction.signature(),
                                    tx_account_locks.writable,
                                    tx_account_locks.readonly,
                                    transaction_status_meta,
                                )
                                .expect("Expect database write to succeed: TransactionStatus");
                        }
                    }
                }
            }
            TransactionStatusMessage::Freeze(slot) => {
                max_complete_transaction_status_slot.fetch_max(slot, Ordering::SeqCst);
            }
        }
        Ok(())
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use {
        super::*,
        crate::transaction_notifier_interface::TransactionNotifier,
        crossbeam_channel::unbounded,
        dashmap::DashMap,
        account_decoder::parse_token::token_amount_to_ui_amount,
        ledger::{genesis_utils::create_genesis_config, get_tmp_ledger_path},
        runtime::bank::{Bank, NonceFull, NoncePartial, RentDebits, TransactionBalancesSet},
        sdk::{
            account_utils::StateMut,
            clock::Slot,
            hash::Hash,
            instruction::CompiledInstruction,
            message::{Message, MessageHeader, SanitizedMessage},
            nonce::{self, state::DurableNonce},
            nonce_account,
            pubkey::Pubkey,
            signature::{Keypair, Signature, Signer},
            system_transaction,
            transaction::{
                SanitizedTransaction, Transaction, TransactionError, VersionedTransaction,
            },
        },
        transaction_status::{
            token_balances::TransactionTokenBalancesSet, TransactionStatusMeta,
            TransactionTokenBalance,
        },
        std::{
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc, RwLock,
            },
            thread::sleep,
            time::Duration,
        },
    };

    struct TestTransactionNotifier {
        notifications: DashMap<(Slot, Signature), (TransactionStatusMeta, SanitizedTransaction)>,
    }

    impl TestTransactionNotifier {
        pub fn new() -> Self {
            Self {
                notifications: DashMap::default(),
            }
        }
    }

    impl TransactionNotifier for TestTransactionNotifier {
        fn notify_transaction(
            &self,
            slot: Slot,
            signature: &Signature,
            transaction_status_meta: &TransactionStatusMeta,
            transaction: &SanitizedTransaction,
        ) {
            self.notifications.insert(
                (slot, *signature),
                (transaction_status_meta.clone(), transaction.clone()),
            );
        }
    }

    fn build_test_transaction_legacy() -> Transaction {
        let keypair1 = Keypair::new();
        let pubkey1 = keypair1.pubkey();
        let zero = Hash::default();
        system_transaction::transfer(&keypair1, &pubkey1, 42, zero)
    }

    fn build_message() -> Message {
        Message {
            header: MessageHeader {
                num_readonly_signed_accounts: 11,
                num_readonly_unsigned_accounts: 12,
                num_required_signatures: 13,
            },
            account_keys: vec![Pubkey::new_unique()],
            recent_blockhash: Hash::new_unique(),
            instructions: vec![CompiledInstruction {
                program_id_index: 1,
                accounts: vec![1, 2, 3],
                data: vec![4, 5, 6],
            }],
        }
    }

    #[test]
    fn test_notify_transaction() {
        let genesis_config = create_genesis_config(2).genesis_config;
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));

        let (transaction_status_sender, transaction_status_receiver) = unbounded();
        let ledger_path = get_tmp_ledger_path!();
        let blockstore =
            Blockstore::open(&ledger_path).expect("Expected to be able to open database ledger");
        let blockstore = Arc::new(blockstore);

        let message_hash = Hash::new_unique();
        let transaction = build_test_transaction_legacy();
        let transaction = VersionedTransaction::from(transaction);
        let transaction =
            SanitizedTransaction::try_create(transaction, message_hash, Some(true), |_| {
                Err(TransactionError::UnsupportedVersion)
            })
            .unwrap();

        let expected_transaction = transaction.clone();
        let pubkey = Pubkey::new_unique();

        let mut nonce_account =
            nonce_account::create_account(1, /*separate_domains:*/ true).into_inner();
        let durable_nonce =
            DurableNonce::from_blockhash(&Hash::new(&[42u8; 32]), /*separate_domains:*/ true);
        let data = nonce::state::Data::new(Pubkey::new(&[1u8; 32]), durable_nonce, 42);
        nonce_account
            .set_state(&nonce::state::Versions::new(
                nonce::State::Initialized(data),
                true, // separate_domains
            ))
            .unwrap();

        let message = build_message();

        let rollback_partial = NoncePartial::new(pubkey, nonce_account.clone());

        let mut rent_debits = RentDebits::default();
        rent_debits.insert(&pubkey, 123, 456);

        let transaction_result = Some(TransactionExecutionDetails {
            status: Ok(()),
            log_messages: None,
            inner_instructions: None,
            durable_nonce_fee: Some(DurableNonceFee::from(
                &NonceFull::from_partial(
                    rollback_partial,
                    &SanitizedMessage::Legacy(message),
                    &[(pubkey, nonce_account)],
                    &rent_debits,
                )
                .unwrap(),
            )),
            executed_units: 0u64,
        });

        let balances = TransactionBalancesSet {
            pre_balances: vec![vec![123456]],
            post_balances: vec![vec![234567]],
        };

        let owner = Pubkey::new_unique().to_string();
        let pre_token_balance = TransactionTokenBalance {
            account_index: 0,
            mint: Pubkey::new_unique().to_string(),
            ui_token_amount: token_amount_to_ui_amount(42, 2),
            owner: owner.clone(),
        };

        let post_token_balance = TransactionTokenBalance {
            account_index: 0,
            mint: Pubkey::new_unique().to_string(),
            ui_token_amount: token_amount_to_ui_amount(58, 2),
            owner,
        };

        let token_balances = TransactionTokenBalancesSet {
            pre_token_balances: vec![vec![pre_token_balance]],
            post_token_balances: vec![vec![post_token_balance]],
        };

        let slot = bank.slot();
        let signature = *transaction.signature();
        let transaction_status_batch = TransactionStatusBatch {
            bank,
            transactions: vec![transaction],
            execution_results: vec![transaction_result],
            balances,
            token_balances,
            rent_debits: vec![rent_debits],
        };

        let test_notifier = Arc::new(RwLock::new(TestTransactionNotifier::new()));

        let exit = Arc::new(AtomicBool::new(false));
        let transaction_status_service = TransactionStatusService::new(
            transaction_status_receiver,
            Arc::new(AtomicU64::default()),
            false,
            Some(test_notifier.clone()),
            blockstore,
            &exit,
        );

        transaction_status_sender
            .send(TransactionStatusMessage::Batch(transaction_status_batch))
            .unwrap();
        sleep(Duration::from_millis(500));

        exit.store(true, Ordering::Relaxed);
        transaction_status_service.join().unwrap();
        let notifier = test_notifier.read().unwrap();
        assert_eq!(notifier.notifications.len(), 1);
        assert!(notifier.notifications.contains_key(&(slot, signature)));

        let result = &*notifier.notifications.get(&(slot, signature)).unwrap();
        assert_eq!(expected_transaction.signature(), result.1.signature());
    }
}
