// use {
//     crate::tpu_info::TpuInfo,
//     log::*,
//     solana_metrics::{datapoint_warn, inc_new_counter_info},
//     solana_runtime::{bank::Bank, bank_forks::BankForks},
//     solana_sdk::{hash::Hash, nonce_account, pubkey::Pubkey, signature::Signature},
//     std::{
//         collections::hash_map::{Entry, HashMap},
//         net::{SocketAddr, UdpSocket},
//         sync::{
//             mpsc::{Receiver, RecvTimeoutError},
//             Arc, RwLock,
//         },
//         thread::{self, Builder, JoinHandle},
//         time::{Duration, Instant},
//     },
// };

use std::thread::{self, Builder, JoinHandle},

pub struct TransactionInfo {
    pub signature: Signature,
    pub wire_transaction: Vec<u8>,
    pub last_valid_block_height: u64,
    pub durable_nonce_info: Option<(Pubkey, Hash)>,
    pub max_retries: Option<usize>,
    retries: usize,
}

impl TransactionInfo {
    pub fn new(
        signature: Signature,
        wire_transaction: Vec<u8>,
        last_valid_block_height: u64,
        durable_nonce_info: Option<(Pubkey, Hash)>,
        max_retries: Option<usize>,
    ) -> Self {
        Self {
            signature,
            wire_transaction,
            last_valid_block_height,
            durable_nonce_info,
            max_retries,
            retries: 0,
        }
    }
}

pub struct SendTransactionService {
    thread: JoinHandle<()>,
}

impl SendTransactionService {
    pub fn new<T: TpuInfo + std::marker::Send + 'static>(
        tpu_address: SocketAddr,
        bank_forks: &Arc<RwLock<BankForks>>,
        leader_info: Option<T>,
        receiver: Receiver<TransactionInfo>,
        retry_rate_ms: u64,
        leader_forward_count: u64,
    ) -> Self {
        let config = Config {
            retry_rate_ms,
            leader_forward_count,
            ..Config::default()
        };
        Self::new_with_config(tpu_address, bank_forks, leader_info, receiver, config)
    }

    pub fn new_with_config<T: TpuInfo + std::marker::Send + 'static>(
        tpu_address: SocketAddr,
        bank_forks: &Arc<RwLock<BankForks>>,
        leader_info: Option<T>,
        receiver: Receiver<TransactionInfo>,
        config: Config,
    ) -> Self {
        let thread = Self::retry_thread(
            tpu_address,
            receiver,
            bank_forks.clone(),
            leader_info,
            config,
        );
        Self { thread }
    }

    fn retry_thread<T: TpuInfo + std::marker::Send + 'static>(
        tpu_address: SocketAddr,
        receiver: Receiver<TransactionInfo>,
        bank_forks: Arc<RwLock<BankForks>>,
        mut leader_info: Option<T>,
        config: Config,
    ) -> JoinHandle<()> {
        let mut last_status_check = Instant::now();
        let mut last_leader_refresh = Instant::now();
        let mut transactions = HashMap::new();
        let send_socket = UdpSocket::bind("0.0.0.0:0").unwrap();

        if let Some(leader_info) = leader_info.as_mut() {
            leader_info.refresh_recent_peers();
        }

        Builder::new()
            .name("send-tx-sv2".to_string())
            .spawn(move || loop {
                match receiver.recv_timeout(Duration::from_millis(1000.min(config.retry_rate_ms))) {
                    Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {}
                    Ok(transaction_info) => {
                        inc_new_counter_info!("send_transaction_service-recv-tx", 1);
                        let transactions_len = transactions.len();
                        let entry = transactions.entry(transaction_info.signature);
                        if let Entry::Vacant(_) = entry {
                            let addresses = leader_info.as_ref().map(|leader_info| {
                                leader_info.get_leader_tpus(config.leader_forward_count)
                            });
                            let addresses = addresses
                                .map(|address_list| {
                                    if address_list.is_empty() {
                                        vec![&tpu_address]
                                    } else {
                                        address_list
                                    }
                                })
                                .unwrap_or_else(|| vec![&tpu_address]);
                            for address in addresses {
                                Self::send_transaction(
                                    &send_socket,
                                    address,
                                    &transaction_info.wire_transaction,
                                );
                            }
                            if transactions_len < MAX_TRANSACTION_QUEUE_SIZE {
                                inc_new_counter_info!("send_transaction_service-insert-tx", 1);
                                entry.or_insert(transaction_info);
                            } else {
                                datapoint_warn!("send_transaction_service-queue-overflow");
                            }
                        } else {
                            inc_new_counter_info!("send_transaction_service-recv-duplicate", 1);
                        }
                    }
                }

                if last_status_check.elapsed().as_millis() as u64 >= config.retry_rate_ms {
                    if !transactions.is_empty() {
                        datapoint_info!(
                            "send_transaction_service-queue-size",
                            ("len", transactions.len(), i64)
                        );
                        let (root_bank, working_bank) = {
                            let bank_forks = bank_forks.read().unwrap();
                            (
                                bank_forks.root_bank().clone(),
                                bank_forks.working_bank().clone(),
                            )
                        };

                        let _result = Self::process_transactions(
                            &working_bank,
                            &root_bank,
                            &send_socket,
                            &tpu_address,
                            &mut transactions,
                            &leader_info,
                            &config,
                        );
                    }
                    last_status_check = Instant::now();
                    if last_leader_refresh.elapsed().as_millis() > 1000 {
                        if let Some(leader_info) = leader_info.as_mut() {
                            leader_info.refresh_recent_peers();
                        }
                        last_leader_refresh = Instant::now();
                    }
                }
            })
            .unwrap()
    }

    fn process_transactions<T: TpuInfo>(
        working_bank: &Arc<Bank>,
        root_bank: &Arc<Bank>,
        send_socket: &UdpSocket,
        tpu_address: &SocketAddr,
        transactions: &mut HashMap<Signature, TransactionInfo>,
        leader_info: &Option<T>,
        config: &Config,
    ) -> ProcessTransactionsResult {
        let mut result = ProcessTransactionsResult::default();

        transactions.retain(|signature, mut transaction_info| {
            if transaction_info.durable_nonce_info.is_some() {
                inc_new_counter_info!("send_transaction_service-nonced", 1);
            }
            if root_bank.has_signature(signature) {
                info!("Transaction is rooted: {}", signature);
                result.rooted += 1;
                inc_new_counter_info!("send_transaction_service-rooted", 1);
                return false;
            }
            if let Some((nonce_pubkey, durable_nonce)) = transaction_info.durable_nonce_info {
                let nonce_account = working_bank.get_account(&nonce_pubkey).unwrap_or_default();
                let verify_nonce_account = nonce_account::verify_nonce_account(
                    &nonce_account,
                    &durable_nonce,
                    working_bank.separate_nonce_from_blockhash(),
                );
                if verify_nonce_account.is_none()
                    && working_bank.get_signature_status_slot(signature).is_none()
                {
                    info!("Dropping expired durable-nonce transaction: {}", signature);
                    result.expired += 1;
                    inc_new_counter_info!("send_transaction_service-expired", 1);
                    return false;
                }
            }
            if transaction_info.last_valid_block_height < root_bank.block_height() {
                info!("Dropping expired transaction: {}", signature);
                result.expired += 1;
                inc_new_counter_info!("send_transaction_service-expired", 1);
                return false;
            }

            let max_retries = transaction_info
                .max_retries
                .or(config.default_max_retries)
                .map(|max_retries| max_retries.min(config.service_max_retries));

            if let Some(max_retries) = max_retries {
                if transaction_info.retries >= max_retries {
                    info!("Dropping transaction due to max retries: {}", signature);
                    result.max_retries_elapsed += 1;
                    inc_new_counter_info!("send_transaction_service-max_retries", 1);
                    return false;
                }
            }

            match working_bank.get_signature_status_slot(signature) {
                None => {
                    // Transaction is unknown to the working bank, it might have been
                    // dropped or landed in another fork.  Re-send it
                    info!("Retrying transaction: {}", signature);
                    result.retried += 1;
                    transaction_info.retries += 1;
                    inc_new_counter_info!("send_transaction_service-retry", 1);
                    let addresses = leader_info.as_ref().map(|leader_info| {
                        leader_info.get_leader_tpus(config.leader_forward_count)
                    });
                    let addresses = addresses
                        .map(|address_list| {
                            if address_list.is_empty() {
                                vec![tpu_address]
                            } else {
                                address_list
                            }
                        })
                        .unwrap_or_else(|| vec![tpu_address]);
                    for address in addresses {
                        Self::send_transaction(
                            send_socket,
                            address,
                            &transaction_info.wire_transaction,
                        );
                    }
                    true
                }
                Some((_slot, status)) => {
                    if status.is_err() {
                        info!("Dropping failed transaction: {}", signature);
                        result.failed += 1;
                        inc_new_counter_info!("send_transaction_service-failed", 1);
                        false
                    } else {
                        result.retained += 1;
                        true
                    }
                }
            }
        });

        result
    }

    fn send_transaction(
        send_socket: &UdpSocket,
        tpu_address: &SocketAddr,
        wire_transaction: &[u8],
    ) {
        if let Err(err) = send_socket.send_to(wire_transaction, tpu_address) {
            warn!("Failed to send transaction to {}: {:?}", tpu_address, err);
        }
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread.join()
    }
}