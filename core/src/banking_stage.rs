//! The `banking_stage` processes Transaction messages. It is intended to be used
//! to contruct a software pipeline. The stage uses all available CPU cores and
//! can do its processing in parallel with signature verification on the GPU.
use {
    crate::{
        leader_slot_banking_stage_metrics::{LeaderSlotMetricsTracker, ProcessTransactionsSummary},
        leader_slot_banking_stage_timing_metrics::{
            LeaderExecuteAndCommitTimings, RecordTransactionsTimings,
        },
        qos_service::QosService,
    },
    crossbeam_channel::{Receiver as CrossbeamReceiver, RecvTimeoutError},
    histogram::Histogram,
    itertools::Itertools,
    entry::entry::hash_transactions,
    gossip::{cluster_info::ClusterInfo, contact_info::ContactInfo},
    ledger::blockstore_processor::TransactionStatusSender,
    measure::measure::Measure,
    metrics::{inc_new_counter_debug, inc_new_counter_info},
    perf::{
        cuda_runtime::PinnedVec,
        data_budget::DataBudget,
        packet::{Packet, PacketBatch, PACKETS_PER_BATCH},
        perf_libs,
    },
    poh::poh_recorder::{BankStart, PohRecorder, PohRecorderError, TransactionRecorder},
    program_runtime::timings::ExecuteTimings,
    runtime::{
        bank::{
            Bank, CommitTransactionCounts, LoadAndExecuteTransactionsOutput,
            TransactionBalancesSet, TransactionCheckResult, TransactionExecutionResult,
        },
        bank_utils,
        cost_model::{CostModel, TransactionCost},
        transaction_batch::TransactionBatch,
        transaction_error_metrics::TransactionErrorMetrics,
        vote_sender_types::ReplayVoteSender,
    },
    sdk::{
        clock::{
            Slot, DEFAULT_TICKS_PER_SLOT, MAX_PROCESSING_AGE, MAX_TRANSACTION_FORWARDING_DELAY,
            MAX_TRANSACTION_FORWARDING_DELAY_GPU,
        },
        feature_set,
        message::{
            v0::{LoadedAddresses, MessageAddressTableLookup},
            Message,
        },
        pubkey::Pubkey,
        saturating_add_assign,
        short_vec::decode_shortu16_len,
        signature::Signature,
        timing::{duration_as_ms, timestamp, AtomicInterval},
        transaction::{self, SanitizedTransaction, TransactionError, VersionedTransaction},
    },
    sino_streamer::sendmmsg::{batch_send, SendPktsError},
    transaction_status::token_balances::{
        collect_token_balances, TransactionTokenBalancesSet,
    },
    std::{
        cmp,
        collections::{HashMap, VecDeque},
        env,
        mem::size_of,
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicU64, AtomicUsize, Ordering},
            Arc, Mutex, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

/// (packets, valid_indexes, forwarded)
/// Batch of packets with a list of which are valid and if this batch has been forwarded.
type PacketBatchAndOffsets = (PacketBatch, Vec<usize>, bool);

pub type UnprocessedPacketBatches = VecDeque<PacketBatchAndOffsets>;

/// Transaction forwarding
pub const FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET: u64 = 2;
pub const HOLD_TRANSACTIONS_SLOT_OFFSET: u64 = 20;

// Fixed thread size seems to be fastest on GCP setup
pub const NUM_THREADS: u32 = 6;

const TOTAL_BUFFERED_PACKETS: usize = 700_000;

const MAX_NUM_TRANSACTIONS_PER_BATCH: usize = 64;

const NUM_VOTE_PROCESSING_THREADS: u32 = 2;
const MIN_THREADS_BANKING: u32 = 1;

const SLOT_BOUNDARY_CHECK_PERIOD: Duration = Duration::from_millis(10);

pub struct ProcessTransactionBatchOutput {
    // The number of transactions filtered out by the cost model
    cost_model_throttled_transactions_count: usize,
    // Amount of time spent running the cost model
    cost_model_us: u64,
    execute_and_commit_transactions_output: ExecuteAndCommitTransactionsOutput,
}

struct RecordTransactionsSummary {
    // Metrics describing how time was spent recording transactions
    record_transactions_timings: RecordTransactionsTimings,
    // Result of trying to record the transactions into the PoH stream
    result: Result<usize, PohRecorderError>,
    // Transactions that failed record, and are retryable
    retryable_indexes: Vec<usize>,
}

#[derive(Debug)]
pub enum CommitTransactionDetails {
    Committed { compute_units: u64 },
    NotCommitted,
}

pub struct ExecuteAndCommitTransactionsOutput {
    // Total number of transactions that were passed as candidates for execution
    transactions_attempted_execution_count: usize,
    // The number of transactions of that were executed. See description of in `ProcessTransactionsSummary`
    // for possible outcomes of execution.
    executed_transactions_count: usize,
    // Total number of the executed transactions that returned success/not
    // an error.
    executed_with_successful_result_count: usize,
    // Transactions that either were not executed, or were executed and failed to be committed due
    // to the block ending.
    retryable_transaction_indexes: Vec<usize>,
    // A result that indicates whether transactions were successfully
    // committed into the Poh stream.
    commit_transactions_result: Result<Vec<CommitTransactionDetails>, PohRecorderError>,
    execute_and_commit_timings: LeaderExecuteAndCommitTimings,
    error_counters: TransactionErrorMetrics,
}

#[derive(Debug, Default)]
pub struct BankingStageStats {
    last_report: AtomicInterval,
    id: u32,
    receive_and_buffer_packets_count: AtomicUsize,
    dropped_packet_batches_count: AtomicUsize,
    dropped_packets_count: AtomicUsize,
    newly_buffered_packets_count: AtomicUsize,
    current_buffered_packets_count: AtomicUsize,
    current_buffered_packet_batches_count: AtomicUsize,
    rebuffered_packets_count: AtomicUsize,
    consumed_buffered_packets_count: AtomicUsize,
    end_of_slot_filtered_invalid_count: AtomicUsize,
    batch_packet_indexes_len: Histogram,

    // Timing
    consume_buffered_packets_elapsed: AtomicU64,
    receive_and_buffer_packets_elapsed: AtomicU64,
    handle_retryable_packets_elapsed: AtomicU64,
    filter_pending_packets_elapsed: AtomicU64,
    packet_conversion_elapsed: AtomicU64,
    unprocessed_packet_conversion_elapsed: AtomicU64,
    transaction_processing_elapsed: AtomicU64,
}

impl BankingStageStats {
    pub fn new(id: u32) -> Self {
        BankingStageStats {
            id,
            batch_packet_indexes_len: Histogram::configure()
                .max_value(PACKETS_PER_BATCH as u64)
                .build()
                .unwrap(),
            ..BankingStageStats::default()
        }
    }

    fn is_empty(&self) -> bool {
        0 == self
            .receive_and_buffer_packets_count
            .load(Ordering::Relaxed) as u64
            + self.dropped_packet_batches_count.load(Ordering::Relaxed) as u64
            + self.dropped_packets_count.load(Ordering::Relaxed) as u64
            + self.newly_buffered_packets_count.load(Ordering::Relaxed) as u64
            + self.current_buffered_packets_count.load(Ordering::Relaxed) as u64
            + self
                .current_buffered_packet_batches_count
                .load(Ordering::Relaxed) as u64
            + self.rebuffered_packets_count.load(Ordering::Relaxed) as u64
            + self.consumed_buffered_packets_count.load(Ordering::Relaxed) as u64
            + self
                .consume_buffered_packets_elapsed
                .load(Ordering::Relaxed)
            + self
                .receive_and_buffer_packets_elapsed
                .load(Ordering::Relaxed)
            + self
                .handle_retryable_packets_elapsed
                .load(Ordering::Relaxed)
            + self.filter_pending_packets_elapsed.load(Ordering::Relaxed)
            + self.packet_conversion_elapsed.load(Ordering::Relaxed)
            + self
                .unprocessed_packet_conversion_elapsed
                .load(Ordering::Relaxed)
            + self.transaction_processing_elapsed.load(Ordering::Relaxed)
            + self.batch_packet_indexes_len.entries()
    }

    fn report(&mut self, report_interval_ms: u64) {
        // skip repoting metrics if stats is empty
        if self.is_empty() {
            return;
        }
        if self.last_report.should_update(report_interval_ms) {
            datapoint_info!(
                "banking_stage-loop-stats",
                ("id", self.id as i64, i64),
                (
                    "receive_and_buffer_packets_count",
                    self.receive_and_buffer_packets_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "dropped_packet_batches_count",
                    self.dropped_packet_batches_count.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "dropped_packets_count",
                    self.dropped_packets_count.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "newly_buffered_packets_count",
                    self.newly_buffered_packets_count.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "current_buffered_packet_batches_count",
                    self.current_buffered_packet_batches_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "current_buffered_packets_count",
                    self.current_buffered_packets_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "rebuffered_packets_count",
                    self.rebuffered_packets_count.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "consumed_buffered_packets_count",
                    self.consumed_buffered_packets_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "end_of_slot_filtered_invalid_count",
                    self.end_of_slot_filtered_invalid_count
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "consume_buffered_packets_elapsed",
                    self.consume_buffered_packets_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "receive_and_buffer_packets_elapsed",
                    self.receive_and_buffer_packets_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "handle_retryable_packets_elapsed",
                    self.handle_retryable_packets_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "filter_pending_packets_elapsed",
                    self.filter_pending_packets_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "packet_conversion_elapsed",
                    self.packet_conversion_elapsed.swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "unprocessed_packet_conversion_elapsed",
                    self.unprocessed_packet_conversion_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "transaction_processing_elapsed",
                    self.transaction_processing_elapsed
                        .swap(0, Ordering::Relaxed) as i64,
                    i64
                ),
                (
                    "packet_batch_indices_len_min",
                    self.batch_packet_indexes_len.minimum().unwrap_or(0) as i64,
                    i64
                ),
                (
                    "packet_batch_indices_len_max",
                    self.batch_packet_indexes_len.maximum().unwrap_or(0) as i64,
                    i64
                ),
                (
                    "packet_batch_indices_len_mean",
                    self.batch_packet_indexes_len.mean().unwrap_or(0) as i64,
                    i64
                ),
                (
                    "packet_batch_indices_len_90pct",
                    self.batch_packet_indexes_len.percentile(90.0).unwrap_or(0) as i64,
                    i64
                )
            );
            self.batch_packet_indexes_len.clear();
        }
    }
}

#[derive(Debug, Default)]
pub struct BatchedTransactionCostDetails {
    pub batched_signature_cost: u64,
    pub batched_write_lock_cost: u64,
    pub batched_data_bytes_cost: u64,
    pub batched_builtins_execute_cost: u64,
    pub batched_bpf_execute_cost: u64,
}

#[derive(Debug, Default)]
struct EndOfSlot {
    next_slot_leader: Option<Pubkey>,
    working_bank: Option<Arc<Bank>>,
}

/// Stores the stage's thread handle and output receiver.
pub struct BankingStage {
    bank_thread_hdls: Vec<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
pub enum BufferedPacketsDecision {
    Consume(u128),
    Forward,
    ForwardAndHold,
    Hold,
}

#[derive(Debug, Clone)]
pub enum ForwardOption {
    NotForward,
    ForwardTpuVote,
    ForwardTransaction,
}

impl BankingStage {
    /// Create the stage using `bank`. Exit when `verified_receiver` is dropped.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        cluster_info: &Arc<ClusterInfo>,
        poh_recorder: &Arc<Mutex<PohRecorder>>,
        verified_receiver: CrossbeamReceiver<Vec<PacketBatch>>,
        tpu_verified_vote_receiver: CrossbeamReceiver<Vec<PacketBatch>>,
        verified_vote_receiver: CrossbeamReceiver<Vec<PacketBatch>>,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: ReplayVoteSender,
        cost_model: Arc<RwLock<CostModel>>,
    ) -> Self {
        Self::new_num_threads(
            cluster_info,
            poh_recorder,
            verified_receiver,
            tpu_verified_vote_receiver,
            verified_vote_receiver,
            Self::num_threads(),
            transaction_status_sender,
            gossip_vote_sender,
            cost_model,
        )
    }

    fn new_num_threads(
        cluster_info: &Arc<ClusterInfo>,
        poh_recorder: &Arc<Mutex<PohRecorder>>,
        verified_receiver: CrossbeamReceiver<Vec<PacketBatch>>,
        tpu_verified_vote_receiver: CrossbeamReceiver<Vec<PacketBatch>>,
        verified_vote_receiver: CrossbeamReceiver<Vec<PacketBatch>>,
        num_threads: u32,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: ReplayVoteSender,
        cost_model: Arc<RwLock<CostModel>>,
    ) -> Self {
        let batch_limit = TOTAL_BUFFERED_PACKETS / ((num_threads - 1) as usize * PACKETS_PER_BATCH);
        // Single thread to generate entries from many banks.
        // This thread talks to poh_service and broadcasts the entries once they have been recorded.
        // Once an entry has been recorded, its blockhash is registered with the bank.
        let data_budget = Arc::new(DataBudget::default());
        let qos_service = Arc::new(QosService::new(cost_model));
        // Many banks that process transactions in parallel.
        assert!(num_threads >= NUM_VOTE_PROCESSING_THREADS + MIN_THREADS_BANKING);
        let bank_thread_hdls: Vec<JoinHandle<()>> = (0..num_threads)
            .map(|i| {
                let (verified_receiver, forward_option) = match i {
                    0 => {
                        // Disable forwarding of vote transactions
                        // from gossip. Note - votes can also arrive from tpu
                        (verified_vote_receiver.clone(), ForwardOption::NotForward)
                    }
                    1 => (
                        tpu_verified_vote_receiver.clone(),
                        ForwardOption::ForwardTpuVote,
                    ),
                    _ => (verified_receiver.clone(), ForwardOption::ForwardTransaction),
                };

                let poh_recorder = poh_recorder.clone();
                let cluster_info = cluster_info.clone();
                let mut recv_start = Instant::now();
                let transaction_status_sender = transaction_status_sender.clone();
                let gossip_vote_sender = gossip_vote_sender.clone();
                let data_budget = data_budget.clone();
                let qos_service = qos_service.clone();
                Builder::new()
                    .name("solana-banking-stage-tx".to_string())
                    .spawn(move || {
                        Self::process_loop(
                            &verified_receiver,
                            &poh_recorder,
                            &cluster_info,
                            &mut recv_start,
                            forward_option,
                            i,
                            batch_limit,
                            transaction_status_sender,
                            gossip_vote_sender,
                            &data_budget,
                            qos_service,
                        );
                    })
                    .unwrap()
            })
            .collect();
        Self { bank_thread_hdls }
    }

    fn filter_valid_packets_for_forwarding<'a>(
        packet_batches: impl Iterator<Item = &'a PacketBatchAndOffsets>,
    ) -> Vec<&'a Packet> {
        packet_batches
            .filter(|(_batch, _indexes, forwarded)| !forwarded)
            .flat_map(|(batch, valid_indexes, _forwarded)| {
                valid_indexes.iter().map(move |x| &batch.packets[*x])
            })
            .collect()
    }

    /// Forwards all valid, unprocessed packets in the buffer, up to a rate limit. Returns
    /// the number of successfully forwarded packets in second part of tuple
    fn forward_buffered_packets(
        socket: &std::net::UdpSocket,
        tpu_forwards: &std::net::SocketAddr,
        packets: Vec<&Packet>,
        data_budget: &DataBudget,
    ) -> (std::io::Result<()>, usize) {
        const INTERVAL_MS: u64 = 100;
        const MAX_BYTES_PER_SECOND: usize = 10_000 * 1200;
        const MAX_BYTES_PER_INTERVAL: usize = MAX_BYTES_PER_SECOND * INTERVAL_MS as usize / 1000;
        const MAX_BYTES_BUDGET: usize = MAX_BYTES_PER_INTERVAL * 5;
        data_budget.update(INTERVAL_MS, |bytes| {
            std::cmp::min(
                bytes.saturating_add(MAX_BYTES_PER_INTERVAL),
                MAX_BYTES_BUDGET,
            )
        });

        let packet_vec: Vec<_> = packets
            .iter()
            .filter_map(|p| {
                if !p.meta.forwarded() && data_budget.take(p.meta.size) {
                    Some((&p.data[..p.meta.size], tpu_forwards))
                } else {
                    None
                }
            })
            .collect();

        if !packet_vec.is_empty() {
            inc_new_counter_info!("banking_stage-forwarded_packets", packet_vec.len());
            if let Err(SendPktsError::IoError(ioerr, num_failed)) = batch_send(socket, &packet_vec)
            {
                return (Err(ioerr), packet_vec.len().saturating_sub(num_failed));
            }
        }

        (Ok(()), packet_vec.len())
    }

    // Returns whether the given `PacketBatch` has any more remaining unprocessed
    // transactions
    fn update_buffered_packets_with_new_unprocessed(
        original_unprocessed_indexes: &mut Vec<usize>,
        new_unprocessed_indexes: Vec<usize>,
    ) -> bool {
        let has_more_unprocessed_transactions =
            Self::packet_has_more_unprocessed_transactions(&new_unprocessed_indexes);
        if has_more_unprocessed_transactions {
            *original_unprocessed_indexes = new_unprocessed_indexes
        };
        has_more_unprocessed_transactions
    }

    #[allow(clippy::too_many_arguments)]
    pub fn consume_buffered_packets(
        my_pubkey: &Pubkey,
        max_tx_ingestion_ns: u128,
        poh_recorder: &Arc<Mutex<PohRecorder>>,
        buffered_packet_batches: &mut UnprocessedPacketBatches,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        test_fn: Option<impl Fn()>,
        banking_stage_stats: &BankingStageStats,
        recorder: &TransactionRecorder,
        qos_service: &Arc<QosService>,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) {
        let mut rebuffered_packet_count = 0;
        let mut consumed_buffered_packets_count = 0;
        let buffered_packet_batches_len = buffered_packet_batches.len();
        let mut proc_start = Measure::start("consume_buffered_process");
        let mut reached_end_of_slot: Option<EndOfSlot> = None;

        // #[allow(unstable_name_collisions)]
        buffered_packet_batches.retain_mut(|buffered_packet_batch_and_offsets| {
            let (packet_batch, ref mut original_unprocessed_indexes, _forwarded) =
                buffered_packet_batch_and_offsets;
            if let Some(end_of_slot) = &reached_end_of_slot {
                let (should_retain, end_of_slot_filtering_time) = Measure::this(
                    |_| {
                        // We've hit the end of this slot, no need to perform more processing,
                        // just filter the remaining packets for the invalid (e.g. too old) ones
                        // if the working_bank is available
                        if let Some(bank) = &end_of_slot.working_bank {
                            let new_unprocessed_indexes =
                                Self::filter_unprocessed_packets_at_end_of_slot(
                                    bank,
                                    packet_batch,
                                    original_unprocessed_indexes,
                                    my_pubkey,
                                    end_of_slot.next_slot_leader,
                                    banking_stage_stats,
                                );

                            let end_of_slot_filtered_invalid_count = original_unprocessed_indexes
                                .len()
                                .saturating_sub(new_unprocessed_indexes.len());

                            slot_metrics_tracker.increment_end_of_slot_filtered_invalid_count(
                                end_of_slot_filtered_invalid_count as u64,
                            );

                            banking_stage_stats
                                .end_of_slot_filtered_invalid_count
                                .fetch_add(end_of_slot_filtered_invalid_count, Ordering::Relaxed);

                            Self::update_buffered_packets_with_new_unprocessed(
                                original_unprocessed_indexes,
                                new_unprocessed_indexes,
                            )
                        } else {
                            true
                        }
                    },
                    (),
                    "end_of_slot_filtering",
                );
                slot_metrics_tracker
                    .increment_end_of_slot_filtering_us(end_of_slot_filtering_time.as_us());
                should_retain
            } else {
                let (bank_start, poh_recorder_lock_time) = Measure::this(
                    |_| poh_recorder.lock().unwrap().bank_start(),
                    (),
                    "poh_recorder_lock",
                );
                slot_metrics_tracker.increment_consume_buffered_packets_poh_recorder_lock_us(
                    poh_recorder_lock_time.as_us(),
                );
                if let Some(BankStart {
                    working_bank,
                    bank_creation_time,
                }) = bank_start
                {
                    let (process_transactions_summary, process_packets_transactions_time) =
                        Measure::this(
                            |_| {
                                Self::process_packets_transactions(
                                    &working_bank,
                                    &bank_creation_time,
                                    recorder,
                                    packet_batch,
                                    original_unprocessed_indexes.to_owned(),
                                    transaction_status_sender.clone(),
                                    gossip_vote_sender,
                                    banking_stage_stats,
                                    qos_service,
                                    slot_metrics_tracker,
                                )
                            },
                            (),
                            "process_packets_transactions",
                        );
                    slot_metrics_tracker.increment_process_packets_transactions_us(
                        process_packets_transactions_time.as_us(),
                    );

                    let ProcessTransactionsSummary {
                        reached_max_poh_height,
                        retryable_transaction_indexes,
                        ..
                    } = process_transactions_summary;

                    if reached_max_poh_height
                        || !Bank::should_bank_still_be_processing_txs(
                            &bank_creation_time,
                            max_tx_ingestion_ns,
                        )
                    {
                        let poh_recorder_lock_time = {
                            let (poh_recorder_locked, poh_recorder_lock_time) = Measure::this(
                                |_| poh_recorder.lock().unwrap(),
                                (),
                                "poh_recorder_lock",
                            );

                            reached_end_of_slot = Some(EndOfSlot {
                                next_slot_leader: poh_recorder_locked.next_slot_leader(),
                                working_bank: Some(working_bank),
                            });
                            poh_recorder_lock_time
                        };
                        slot_metrics_tracker
                            .increment_consume_buffered_packets_poh_recorder_lock_us(
                                poh_recorder_lock_time.as_us(),
                            );
                    }

                    // The difference between all transactions passed to execution and the ones that
                    // are retryable were the ones that were either:
                    // 1) Committed into the block
                    // 2) Dropped without being committed because they had some fatal error (too old,
                    // duplicate signature, etc.)
                    //
                    // Note: This assumes that every packet deserializes into one transaction!
                    consumed_buffered_packets_count += original_unprocessed_indexes
                        .len()
                        .saturating_sub(retryable_transaction_indexes.len());

                    // Out of the buffered packets just retried, collect any still unprocessed
                    // transactions in this batch for forwarding
                    rebuffered_packet_count += retryable_transaction_indexes.len();
                    let has_more_unprocessed_transactions =
                        Self::update_buffered_packets_with_new_unprocessed(
                            original_unprocessed_indexes,
                            retryable_transaction_indexes,
                        );
                    if let Some(test_fn) = &test_fn {
                        test_fn();
                    }
                    has_more_unprocessed_transactions
                } else {
                    // mark as end-of-slot to avoid aggressively lock poh for the remaining for
                    // packet batches in buffer
                    let poh_recorder_lock_time = {
                        let (poh_recorder_locked, poh_recorder_lock_time) = Measure::this(
                            |_| poh_recorder.lock().unwrap(),
                            (),
                            "poh_recorder_lock",
                        );

                        reached_end_of_slot = Some(EndOfSlot {
                            next_slot_leader: poh_recorder_locked.next_slot_leader(),
                            working_bank: None,
                        });
                        poh_recorder_lock_time
                    };
                    slot_metrics_tracker.increment_consume_buffered_packets_poh_recorder_lock_us(
                        poh_recorder_lock_time.as_us(),
                    );

                    // `original_unprocessed_indexes` must have remaining packets to process
                    // if not yet processed.
                    assert!(Self::packet_has_more_unprocessed_transactions(
                        original_unprocessed_indexes
                    ));
                    true
                }
            }
        });

        proc_start.stop();

        debug!(
            "@{:?} done processing buffered batches: {} time: {:?}ms tx count: {} tx/s: {}",
            timestamp(),
            buffered_packet_batches_len,
            proc_start.as_ms(),
            consumed_buffered_packets_count,
            (consumed_buffered_packets_count as f32) / (proc_start.as_s())
        );

        banking_stage_stats
            .consume_buffered_packets_elapsed
            .fetch_add(proc_start.as_us(), Ordering::Relaxed);
        banking_stage_stats
            .rebuffered_packets_count
            .fetch_add(rebuffered_packet_count, Ordering::Relaxed);
        banking_stage_stats
            .consumed_buffered_packets_count
            .fetch_add(consumed_buffered_packets_count, Ordering::Relaxed);
    }

    fn consume_or_forward_packets(
        my_pubkey: &Pubkey,
        leader_pubkey: Option<Pubkey>,
        bank_still_processing_txs: Option<&Arc<Bank>>,
        would_be_leader: bool,
        would_be_leader_shortly: bool,
    ) -> BufferedPacketsDecision {
        // If has active bank, then immediately process buffered packets
        // otherwise, based on leader schedule to either forward or hold packets
        if let Some(bank) = bank_still_processing_txs {
            // If the bank is available, this node is the leader
            BufferedPacketsDecision::Consume(bank.ns_per_slot)
        } else if would_be_leader_shortly {
            // If the node will be the leader soon, hold the packets for now
            BufferedPacketsDecision::Hold
        } else if would_be_leader {
            // Node will be leader within ~20 slots, hold the transactions in
            // case it is the only node which produces an accepted slot.
            BufferedPacketsDecision::ForwardAndHold
        } else if let Some(x) = leader_pubkey {
            if x != *my_pubkey {
                // If the current node is not the leader, forward the buffered packets
                BufferedPacketsDecision::Forward
            } else {
                // If the current node is the leader, return the buffered packets as is
                BufferedPacketsDecision::Hold
            }
        } else {
            // We don't know the leader. Hold the packets for now
            BufferedPacketsDecision::Hold
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_buffered_packets(
        my_pubkey: &Pubkey,
        socket: &std::net::UdpSocket,
        poh_recorder: &Arc<Mutex<PohRecorder>>,
        cluster_info: &ClusterInfo,
        buffered_packet_batches: &mut UnprocessedPacketBatches,
        forward_option: &ForwardOption,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        banking_stage_stats: &BankingStageStats,
        recorder: &TransactionRecorder,
        data_budget: &DataBudget,
        qos_service: &Arc<QosService>,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) {
        let (decision, make_decision_time) = Measure::this(
            |_| {
                let bank_start;
                let (
                    leader_at_slot_offset,
                    bank_still_processing_txs,
                    would_be_leader,
                    would_be_leader_shortly,
                ) = {
                    let poh = poh_recorder.lock().unwrap();
                    bank_start = poh.bank_start();
                    (
                        poh.leader_after_n_slots(FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET),
                        PohRecorder::get_working_bank_if_not_expired(&bank_start.as_ref()),
                        poh.would_be_leader(HOLD_TRANSACTIONS_SLOT_OFFSET * DEFAULT_TICKS_PER_SLOT),
                        poh.would_be_leader(
                            (FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET - 1)
                                * DEFAULT_TICKS_PER_SLOT,
                        ),
                    )
                };
                slot_metrics_tracker.update_on_leader_slot_boundary(&bank_start);
                Self::consume_or_forward_packets(
                    my_pubkey,
                    leader_at_slot_offset,
                    bank_still_processing_txs,
                    would_be_leader,
                    would_be_leader_shortly,
                )
            },
            (),
            "make_decision",
        );
        slot_metrics_tracker.increment_make_decision_us(make_decision_time.as_us());

        match decision {
            BufferedPacketsDecision::Consume(max_tx_ingestion_ns) => {
                let (_, consume_buffered_packets_time) = Measure::this(
                    |_| {
                        Self::consume_buffered_packets(
                            my_pubkey,
                            max_tx_ingestion_ns,
                            poh_recorder,
                            buffered_packet_batches,
                            transaction_status_sender,
                            gossip_vote_sender,
                            None::<Box<dyn Fn()>>,
                            banking_stage_stats,
                            recorder,
                            qos_service,
                            slot_metrics_tracker,
                        )
                    },
                    (),
                    "consume_buffered_packets",
                );
                slot_metrics_tracker
                    .increment_consume_buffered_packets_us(consume_buffered_packets_time.as_us());
            }
            BufferedPacketsDecision::Forward => {
                let (_, forward_time) = Measure::this(
                    |_| {
                        Self::handle_forwarding(
                            forward_option,
                            cluster_info,
                            buffered_packet_batches,
                            poh_recorder,
                            socket,
                            false,
                            data_budget,
                            slot_metrics_tracker,
                        )
                    },
                    (),
                    "forward",
                );
                slot_metrics_tracker.increment_forward_us(forward_time.as_us());
            }
            BufferedPacketsDecision::ForwardAndHold => {
                let (_, forward_and_hold_time) = Measure::this(
                    |_| {
                        Self::handle_forwarding(
                            forward_option,
                            cluster_info,
                            buffered_packet_batches,
                            poh_recorder,
                            socket,
                            true,
                            data_budget,
                            slot_metrics_tracker,
                        )
                    },
                    (),
                    "forward_and_hold",
                );
                slot_metrics_tracker.increment_forward_and_hold_us(forward_and_hold_time.as_us());
            }
            _ => (),
        }
    }

    fn handle_forwarding(
        forward_option: &ForwardOption,
        cluster_info: &ClusterInfo,
        buffered_packet_batches: &mut UnprocessedPacketBatches,
        poh_recorder: &Arc<Mutex<PohRecorder>>,
        socket: &UdpSocket,
        hold: bool,
        data_budget: &DataBudget,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) {
        let addr = match forward_option {
            ForwardOption::NotForward => {
                if !hold {
                    buffered_packet_batches.clear();
                }
                return;
            }
            ForwardOption::ForwardTransaction => {
                next_leader_tpu_forwards(cluster_info, poh_recorder)
            }
            ForwardOption::ForwardTpuVote => next_leader_tpu_vote(cluster_info, poh_recorder),
        };
        let addr = match addr {
            Some(addr) => addr,
            None => return,
        };

        let forwardable_packets =
            Self::filter_valid_packets_for_forwarding(buffered_packet_batches.iter());
        let forwardable_packets_len = forwardable_packets.len();
        let (_forward_result, sucessful_forwarded_packets_count) =
            Self::forward_buffered_packets(socket, &addr, forwardable_packets, data_budget);
        let failed_forwarded_packets_count =
            forwardable_packets_len.saturating_sub(sucessful_forwarded_packets_count);

        if failed_forwarded_packets_count > 0 {
            slot_metrics_tracker
                .increment_failed_forwarded_packets_count(failed_forwarded_packets_count as u64);
            slot_metrics_tracker.increment_packet_batch_forward_failure_count(1);
        }

        if sucessful_forwarded_packets_count > 0 {
            slot_metrics_tracker.increment_successful_forwarded_packets_count(
                sucessful_forwarded_packets_count as u64,
            );
        }

        if hold {
            buffered_packet_batches.retain(|(_, index, _)| !index.is_empty());
            for (_, _, forwarded) in buffered_packet_batches.iter_mut() {
                *forwarded = true;
            }
        } else {
            slot_metrics_tracker
                .increment_cleared_from_buffer_after_forward_count(forwardable_packets_len as u64);
            buffered_packet_batches.clear();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_loop(
        verified_receiver: &CrossbeamReceiver<Vec<PacketBatch>>,
        poh_recorder: &Arc<Mutex<PohRecorder>>,
        cluster_info: &ClusterInfo,
        recv_start: &mut Instant,
        forward_option: ForwardOption,
        id: u32,
        batch_limit: usize,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: ReplayVoteSender,
        data_budget: &DataBudget,
        qos_service: Arc<QosService>,
    ) {
        let recorder = poh_recorder.lock().unwrap().recorder();
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut buffered_packet_batches = VecDeque::with_capacity(batch_limit);
        let mut banking_stage_stats = BankingStageStats::new(id);

        let mut slot_metrics_tracker = LeaderSlotMetricsTracker::new(id);
        let mut last_metrics_update = Instant::now();

        loop {
            let my_pubkey = cluster_info.id();
            if !buffered_packet_batches.is_empty() {
                let (_, process_buffered_packets_time) = Measure::this(
                    |_| {
                        Self::process_buffered_packets(
                            &my_pubkey,
                            &socket,
                            poh_recorder,
                            cluster_info,
                            &mut buffered_packet_batches,
                            &forward_option,
                            transaction_status_sender.clone(),
                            &gossip_vote_sender,
                            &banking_stage_stats,
                            &recorder,
                            data_budget,
                            &qos_service,
                            &mut slot_metrics_tracker,
                        )
                    },
                    (),
                    "process_buffered_packets",
                );
                slot_metrics_tracker
                    .increment_process_buffered_packets_us(process_buffered_packets_time.as_us());
            }

            // avoid excessively locking poh_recorder
            if last_metrics_update.elapsed() >= SLOT_BOUNDARY_CHECK_PERIOD {
                let (_, slot_metrics_checker_check_slot_boundary_time) = Measure::this(
                    |_| {
                        let current_poh_bank = {
                            let poh = poh_recorder.lock().unwrap();
                            poh.bank_start()
                        };
                        slot_metrics_tracker.update_on_leader_slot_boundary(&current_poh_bank);
                    },
                    (),
                    "slot_metrics_checker_check_slot_boundary",
                );
                slot_metrics_tracker.increment_slot_metrics_check_slot_boundary_us(
                    slot_metrics_checker_check_slot_boundary_time.as_us(),
                );

                last_metrics_update = Instant::now();
            }

            let recv_timeout = if !buffered_packet_batches.is_empty() {
                // If there are buffered packets, run the equivalent of try_recv to try reading more
                // packets. This prevents starving BankingStage::consume_buffered_packets due to
                // buffered_packet_batches containing transactions that exceed the cost model for
                // the current bank.
                Duration::from_millis(0)
            } else {
                // Default wait time
                Duration::from_millis(100)
            };

            let (res, receive_and_buffer_packets_time) = Measure::this(
                |_| {
                    Self::receive_and_buffer_packets(
                        verified_receiver,
                        recv_start,
                        recv_timeout,
                        id,
                        batch_limit,
                        &mut buffered_packet_batches,
                        &mut banking_stage_stats,
                        &mut slot_metrics_tracker,
                    )
                },
                (),
                "receive_and_buffer_packets",
            );
            slot_metrics_tracker
                .increment_receive_and_buffer_packets_us(receive_and_buffer_packets_time.as_us());

            match res {
                Ok(()) | Err(RecvTimeoutError::Timeout) => (),
                Err(RecvTimeoutError::Disconnected) => break,
            }
            banking_stage_stats.report(1000);
        }
    }

    pub fn num_threads() -> u32 {
        cmp::max(
            env::var("SOLANA_BANKING_THREADS")
                .map(|x| x.parse().unwrap_or(NUM_THREADS))
                .unwrap_or(NUM_THREADS),
            NUM_VOTE_PROCESSING_THREADS + MIN_THREADS_BANKING,
        )
    }

    #[allow(clippy::match_wild_err_arm)]
    fn record_transactions(
        bank_slot: Slot,
        txs: &[SanitizedTransaction],
        execution_results: &[TransactionExecutionResult],
        recorder: &TransactionRecorder,
    ) -> RecordTransactionsSummary {
        let mut record_transactions_timings = RecordTransactionsTimings::default();
        let (
            (processed_transactions, processed_transactions_indexes),
            execution_results_to_transactions_time,
        ): ((Vec<_>, Vec<_>), Measure) = Measure::this(
            |_| {
                execution_results
                    .iter()
                    .zip(txs)
                    .enumerate()
                    .filter_map(|(i, (execution_result, tx))| {
                        if execution_result.was_executed() {
                            Some((tx.to_versioned_transaction(), i))
                        } else {
                            None
                        }
                    })
                    .unzip()
            },
            (),
            " execution_results_to_transactions",
        );
        record_transactions_timings.execution_results_to_transactions_us =
            execution_results_to_transactions_time.as_us();

        let num_to_commit = processed_transactions.len();
        debug!("num_to_commit: {} ", num_to_commit);
        // unlock all the accounts with errors which are filtered by the above `filter_map`
        if !processed_transactions.is_empty() {
            inc_new_counter_info!("banking_stage-record_count", 1);
            inc_new_counter_info!("banking_stage-record_transactions", num_to_commit);

            let (hash, hash_time) = Measure::this(
                |_| hash_transactions(&processed_transactions[..]),
                (),
                "hash",
            );
            record_transactions_timings.hash_us = hash_time.as_us();

            // record and unlock will unlock all the successful transactions
            let (res, poh_record_time) = Measure::this(
                |_| recorder.record(bank_slot, hash, processed_transactions),
                (),
                "hash",
            );
            record_transactions_timings.poh_record_us = poh_record_time.as_us();

            match res {
                Ok(()) => (),
                Err(PohRecorderError::MaxHeightReached) => {
                    inc_new_counter_info!("banking_stage-max_height_reached", 1);
                    inc_new_counter_info!(
                        "banking_stage-max_height_reached_num_to_commit",
                        num_to_commit
                    );
                    // If record errors, add all the committable transactions (the ones
                    // we just attempted to record) as retryable
                    return RecordTransactionsSummary {
                        record_transactions_timings,
                        result: Err(PohRecorderError::MaxHeightReached),
                        retryable_indexes: processed_transactions_indexes,
                    };
                }
                Err(e) => panic!("Poh recorder returned unexpected error: {:?}", e),
            }
        }

        RecordTransactionsSummary {
            record_transactions_timings,
            result: (Ok(num_to_commit)),
            retryable_indexes: vec![],
        }
    }

    fn execute_and_commit_transactions_locked(
        bank: &Arc<Bank>,
        poh: &TransactionRecorder,
        batch: &TransactionBatch,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
    ) -> ExecuteAndCommitTransactionsOutput {
        let mut execute_and_commit_timings = LeaderExecuteAndCommitTimings::default();
        let mut mint_decimals: HashMap<Pubkey, u8> = HashMap::new();

        let ((pre_balances, pre_token_balances), collect_balances_time) = Measure::this(
            |_| {
                // Use a shorter maximum age when adding transactions into the pipeline.  This will reduce
                // the likelihood of any single thread getting starved and processing old ids.
                // TODO: Banking stage threads should be prioritized to complete faster then this queue
                // expires.
                let pre_balances = if transaction_status_sender.is_some() {
                    bank.collect_balances(batch)
                } else {
                    vec![]
                };

                let pre_token_balances = if transaction_status_sender.is_some() {
                    collect_token_balances(bank, batch, &mut mint_decimals)
                } else {
                    vec![]
                };

                (pre_balances, pre_token_balances)
            },
            (),
            "collect_balances",
        );
        execute_and_commit_timings.collect_balances_us = collect_balances_time.as_us();

        let (load_and_execute_transactions_output, load_execute_time) = Measure::this(
            |_| {
                bank.load_and_execute_transactions(
                    batch,
                    MAX_PROCESSING_AGE,
                    transaction_status_sender.is_some(),
                    transaction_status_sender.is_some(),
                    &mut execute_and_commit_timings.execute_timings,
                    None, // account_overrides
                    Bank::take_evm_state_cloned,
                )
            },
            (),
            "load_execute",
        );
        execute_and_commit_timings.load_execute_us = load_execute_time.as_us();

        let LoadAndExecuteTransactionsOutput {
            mut loaded_transactions,
            execution_results,
            mut retryable_transaction_indexes,
            executed_transactions_count,
            executed_with_successful_result_count,
            signature_count,
            error_counters,
	    evm_patch,
            ..
        } = load_and_execute_transactions_output;

        let mut transactions_execute_and_record_status: Vec<_> = execution_results
            .iter()
            .map(|execution_result| match execution_result {
                TransactionExecutionResult::Executed { details, .. } => {
                    CommitTransactionDetails::Committed {
                        compute_units: details.executed_units,
                    }
                }
                TransactionExecutionResult::NotExecuted { .. } => {
                    CommitTransactionDetails::NotCommitted
                }
            })
            .collect();

        let (last_blockhash, lamports_per_signature) =
            bank.last_blockhash_and_lamports_per_signature();
        let (freeze_lock, freeze_lock_time) =
            Measure::this(|_| bank.freeze_lock(), (), "freeze_lock");
        execute_and_commit_timings.freeze_lock_us = freeze_lock_time.as_us();

        let (record_transactions_summary, record_time) = Measure::this(
            |_| {
                Self::record_transactions(
                    bank.slot(),
                    batch.sanitized_transactions(),
                    &execution_results,
                    poh,
                )
            },
            (),
            "record_transactions",
        );
        execute_and_commit_timings.record_us = record_time.as_us();

        let RecordTransactionsSummary {
            result: commit_transactions_result,
            retryable_indexes: retryable_record_transaction_indexes,
            record_transactions_timings,
        } = record_transactions_summary;
        execute_and_commit_timings.record_transactions_timings = record_transactions_timings;

        // mark transactions that were executed but not recorded
        retryable_record_transaction_indexes.iter().for_each(|i| {
            transactions_execute_and_record_status[*i] = CommitTransactionDetails::NotCommitted;
        });

        inc_new_counter_info!(
            "banking_stage-record_transactions_num_to_commit",
            *commit_transactions_result.as_ref().unwrap_or(&0)
        );
        inc_new_counter_info!(
            "banking_stage-record_transactions_retryable_record_txs",
            retryable_record_transaction_indexes.len()
        );
        retryable_transaction_indexes.extend(retryable_record_transaction_indexes);
        let transactions_attempted_execution_count = execution_results.len();
        if let Err(e) = commit_transactions_result {
            return ExecuteAndCommitTransactionsOutput {
                transactions_attempted_execution_count,
                executed_transactions_count,
                executed_with_successful_result_count,
                retryable_transaction_indexes,
                commit_transactions_result: Err(e),
                execute_and_commit_timings,
                error_counters,
            };
        }

        let sanitized_txs = batch.sanitized_transactions();
        let committed_transaction_count = commit_transactions_result.unwrap();
        // Note: `committed_transaction_count` should equal `executed_transactions_count`, since
        // every executed transaction should have been recorded into the Poh stream if the record
        // was successful (there's no partial records).
        let commit_time_us = if committed_transaction_count != 0 {
            let (tx_results, commit_time) = Measure::this(
                |_| {
                    bank.commit_transactions(
                        sanitized_txs,
                        &mut loaded_transactions,
                        execution_results,
                        last_blockhash,
                        lamports_per_signature,
                        CommitTransactionCounts {
                            committed_transactions_count: executed_transactions_count as u64,
                            committed_with_failure_result_count: executed_transactions_count
                                .saturating_sub(executed_with_successful_result_count)
                                as u64,
                            signature_count,
                        },
                        &mut execute_and_commit_timings.execute_timings,
                        evm_patch,
                    )
                },
                (),
                "commit",
            );
            let commit_time_us = commit_time.as_us();
            execute_and_commit_timings.commit_us = commit_time_us;

            let (_, find_and_send_votes_time) = Measure::this(
                |_| {
                    bank_utils::find_and_send_votes(
                        sanitized_txs,
                        &tx_results,
                        Some(gossip_vote_sender),
                    );
                    if let Some(transaction_status_sender) = transaction_status_sender {
                        let txs = batch.sanitized_transactions().to_vec();
                        let post_balances = bank.collect_balances(batch);
                        let post_token_balances =
                            collect_token_balances(bank, batch, &mut mint_decimals);
                        transaction_status_sender.send_transaction_status_batch(
                            bank.clone(),
                            txs,
                            tx_results.execution_results,
                            TransactionBalancesSet::new(pre_balances, post_balances),
                            TransactionTokenBalancesSet::new(
                                pre_token_balances,
                                post_token_balances,
                            ),
                            tx_results.rent_debits,
                        );
                    }
                },
                (),
                "find_and_send_votes",
            );
            execute_and_commit_timings.find_and_send_votes_us = find_and_send_votes_time.as_us();
            commit_time_us
        } else {
            0
        };

        drop(freeze_lock);

        debug!(
            "bank: {} process_and_record_locked: {}us record: {}us commit: {}us txs_len: {}",
            bank.slot(),
            load_execute_time.as_us(),
            record_time.as_us(),
            commit_time_us,
            sanitized_txs.len(),
        );

        debug!(
            "execute_and_commit_transactions_locked: {:?}",
            execute_and_commit_timings.execute_timings,
        );

        ExecuteAndCommitTransactionsOutput {
            transactions_attempted_execution_count,
            executed_transactions_count,
            executed_with_successful_result_count,
            retryable_transaction_indexes,
            commit_transactions_result: Ok(transactions_execute_and_record_status),
            execute_and_commit_timings,
            error_counters,
        }
    }

    pub fn process_and_record_transactions(
        bank: &Arc<Bank>,
        txs: &[SanitizedTransaction],
        poh: &TransactionRecorder,
        chunk_offset: usize,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        qos_service: &Arc<QosService>,
    ) -> ProcessTransactionBatchOutput {
        let mut cost_model_time = Measure::start("cost_model");

        let transaction_costs = qos_service.compute_transaction_costs(txs.iter());

        let (transactions_qos_results, num_included) =
            qos_service.select_transactions_per_cost(txs.iter(), transaction_costs.iter(), bank);

        let cost_model_throttled_transactions_count = txs.len().saturating_sub(num_included);

        qos_service.accumulate_estimated_transaction_costs(
            &Self::accumulate_batched_transaction_costs(
                transaction_costs.iter(),
                transactions_qos_results.iter(),
            ),
        );
        cost_model_time.stop();

        // Only lock accounts for those transactions are selected for the block;
        // Once accounts are locked, other threads cannot encode transactions that will modify the
        // same account state
        let mut lock_time = Measure::start("lock_time");
        let batch = bank.prepare_sanitized_batch_with_results(txs, transactions_qos_results.iter());
        lock_time.stop();

        // retryable_txs includes AccountInUse, WouldExceedMaxBlockCostLimit
        // WouldExceedMaxAccountCostLimit, WouldExceedMaxVoteCostLimit
        // and WouldExceedMaxAccountDataCostLimit
        let mut execute_and_commit_transactions_output =
            Self::execute_and_commit_transactions_locked(
                bank,
                poh,
                &batch,
                transaction_status_sender,
                gossip_vote_sender,
            );

        let mut unlock_time = Measure::start("unlock_time");
        // Once the accounts are new transactions can enter the pipeline to process them
        drop(batch);
        unlock_time.stop();

        let ExecuteAndCommitTransactionsOutput {
            ref mut retryable_transaction_indexes,
            ref execute_and_commit_timings,
            ref commit_transactions_result,
            ..
        } = execute_and_commit_transactions_output;

        QosService::update_or_remove_transaction_costs(
            transaction_costs.iter(),
            transactions_qos_results.iter(),
            commit_transactions_result.as_ref().ok(),
            bank,
        );

        retryable_transaction_indexes
            .iter_mut()
            .for_each(|x| *x += chunk_offset);

        let (cu, us) =
            Self::accumulate_execute_units_and_time(&execute_and_commit_timings.execute_timings);
        qos_service.accumulate_actual_execute_cu(cu);
        qos_service.accumulate_actual_execute_time(us);

        debug!(
            "bank: {} lock: {}us unlock: {}us txs_len: {}",
            bank.slot(),
            lock_time.as_us(),
            unlock_time.as_us(),
            txs.len(),
        );

        ProcessTransactionBatchOutput {
            cost_model_throttled_transactions_count,
            cost_model_us: cost_model_time.as_us(),
            execute_and_commit_transactions_output,
        }
    }

    // rollup transaction cost details, eg signature_cost, write_lock_cost, data_bytes_cost and
    // execution_cost from the batch of transactions selected for block.
    fn accumulate_batched_transaction_costs<'a>(
        transactions_costs: impl Iterator<Item = &'a TransactionCost>,
        transaction_results: impl Iterator<Item = &'a transaction::Result<()>>,
    ) -> BatchedTransactionCostDetails {
        let mut cost_details = BatchedTransactionCostDetails::default();
        transactions_costs
            .zip(transaction_results)
            .for_each(|(cost, result)| {
                if result.is_ok() {
                    saturating_add_assign!(
                        cost_details.batched_signature_cost,
                        cost.signature_cost
                    );
                    saturating_add_assign!(
                        cost_details.batched_write_lock_cost,
                        cost.write_lock_cost
                    );
                    saturating_add_assign!(
                        cost_details.batched_data_bytes_cost,
                        cost.data_bytes_cost
                    );
                    saturating_add_assign!(
                        cost_details.batched_builtins_execute_cost,
                        cost.builtins_execution_cost
                    );
                    saturating_add_assign!(
                        cost_details.batched_bpf_execute_cost,
                        cost.bpf_execution_cost
                    );
                }
            });
        cost_details
    }

    fn accumulate_execute_units_and_time(execute_timings: &ExecuteTimings) -> (u64, u64) {
        let (units, times): (Vec<_>, Vec<_>) = execute_timings
            .details
            .per_program_timings
            .values()
            .map(|program_timings| {
                (
                    program_timings.accumulated_units,
                    program_timings.accumulated_us,
                )
            })
            .unzip();
        (units.iter().sum(), times.iter().sum())
    }

    /// Sends transactions to the bank.
    ///
    /// Returns the number of transactions successfully processed by the bank, which may be less
    /// than the total number if max PoH height was reached and the bank halted
    fn process_transactions(
        bank: &Arc<Bank>,
        bank_creation_time: &Instant,
        transactions: &[SanitizedTransaction],
        poh: &TransactionRecorder,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        qos_service: &Arc<QosService>,
    ) -> ProcessTransactionsSummary {
        let mut chunk_start = 0;
        let mut all_retryable_tx_indexes = vec![];
        // All the transactions that attempted execution. See description of
        // struct ProcessTransactionsSummary above for possible outcomes.
        let mut total_transactions_attempted_execution_count: usize = 0;
        // All transactions that were executed and committed
        let mut total_committed_transactions_count: usize = 0;
        // All transactions that were executed and committed with a successful result
        let mut total_committed_transactions_with_successful_result_count: usize = 0;
        // All transactions that were executed but then failed record because the
        // slot ended
        let mut total_failed_commit_count: usize = 0;
        let mut total_cost_model_throttled_transactions_count: usize = 0;
        let mut total_cost_model_us: u64 = 0;
        let mut total_execute_and_commit_timings = LeaderExecuteAndCommitTimings::default();
        let mut total_error_counters = TransactionErrorMetrics::default();
        let mut reached_max_poh_height = false;
        while chunk_start != transactions.len() {
            let chunk_end = std::cmp::min(
                transactions.len(),
                chunk_start + MAX_NUM_TRANSACTIONS_PER_BATCH,
            );
            let process_transaction_batch_output = Self::process_and_record_transactions(
                bank,
                &transactions[chunk_start..chunk_end],
                poh,
                chunk_start,
                transaction_status_sender.clone(),
                gossip_vote_sender,
                qos_service,
            );

            let ProcessTransactionBatchOutput {
                cost_model_throttled_transactions_count: new_cost_model_throttled_transactions_count,
                cost_model_us: new_cost_model_us,
                execute_and_commit_transactions_output,
            } = process_transaction_batch_output;
            total_cost_model_throttled_transactions_count =
                total_cost_model_throttled_transactions_count
                    .saturating_add(new_cost_model_throttled_transactions_count);
            total_cost_model_us = total_cost_model_us.saturating_add(new_cost_model_us);

            let ExecuteAndCommitTransactionsOutput {
                transactions_attempted_execution_count: new_transactions_attempted_execution_count,
                executed_transactions_count: new_executed_transactions_count,
                executed_with_successful_result_count: new_executed_with_successful_result_count,
                retryable_transaction_indexes: new_retryable_transaction_indexes,
                commit_transactions_result: new_commit_transactions_result,
                execute_and_commit_timings: new_execute_and_commit_timings,
                error_counters: new_error_counters,
                ..
            } = execute_and_commit_transactions_output;

            total_execute_and_commit_timings.accumulate(&new_execute_and_commit_timings);
            total_error_counters.accumulate(&new_error_counters);
            total_transactions_attempted_execution_count =
                total_transactions_attempted_execution_count
                    .saturating_add(new_transactions_attempted_execution_count);

            trace!(
                "process_transactions result: {:?}",
                new_commit_transactions_result
            );

            if new_commit_transactions_result.is_ok() {
                total_committed_transactions_count = total_committed_transactions_count
                    .saturating_add(new_executed_transactions_count);
                total_committed_transactions_with_successful_result_count =
                    total_committed_transactions_with_successful_result_count
                        .saturating_add(new_executed_with_successful_result_count);
            } else {
                total_failed_commit_count =
                    total_failed_commit_count.saturating_add(new_executed_transactions_count);
            }

            // Add the retryable txs (transactions that errored in a way that warrants a retry)
            // to the list of unprocessed txs.
            all_retryable_tx_indexes.extend_from_slice(&new_retryable_transaction_indexes);

            // If `bank_creation_time` is None, it's a test so ignore the option so
            // allow processing
            let should_bank_still_be_processing_txs =
                Bank::should_bank_still_be_processing_txs(bank_creation_time, bank.ns_per_slot);
            match (
                new_commit_transactions_result,
                should_bank_still_be_processing_txs,
            ) {
                (Err(PohRecorderError::MaxHeightReached), _) | (_, false) => {
                    info!(
                        "process transactions: max height reached slot: {} height: {}",
                        bank.slot(),
                        bank.tick_height()
                    );
                    // process_and_record_transactions has returned all retryable errors in
                    // transactions[chunk_start..chunk_end], so we just need to push the remaining
                    // transactions into the unprocessed queue.
                    all_retryable_tx_indexes.extend(chunk_end..transactions.len());
                    reached_max_poh_height = true;
                    break;
                }
                _ => (),
            }
            // Don't exit early on any other type of error, continue processing...
            chunk_start = chunk_end;
        }

        ProcessTransactionsSummary {
            reached_max_poh_height,
            transactions_attempted_execution_count: total_transactions_attempted_execution_count,
            committed_transactions_count: total_committed_transactions_count,
            committed_transactions_with_successful_result_count:
                total_committed_transactions_with_successful_result_count,
            failed_commit_count: total_failed_commit_count,
            retryable_transaction_indexes: all_retryable_tx_indexes,
            cost_model_throttled_transactions_count: total_cost_model_throttled_transactions_count,
            cost_model_us: total_cost_model_us,
            execute_and_commit_timings: total_execute_and_commit_timings,
            error_counters: total_error_counters,
        }
    }

    // This function creates a filter of transaction results with Ok() for every pending
    // transaction. The non-pending transactions are marked with TransactionError
    fn prepare_filter_for_pending_transactions(
        transactions_len: usize,
        pending_tx_indexes: &[usize],
    ) -> Vec<transaction::Result<()>> {
        let mut mask = vec![Err(TransactionError::BlockhashNotFound); transactions_len];
        pending_tx_indexes.iter().for_each(|x| mask[*x] = Ok(()));
        mask
    }

    // This function returns a vector containing index of all valid transactions. A valid
    // transaction has result Ok() as the value
    fn filter_valid_transaction_indexes(
        valid_txs: &[TransactionCheckResult],
        transaction_indexes: &[usize],
    ) -> Vec<usize> {
        valid_txs
            .iter()
            .enumerate()
            .filter_map(|(index, (x, _h))| if x.is_ok() { Some(index) } else { None })
            .map(|x| transaction_indexes[x])
            .collect_vec()
    }

    /// Read the transaction message from packet data
    fn packet_message(packet: &Packet) -> Option<&[u8]> {
        let (sig_len, sig_size) = decode_shortu16_len(&packet.data).ok()?;
        let msg_start = sig_len
            .checked_mul(size_of::<Signature>())
            .and_then(|v| v.checked_add(sig_size))?;
        let msg_end = packet.meta.size;
        Some(&packet.data[msg_start..msg_end])
    }

    // This function deserializes packets into transactions, computes the blake3 hash of transaction
    // messages, and verifies secp256k1 instructions. A list of sanitized transactions are returned
    // with their packet indexes.
    #[allow(clippy::needless_collect)]
    fn transactions_from_packets(
        packet_batch: &PacketBatch,
        transaction_indexes: &[usize],
        feature_set: &Arc<feature_set::FeatureSet>,
        votes_only: bool,
        address_loader: impl Fn(&[MessageAddressTableLookup]) -> transaction::Result<LoadedAddresses>,
    ) -> (Vec<SanitizedTransaction>, Vec<usize>) {
        transaction_indexes
            .iter()
            .filter_map(|tx_index| {
                let p = &packet_batch.packets[*tx_index];
                if votes_only && !p.meta.is_simple_vote_tx() {
                    return None;
                }

                let tx: VersionedTransaction = p.deserialize_slice(..).ok()?;
                let message_bytes = Self::packet_message(p)?;
                let message_hash = Message::hash_raw_message(message_bytes);
                let tx = SanitizedTransaction::try_create(
                    tx,
                    message_hash,
                    Some(p.meta.is_simple_vote_tx()),
                    &address_loader,
                )
                .ok()?;
                tx.verify_precompiles(feature_set).ok()?;
                Some((tx, *tx_index))
            })
            .unzip()
    }

    /// This function filters pending packets that are still valid
    /// # Arguments
    /// * `transactions` - a batch of transactions deserialized from packets
    /// * `transaction_to_packet_indexes` - maps each transaction to a packet index
    /// * `pending_indexes` - identifies which indexes in the `transactions` list are still pending
    fn filter_pending_packets_from_pending_txs(
        bank: &Arc<Bank>,
        transactions: &[SanitizedTransaction],
        transaction_to_packet_indexes: &[usize],
        pending_indexes: &[usize],
    ) -> Vec<usize> {
        let filter =
            Self::prepare_filter_for_pending_transactions(transactions.len(), pending_indexes);

        let mut error_counters = TransactionErrorMetrics::default();
        // The following code also checks if the blockhash for a transaction is too old
        // The check accounts for
        //  1. Transaction forwarding delay
        //  2. The slot at which the next leader will actually process the transaction
        // Drop the transaction if it will expire by the time the next node receives and processes it
        let api = perf_libs::api();
        let max_tx_fwd_delay = if api.is_none() {
            MAX_TRANSACTION_FORWARDING_DELAY
        } else {
            MAX_TRANSACTION_FORWARDING_DELAY_GPU
        };

        let results = bank.check_transactions(
            transactions,
            &filter,
            (MAX_PROCESSING_AGE)
                .saturating_sub(max_tx_fwd_delay)
                .saturating_sub(FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET as usize),
            &mut error_counters,
        );

        Self::filter_valid_transaction_indexes(&results, transaction_to_packet_indexes)
    }

    #[allow(clippy::too_many_arguments)]
    fn process_packets_transactions(
        bank: &Arc<Bank>,
        bank_creation_time: &Instant,
        poh: &TransactionRecorder,
        packet_batch: &PacketBatch,
        packet_indexes: Vec<usize>,
        transaction_status_sender: Option<TransactionStatusSender>,
        gossip_vote_sender: &ReplayVoteSender,
        banking_stage_stats: &BankingStageStats,
        qos_service: &Arc<QosService>,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) -> ProcessTransactionsSummary {
        // Convert packets to transactions
        let ((transactions, transaction_to_packet_indexes), packet_conversion_time) = Measure::this(
            |_| {
                Self::transactions_from_packets(
                    packet_batch,
                    &packet_indexes,
                    &bank.feature_set,
                    bank.vote_only_bank(),
                    |lookup| bank.load_lookup_table_addresses(lookup),
                )
            },
            (),
            "packet_conversion",
        );
        let packet_conversion_us = packet_conversion_time.as_us();
        slot_metrics_tracker.increment_transactions_from_packets_us(packet_conversion_us);
        banking_stage_stats
            .packet_conversion_elapsed
            .fetch_add(packet_conversion_us, Ordering::Relaxed);
        inc_new_counter_info!("banking_stage-packet_conversion", 1);

        // Process transactions
        let (mut process_transactions_summary, process_transactions_time) = Measure::this(
            |_| {
                Self::process_transactions(
                    bank,
                    bank_creation_time,
                    &transactions,
                    poh,
                    transaction_status_sender,
                    gossip_vote_sender,
                    qos_service,
                )
            },
            (),
            "process_transaction_time",
        );
        let process_transactions_us = process_transactions_time.as_us();
        slot_metrics_tracker.increment_process_transactions_us(process_transactions_us);
        banking_stage_stats
            .transaction_processing_elapsed
            .fetch_add(process_transactions_us, Ordering::Relaxed);

        let ProcessTransactionsSummary {
            ref retryable_transaction_indexes,
            ref error_counters,
            ..
        } = process_transactions_summary;

        slot_metrics_tracker.accumulate_process_transactions_summary(&process_transactions_summary);
        slot_metrics_tracker.accumulate_transaction_errors(error_counters);

        let retryable_tx_count = retryable_transaction_indexes.len();
        inc_new_counter_info!("banking_stage-unprocessed_transactions", retryable_tx_count);

        // Filter out transactions that can't be retried
        let (filtered_retryable_transaction_indexes, filter_retryable_packets_time) = Measure::this(
            |_| {
                Self::filter_pending_packets_from_pending_txs(
                    bank,
                    &transactions,
                    &transaction_to_packet_indexes,
                    retryable_transaction_indexes,
                )
            },
            (),
            "filter_pending_packets_time",
        );
        let filter_retryable_packets_us = filter_retryable_packets_time.as_us();
        slot_metrics_tracker
            .increment_filter_retryable_packets_us(filter_retryable_packets_us);
        banking_stage_stats
            .filter_pending_packets_elapsed
            .fetch_add(filter_retryable_packets_us, Ordering::Relaxed);

        let retryable_packets_filtered_count = retryable_transaction_indexes
            .len()
            .saturating_sub(filtered_retryable_transaction_indexes.len());
        slot_metrics_tracker
            .increment_retryable_packets_filtered_count(retryable_packets_filtered_count as u64);

        inc_new_counter_info!(
            "banking_stage-dropped_tx_before_forwarding",
            retryable_transaction_indexes
                .len()
                .saturating_sub(filtered_retryable_transaction_indexes.len())
        );

        process_transactions_summary.retryable_transaction_indexes =
            filtered_retryable_transaction_indexes;
        process_transactions_summary
    }

    fn filter_unprocessed_packets_at_end_of_slot(
        bank: &Arc<Bank>,
        packet_batch: &PacketBatch,
        transaction_indexes: &[usize],
        my_pubkey: &Pubkey,
        next_leader: Option<Pubkey>,
        banking_stage_stats: &BankingStageStats,
    ) -> Vec<usize> {
        // Check if we are the next leader. If so, let's not filter the packets
        // as we'll filter it again while processing the packets.
        // Filtering helps if we were going to forward the packets to some other node
        if let Some(leader) = next_leader {
            if leader == *my_pubkey {
                return transaction_indexes.to_vec();
            }
        }

        let mut unprocessed_packet_conversion_time =
            Measure::start("unprocessed_packet_conversion");
        let (transactions, transaction_to_packet_indexes) = Self::transactions_from_packets(
            packet_batch,
            transaction_indexes,
            &bank.feature_set,
            bank.vote_only_bank(),
            |lookup| bank.load_lookup_table_addresses(lookup),
        );
        unprocessed_packet_conversion_time.stop();

        let unprocessed_tx_indexes = (0..transactions.len()).collect_vec();
        let filtered_unprocessed_packet_indexes = Self::filter_pending_packets_from_pending_txs(
            bank,
            &transactions,
            &transaction_to_packet_indexes,
            &unprocessed_tx_indexes,
        );

        inc_new_counter_info!(
            "banking_stage-dropped_tx_before_forwarding",
            unprocessed_tx_indexes
                .len()
                .saturating_sub(filtered_unprocessed_packet_indexes.len())
        );
        banking_stage_stats
            .unprocessed_packet_conversion_elapsed
            .fetch_add(
                unprocessed_packet_conversion_time.as_us(),
                Ordering::Relaxed,
            );

        filtered_unprocessed_packet_indexes
    }

    fn generate_packet_indexes(vers: &PinnedVec<Packet>) -> Vec<usize> {
        vers.iter()
            .enumerate()
            .filter(|(_, pkt)| !pkt.meta.discard())
            .map(|(index, _)| index)
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    /// Receive incoming packets, push into unprocessed buffer with packet indexes
    fn receive_and_buffer_packets(
        verified_receiver: &CrossbeamReceiver<Vec<PacketBatch>>,
        recv_start: &mut Instant,
        recv_timeout: Duration,
        id: u32,
        batch_limit: usize,
        buffered_packet_batches: &mut UnprocessedPacketBatches,
        banking_stage_stats: &mut BankingStageStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) -> Result<(), RecvTimeoutError> {
        let mut recv_time = Measure::start("receive_and_buffer_packets_recv");
        let packet_batches = verified_receiver.recv_timeout(recv_timeout)?;
        recv_time.stop();

        let packet_batches_len = packet_batches.len();
        let packet_count: usize = packet_batches.iter().map(|x| x.packets.len()).sum();
        debug!(
            "@{:?} process start stalled for: {:?}ms txs: {} id: {}",
            timestamp(),
            duration_as_ms(&recv_start.elapsed()),
            packet_count,
            id,
        );
        inc_new_counter_debug!("banking_stage-transactions_received", packet_count);
        let mut proc_start = Measure::start("receive_and_buffer_packets_transactions_process");

        let packet_batch_iter = packet_batches.into_iter();
        let mut dropped_packets_count = 0;
        let mut dropped_packet_batches_count = 0;
        let mut newly_buffered_packets_count = 0;
        for packet_batch in packet_batch_iter {
            let packet_indexes = Self::generate_packet_indexes(&packet_batch.packets);
            // Track all the packets incoming from sigverify, both valid and invalid
            slot_metrics_tracker.increment_total_new_valid_packets(packet_indexes.len() as u64);
            slot_metrics_tracker.increment_newly_failed_sigverify_count(
                packet_batch
                    .packets
                    .len()
                    .saturating_sub(packet_indexes.len()) as u64,
            );

            Self::push_unprocessed(
                buffered_packet_batches,
                packet_batch,
                packet_indexes,
                &mut dropped_packet_batches_count,
                &mut dropped_packets_count,
                &mut newly_buffered_packets_count,
                batch_limit,
                banking_stage_stats,
                slot_metrics_tracker,
            );
        }
        proc_start.stop();

        debug!(
            "@{:?} done processing transaction batches: {} time: {:?}ms total count: {} id: {}",
            timestamp(),
            packet_batches_len,
            proc_start.as_ms(),
            packet_count,
            id,
        );
        banking_stage_stats
            .receive_and_buffer_packets_elapsed
            .fetch_add(proc_start.as_us(), Ordering::Relaxed);
        banking_stage_stats
            .receive_and_buffer_packets_count
            .fetch_add(packet_count, Ordering::Relaxed);
        banking_stage_stats
            .dropped_packet_batches_count
            .fetch_add(dropped_packet_batches_count, Ordering::Relaxed);
        banking_stage_stats
            .dropped_packets_count
            .fetch_add(dropped_packets_count, Ordering::Relaxed);
        banking_stage_stats
            .newly_buffered_packets_count
            .fetch_add(newly_buffered_packets_count, Ordering::Relaxed);
        banking_stage_stats
            .current_buffered_packet_batches_count
            .swap(buffered_packet_batches.len(), Ordering::Relaxed);
        banking_stage_stats.current_buffered_packets_count.swap(
            buffered_packet_batches
                .iter()
                .map(|packets| packets.1.len())
                .sum(),
            Ordering::Relaxed,
        );
        *recv_start = Instant::now();
        Ok(())
    }

    fn push_unprocessed(
        unprocessed_packet_batches: &mut UnprocessedPacketBatches,
        packet_batch: PacketBatch,
        packet_indexes: Vec<usize>,
        dropped_packet_batches_count: &mut usize,
        dropped_packets_count: &mut usize,
        newly_buffered_packets_count: &mut usize,
        batch_limit: usize,
        banking_stage_stats: &mut BankingStageStats,
        slot_metrics_tracker: &mut LeaderSlotMetricsTracker,
    ) {
        if Self::packet_has_more_unprocessed_transactions(&packet_indexes) {
            if unprocessed_packet_batches.len() >= batch_limit {
                *dropped_packet_batches_count += 1;
                if let Some(dropped_batch) = unprocessed_packet_batches.pop_front() {
                    *dropped_packets_count += dropped_batch.1.len();
                    slot_metrics_tracker.increment_exceeded_buffer_limit_dropped_packets_count(
                        dropped_batch.1.len() as u64,
                    );
                }
            }
            let _ = banking_stage_stats
                .batch_packet_indexes_len
                .increment(packet_indexes.len() as u64);

            *newly_buffered_packets_count += packet_indexes.len();
            slot_metrics_tracker
                .increment_newly_buffered_packets_count(packet_indexes.len() as u64);
            unprocessed_packet_batches.push_back((packet_batch, packet_indexes, false));
        }
    }

    fn packet_has_more_unprocessed_transactions(packet_indexes: &[usize]) -> bool {
        !packet_indexes.is_empty()
    }

    pub fn join(self) -> thread::Result<()> {
        for bank_thread_hdl in self.bank_thread_hdls {
            bank_thread_hdl.join()?;
        }
        Ok(())
    }
}

pub(crate) fn next_leader_tpu(
    cluster_info: &ClusterInfo,
    poh_recorder: &Mutex<PohRecorder>,
) -> Option<std::net::SocketAddr> {
    next_leader_x(cluster_info, poh_recorder, |leader| leader.tpu)
}

fn next_leader_tpu_forwards(
    cluster_info: &ClusterInfo,
    poh_recorder: &Mutex<PohRecorder>,
) -> Option<std::net::SocketAddr> {
    next_leader_x(cluster_info, poh_recorder, |leader| leader.tpu_forwards)
}

pub(crate) fn next_leader_tpu_vote(
    cluster_info: &ClusterInfo,
    poh_recorder: &Mutex<PohRecorder>,
) -> Option<std::net::SocketAddr> {
    next_leader_x(cluster_info, poh_recorder, |leader| leader.tpu_vote)
}

fn next_leader_x<F>(
    cluster_info: &ClusterInfo,
    poh_recorder: &Mutex<PohRecorder>,
    port_selector: F,
) -> Option<std::net::SocketAddr>
where
    F: FnOnce(&ContactInfo) -> SocketAddr,
{
    let leader_pubkey = poh_recorder
        .lock()
        .unwrap()
        .leader_after_n_slots(FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET);
    if let Some(leader_pubkey) = leader_pubkey {
        cluster_info.lookup_contact_info(&leader_pubkey, port_selector)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crossbeam_channel::unbounded,
        itertools::Itertools,
        entry::entry::{next_entry, Entry, EntrySlice},
        gossip::{cluster_info::Node, contact_info::ContactInfo},
        ledger::{
            blockstore::{entries_to_test_shreds, Blockstore},
            genesis_utils::{create_genesis_config, GenesisConfigInfo},
            get_tmp_ledger_path_auto_delete,
            leader_schedule_cache::LeaderScheduleCache,
        },
        perf::packet::{to_packet_batches, PacketFlags},
        poh::{
            poh_recorder::{create_test_recorder, Record, WorkingBankEntry},
            poh_service::PohService,
        },
        program_runtime::{invoke_context::Executors, timings::ProgramTiming},
        rpc::transaction_status_service::TransactionStatusService,
        runtime::bank::TransactionExecutionDetails,
        sdk::{
            hash::Hash,
            instruction::InstructionError,
            poh_config::PohConfig,
            signature::{Keypair, Signer},
            system_instruction::SystemError,
            system_transaction,
            transaction::{Transaction, TransactionError},
        },
        sino_streamer::{recvmmsg::recv_mmsg, socket::SocketAddrSpace},
        transaction_status::TransactionWithMetadata,
        vote_program::vote_transaction,
        std::{
            cell::RefCell,
            net::SocketAddr,
            path::Path,
            rc::Rc,
            sync::{
                atomic::{AtomicBool, Ordering},
                mpsc::Receiver,
            },
            thread::sleep,
        },
    };

    fn new_test_cluster_info(contact_info: ContactInfo) -> ClusterInfo {
        ClusterInfo::new(
            contact_info,
            Arc::new(Keypair::new()),
            SocketAddrSpace::Unspecified,
        )
    }

    fn new_execution_result(status: Result<(), TransactionError>) -> TransactionExecutionResult {
        TransactionExecutionResult::Executed {
            details: TransactionExecutionDetails {
                status,
                log_messages: None,
                inner_instructions: None,
                durable_nonce_fee: None,
                executed_units: 0u64,
            },
            executors: Rc::new(RefCell::new(Executors::default())),
        }
    }

    #[test]
    fn test_banking_stage_shutdown1() {
        let genesis_config = create_genesis_config(2).genesis_config;
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
        let (verified_sender, verified_receiver) = unbounded();
        let (gossip_verified_vote_sender, gossip_verified_vote_receiver) = unbounded();
        let (tpu_vote_sender, tpu_vote_receiver) = unbounded();
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let blockstore = Arc::new(
                Blockstore::open(ledger_path.path())
                    .expect("Expected to be able to open database ledger"),
            );
            let (exit, poh_recorder, poh_service, _entry_receiever) =
                create_test_recorder(&bank, &blockstore, None, None);
            let cluster_info = new_test_cluster_info(Node::new_localhost().info);
            let cluster_info = Arc::new(cluster_info);
            let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();

            let banking_stage = BankingStage::new(
                &cluster_info,
                &poh_recorder,
                verified_receiver,
                tpu_vote_receiver,
                gossip_verified_vote_receiver,
                None,
                gossip_vote_sender,
                Arc::new(RwLock::new(CostModel::default())),
            );
            drop(verified_sender);
            drop(gossip_verified_vote_sender);
            drop(tpu_vote_sender);
            exit.store(true, Ordering::Relaxed);
            banking_stage.join().unwrap();
            poh_service.join().unwrap();
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    #[test]
    fn test_banking_stage_tick() {
        sino_logger::setup();
        let GenesisConfigInfo {
            mut genesis_config, ..
        } = create_genesis_config(2);
        genesis_config.ticks_per_slot = 4;
        let num_extra_ticks = 2;
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
        let start_hash = bank.last_blockhash();
        let (verified_sender, verified_receiver) = unbounded();
        let (tpu_vote_sender, tpu_vote_receiver) = unbounded();
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let blockstore = Arc::new(
                Blockstore::open(ledger_path.path())
                    .expect("Expected to be able to open database ledger"),
            );
            let poh_config = PohConfig {
                target_tick_count: Some(bank.max_tick_height() + num_extra_ticks),
                ..PohConfig::default()
            };
            let (exit, poh_recorder, poh_service, entry_receiver) =
                create_test_recorder(&bank, &blockstore, Some(poh_config), None);
            let cluster_info = new_test_cluster_info(Node::new_localhost().info);
            let cluster_info = Arc::new(cluster_info);
            let (verified_gossip_vote_sender, verified_gossip_vote_receiver) = unbounded();
            let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();

            let banking_stage = BankingStage::new(
                &cluster_info,
                &poh_recorder,
                verified_receiver,
                tpu_vote_receiver,
                verified_gossip_vote_receiver,
                None,
                gossip_vote_sender,
                Arc::new(RwLock::new(CostModel::default())),
            );
            trace!("sending bank");
            drop(verified_sender);
            drop(verified_gossip_vote_sender);
            drop(tpu_vote_sender);
            exit.store(true, Ordering::Relaxed);
            poh_service.join().unwrap();
            drop(poh_recorder);

            trace!("getting entries");
            let entries: Vec<_> = entry_receiver
                .iter()
                .map(|(_bank, (entry, _tick_height))| entry)
                .collect();
            trace!("done");
            assert_eq!(entries.len(), genesis_config.ticks_per_slot as usize);
            assert!(entries.verify(&start_hash));
            assert_eq!(entries[entries.len() - 1].hash, bank.last_blockhash());
            banking_stage.join().unwrap();
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    pub fn convert_from_old_verified(
        mut with_vers: Vec<(PacketBatch, Vec<u8>)>,
    ) -> Vec<PacketBatch> {
        with_vers.iter_mut().for_each(|(b, v)| {
            b.packets
                .iter_mut()
                .zip(v)
                .for_each(|(p, f)| p.meta.set_discard(*f == 0))
        });
        with_vers.into_iter().map(|(b, _)| b).collect()
    }

    #[test]
    fn test_banking_stage_entries_only() {
        sino_logger::setup();
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_slow_genesis_config(10);
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
        let start_hash = bank.last_blockhash();
        let (verified_sender, verified_receiver) = unbounded();
        let (tpu_vote_sender, tpu_vote_receiver) = unbounded();
        let (gossip_verified_vote_sender, gossip_verified_vote_receiver) = unbounded();
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let blockstore = Arc::new(
                Blockstore::open(ledger_path.path())
                    .expect("Expected to be able to open database ledger"),
            );
            let poh_config = PohConfig {
                // limit tick count to avoid clearing working_bank at PohRecord then
                // PohRecorderError(MaxHeightReached) at BankingStage
                target_tick_count: Some(bank.max_tick_height() - 1),
                ..PohConfig::default()
            };
            let (exit, poh_recorder, poh_service, entry_receiver) =
                create_test_recorder(&bank, &blockstore, Some(poh_config), None);
            let cluster_info = new_test_cluster_info(Node::new_localhost().info);
            let cluster_info = Arc::new(cluster_info);
            let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();

            let banking_stage = BankingStage::new(
                &cluster_info,
                &poh_recorder,
                verified_receiver,
                tpu_vote_receiver,
                gossip_verified_vote_receiver,
                None,
                gossip_vote_sender,
                Arc::new(RwLock::new(CostModel::default())),
            );

            // fund another account so we can send 2 good transactions in a single batch.
            let keypair = Keypair::new();
            let fund_tx =
                system_transaction::transfer(&mint_keypair, &keypair.pubkey(), 2, start_hash);
            bank.process_transaction(&fund_tx).unwrap();

            // good tx
            let to = sdk::pubkey::new_rand();
            let tx = system_transaction::transfer(&mint_keypair, &to, 1, start_hash);

            // good tx, but no verify
            let to2 = sdk::pubkey::new_rand();
            let tx_no_ver = system_transaction::transfer(&keypair, &to2, 2, start_hash);

            // bad tx, AccountNotFound
            let keypair = Keypair::new();
            let to3 = sdk::pubkey::new_rand();
            let tx_anf = system_transaction::transfer(&keypair, &to3, 1, start_hash);

            // send 'em over
            let packet_batches = to_packet_batches(&[tx_no_ver, tx_anf, tx], 3);

            // glad they all fit
            assert_eq!(packet_batches.len(), 1);

            let packet_batches = packet_batches
                .into_iter()
                .map(|batch| (batch, vec![0u8, 1u8, 1u8]))
                .collect();
            let packet_batches = convert_from_old_verified(packet_batches);
            verified_sender // no_ver, anf, tx
                .send(packet_batches)
                .unwrap();

            drop(verified_sender);
            drop(tpu_vote_sender);
            drop(gossip_verified_vote_sender);
            // wait until banking_stage to finish up all packets
            banking_stage.join().unwrap();

            exit.store(true, Ordering::Relaxed);
            poh_service.join().unwrap();
            drop(poh_recorder);

            let mut blockhash = start_hash;
            let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
            bank.process_transaction(&fund_tx).unwrap();
            //receive entries + ticks
            loop {
                let entries: Vec<Entry> = entry_receiver
                    .iter()
                    .map(|(_bank, (entry, _tick_height))| entry)
                    .collect();

                assert!(entries.verify(&blockhash));
                if !entries.is_empty() {
                    blockhash = entries.last().unwrap().hash;
                    for entry in entries {
                        bank.process_entry_transactions(entry.transactions)
                            .iter()
                            .for_each(|x| assert_eq!(*x, Ok(())));
                    }
                }

                if bank.get_balance(&to) == 1 {
                    break;
                }

                sleep(Duration::from_millis(200));
            }

            assert_eq!(bank.get_balance(&to), 1);
            assert_eq!(bank.get_balance(&to2), 0);

            drop(entry_receiver);
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    #[test]
    fn test_banking_stage_entryfication() {
        sino_logger::setup();
        // In this attack we'll demonstrate that a verifier can interpret the ledger
        // differently if either the server doesn't signal the ledger to add an
        // Entry OR if the verifier tries to parallelize across multiple Entries.
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_slow_genesis_config(2);
        let (verified_sender, verified_receiver) = unbounded();

        // Process a batch that includes a transaction that receives two lamports.
        let alice = Keypair::new();
        let tx =
            system_transaction::transfer(&mint_keypair, &alice.pubkey(), 2, genesis_config.hash());

        let packet_batches = to_packet_batches(&[tx], 1);
        let packet_batches = packet_batches
            .into_iter()
            .map(|batch| (batch, vec![1u8]))
            .collect();
        let packet_batches = convert_from_old_verified(packet_batches);
        verified_sender.send(packet_batches).unwrap();

        // Process a second batch that uses the same from account, so conflicts with above TX
        let tx =
            system_transaction::transfer(&mint_keypair, &alice.pubkey(), 1, genesis_config.hash());
        let packet_batches = to_packet_batches(&[tx], 1);
        let packet_batches = packet_batches
            .into_iter()
            .map(|batch| (batch, vec![1u8]))
            .collect();
        let packet_batches = convert_from_old_verified(packet_batches);
        verified_sender.send(packet_batches).unwrap();

        let (vote_sender, vote_receiver) = unbounded();
        let (tpu_vote_sender, tpu_vote_receiver) = unbounded();
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();

            let entry_receiver = {
                // start a banking_stage to eat verified receiver
                let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
                let blockstore = Arc::new(
                    Blockstore::open(ledger_path.path())
                        .expect("Expected to be able to open database ledger"),
                );
                let poh_config = PohConfig {
                    // limit tick count to avoid clearing working_bank at
                    // PohRecord then PohRecorderError(MaxHeightReached) at BankingStage
                    target_tick_count: Some(bank.max_tick_height() - 1),
                    ..PohConfig::default()
                };
                let (exit, poh_recorder, poh_service, entry_receiver) =
                    create_test_recorder(&bank, &blockstore, Some(poh_config), None);
                let cluster_info = new_test_cluster_info(Node::new_localhost().info);
                let cluster_info = Arc::new(cluster_info);
                let _banking_stage = BankingStage::new_num_threads(
                    &cluster_info,
                    &poh_recorder,
                    verified_receiver,
                    tpu_vote_receiver,
                    vote_receiver,
                    3,
                    None,
                    gossip_vote_sender,
                    Arc::new(RwLock::new(CostModel::default())),
                );

                // wait for banking_stage to eat the packets
                while bank.get_balance(&alice.pubkey()) < 2 {
                    sleep(Duration::from_millis(100));
                }
                exit.store(true, Ordering::Relaxed);
                poh_service.join().unwrap();
                entry_receiver
            };
            drop(verified_sender);
            drop(vote_sender);
            drop(tpu_vote_sender);

            // consume the entire entry_receiver, feed it into a new bank
            // check that the balance is what we expect.
            let entries: Vec<_> = entry_receiver
                .iter()
                .map(|(_bank, (entry, _tick_height))| entry)
                .collect();

            let bank = Bank::new_no_wallclock_throttle_for_tests(&genesis_config);
            for entry in entries {
                bank.process_entry_transactions(entry.transactions)
                    .iter()
                    .for_each(|x| assert_eq!(*x, Ok(())));
            }

            // Assert the user holds two lamports, not three. If the stage only outputs one
            // entry, then the second transaction will be rejected, because it drives
            // the account balance below zero before the credit is added.
            assert_eq!(bank.get_balance(&alice.pubkey()), 2);
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    fn sanitize_transactions(txs: Vec<Transaction>) -> Vec<SanitizedTransaction> {
        txs.into_iter()
            .map(SanitizedTransaction::from_transaction_for_tests)
            .collect()
    }

    #[test]
    fn test_bank_record_transactions() {
        sino_logger::setup();

        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config(10_000);
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let blockstore = Blockstore::open(ledger_path.path())
                .expect("Expected to be able to open database ledger");
            let (poh_recorder, entry_receiver, record_receiver) = PohRecorder::new(
                // TODO use record_receiver
                bank.tick_height(),
                bank.last_blockhash(),
                bank.clone(),
                None,
                bank.ticks_per_slot(),
                &Pubkey::default(),
                &Arc::new(blockstore),
                &Arc::new(LeaderScheduleCache::new_from_bank(&bank)),
                &Arc::new(PohConfig::default()),
                Arc::new(AtomicBool::default()),
            );
            let recorder = poh_recorder.recorder();
            let poh_recorder = Arc::new(Mutex::new(poh_recorder));

            let poh_simulator = simulate_poh(record_receiver, &poh_recorder);

            poh_recorder.lock().unwrap().set_bank(&bank);
            let pubkey = sdk::pubkey::new_rand();
            let keypair2 = Keypair::new();
            let pubkey2 = sdk::pubkey::new_rand();

            let txs = sanitize_transactions(vec![
                system_transaction::transfer(&mint_keypair, &pubkey, 1, genesis_config.hash()),
                system_transaction::transfer(&keypair2, &pubkey2, 1, genesis_config.hash()),
            ]);

            let mut results = vec![new_execution_result(Ok(())); 2];
            let _ = BankingStage::record_transactions(bank.slot(), &txs, &results, &recorder);
            let (_bank, (entry, _tick_height)) = entry_receiver.recv().unwrap();
            assert_eq!(entry.transactions.len(), txs.len());

            // InstructionErrors should still be recorded
            results[0] = new_execution_result(Err(TransactionError::InstructionError(
                1,
                SystemError::ResultWithNegativeLamports.into(),
            )));
            let RecordTransactionsSummary {
                result,
                retryable_indexes,
                ..
            } = BankingStage::record_transactions(bank.slot(), &txs, &results, &recorder);
            result.unwrap();
            assert!(retryable_indexes.is_empty());
            let (_bank, (entry, _tick_height)) = entry_receiver.recv().unwrap();
            assert_eq!(entry.transactions.len(), txs.len());

            // Other TransactionErrors should not be recorded
            results[0] = TransactionExecutionResult::NotExecuted(TransactionError::AccountNotFound);
            let RecordTransactionsSummary {
                result,
                retryable_indexes,
                ..
            } = BankingStage::record_transactions(bank.slot(), &txs, &results, &recorder);
            result.unwrap();
            assert!(retryable_indexes.is_empty());
            let (_bank, (entry, _tick_height)) = entry_receiver.recv().unwrap();
            assert_eq!(entry.transactions.len(), txs.len() - 1);

            // Once bank is set to a new bank (setting bank.slot() + 1 in record_transactions),
            // record_transactions should throw MaxHeightReached and return the set of retryable
            // txs
            let next_slot = bank.slot() + 1;
            let RecordTransactionsSummary {
                result,
                retryable_indexes,
                ..
            } = BankingStage::record_transactions(next_slot, &txs, &results, &recorder);
            assert_matches!(result, Err(PohRecorderError::MaxHeightReached));
            // The first result was an error so it's filtered out. The second result was Ok(),
            // so it should be marked as retryable
            assert_eq!(retryable_indexes, vec![1]);
            // Should receive nothing from PohRecorder b/c record failed
            assert!(entry_receiver.try_recv().is_err());

            poh_recorder
                .lock()
                .unwrap()
                .is_exited
                .store(true, Ordering::Relaxed);
            let _ = poh_simulator.join();
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    #[test]
    fn test_bank_prepare_filter_for_pending_transaction() {
        assert_eq!(
            BankingStage::prepare_filter_for_pending_transactions(6, &[2, 4, 5]),
            vec![
                Err(TransactionError::BlockhashNotFound),
                Err(TransactionError::BlockhashNotFound),
                Ok(()),
                Err(TransactionError::BlockhashNotFound),
                Ok(()),
                Ok(())
            ]
        );

        assert_eq!(
            BankingStage::prepare_filter_for_pending_transactions(6, &[0, 2, 3]),
            vec![
                Ok(()),
                Err(TransactionError::BlockhashNotFound),
                Ok(()),
                Ok(()),
                Err(TransactionError::BlockhashNotFound),
                Err(TransactionError::BlockhashNotFound),
            ]
        );
    }

    #[test]
    fn test_bank_filter_valid_transaction_indexes() {
        assert_eq!(
            BankingStage::filter_valid_transaction_indexes(
                &[
                    (Err(TransactionError::BlockhashNotFound), None),
                    (Err(TransactionError::BlockhashNotFound), None),
                    (Ok(()), None),
                    (Err(TransactionError::BlockhashNotFound), None),
                    (Ok(()), None),
                    (Ok(()), None),
                ],
                &[2, 4, 5, 9, 11, 13]
            ),
            [5, 11, 13]
        );

        assert_eq!(
            BankingStage::filter_valid_transaction_indexes(
                &[
                    (Ok(()), None),
                    (Err(TransactionError::BlockhashNotFound), None),
                    (Err(TransactionError::BlockhashNotFound), None),
                    (Ok(()), None),
                    (Ok(()), None),
                    (Ok(()), None),
                ],
                &[1, 6, 7, 9, 31, 43]
            ),
            [1, 9, 31, 43]
        );
    }

    #[test]
    fn test_should_process_or_forward_packets() {
        let my_pubkey = sdk::pubkey::new_rand();
        let my_pubkey1 = sdk::pubkey::new_rand();
        let bank = Arc::new(Bank::default_for_tests());
        // having active bank allows to consume immediately
        assert_matches!(
            BankingStage::consume_or_forward_packets(&my_pubkey, None, Some(&bank), false, false),
            BufferedPacketsDecision::Consume(_)
        );
        assert_matches!(
            BankingStage::consume_or_forward_packets(&my_pubkey, None, None, false, false),
            BufferedPacketsDecision::Hold
        );
        assert_matches!(
            BankingStage::consume_or_forward_packets(&my_pubkey1, None, None, false, false),
            BufferedPacketsDecision::Hold
        );

        assert_matches!(
            BankingStage::consume_or_forward_packets(
                &my_pubkey,
                Some(my_pubkey1),
                None,
                false,
                false
            ),
            BufferedPacketsDecision::Forward
        );

        assert_matches!(
            BankingStage::consume_or_forward_packets(
                &my_pubkey,
                Some(my_pubkey1),
                None,
                true,
                true
            ),
            BufferedPacketsDecision::Hold
        );
        assert_matches!(
            BankingStage::consume_or_forward_packets(
                &my_pubkey,
                Some(my_pubkey1),
                None,
                true,
                false
            ),
            BufferedPacketsDecision::ForwardAndHold
        );
        assert_matches!(
            BankingStage::consume_or_forward_packets(
                &my_pubkey,
                Some(my_pubkey1),
                Some(&bank),
                false,
                false
            ),
            BufferedPacketsDecision::Consume(_)
        );
        assert_matches!(
            BankingStage::consume_or_forward_packets(
                &my_pubkey1,
                Some(my_pubkey1),
                None,
                false,
                false
            ),
            BufferedPacketsDecision::Hold
        );
        assert_matches!(
            BankingStage::consume_or_forward_packets(
                &my_pubkey1,
                Some(my_pubkey1),
                Some(&bank),
                false,
                false
            ),
            BufferedPacketsDecision::Consume(_)
        );
    }

    fn create_slow_genesis_config(lamports: u64) -> GenesisConfigInfo {
        let mut config_info = create_genesis_config(lamports);
        // For these tests there's only 1 slot, don't want to run out of ticks
        config_info.genesis_config.ticks_per_slot *= 8;
        config_info
    }

    #[test]
    fn test_bank_process_and_record_transactions() {
        sino_logger::setup();
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_slow_genesis_config(10_000);
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
        let pubkey = sdk::pubkey::new_rand();

        let transactions = sanitize_transactions(vec![system_transaction::transfer(
            &mint_keypair,
            &pubkey,
            1,
            genesis_config.hash(),
        )]);

        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let blockstore = Blockstore::open(ledger_path.path())
                .expect("Expected to be able to open database ledger");
            let (poh_recorder, entry_receiver, record_receiver) = PohRecorder::new(
                bank.tick_height(),
                bank.last_blockhash(),
                bank.clone(),
                Some((4, 4)),
                bank.ticks_per_slot(),
                &pubkey,
                &Arc::new(blockstore),
                &Arc::new(LeaderScheduleCache::new_from_bank(&bank)),
                &Arc::new(PohConfig::default()),
                Arc::new(AtomicBool::default()),
            );
            let recorder = poh_recorder.recorder();
            let poh_recorder = Arc::new(Mutex::new(poh_recorder));

            let poh_simulator = simulate_poh(record_receiver, &poh_recorder);

            poh_recorder.lock().unwrap().set_bank(&bank);
            let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();

            let process_transactions_batch_output = BankingStage::process_and_record_transactions(
                &bank,
                &transactions,
                &recorder,
                0,
                None,
                &gossip_vote_sender,
                &Arc::new(QosService::new(Arc::new(RwLock::new(CostModel::default())))),
            );

            let ExecuteAndCommitTransactionsOutput {
                transactions_attempted_execution_count,
                executed_transactions_count,
                executed_with_successful_result_count,
                commit_transactions_result,
                ..
            } = process_transactions_batch_output.execute_and_commit_transactions_output;

            assert_eq!(transactions_attempted_execution_count, 1);
            assert_eq!(executed_transactions_count, 1);
            assert_eq!(executed_with_successful_result_count, 1);
            assert!(commit_transactions_result.is_ok());

            // Tick up to max tick height
            while poh_recorder.lock().unwrap().tick_height() != bank.max_tick_height() {
                poh_recorder.lock().unwrap().tick();
            }

            let mut done = false;
            // read entries until I find mine, might be ticks...
            while let Ok((_bank, (entry, _tick_height))) = entry_receiver.recv() {
                if !entry.is_tick() {
                    trace!("got entry");
                    assert_eq!(entry.transactions.len(), transactions.len());
                    assert_eq!(bank.get_balance(&pubkey), 1);
                    done = true;
                }
                if done {
                    break;
                }
            }
            trace!("done ticking");

            assert!(done);

            let transactions = sanitize_transactions(vec![system_transaction::transfer(
                &mint_keypair,
                &pubkey,
                2,
                genesis_config.hash(),
            )]);

            let process_transactions_batch_output = BankingStage::process_and_record_transactions(
                &bank,
                &transactions,
                &recorder,
                0,
                None,
                &gossip_vote_sender,
                &Arc::new(QosService::new(Arc::new(RwLock::new(CostModel::default())))),
            );

            let ExecuteAndCommitTransactionsOutput {
                transactions_attempted_execution_count,
                executed_transactions_count,
                executed_with_successful_result_count,
                retryable_transaction_indexes,
                commit_transactions_result,
                ..
            } = process_transactions_batch_output.execute_and_commit_transactions_output;
            assert_eq!(transactions_attempted_execution_count, 1);
            // Transactions was still executed, just wasn't committed, so should be counted here.
            assert_eq!(executed_transactions_count, 1);
            assert_eq!(executed_with_successful_result_count, 1);
            assert_eq!(retryable_transaction_indexes, vec![0]);
            assert_matches!(
                commit_transactions_result,
                Err(PohRecorderError::MaxHeightReached)
            );

            poh_recorder
                .lock()
                .unwrap()
                .is_exited
                .store(true, Ordering::Relaxed);
            let _ = poh_simulator.join();

            assert_eq!(bank.get_balance(&pubkey), 1);
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    #[test]
    fn test_bank_process_and_record_transactions_cost_tracker() {
        sino_logger::setup();
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_slow_genesis_config(10_000);
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
        let pubkey = sdk::pubkey::new_rand();

        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let blockstore = Blockstore::open(ledger_path.path())
                .expect("Expected to be able to open database ledger");
            let (poh_recorder, _entry_receiver, record_receiver) = PohRecorder::new(
                bank.tick_height(),
                bank.last_blockhash(),
                bank.clone(),
                Some((4, 4)),
                bank.ticks_per_slot(),
                &pubkey,
                &Arc::new(blockstore),
                &Arc::new(LeaderScheduleCache::new_from_bank(&bank)),
                &Arc::new(PohConfig::default()),
                Arc::new(AtomicBool::default()),
            );
            let recorder = poh_recorder.recorder();
            let poh_recorder = Arc::new(Mutex::new(poh_recorder));

            let poh_simulator = simulate_poh(record_receiver, &poh_recorder);

            poh_recorder.lock().unwrap().set_bank(&bank);
            let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();

            let qos_service =
                Arc::new(QosService::new(Arc::new(RwLock::new(CostModel::default()))));

            let get_block_cost = || bank.read_cost_tracker().unwrap().block_cost();
            let get_tx_count = || bank.read_cost_tracker().unwrap().transaction_count();
            assert_eq!(get_block_cost(), 0);
            assert_eq!(get_tx_count(), 0);

            //
            // TEST: cost tracker's block cost increases when successfully processing a tx
            //

            let transactions = sanitize_transactions(vec![system_transaction::transfer(
                &mint_keypair,
                &pubkey,
                1,
                genesis_config.hash(),
            )]);

            let process_transactions_batch_output = BankingStage::process_and_record_transactions(
                &bank,
                &transactions,
                &recorder,
                0,
                None,
                &gossip_vote_sender,
                &qos_service,
            );

            let ExecuteAndCommitTransactionsOutput {
                executed_with_successful_result_count,
                commit_transactions_result,
                ..
            } = process_transactions_batch_output.execute_and_commit_transactions_output;
            assert_eq!(executed_with_successful_result_count, 1);
            assert!(commit_transactions_result.is_ok());

            let single_transfer_cost = get_block_cost();
            assert_ne!(single_transfer_cost, 0);
            assert_eq!(get_tx_count(), 1);

            //
            // TEST: When a tx in a batch can't be executed (here because of account
            // locks), then its cost does not affect the cost tracker.
            //

            let allocate_keypair = Keypair::new();
            let transactions = sanitize_transactions(vec![
                system_transaction::transfer(&mint_keypair, &pubkey, 2, genesis_config.hash()),
                // intentionally use a tx that has a different cost
                system_transaction::allocate(
                    &mint_keypair,
                    &allocate_keypair,
                    genesis_config.hash(),
                    1,
                ),
            ]);

            let process_transactions_batch_output = BankingStage::process_and_record_transactions(
                &bank,
                &transactions,
                &recorder,
                0,
                None,
                &gossip_vote_sender,
                &qos_service,
            );

            let ExecuteAndCommitTransactionsOutput {
                executed_with_successful_result_count,
                commit_transactions_result,
                retryable_transaction_indexes,
                ..
            } = process_transactions_batch_output.execute_and_commit_transactions_output;
            assert_eq!(executed_with_successful_result_count, 1);
            assert!(commit_transactions_result.is_ok());
            assert_eq!(retryable_transaction_indexes, vec![1]);

            assert_eq!(get_block_cost(), 2 * single_transfer_cost);
            assert_eq!(get_tx_count(), 2);

            poh_recorder
                .lock()
                .unwrap()
                .is_exited
                .store(true, Ordering::Relaxed);
            let _ = poh_simulator.join();
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    fn simulate_poh(
        record_receiver: CrossbeamReceiver<Record>,
        poh_recorder: &Arc<Mutex<PohRecorder>>,
    ) -> JoinHandle<()> {
        let poh_recorder = poh_recorder.clone();
        let is_exited = poh_recorder.lock().unwrap().is_exited.clone();
        let tick_producer = Builder::new()
            .name("solana-simulate_poh".to_string())
            .spawn(move || loop {
                PohService::read_record_receiver_and_process(
                    &poh_recorder,
                    &record_receiver,
                    Duration::from_millis(10),
                );
                if is_exited.load(Ordering::Relaxed) {
                    break;
                }
            });
        tick_producer.unwrap()
    }

    #[test]
    fn test_bank_process_and_record_transactions_account_in_use() {
        sino_logger::setup();
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_slow_genesis_config(10_000);
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
        let pubkey = sdk::pubkey::new_rand();
        let pubkey1 = sdk::pubkey::new_rand();

        let transactions = sanitize_transactions(vec![
            system_transaction::transfer(&mint_keypair, &pubkey, 1, genesis_config.hash()),
            system_transaction::transfer(&mint_keypair, &pubkey1, 1, genesis_config.hash()),
        ]);

        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let blockstore = Blockstore::open(ledger_path.path())
                .expect("Expected to be able to open database ledger");
            let (poh_recorder, _entry_receiver, record_receiver) = PohRecorder::new(
                bank.tick_height(),
                bank.last_blockhash(),
                bank.clone(),
                Some((4, 4)),
                bank.ticks_per_slot(),
                &pubkey,
                &Arc::new(blockstore),
                &Arc::new(LeaderScheduleCache::new_from_bank(&bank)),
                &Arc::new(PohConfig::default()),
                Arc::new(AtomicBool::default()),
            );
            let recorder = poh_recorder.recorder();
            let poh_recorder = Arc::new(Mutex::new(poh_recorder));

            poh_recorder.lock().unwrap().set_bank(&bank);

            let poh_simulator = simulate_poh(record_receiver, &poh_recorder);

            let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();

            let process_transactions_batch_output = BankingStage::process_and_record_transactions(
                &bank,
                &transactions,
                &recorder,
                0,
                None,
                &gossip_vote_sender,
                &Arc::new(QosService::new(Arc::new(RwLock::new(CostModel::default())))),
            );

            poh_recorder
                .lock()
                .unwrap()
                .is_exited
                .store(true, Ordering::Relaxed);
            let _ = poh_simulator.join();

            let ExecuteAndCommitTransactionsOutput {
                transactions_attempted_execution_count,
                executed_transactions_count,
                retryable_transaction_indexes,
                commit_transactions_result,
                ..
            } = process_transactions_batch_output.execute_and_commit_transactions_output;

            assert_eq!(transactions_attempted_execution_count, 2);
            assert_eq!(executed_transactions_count, 1);
            assert_eq!(retryable_transaction_indexes, vec![1],);
            assert!(commit_transactions_result.is_ok());
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    #[test]
    fn test_filter_valid_packets() {
        sino_logger::setup();

        let mut packet_batches = (0..16)
            .map(|packets_id| {
                let packet_batch = PacketBatch::new(
                    (0..32)
                        .map(|packet_id| {
                            let mut p = Packet::default();
                            p.meta.port = packets_id << 8 | packet_id;
                            p
                        })
                        .collect_vec(),
                );
                let valid_indexes = (0..32)
                    .filter_map(|x| if x % 2 != 0 { Some(x as usize) } else { None })
                    .collect_vec();
                (packet_batch, valid_indexes, false)
            })
            .collect_vec();

        let result = BankingStage::filter_valid_packets_for_forwarding(packet_batches.iter());

        assert_eq!(result.len(), 256);

        let _ = result
            .into_iter()
            .enumerate()
            .map(|(index, p)| {
                let packets_id = index / 16;
                let packet_id = (index % 16) * 2 + 1;
                assert_eq!(p.meta.port, (packets_id << 8 | packet_id) as u16);
            })
            .collect_vec();

        packet_batches[0].2 = true;
        let result = BankingStage::filter_valid_packets_for_forwarding(packet_batches.iter());
        assert_eq!(result.len(), 240);
    }

    #[test]
    fn test_process_transactions_returns_unprocessed_txs() {
        sino_logger::setup();
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_slow_genesis_config(10_000);
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));

        let pubkey = sdk::pubkey::new_rand();

        let transactions = sanitize_transactions(vec![system_transaction::transfer(
            &mint_keypair,
            &pubkey,
            1,
            genesis_config.hash(),
        )]);

        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let blockstore = Blockstore::open(ledger_path.path())
                .expect("Expected to be able to open database ledger");
            let (poh_recorder, _entry_receiver, record_receiver) = PohRecorder::new(
                bank.tick_height(),
                bank.last_blockhash(),
                bank.clone(),
                Some((4, 4)),
                bank.ticks_per_slot(),
                &sdk::pubkey::new_rand(),
                &Arc::new(blockstore),
                &Arc::new(LeaderScheduleCache::new_from_bank(&bank)),
                &Arc::new(PohConfig::default()),
                Arc::new(AtomicBool::default()),
            );

            // Poh Recorder has no working bank, so should throw MaxHeightReached error on
            // record
            let recorder = poh_recorder.recorder();

            let poh_simulator = simulate_poh(record_receiver, &Arc::new(Mutex::new(poh_recorder)));

            let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();

            let process_transactions_summary = BankingStage::process_transactions(
                &bank,
                &Instant::now(),
                &transactions,
                &recorder,
                None,
                &gossip_vote_sender,
                &Arc::new(QosService::new(Arc::new(RwLock::new(CostModel::default())))),
            );

            let ProcessTransactionsSummary {
                reached_max_poh_height,
                transactions_attempted_execution_count,
                committed_transactions_count,
                committed_transactions_with_successful_result_count,
                failed_commit_count,
                mut retryable_transaction_indexes,
                ..
            } = process_transactions_summary;
            assert!(reached_max_poh_height);
            assert_eq!(transactions_attempted_execution_count, 1);
            assert_eq!(failed_commit_count, 1);
            // MaxHeightReached error does not commit, should be zero here
            assert_eq!(committed_transactions_count, 0);
            assert_eq!(committed_transactions_with_successful_result_count, 0);

            retryable_transaction_indexes.sort_unstable();
            let expected: Vec<usize> = (0..transactions.len()).collect();
            assert_eq!(retryable_transaction_indexes, expected);

            recorder.is_exited.store(true, Ordering::Relaxed);
            let _ = poh_simulator.join();
        }

        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    fn execute_transactions_with_dummy_poh_service(
        bank: Arc<Bank>,
        transactions: Vec<Transaction>,
    ) -> ProcessTransactionsSummary {
        let transactions = sanitize_transactions(transactions);
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        let blockstore = Blockstore::open(ledger_path.path())
            .expect("Expected to be able to open database ledger");
        let (poh_recorder, _entry_receiver, record_receiver) = PohRecorder::new(
            bank.tick_height(),
            bank.last_blockhash(),
            bank.clone(),
            Some((4, 4)),
            bank.ticks_per_slot(),
            &Pubkey::new_unique(),
            &Arc::new(blockstore),
            &Arc::new(LeaderScheduleCache::new_from_bank(&bank)),
            &Arc::new(PohConfig::default()),
            Arc::new(AtomicBool::default()),
        );
        let recorder = poh_recorder.recorder();
        let poh_recorder = Arc::new(Mutex::new(poh_recorder));

        poh_recorder.lock().unwrap().set_bank(&bank);

        let poh_simulator = simulate_poh(record_receiver, &poh_recorder);

        let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();

        let process_transactions_summary = BankingStage::process_transactions(
            &bank,
            &Instant::now(),
            &transactions,
            &recorder,
            None,
            &gossip_vote_sender,
            &Arc::new(QosService::new(Arc::new(RwLock::new(CostModel::default())))),
        );

        poh_recorder
            .lock()
            .unwrap()
            .is_exited
            .store(true, Ordering::Relaxed);
        let _ = poh_simulator.join();

        process_transactions_summary
    }

    #[test]
    fn test_process_transactions_instruction_error() {
        sino_logger::setup();
        let lamports = 10_000;
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_slow_genesis_config(lamports);
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));

        // Transfer more than the balance of the mint keypair, should cause a
        // InstructionError::InsufficientFunds that is then committed. Needs to be
        // MAX_NUM_TRANSACTIONS_PER_BATCH at least so it doesn't conflict on account locks
        // with the below transaction
        let mut transactions = vec![
            system_transaction::transfer(
                &mint_keypair,
                &Pubkey::new_unique(),
                lamports + 1,
                genesis_config.hash(),
            );
            MAX_NUM_TRANSACTIONS_PER_BATCH
        ];

        // Make one transaction that will succeed.
        transactions.push(system_transaction::transfer(
            &mint_keypair,
            &Pubkey::new_unique(),
            1,
            genesis_config.hash(),
        ));

        let transactions_count = transactions.len();
        let ProcessTransactionsSummary {
            reached_max_poh_height,
            transactions_attempted_execution_count,
            committed_transactions_count,
            committed_transactions_with_successful_result_count,
            failed_commit_count,
            retryable_transaction_indexes,
            ..
        } = execute_transactions_with_dummy_poh_service(bank, transactions);

        // All the transactions should have been replayed, but only 1 committed
        assert!(!reached_max_poh_height);
        assert_eq!(transactions_attempted_execution_count, transactions_count);
        // Both transactions should have been committed, even though one was an error,
        // because InstructionErrors are committed
        assert_eq!(committed_transactions_count, 2);
        assert_eq!(committed_transactions_with_successful_result_count, 1);
        assert_eq!(failed_commit_count, 0);
        assert_eq!(
            retryable_transaction_indexes,
            (1..transactions_count - 1).collect::<Vec<usize>>()
        );
    }
    #[test]
    fn test_process_transactions_account_in_use() {
        sino_logger::setup();
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_slow_genesis_config(10_000);
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));

        // Make all repetitive transactions that conflict on the `mint_keypair`, so only 1 should be executed
        let mut transactions = vec![
            system_transaction::transfer(
                &mint_keypair,
                &Pubkey::new_unique(),
                1,
                genesis_config.hash()
            );
            MAX_NUM_TRANSACTIONS_PER_BATCH
        ];

        // Make one more in separate batch that also conflicts, but because it's in a separate batch, it
        // should be executed
        transactions.push(system_transaction::transfer(
            &mint_keypair,
            &Pubkey::new_unique(),
            1,
            genesis_config.hash(),
        ));

        let transactions_count = transactions.len();
        let ProcessTransactionsSummary {
            reached_max_poh_height,
            transactions_attempted_execution_count,
            committed_transactions_count,
            committed_transactions_with_successful_result_count,
            failed_commit_count,
            retryable_transaction_indexes,
            ..
        } = execute_transactions_with_dummy_poh_service(bank, transactions);

        // All the transactions should have been replayed, but only 2 committed (first and last)
        assert!(!reached_max_poh_height);
        assert_eq!(transactions_attempted_execution_count, transactions_count);
        assert_eq!(committed_transactions_count, 2);
        assert_eq!(committed_transactions_with_successful_result_count, 2);
        assert_eq!(failed_commit_count, 0,);

        // Everything except first and last index of the transactions failed and are last retryable
        assert_eq!(
            retryable_transaction_indexes,
            (1..transactions_count - 1).collect::<Vec<usize>>()
        );
    }

    #[test]
    fn test_write_persist_transaction_status() {
        sino_logger::setup();
        let GenesisConfigInfo {
            mut genesis_config,
            mint_keypair,
            ..
        } = create_slow_genesis_config(sdk::native_token::sol_to_lamports(1000.0));
        genesis_config.rent.lamports_per_byte_year = 50;
        genesis_config.rent.exemption_threshold = 2.0;
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
        let rent_exempt_minimum = bank.get_minimum_balance_for_rent_exemption(0);
        let pubkey = sdk::pubkey::new_rand();
        let pubkey1 = sdk::pubkey::new_rand();
        let keypair1 = Keypair::new();

        let success_tx =
            system_transaction::transfer(&mint_keypair, &pubkey, 0, genesis_config.hash());
        let success_signature = success_tx.signatures[0];
        let entry_1 = next_entry(&genesis_config.hash(), 1, vec![success_tx.clone()]);
        let ix_error_tx =
            system_transaction::transfer(&keypair1, &pubkey1, std::u64::MAX, genesis_config.hash());
        let ix_error_signature = ix_error_tx.signatures[0];
        let entry_2 = next_entry(&entry_1.hash, 1, vec![ix_error_tx.clone()]);
        let entries = vec![entry_1, entry_2];

        let transactions = sanitize_transactions(vec![success_tx, ix_error_tx]);
        bank.transfer(rent_exempt_minimum, &mint_keypair, &keypair1.pubkey())
            .unwrap();

        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let blockstore = Blockstore::open(ledger_path.path())
                .expect("Expected to be able to open database ledger");
            let blockstore = Arc::new(blockstore);
            let (poh_recorder, _entry_receiver, record_receiver) = PohRecorder::new(
                bank.tick_height(),
                bank.last_blockhash(),
                bank.clone(),
                Some((4, 4)),
                bank.ticks_per_slot(),
                &pubkey,
                &blockstore,
                &Arc::new(LeaderScheduleCache::new_from_bank(&bank)),
                &Arc::new(PohConfig::default()),
                Arc::new(AtomicBool::default()),
            );
            let recorder = poh_recorder.recorder();
            let poh_recorder = Arc::new(Mutex::new(poh_recorder));

            let poh_simulator = simulate_poh(record_receiver, &poh_recorder);

            poh_recorder.lock().unwrap().set_bank(&bank);

            let shreds = entries_to_test_shreds(entries, bank.slot(), 0, true, 0);
            blockstore.insert_shreds(shreds, None, false).unwrap();
            blockstore.set_roots(std::iter::once(&bank.slot())).unwrap();

            let (transaction_status_sender, transaction_status_receiver) = unbounded();
            let transaction_status_service = TransactionStatusService::new(
                transaction_status_receiver,
                Arc::new(AtomicU64::default()),
                true,
                None,
                blockstore.clone(),
                &Arc::new(AtomicBool::new(false)),
            );

            let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();

            let _ = BankingStage::process_and_record_transactions(
                &bank,
                &transactions,
                &recorder,
                0,
                Some(TransactionStatusSender {
                    sender: transaction_status_sender,
                    enable_cpi_and_log_storage: false,
                }),
                &gossip_vote_sender,
                &Arc::new(QosService::new(Arc::new(RwLock::new(CostModel::default())))),
            );

            transaction_status_service.join().unwrap();

            let confirmed_block = blockstore.get_rooted_block(bank.slot(), false).unwrap();
            let actual_tx_results: Vec<_> = confirmed_block
                .transactions
                .into_iter()
                .map(|TransactionWithMetadata { transaction, meta }| {
                    (transaction.signatures[0], meta.status)
                })
                .collect();
            let expected_tx_results = vec![
                (success_signature, Ok(())),
                (
                    ix_error_signature,
                    Err(TransactionError::InstructionError(
                        0,
                        InstructionError::Custom(1),
                    )),
                ),
            ];
            assert_eq!(actual_tx_results, expected_tx_results);

            poh_recorder
                .lock()
                .unwrap()
                .is_exited
                .store(true, Ordering::Relaxed);
            let _ = poh_simulator.join();
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    #[allow(clippy::type_complexity)]
    fn setup_conflicting_transactions(
        ledger_path: &Path,
    ) -> (
        Vec<Transaction>,
        Arc<Bank>,
        Arc<Mutex<PohRecorder>>,
        Receiver<WorkingBankEntry>,
        JoinHandle<()>,
    ) {
        Blockstore::destroy(ledger_path).unwrap();
        let genesis_config_info = create_slow_genesis_config(10_000);
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = &genesis_config_info;
        let blockstore =
            Blockstore::open(ledger_path).expect("Expected to be able to open database ledger");
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(genesis_config));
        let exit = Arc::new(AtomicBool::default());
        let (poh_recorder, entry_receiver, record_receiver) = PohRecorder::new(
            bank.tick_height(),
            bank.last_blockhash(),
            bank.clone(),
            Some((4, 4)),
            bank.ticks_per_slot(),
            &sdk::pubkey::new_rand(),
            &Arc::new(blockstore),
            &Arc::new(LeaderScheduleCache::new_from_bank(&bank)),
            &Arc::new(PohConfig::default()),
            exit,
        );
        let poh_recorder = Arc::new(Mutex::new(poh_recorder));

        // Set up unparallelizable conflicting transactions
        let pubkey0 = sdk::pubkey::new_rand();
        let pubkey1 = sdk::pubkey::new_rand();
        let pubkey2 = sdk::pubkey::new_rand();
        let transactions = vec![
            system_transaction::transfer(mint_keypair, &pubkey0, 1, genesis_config.hash()),
            system_transaction::transfer(mint_keypair, &pubkey1, 1, genesis_config.hash()),
            system_transaction::transfer(mint_keypair, &pubkey2, 1, genesis_config.hash()),
        ];
        let poh_simulator = simulate_poh(record_receiver, &poh_recorder);

        (
            transactions,
            bank,
            poh_recorder,
            entry_receiver,
            poh_simulator,
        )
    }

    #[test]
    fn test_consume_buffered_packets() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let (transactions, bank, poh_recorder, _entry_receiver, poh_simulator) =
                setup_conflicting_transactions(ledger_path.path());
            let recorder = poh_recorder.lock().unwrap().recorder();
            let num_conflicting_transactions = transactions.len();
            let mut packet_batches = to_packet_batches(&transactions, num_conflicting_transactions);
            assert_eq!(packet_batches.len(), 1);
            assert_eq!(
                packet_batches[0].packets.len(),
                num_conflicting_transactions
            );
            let packet_batch = packet_batches.pop().unwrap();
            let mut buffered_packet_batches: UnprocessedPacketBatches = vec![(
                packet_batch,
                (0..num_conflicting_transactions).into_iter().collect(),
                false,
            )]
            .into_iter()
            .collect();

            let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();

            // When the working bank in poh_recorder is None, no packets should be processed
            assert!(!poh_recorder.lock().unwrap().has_bank());
            let max_tx_processing_ns = std::u128::MAX;
            BankingStage::consume_buffered_packets(
                &Pubkey::default(),
                max_tx_processing_ns,
                &poh_recorder,
                &mut buffered_packet_batches,
                None,
                &gossip_vote_sender,
                None::<Box<dyn Fn()>>,
                &BankingStageStats::default(),
                &recorder,
                &Arc::new(QosService::new(Arc::new(RwLock::new(CostModel::default())))),
                &mut LeaderSlotMetricsTracker::new(0),
            );
            assert_eq!(
                buffered_packet_batches[0].1.len(),
                num_conflicting_transactions
            );
            // When the poh recorder has a bank, should process all non conflicting buffered packets.
            // Processes one packet per iteration of the loop
            for num_expected_unprocessed in (0..num_conflicting_transactions).rev() {
                poh_recorder.lock().unwrap().set_bank(&bank);
                BankingStage::consume_buffered_packets(
                    &Pubkey::default(),
                    max_tx_processing_ns,
                    &poh_recorder,
                    &mut buffered_packet_batches,
                    None,
                    &gossip_vote_sender,
                    None::<Box<dyn Fn()>>,
                    &BankingStageStats::default(),
                    &recorder,
                    &Arc::new(QosService::new(Arc::new(RwLock::new(CostModel::default())))),
                    &mut LeaderSlotMetricsTracker::new(0),
                );
                if num_expected_unprocessed == 0 {
                    assert!(buffered_packet_batches.is_empty())
                } else {
                    assert_eq!(buffered_packet_batches[0].1.len(), num_expected_unprocessed);
                }
            }
            poh_recorder
                .lock()
                .unwrap()
                .is_exited
                .store(true, Ordering::Relaxed);
            let _ = poh_simulator.join();
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    #[test]
    fn test_consume_buffered_packets_interrupted() {
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let (transactions, bank, poh_recorder, _entry_receiver, poh_simulator) =
                setup_conflicting_transactions(ledger_path.path());
            let num_conflicting_transactions = transactions.len();
            let packet_batches = to_packet_batches(&transactions, 1);
            assert_eq!(packet_batches.len(), num_conflicting_transactions);
            for single_packet_batch in &packet_batches {
                assert_eq!(single_packet_batch.packets.len(), 1);
            }
            let mut buffered_packet_batches: UnprocessedPacketBatches = packet_batches
                .clone()
                .into_iter()
                .map(|single_packets| (single_packets, vec![0], false))
                .collect();

            let (continue_sender, continue_receiver) = unbounded();
            let (finished_packet_sender, finished_packet_receiver) = unbounded();

            let test_fn = Some(move || {
                finished_packet_sender.send(()).unwrap();
                continue_receiver.recv().unwrap();
            });
            // When the poh recorder has a bank, it should process all non conflicting buffered packets.
            // Because each conflicting transaction is in it's own `Packet` within a `PacketBatch`, then
            // each iteration of this loop will process one element of the batch per iteration of the
            // loop.
            let interrupted_iteration = 1;
            poh_recorder.lock().unwrap().set_bank(&bank);
            let poh_recorder_ = poh_recorder.clone();
            let recorder = poh_recorder_.lock().unwrap().recorder();
            let (gossip_vote_sender, _gossip_vote_receiver) = unbounded();
            // Start up thread to process the banks
            let t_consume = Builder::new()
                .name("consume-buffered-packets".to_string())
                .spawn(move || {
                    BankingStage::consume_buffered_packets(
                        &Pubkey::default(),
                        std::u128::MAX,
                        &poh_recorder_,
                        &mut buffered_packet_batches,
                        None,
                        &gossip_vote_sender,
                        test_fn,
                        &BankingStageStats::default(),
                        &recorder,
                        &Arc::new(QosService::new(Arc::new(RwLock::new(CostModel::default())))),
                        &mut LeaderSlotMetricsTracker::new(0),
                    );

                    // Check everything is correct. All indexes after `interrupted_iteration`
                    // should still be unprocessed
                    assert_eq!(
                        buffered_packet_batches.len(),
                        packet_batches[interrupted_iteration + 1..].len()
                    );
                    for ((remaining_unprocessed_packet, _, _forwarded), original_packet) in
                        buffered_packet_batches
                            .iter()
                            .zip(&packet_batches[interrupted_iteration + 1..])
                    {
                        assert_eq!(
                            remaining_unprocessed_packet.packets[0],
                            original_packet.packets[0]
                        );
                    }
                })
                .unwrap();

            for i in 0..=interrupted_iteration {
                finished_packet_receiver.recv().unwrap();
                if i == interrupted_iteration {
                    poh_recorder
                        .lock()
                        .unwrap()
                        .schedule_dummy_max_height_reached_failure();
                }
                continue_sender.send(()).unwrap();
            }

            t_consume.join().unwrap();
            poh_recorder
                .lock()
                .unwrap()
                .is_exited
                .store(true, Ordering::Relaxed);
            let _ = poh_simulator.join();
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    #[test]
    fn test_forwarder_budget() {
        sino_logger::setup();
        // Create `PacketBatch` with 1 unprocessed packet
        let packet = Packet::from_data(None, &[0]).unwrap();
        let single_packet_batch = PacketBatch::new(vec![packet]);

        let genesis_config_info = create_slow_genesis_config(10_000);
        let GenesisConfigInfo {
            genesis_config,
            validator_pubkey,
            ..
        } = &genesis_config_info;

        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(genesis_config));
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let blockstore = Arc::new(
                Blockstore::open(ledger_path.path())
                    .expect("Expected to be able to open database ledger"),
            );
            let poh_config = PohConfig {
                // limit tick count to avoid clearing working_bank at
                // PohRecord then PohRecorderError(MaxHeightReached) at BankingStage
                target_tick_count: Some(bank.max_tick_height() - 1),
                ..PohConfig::default()
            };

            let (exit, poh_recorder, poh_service, _entry_receiver) =
                create_test_recorder(&bank, &blockstore, Some(poh_config), None);

            let local_node = Node::new_localhost_with_pubkey(validator_pubkey);
            let cluster_info = new_test_cluster_info(local_node.info);
            let send_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
            let recv_socket = &local_node.sockets.tpu_forwards[0];

            let test_cases = vec![
                ("budget-restricted", DataBudget::restricted(), 0),
                ("budget-available", DataBudget::default(), 1),
            ];

            for (name, data_budget, expected_num_forwarded) in test_cases {
                let mut unprocessed_packet_batches: UnprocessedPacketBatches =
                    vec![(single_packet_batch.clone(), vec![0], false)]
                        .into_iter()
                        .collect();
                BankingStage::handle_forwarding(
                    &ForwardOption::ForwardTransaction,
                    &cluster_info,
                    &mut unprocessed_packet_batches,
                    &poh_recorder,
                    &send_socket,
                    true,
                    &data_budget,
                    &mut LeaderSlotMetricsTracker::new(0),
                );

                recv_socket
                    .set_nonblocking(expected_num_forwarded == 0)
                    .unwrap();

                let mut packets = vec![Packet::default(); 2];
                let num_received = recv_mmsg(recv_socket, &mut packets[..]).unwrap_or_default();
                assert_eq!(num_received, expected_num_forwarded, "{}", name);
            }

            exit.store(true, Ordering::Relaxed);
            poh_service.join().unwrap();
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    #[test]
    fn test_handle_forwarding() {
        sino_logger::setup();

        const FWD_PACKET: u8 = 1;
        let forwarded_packet = {
            let mut packet = Packet::from_data(None, &[FWD_PACKET]).unwrap();
            packet.meta.flags |= PacketFlags::FORWARDED;
            packet
        };

        const NORMAL_PACKET: u8 = 2;
        let normal_packet = Packet::from_data(None, &[NORMAL_PACKET]).unwrap();

        let packet_batch = PacketBatch::new(vec![forwarded_packet, normal_packet]);
        let mut unprocessed_packet_batches: UnprocessedPacketBatches =
            vec![(packet_batch, vec![0, 1], false)]
                .into_iter()
                .collect();

        let genesis_config_info = create_slow_genesis_config(10_000);
        let GenesisConfigInfo {
            genesis_config,
            validator_pubkey,
            ..
        } = &genesis_config_info;
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(genesis_config));
        let ledger_path = get_tmp_ledger_path_auto_delete!();
        {
            let blockstore = Arc::new(
                Blockstore::open(ledger_path.path())
                    .expect("Expected to be able to open database ledger"),
            );
            let poh_config = PohConfig {
                // limit tick count to avoid clearing working_bank at
                // PohRecord then PohRecorderError(MaxHeightReached) at BankingStage
                target_tick_count: Some(bank.max_tick_height() - 1),
                ..PohConfig::default()
            };

            let (exit, poh_recorder, poh_service, _entry_receiver) =
                create_test_recorder(&bank, &blockstore, Some(poh_config), None);

            let local_node = Node::new_localhost_with_pubkey(validator_pubkey);
            let cluster_info = new_test_cluster_info(local_node.info);
            let send_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
            let recv_socket = &local_node.sockets.tpu_forwards[0];

            let test_cases = vec![
                ("not-forward", ForwardOption::NotForward, true, vec![], 2),
                (
                    "fwd-normal",
                    ForwardOption::ForwardTransaction,
                    true,
                    vec![NORMAL_PACKET],
                    2,
                ),
                (
                    "fwd-no-op",
                    ForwardOption::ForwardTransaction,
                    true,
                    vec![],
                    2,
                ),
                (
                    "fwd-no-hold",
                    ForwardOption::ForwardTransaction,
                    false,
                    vec![],
                    0,
                ),
            ];

            for (name, forward_option, hold, expected_ids, expected_num_unprocessed) in test_cases {
                BankingStage::handle_forwarding(
                    &forward_option,
                    &cluster_info,
                    &mut unprocessed_packet_batches,
                    &poh_recorder,
                    &send_socket,
                    hold,
                    &DataBudget::default(),
                    &mut LeaderSlotMetricsTracker::new(0),
                );

                recv_socket
                    .set_nonblocking(expected_ids.is_empty())
                    .unwrap();

                let mut packets = vec![Packet::default(); 2];
                let num_received = recv_mmsg(recv_socket, &mut packets[..]).unwrap_or_default();
                assert_eq!(num_received, expected_ids.len(), "{}", name);
                for (i, expected_id) in expected_ids.iter().enumerate() {
                    assert_eq!(packets[i].meta.size, 1);
                    assert_eq!(packets[i].data[0], *expected_id, "{}", name);
                }

                let num_unprocessed_packets: usize = unprocessed_packet_batches
                    .iter()
                    .map(|(b, ..)| b.packets.len())
                    .sum();
                assert_eq!(
                    num_unprocessed_packets, expected_num_unprocessed,
                    "{}",
                    name
                );
            }

            exit.store(true, Ordering::Relaxed);
            poh_service.join().unwrap();
        }
        Blockstore::destroy(ledger_path.path()).unwrap();
    }

    #[test]
    fn test_push_unprocessed_batch_limit() {
        sino_logger::setup();
        // Create `PacketBatch` with 2 unprocessed packets
        let new_packet_batch = PacketBatch::new(vec![Packet::default(); 2]);
        let mut unprocessed_packets: UnprocessedPacketBatches =
            vec![(new_packet_batch, vec![0, 1], false)]
                .into_iter()
                .collect();
        // Set the limit to 2
        let batch_limit = 2;
        // Create new unprocessed packets and add to a batch
        let new_packet_batch = PacketBatch::new(vec![Packet::default()]);
        let packet_indexes = vec![];

        let mut dropped_packet_batches_count = 0;
        let mut dropped_packets_count = 0;
        let mut newly_buffered_packets_count = 0;
        let mut banking_stage_stats = BankingStageStats::default();
        // Because the set of unprocessed `packet_indexes` is empty, the
        // packets are not added to the unprocessed queue
        BankingStage::push_unprocessed(
            &mut unprocessed_packets,
            new_packet_batch.clone(),
            packet_indexes,
            &mut dropped_packet_batches_count,
            &mut dropped_packets_count,
            &mut newly_buffered_packets_count,
            batch_limit,
            &mut banking_stage_stats,
            &mut LeaderSlotMetricsTracker::new(0),
        );
        assert_eq!(unprocessed_packets.len(), 1);
        assert_eq!(dropped_packet_batches_count, 0);
        assert_eq!(dropped_packets_count, 0);
        assert_eq!(newly_buffered_packets_count, 0);

        // Because the set of unprocessed `packet_indexes` is non-empty, the
        // packets are added to the unprocessed queue
        let packet_indexes = vec![0];
        BankingStage::push_unprocessed(
            &mut unprocessed_packets,
            new_packet_batch,
            packet_indexes.clone(),
            &mut dropped_packet_batches_count,
            &mut dropped_packets_count,
            &mut newly_buffered_packets_count,
            batch_limit,
            &mut banking_stage_stats,
            &mut LeaderSlotMetricsTracker::new(0),
        );
        assert_eq!(unprocessed_packets.len(), 2);
        assert_eq!(dropped_packet_batches_count, 0);
        assert_eq!(dropped_packets_count, 0);
        assert_eq!(newly_buffered_packets_count, 1);

        // Because we've reached the batch limit, old unprocessed packets are
        // dropped and the new one is appended to the end
        let new_packet_batch = PacketBatch::new(vec![Packet::from_data(
            Some(&SocketAddr::from(([127, 0, 0, 1], 8001))),
            42,
        )
        .unwrap()]);
        assert_eq!(unprocessed_packets.len(), batch_limit);
        BankingStage::push_unprocessed(
            &mut unprocessed_packets,
            new_packet_batch.clone(),
            packet_indexes,
            &mut dropped_packet_batches_count,
            &mut dropped_packets_count,
            &mut newly_buffered_packets_count,
            batch_limit,
            &mut banking_stage_stats,
            &mut LeaderSlotMetricsTracker::new(0),
        );
        assert_eq!(unprocessed_packets.len(), 2);
        assert_eq!(
            unprocessed_packets[1].0.packets[0],
            new_packet_batch.packets[0]
        );
        assert_eq!(dropped_packet_batches_count, 1);
        assert_eq!(dropped_packets_count, 2);
        assert_eq!(newly_buffered_packets_count, 2);
    }

    #[test]
    fn test_packet_message() {
        let keypair = Keypair::new();
        let pubkey = sdk::pubkey::new_rand();
        let blockhash = Hash::new_unique();
        let transaction = system_transaction::transfer(&keypair, &pubkey, 1, blockhash);
        let packet = Packet::from_data(None, &transaction).unwrap();
        assert_eq!(
            BankingStage::packet_message(&packet).unwrap().to_vec(),
            transaction.message_data()
        );
    }

    #[cfg(test)]
    fn make_test_packets(
        transactions: Vec<Transaction>,
        vote_indexes: Vec<usize>,
    ) -> (PacketBatch, Vec<usize>) {
        let capacity = transactions.len();
        let mut packet_batch = PacketBatch::with_capacity(capacity);
        let mut packet_indexes = Vec::with_capacity(capacity);
        packet_batch.packets.resize(capacity, Packet::default());
        for (index, tx) in transactions.iter().enumerate() {
            Packet::populate_packet(&mut packet_batch.packets[index], None, tx).ok();
            packet_indexes.push(index);
        }
        for index in vote_indexes.iter() {
            packet_batch.packets[*index].meta.flags |= PacketFlags::SIMPLE_VOTE_TX;
        }
        (packet_batch, packet_indexes)
    }

    #[test]
    fn test_transactions_from_packets() {
        use sdk::feature_set::FeatureSet;
        let keypair = Keypair::new();
        let transfer_tx =
            system_transaction::transfer(&keypair, &keypair.pubkey(), 1, Hash::default());
        let vote_tx = vote_transaction::new_vote_transaction(
            vec![42],
            Hash::default(),
            Hash::default(),
            &keypair,
            &keypair,
            &keypair,
            None,
        );

        // packets with no votes
        {
            let vote_indexes = vec![];
            let (packet_batch, packet_indexes) =
                make_test_packets(vec![transfer_tx.clone(), transfer_tx.clone()], vote_indexes);

            let mut votes_only = false;
            let (txs, tx_packet_index) = BankingStage::transactions_from_packets(
                &packet_batch,
                &packet_indexes,
                &Arc::new(FeatureSet::default()),
                votes_only,
                |_| Err(TransactionError::UnsupportedVersion),
            );
            assert_eq!(2, txs.len());
            assert_eq!(vec![0, 1], tx_packet_index);

            votes_only = true;
            let (txs, tx_packet_index) = BankingStage::transactions_from_packets(
                &packet_batch,
                &packet_indexes,
                &Arc::new(FeatureSet::default()),
                votes_only,
                |_| Err(TransactionError::UnsupportedVersion),
            );
            assert_eq!(0, txs.len());
            assert_eq!(0, tx_packet_index.len());
        }

        // packets with some votes
        {
            let vote_indexes = vec![0, 2];
            let (packet_batch, packet_indexes) = make_test_packets(
                vec![vote_tx.clone(), transfer_tx, vote_tx.clone()],
                vote_indexes,
            );

            let mut votes_only = false;
            let (txs, tx_packet_index) = BankingStage::transactions_from_packets(
                &packet_batch,
                &packet_indexes,
                &Arc::new(FeatureSet::default()),
                votes_only,
                |_| Err(TransactionError::UnsupportedVersion),
            );
            assert_eq!(3, txs.len());
            assert_eq!(vec![0, 1, 2], tx_packet_index);

            votes_only = true;
            let (txs, tx_packet_index) = BankingStage::transactions_from_packets(
                &packet_batch,
                &packet_indexes,
                &Arc::new(FeatureSet::default()),
                votes_only,
                |_| Err(TransactionError::UnsupportedVersion),
            );
            assert_eq!(2, txs.len());
            assert_eq!(vec![0, 2], tx_packet_index);
        }

        // packets with all votes
        {
            let vote_indexes = vec![0, 1, 2];
            let (packet_batch, packet_indexes) = make_test_packets(
                vec![vote_tx.clone(), vote_tx.clone(), vote_tx],
                vote_indexes,
            );

            let mut votes_only = false;
            let (txs, tx_packet_index) = BankingStage::transactions_from_packets(
                &packet_batch,
                &packet_indexes,
                &Arc::new(FeatureSet::default()),
                votes_only,
                |_| Err(TransactionError::UnsupportedVersion),
            );
            assert_eq!(3, txs.len());
            assert_eq!(vec![0, 1, 2], tx_packet_index);

            votes_only = true;
            let (txs, tx_packet_index) = BankingStage::transactions_from_packets(
                &packet_batch,
                &packet_indexes,
                &Arc::new(FeatureSet::default()),
                votes_only,
                |_| Err(TransactionError::UnsupportedVersion),
            );
            assert_eq!(3, txs.len());
            assert_eq!(vec![0, 1, 2], tx_packet_index);
        }
    }

    #[test]
    fn test_accumulate_batched_transaction_costs() {
        let signature_cost = 1;
        let write_lock_cost = 2;
        let data_bytes_cost = 3;
        let builtins_execution_cost = 4;
        let bpf_execution_cost = 10;
        let num_txs = 4;

        let tx_costs: Vec<_> = (0..num_txs)
            .map(|_| TransactionCost {
                signature_cost,
                write_lock_cost,
                data_bytes_cost,
                builtins_execution_cost,
                bpf_execution_cost,
                ..TransactionCost::default()
            })
            .collect();
        let tx_results: Vec<_> = (0..num_txs)
            .map(|n| {
                if n % 2 == 0 {
                    Ok(())
                } else {
                    Err(TransactionError::WouldExceedMaxBlockCostLimit)
                }
            })
            .collect();
        // should only accumulate half of the costs that are OK
        let expected_signatures = signature_cost * (num_txs / 2);
        let expected_write_locks = write_lock_cost * (num_txs / 2);
        let expected_data_bytes = data_bytes_cost * (num_txs / 2);
        let expected_builtins_execution_costs = builtins_execution_cost * (num_txs / 2);
        let expected_bpf_execution_costs = bpf_execution_cost * (num_txs / 2);
        let batched_transaction_details =
            BankingStage::accumulate_batched_transaction_costs(tx_costs.iter(), tx_results.iter());
        assert_eq!(
            expected_signatures,
            batched_transaction_details.batched_signature_cost
        );
        assert_eq!(
            expected_write_locks,
            batched_transaction_details.batched_write_lock_cost
        );
        assert_eq!(
            expected_data_bytes,
            batched_transaction_details.batched_data_bytes_cost
        );
        assert_eq!(
            expected_builtins_execution_costs,
            batched_transaction_details.batched_builtins_execute_cost
        );
        assert_eq!(
            expected_bpf_execution_costs,
            batched_transaction_details.batched_bpf_execute_cost
        );
    }

    #[test]
    fn test_accumulate_execute_units_and_time() {
        let mut execute_timings = ExecuteTimings::default();
        let mut expected_units = 0;
        let mut expected_us = 0;

        for n in 0..10 {
            execute_timings.details.per_program_timings.insert(
                Pubkey::new_unique(),
                ProgramTiming {
                    accumulated_us: n * 100,
                    accumulated_units: n * 1000,
                    count: n as u32,
                    errored_txs_compute_consumed: vec![],
                    total_errored_units: 0,
                },
            );
            expected_us += n * 100;
            expected_units += n * 1000;
        }

        let (units, us) = BankingStage::accumulate_execute_units_and_time(&execute_timings);

        assert_eq!(expected_units, units);
        assert_eq!(expected_us, us);
    }
}
