use {
    crate::{
        client_error::ClientError,
    pubsub_client::{PubsubClient, PubsubClientError, PubsubClientSubscription},
    rpc_client::RpcClient,
        rpc_request::MAX_GET_SIGNATURE_STATUSES_QUERY_ITEMS,
        rpc_response::SlotUpdate,
        spinner,
    },
    bincode::serialize,
    log::*,
    sdk::{
        clock::Slot,
        commitment_config::CommitmentConfig,
        message::Message,
        pubkey::Pubkey,
        signature::SignerError,
        signers::Signers,
        transaction::{Transaction, TransactionError},
    },
    std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{SocketAddr, UdpSocket},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
        thread::{sleep, JoinHandle},
        time::{Duration, Instant},
    },
    thiserror::Error,
};

#[derive(Error, Debug)]
pub enum TpuSenderError {
    #[error("Pubsub error: {0:?}")]
    PubsubError(#[from] PubsubClientError),
    #[error("RPC error: {0:?}")]
    RpcError(#[from] ClientError),
    #[error("IO error: {0:?}")]
    IoError(#[from] std::io::Error),
    #[error("Signer error: {0:?}")]
    SignerError(#[from] SignerError),
    #[error("Custom error: {0}")]
    Custom(String),
}

type Result<T> = std::result::Result<T, TpuSenderError>;

/// Default number of slots used to build TPU socket fanout set
pub const DEFAULT_FANOUT_SLOTS: u64 = 12;

/// Maximum number of slots used to build TPU socket fanout set
pub const MAX_FANOUT_SLOTS: u64 = 100;

/// Config params for `TpuClient`
#[derive(Clone, Debug)]
pub struct TpuClientConfig {
    /// The range of upcoming slots to include when determining which
    /// leaders to send transactions to (min: 1, max: `MAX_FANOUT_SLOTS`)
    pub fanout_slots: u64,
}

impl Default for TpuClientConfig {
    fn default() -> Self {
        Self {
            fanout_slots: DEFAULT_FANOUT_SLOTS,
        }
    }
}

/// Client which sends transactions directly to the current leader's TPU port over UDP.
/// The client uses RPC to determine the current leader and fetch node contact info
pub struct TpuClient {
    send_socket: UdpSocket,
    fanout_slots: u64,
    leader_tpu_service: LeaderTpuService,
    exit: Arc<AtomicBool>,
    rpc_client: Arc<RpcClient>,
}

impl TpuClient {
    /// Serialize and send transaction to the current and upcoming leader TPUs according to fanout
    /// size
    pub fn send_transaction(&self, transaction: &Transaction) -> bool {
        let wire_transaction = serialize(transaction).expect("serialization should succeed");
        self.send_wire_transaction(&wire_transaction)
    }

    /// Send a wire transaction to the current and upcoming leader TPUs according to fanout size
    pub fn send_wire_transaction(&self, wire_transaction: &[u8]) -> bool {
        let mut sent = false;
        for tpu_address in self
            .leader_tpu_service
            .leader_tpu_sockets(self.fanout_slots)
        {
            if self
                .send_socket
                .send_to(wire_transaction, tpu_address)
                .is_ok()
            {
                sent = true;
            }
        }
        sent
    }

    /// Create a new client that disconnects when dropped
    pub fn new(
        rpc_client: Arc<RpcClient>,
        websocket_url: &str,
        config: TpuClientConfig,
    ) -> Result<Self> {
        let exit = Arc::new(AtomicBool::new(false));
        let leader_tpu_service =
            LeaderTpuService::new(rpc_client.clone(), websocket_url, exit.clone())?;

        Ok(Self {
            send_socket: UdpSocket::bind("0.0.0.0:0").unwrap(),
            fanout_slots: config.fanout_slots.clamp(1, MAX_FANOUT_SLOTS),
            leader_tpu_service,
            exit,
            rpc_client,
        })
    }

    pub fn send_and_confirm_messages_with_spinner<T: Signers>(
        &self,
        messages: &[Message],
        signers: &T,
    ) -> Result<Vec<Option<TransactionError>>> {
        let mut expired_blockhash_retries = 5;
        /* Send at ~100 TPS */
        const SEND_TRANSACTION_INTERVAL: Duration = Duration::from_millis(10);
        /* Retry batch send after 4 seconds */
        const TRANSACTION_RESEND_INTERVAL: Duration = Duration::from_secs(4);

        let progress_bar = spinner::new_progress_bar();
        progress_bar.set_message("Setting up...");

        let mut transactions = messages
            .iter()
            .enumerate()
            .map(|(i, message)| (i, Transaction::new_unsigned(message.clone())))
            .collect::<Vec<_>>();
        let num_transactions = transactions.len() as f64;
        let mut transaction_errors = vec![None; transactions.len()];
        let set_message = |confirmed_transactions,
                           block_height: Option<u64>,
                           last_valid_block_height: u64,
                           status: &str| {
            progress_bar.set_message(format!(
                "{:>5.1}% | {:<40}{}",
                confirmed_transactions as f64 * 100. / num_transactions,
                status,
                match block_height {
                    Some(block_height) => format!(
                        " [block height {}; re-sign in {} blocks]",
                        block_height,
                        last_valid_block_height.saturating_sub(block_height),
                    ),
                    None => String::new(),
                },
            ));
        };

        let mut confirmed_transactions = 0;
        let mut block_height = self.rpc_client.get_block_height()?;
        while expired_blockhash_retries > 0 {
            let (blockhash, last_valid_block_height) = self
                .rpc_client
                .get_latest_blockhash_with_commitment(self.rpc_client.commitment())?;

            let mut pending_transactions = HashMap::new();
            for (i, mut transaction) in transactions {
                transaction.try_sign(signers, blockhash)?;
                pending_transactions.insert(transaction.signatures[0], (i, transaction));
            }

            let mut last_resend = Instant::now() - TRANSACTION_RESEND_INTERVAL;
            while block_height <= last_valid_block_height {
                let num_transactions = pending_transactions.len();

                // Periodically re-send all pending transactions
                if Instant::now().duration_since(last_resend) > TRANSACTION_RESEND_INTERVAL {
                    for (index, (_i, transaction)) in pending_transactions.values().enumerate() {
                        if !self.send_transaction(transaction) {
                            let _result = self.rpc_client.send_transaction(transaction).ok();
                        }
                        set_message(
                            confirmed_transactions,
                            None, //block_height,
                            last_valid_block_height,
                            &format!("Sending {}/{} transactions", index + 1, num_transactions,),
                        );
                        sleep(SEND_TRANSACTION_INTERVAL);
                    }
                    last_resend = Instant::now();
                }

                // Wait for the next block before checking for transaction statuses
                let mut block_height_refreshes = 10;
                set_message(
                    confirmed_transactions,
                    Some(block_height),
                    last_valid_block_height,
                    &format!("Waiting for next block, {} pending...", num_transactions),
                );
                let mut new_block_height = block_height;
                while block_height == new_block_height && block_height_refreshes > 0 {
                    sleep(Duration::from_millis(500));
                    new_block_height = self.rpc_client.get_block_height()?;
                    block_height_refreshes -= 1;
                }
                block_height = new_block_height;

                // Collect statuses for the transactions, drop those that are confirmed
                let pending_signatures = pending_transactions.keys().cloned().collect::<Vec<_>>();
                for pending_signatures_chunk in
                    pending_signatures.chunks(MAX_GET_SIGNATURE_STATUSES_QUERY_ITEMS)
                {
                    if let Ok(result) = self
                        .rpc_client
                        .get_signature_statuses(pending_signatures_chunk)
                    {
                        let statuses = result.value;
                        for (signature, status) in
                            pending_signatures_chunk.iter().zip(statuses.into_iter())
                        {
                            if let Some(status) = status {
                                if status.satisfies_commitment(self.rpc_client.commitment()) {
                                    if let Some((i, _)) = pending_transactions.remove(signature) {
                                        confirmed_transactions += 1;
                                        if status.err.is_some() {
                                            progress_bar.println(format!(
                                                "Failed transaction: {:?}",
                                                status
                                            ));
                                        }
                                        transaction_errors[i] = status.err;
                                    }
                                }
                            }
                        }
                    }
                    set_message(
                        confirmed_transactions,
                        Some(block_height),
                        last_valid_block_height,
                        "Checking transaction status...",
                    );
                }

                if pending_transactions.is_empty() {
                    return Ok(transaction_errors);
                }
            }

            transactions = pending_transactions.into_values().collect();
            progress_bar.println(format!(
                "Blockhash expired. {} retries remaining",
                expired_blockhash_retries
            ));
            expired_blockhash_retries -= 1;
        }
        Err(TpuSenderError::Custom("Max retries exceeded".into()))
    }
}

impl Drop for TpuClient {
    fn drop(&mut self) {
        self.exit.store(true, Ordering::Relaxed);
        self.leader_tpu_service.join();
    }
}

struct LeaderTpuCache {
    first_slot: Slot,
    leaders: Vec<Pubkey>,
    leader_tpu_map: HashMap<Pubkey, SocketAddr>,
    slots_in_epoch: Slot,
    last_epoch_info_slot: Slot,
}

impl LeaderTpuCache {
    fn new(rpc_client: &RpcClient, first_slot: Slot) -> Result<Self> {
        let slots_in_epoch = rpc_client.get_epoch_info()?.slots_in_epoch;
        let leaders = Self::fetch_slot_leaders(rpc_client, first_slot, slots_in_epoch)?;
        let leader_tpu_map = Self::fetch_cluster_tpu_sockets(rpc_client)?;
        Ok(Self {
            first_slot,
            leaders,
            leader_tpu_map,
            slots_in_epoch,
            last_epoch_info_slot: first_slot,
        })
    }

    // Last slot that has a cached leader pubkey
    fn last_slot(&self) -> Slot {
        self.first_slot + self.leaders.len().saturating_sub(1) as u64
    }

    // Get the TPU sockets for the current leader and upcoming leaders according to fanout size
    fn get_leader_sockets(&self, current_slot: Slot, fanout_slots: u64) -> Vec<SocketAddr> {
        let mut leader_set = HashSet::new();
        let mut leader_sockets = Vec::new();
        for leader_slot in current_slot..current_slot + fanout_slots {
            if let Some(leader) = self.get_slot_leader(leader_slot) {
                if let Some(tpu_socket) = self.leader_tpu_map.get(leader) {
                    if leader_set.insert(*leader) {
                        leader_sockets.push(*tpu_socket);
                    }
                } else {
                    // The leader is probably delinquent
                    trace!("TPU not available for leader {}", leader);
                }
            } else {
                // Overran the local leader schedule cache
                warn!(
                    "Leader not known for slot {}; cache holds slots [{},{}]",
                    leader_slot,
                    self.first_slot,
                    self.last_slot()
                );
            }
        }
        leader_sockets
    }

    fn get_slot_leader(&self, slot: Slot) -> Option<&Pubkey> {
        if slot >= self.first_slot {
            let index = slot - self.first_slot;
            self.leaders.get(index as usize)
        } else {
            None
        }
    }

    fn fetch_cluster_tpu_sockets(rpc_client: &RpcClient) -> Result<HashMap<Pubkey, SocketAddr>> {
        let cluster_contact_info = rpc_client.get_cluster_nodes()?;
        Ok(cluster_contact_info
            .into_iter()
            .filter_map(|contact_info| {
                Some((
                    Pubkey::from_str(&contact_info.pubkey).ok()?,
                    contact_info.tpu?,
                ))
            })
            .collect())
    }

    fn fetch_slot_leaders(
        rpc_client: &RpcClient,
        start_slot: Slot,
        slots_in_epoch: Slot,
    ) -> Result<Vec<Pubkey>> {
        let fanout = (2 * MAX_FANOUT_SLOTS).min(slots_in_epoch);
        Ok(rpc_client.get_slot_leaders(start_slot, fanout)?)
    }
}

// 48 chosen because it's unlikely that 12 leaders in a row will miss their slots
const MAX_SLOT_SKIP_DISTANCE: u64 = 48;

#[derive(Clone, Debug)]
struct RecentLeaderSlots(Arc<RwLock<VecDeque<Slot>>>);
impl RecentLeaderSlots {
    fn new(current_slot: Slot) -> Self {
        let mut recent_slots = VecDeque::new();
        recent_slots.push_back(current_slot);
        Self(Arc::new(RwLock::new(recent_slots)))
    }

    fn record_slot(&self, current_slot: Slot) {
        let mut recent_slots = self.0.write().unwrap();
        recent_slots.push_back(current_slot);
        // 12 recent slots should be large enough to avoid a misbehaving
        // validator from affecting the median recent slot
        while recent_slots.len() > 12 {
            recent_slots.pop_front();
        }
    }

    // Estimate the current slot from recent slot notifications.
    fn estimated_current_slot(&self) -> Slot {
        let mut recent_slots: Vec<Slot> = self.0.read().unwrap().iter().cloned().collect();
        assert!(!recent_slots.is_empty());
        recent_slots.sort_unstable();

        // Validators can broadcast invalid blocks that are far in the future
        // so check if the current slot is in line with the recent progression.
        let max_index = recent_slots.len() - 1;
        let median_index = max_index / 2;
        let median_recent_slot = recent_slots[median_index];
        let expected_current_slot = median_recent_slot + (max_index - median_index) as u64;
        let max_reasonable_current_slot = expected_current_slot + MAX_SLOT_SKIP_DISTANCE;

        // Return the highest slot that doesn't exceed what we believe is a
        // reasonable slot.
        recent_slots
            .into_iter()
            .rev()
            .find(|slot| *slot <= max_reasonable_current_slot)
            .unwrap()
    }
}

#[cfg(test)]
impl From<Vec<Slot>> for RecentLeaderSlots {
    fn from(recent_slots: Vec<Slot>) -> Self {
        assert!(!recent_slots.is_empty());
        Self(Arc::new(RwLock::new(recent_slots.into_iter().collect())))
    }
}

/// Service that tracks upcoming leaders and maintains an up-to-date mapping
/// of leader id to TPU socket address.
struct LeaderTpuService {
    recent_slots: RecentLeaderSlots,
    leader_tpu_cache: Arc<RwLock<LeaderTpuCache>>,
    subscription: Option<PubsubClientSubscription<SlotUpdate>>,
    t_leader_tpu_service: Option<JoinHandle<()>>,
}

impl LeaderTpuService {
    fn new(rpc_client: Arc<RpcClient>, websocket_url: &str, exit: Arc<AtomicBool>) -> Result<Self> {
        let start_slot = rpc_client.get_slot_with_commitment(CommitmentConfig::processed())?;

        let recent_slots = RecentLeaderSlots::new(start_slot);
        let leader_tpu_cache = Arc::new(RwLock::new(LeaderTpuCache::new(&rpc_client, start_slot)?));

        let subscription = if !websocket_url.is_empty() {
            let recent_slots = recent_slots.clone();
            Some(PubsubClient::slot_updates_subscribe(
                websocket_url,
                move |update| {
                    let current_slot = match update {
                        // This update indicates that a full slot was received by the connected
                        // node so we can stop sending transactions to the leader for that slot
                        SlotUpdate::Completed { slot, .. } => slot.saturating_add(1),
                        // This update indicates that we have just received the first shred from
                        // the leader for this slot and they are probably still accepting transactions.
                        SlotUpdate::FirstShredReceived { slot, .. } => slot,
                        _ => return,
                    };

                    recent_slots.record_slot(current_slot);
                },
            )?)
        } else {
            None
        };

        let t_leader_tpu_service = Some({
            let recent_slots = recent_slots.clone();
            let leader_tpu_cache = leader_tpu_cache.clone();
            std::thread::Builder::new()
                .name("ldr-tpu-srv".to_string())
                .spawn(move || Self::run(rpc_client, recent_slots, leader_tpu_cache, exit))
                .unwrap()
        });

        Ok(LeaderTpuService {
            recent_slots,
            leader_tpu_cache,
            subscription,
            t_leader_tpu_service,
        })
    }

    fn join(&mut self) {
        if let Some(mut subscription) = self.subscription.take() {
            let _ = subscription.send_unsubscribe();
            let _ = subscription.shutdown();
        }
        if let Some(t_handle) = self.t_leader_tpu_service.take() {
            t_handle.join().unwrap();
        }
    }

    fn leader_tpu_sockets(&self, fanout_slots: u64) -> Vec<SocketAddr> {
        let current_slot = self.recent_slots.estimated_current_slot();
        self.leader_tpu_cache
            .read()
            .unwrap()
            .get_leader_sockets(current_slot, fanout_slots)
    }

    fn run(
        rpc_client: Arc<RpcClient>,
        recent_slots: RecentLeaderSlots,
        leader_tpu_cache: Arc<RwLock<LeaderTpuCache>>,
        exit: Arc<AtomicBool>,
    ) {
        let mut last_cluster_refresh = Instant::now();
        let mut sleep_ms = 1000;
        loop {
            if exit.load(Ordering::Relaxed) {
                break;
            }

            // Sleep a few slots before checking if leader cache needs to be refreshed again
            std::thread::sleep(Duration::from_millis(sleep_ms));
            sleep_ms = 1000;

            // Refresh cluster TPU ports every 5min in case validators restart with new port configuration
            // or new validators come online
            if last_cluster_refresh.elapsed() > Duration::from_secs(5 * 60) {
                match LeaderTpuCache::fetch_cluster_tpu_sockets(&rpc_client) {
                    Ok(leader_tpu_map) => {
                        leader_tpu_cache.write().unwrap().leader_tpu_map = leader_tpu_map;
                        last_cluster_refresh = Instant::now();
                    }
                    Err(err) => {
                        warn!("Failed to fetch cluster tpu sockets: {}", err);
                        sleep_ms = 100;
                    }
                }
            }

            let estimated_current_slot = recent_slots.estimated_current_slot();
            let (last_slot, last_epoch_info_slot, mut slots_in_epoch) = {
                let leader_tpu_cache = leader_tpu_cache.read().unwrap();
                (
                    leader_tpu_cache.last_slot(),
                    leader_tpu_cache.last_epoch_info_slot,
                    leader_tpu_cache.slots_in_epoch,
                )
            };
            if estimated_current_slot >= last_epoch_info_slot.saturating_sub(slots_in_epoch) {
                if let Ok(epoch_info) = rpc_client.get_epoch_info() {
                    slots_in_epoch = epoch_info.slots_in_epoch;
                    let mut leader_tpu_cache = leader_tpu_cache.write().unwrap();
                    leader_tpu_cache.slots_in_epoch = slots_in_epoch;
                    leader_tpu_cache.last_epoch_info_slot = estimated_current_slot;
                }
            }
            if estimated_current_slot >= last_slot.saturating_sub(MAX_FANOUT_SLOTS) {
                match LeaderTpuCache::fetch_slot_leaders(
                    &rpc_client,
                    estimated_current_slot,
                    slots_in_epoch,
                ) {
                    Ok(slot_leaders) => {
                        let mut leader_tpu_cache = leader_tpu_cache.write().unwrap();
                        leader_tpu_cache.first_slot = estimated_current_slot;
                        leader_tpu_cache.leaders = slot_leaders;
                    }
                    Err(err) => {
                        warn!(
                            "Failed to fetch slot leaders (current estimated slot: {}): {}",
                            estimated_current_slot, err
                        );
                        sleep_ms = 100;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_slot(recent_slots: RecentLeaderSlots, expected_slot: Slot) {
        assert_eq!(recent_slots.estimated_current_slot(), expected_slot);
    }

    #[test]
    fn test_recent_leader_slots() {
        assert_slot(RecentLeaderSlots::new(0), 0);

        let mut recent_slots: Vec<Slot> = (1..=12).collect();
        assert_slot(RecentLeaderSlots::from(recent_slots.clone()), 12);

        recent_slots.reverse();
        assert_slot(RecentLeaderSlots::from(recent_slots), 12);

        assert_slot(
            RecentLeaderSlots::from(vec![0, 1 + MAX_SLOT_SKIP_DISTANCE]),
            1 + MAX_SLOT_SKIP_DISTANCE,
        );
        assert_slot(
            RecentLeaderSlots::from(vec![0, 2 + MAX_SLOT_SKIP_DISTANCE]),
            0,
        );

        assert_slot(RecentLeaderSlots::from(vec![1]), 1);
        assert_slot(RecentLeaderSlots::from(vec![1, 100]), 1);
        assert_slot(RecentLeaderSlots::from(vec![1, 2, 100]), 2);
        assert_slot(RecentLeaderSlots::from(vec![1, 2, 3, 100]), 3);
        assert_slot(RecentLeaderSlots::from(vec![1, 2, 3, 99, 100]), 3);
    }
}
