//! The `cluster_info` module defines a data structure that is shared by all the nodes in the network over
//! a gossip control plane.  The goal is to share small bits of off-chain information and detect and
//! repair partitions.
//!
//! This CRDT only supports a very limited set of types.  A map of Pubkey -> Versioned Struct.
//! The last version is always picked during an update.
//!
//! The network is arranged in layers:
//!
//! * layer 0 - Leader.
//! * layer 1 - As many nodes as we can fit
//! * layer 2 - Everyone else, if layer 1 is `2^10`, layer 2 should be able to fit `2^20` number of nodes.
//!
//! Bank needs to provide an interface for us to query the stake weight
use {
    crate::{
        cluster_info_metrics::{
            submit_gossip_stats, Counter, GossipStats, ScopedTimer, TimedGuard,
        },
        contact_info::ContactInfo,
        crds::{Crds, Cursor, GossipRoute},
        crds_gossip::CrdsGossip,
        crds_gossip_error::CrdsGossipError,
        crds_gossip_pull::{CrdsFilter, ProcessPullStats, CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS},
        crds_value::{
            self, CrdsData, CrdsValue, CrdsValueLabel, EpochSlotsIndex, IncrementalSnapshotHashes,
            LowestSlot, NodeInstance, SnapshotHashes, Version, Vote, MAX_WALLCLOCK,
        },
        epoch_slots::EpochSlots,
        gossip_error::GossipError,
        ping_pong::{self, PingCache, Pong},
        socketaddr, socketaddr_any,
        weighted_shuffle::WeightedShuffle,
    },
    bincode::{serialize, serialized_size},
    itertools::Itertools,
    rand::{seq::SliceRandom, thread_rng, CryptoRng, Rng},
    rayon::{prelude::*, ThreadPool, ThreadPoolBuilder},
    serde::ser::Serialize,
    ledger::shred::Shred,
    measure::measure::Measure,
    metrics::{inc_new_counter_debug, inc_new_counter_error},
    sino_net_utils::{
        bind_common, bind_common_in_range, bind_in_range, bind_two_consecutive_in_range,
        find_available_port_in_range, multi_bind_in_range, PortRange,
    },
    perf::{
        data_budget::DataBudget,
        packet::{
            to_packet_batch_with_destination, Packet, PacketBatch, PacketBatchRecycler,
            PACKET_DATA_SIZE,
        },
    },
    rayon_threadlimit::get_thread_count,
    runtime::{bank_forks::BankForks, vote_parser},
    sdk::{
        clock::{Slot, DEFAULT_MS_PER_SLOT, DEFAULT_SLOTS_PER_EPOCH},
        feature_set::FeatureSet,
        hash::Hash,
        pubkey::Pubkey,
        quic::QUIC_PORT_OFFSET,
        sanitize::{Sanitize, SanitizeError},
        signature::{Keypair, Signable, Signature, Signer},
        timing::timestamp,
        transaction::Transaction,
    },
    sino_streamer::{
        packet,
        sendmmsg::{multi_target_send, SendPktsError},
        socket::SocketAddrSpace,
        streamer::{PacketBatchReceiver, PacketBatchSender},
    },
    vote_program::vote_state::MAX_LOCKOUT_HISTORY,
    std::{
        borrow::Cow,
        collections::{hash_map::Entry, HashMap, HashSet, VecDeque},
        fmt::Debug,
        fs::{self, File},
        io::BufReader,
        iter::repeat,
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
        ops::{Deref, Div},
        path::{Path, PathBuf},
        result::Result,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc::{Receiver, RecvTimeoutError, Sender},
            Arc, Mutex, RwLock, RwLockReadGuard,
        },
        thread::{sleep, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

pub const VALIDATOR_PORT_RANGE: PortRange = (8000, 10_000);
pub const MINIMUM_VALIDATOR_PORT_RANGE_WIDTH: u16 = 12; // VALIDATOR_PORT_RANGE must be at least this wide

/// The Data plane fanout size, also used as the neighborhood size
pub const DATA_PLANE_FANOUT: usize = 200;
/// milliseconds we sleep for between gossip requests
pub const GOSSIP_SLEEP_MILLIS: u64 = 100;
/// The maximum size of a bloom filter
pub const MAX_BLOOM_SIZE: usize = MAX_CRDS_OBJECT_SIZE;
pub const MAX_CRDS_OBJECT_SIZE: usize = 928;
/// A hard limit on incoming gossip messages
/// Chosen to be able to handle 1Gbps of pure gossip traffic
/// 128MB/PACKET_DATA_SIZE
const MAX_GOSSIP_TRAFFIC: usize = 128_000_000 / PACKET_DATA_SIZE;
/// Max size of serialized crds-values in a Protocol::PushMessage packet. This
/// is equal to PACKET_DATA_SIZE minus serialized size of an empty push
/// message: Protocol::PushMessage(Pubkey::default(), Vec::default())
const PUSH_MESSAGE_MAX_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 44;
const DUPLICATE_SHRED_MAX_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 115;
/// Maximum number of hashes in SnapshotHashes/AccountsHashes a node publishes
/// such that the serialized size of the push/pull message stays below
/// PACKET_DATA_SIZE.
// TODO: Update this to 26 once payload sizes are upgraded across fleet.
pub const MAX_SNAPSHOT_HASHES: usize = 16;
/// Maximum number of hashes in IncrementalSnapshotHashes a node publishes
/// such that the serialized size of the push/pull message stays below
/// PACKET_DATA_SIZE.
pub const MAX_INCREMENTAL_SNAPSHOT_HASHES: usize = 25;
/// Maximum number of origin nodes that a PruneData may contain, such that the
/// serialized size of the PruneMessage stays below PACKET_DATA_SIZE.
const MAX_PRUNE_DATA_NODES: usize = 32;
/// Number of bytes in the randomly generated token sent with ping messages.
const GOSSIP_PING_TOKEN_SIZE: usize = 32;
const GOSSIP_PING_CACHE_CAPACITY: usize = 65536;
const GOSSIP_PING_CACHE_TTL: Duration = Duration::from_secs(1280);
pub const DEFAULT_CONTACT_DEBUG_INTERVAL_MILLIS: u64 = 10_000;
pub const DEFAULT_CONTACT_SAVE_INTERVAL_MILLIS: u64 = 60_000;
/// Minimum serialized size of a Protocol::PullResponse packet.
const PULL_RESPONSE_MIN_SERIALIZED_SIZE: usize = 161;
// Limit number of unique pubkeys in the crds table.
pub(crate) const CRDS_UNIQUE_PUBKEY_CAPACITY: usize = 8192;
/// Minimum stake that a node should have so that its CRDS values are
/// propagated through gossip (few types are exempted).
const MIN_STAKE_FOR_GOSSIP: u64 = sdk::native_token::WENS_PER_SOR;
/// Minimum number of staked nodes for enforcing stakes in gossip.
const MIN_NUM_STAKED_NODES: usize = 500;

#[derive(Debug, PartialEq, Eq)]
pub enum ClusterInfoError {
    NoPeers,
    NoLeader,
    BadContactInfo,
    BadGossipAddress,
    TooManyIncrementalSnapshotHashes,
}

pub struct ClusterInfo {
    /// The network
    pub gossip: CrdsGossip,
    /// set the keypair that will be used to sign crds values generated. It is unset only in tests.
    keypair: RwLock<Arc<Keypair>>,
    /// Network entrypoints
    entrypoints: RwLock<Vec<ContactInfo>>,
    outbound_budget: DataBudget,
    my_contact_info: RwLock<ContactInfo>,
    ping_cache: Mutex<PingCache>,
    stats: GossipStats,
    socket: UdpSocket,
    local_message_pending_push_queue: Mutex<Vec<CrdsValue>>,
    contact_debug_interval: u64, // milliseconds, 0 = disabled
    contact_save_interval: u64,  // milliseconds, 0 = disabled
    instance: RwLock<NodeInstance>,
    contact_info_path: PathBuf,
    socket_addr_space: SocketAddrSpace,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, AbiExample)]
pub(crate) struct PruneData {
    /// Pubkey of the node that sent this prune data
    pubkey: Pubkey,
    /// Pubkeys of nodes that should be pruned
    prunes: Vec<Pubkey>,
    /// Signature of this Prune Message
    signature: Signature,
    /// The Pubkey of the intended node/destination for this message
    destination: Pubkey,
    /// Wallclock of the node that generated this message
    wallclock: u64,
}

impl PruneData {
    ///// New random PruneData for tests and benchmarks.
    // #[cfg(test)]
    // fn new_rand<R: Rng>(rng: &mut R, self_keypair: &Keypair, num_nodes: Option<usize>) -> Self {
    //     let wallclock = crds_value::new_rand_timestamp(rng);
    //     let num_nodes = num_nodes.unwrap_or_else(|| rng.gen_range(0, MAX_PRUNE_DATA_NODES + 1));
    //     let prunes = std::iter::repeat_with(Pubkey::new_unique)
    //         .take(num_nodes)
    //         .collect();
    //     let mut prune_data = PruneData {
    //         pubkey: self_keypair.pubkey(),
    //         prunes,
    //         signature: Signature::default(),
    //         destination: Pubkey::new_unique(),
    //         wallclock,
    //     };
    //     prune_data.sign(self_keypair);
    //     prune_data
    // }
}

impl Sanitize for PruneData {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        if self.wallclock >= MAX_WALLCLOCK {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        Ok(())
    }
}

impl Signable for PruneData {
    fn pubkey(&self) -> Pubkey {
        self.pubkey
    }

    fn signable_data(&self) -> Cow<[u8]> {
        #[derive(Serialize)]
        struct SignData {
            pubkey: Pubkey,
            prunes: Vec<Pubkey>,
            destination: Pubkey,
            wallclock: u64,
        }
        let data = SignData {
            pubkey: self.pubkey,
            prunes: self.prunes.clone(),
            destination: self.destination,
            wallclock: self.wallclock,
        };
        Cow::Owned(serialize(&data).expect("serialize PruneData"))
    }

    fn get_signature(&self) -> Signature {
        self.signature
    }

    fn set_signature(&mut self, signature: Signature) {
        self.signature = signature
    }
}

struct PullData {
    from_addr: SocketAddr,
    caller: CrdsValue,
    filter: CrdsFilter,
}

// pub fn make_accounts_hashes_message(
//     keypair: &Keypair,
//     accounts_hashes: Vec<(Slot, Hash)>,
// ) -> Option<CrdsValue> {
//     let message = CrdsData::AccountsHashes(SnapshotHashes::new(keypair.pubkey(), accounts_hashes));
//     Some(CrdsValue::new_signed(message, keypair))
// }

pub(crate) type Ping = ping_pong::Ping<[u8; GOSSIP_PING_TOKEN_SIZE]>;

// TODO These messages should go through the gpu pipeline for spam filtering
#[frozen_abi(digest = "C1nR7B7CgMyUYo6h3z2KXcS38JSwF6y8jmZ6Y9Cz7XEd")]
#[derive(Serialize, Deserialize, Debug, AbiEnumVisitor, AbiExample)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Protocol {
    /// Gossip protocol messages
    PullRequest(CrdsFilter, CrdsValue),
    PullResponse(Pubkey, Vec<CrdsValue>),
    PushMessage(Pubkey, Vec<CrdsValue>),
    // TODO: Remove the redundant outer pubkey here,
    // and use the inner PruneData.pubkey instead.
    PruneMessage(Pubkey, PruneData),
    PingMessage(Ping),
    PongMessage(Pong),
}

impl Protocol {
    fn par_verify(self) -> Option<Self> {
        match self {
            Protocol::PullRequest(_, ref caller) => {
                if caller.verify() {
                    Some(self)
                } else {
                    inc_new_counter_info!("cluster_info-gossip_pull_request_verify_fail", 1);
                    None
                }
            }
            Protocol::PullResponse(from, data) => {
                let size = data.len();
                let data: Vec<_> = data.into_par_iter().filter(Signable::verify).collect();
                if size != data.len() {
                    inc_new_counter_info!(
                        "cluster_info-gossip_pull_response_verify_fail",
                        size - data.len()
                    );
                }
                if data.is_empty() {
                    None
                } else {
                    Some(Protocol::PullResponse(from, data))
                }
            }
            Protocol::PushMessage(from, data) => {
                let size = data.len();
                let data: Vec<_> = data.into_par_iter().filter(Signable::verify).collect();
                if size != data.len() {
                    inc_new_counter_info!(
                        "cluster_info-gossip_push_msg_verify_fail",
                        size - data.len()
                    );
                }
                if data.is_empty() {
                    None
                } else {
                    Some(Protocol::PushMessage(from, data))
                }
            }
            Protocol::PruneMessage(_, ref data) => {
                if data.verify() {
                    Some(self)
                } else {
                    inc_new_counter_debug!("cluster_info-gossip_prune_msg_verify_fail", 1);
                    None
                }
            }
            Protocol::PingMessage(ref ping) => {
                if ping.verify() {
                    Some(self)
                } else {
                    inc_new_counter_info!("cluster_info-gossip_ping_msg_verify_fail", 1);
                    None
                }
            }
            Protocol::PongMessage(ref pong) => {
                if pong.verify() {
                    Some(self)
                } else {
                    inc_new_counter_info!("cluster_info-gossip_pong_msg_verify_fail", 1);
                    None
                }
            }
        }
    }
}

impl Sanitize for Protocol {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        match self {
            Protocol::PullRequest(filter, val) => {
                filter.sanitize()?;
                val.sanitize()
            }
            Protocol::PullResponse(_, val) => val.sanitize(),
            Protocol::PushMessage(_, val) => val.sanitize(),
            Protocol::PruneMessage(from, val) => {
                if *from != val.pubkey {
                    Err(SanitizeError::InvalidValue)
                } else {
                    val.sanitize()
                }
            }
            Protocol::PingMessage(ping) => ping.sanitize(),
            Protocol::PongMessage(pong) => pong.sanitize(),
        }
    }
}

// Retains only CRDS values associated with nodes with enough stake.
// (some crds types are exempted)
fn retain_staked(values: &mut Vec<CrdsValue>, stakes: &HashMap<Pubkey, u64>) {
    values.retain(|value| {
        match value.data {
            CrdsData::ContactInfo(_) => true,
            // May Impact new validators starting up without any stake yet.
            CrdsData::Vote(_, _) => true,
            // Unstaked nodes can still help repair.
            CrdsData::EpochSlots(_, _) => true,
            // Unstaked nodes can still serve snapshots.
            CrdsData::SnapshotHashes(_) | CrdsData::IncrementalSnapshotHashes(_) => true,
            // Otherwise unstaked voting nodes will show up with no version in
            // the various dashboards.
            CrdsData::Version(_) => true,
            CrdsData::NodeInstance(_) => true,
            // getHealth fails if account hashes are not propagated.
            CrdsData::AccountsHashes(_) => true,
            CrdsData::LowestSlot(_, _)
            | CrdsData::LegacyVersion(_)
            | CrdsData::DuplicateShred(_, _) => {
                let stake = stakes.get(&value.pubkey()).copied();
                stake.unwrap_or_default() >= MIN_STAKE_FOR_GOSSIP
            }
        }
    })
}

impl ClusterInfo {
    pub fn new(
        contact_info: ContactInfo,
        keypair: Arc<Keypair>,
        socket_addr_space: SocketAddrSpace,
    ) -> Self {
        let id = contact_info.id;
        let me = Self {
            gossip: CrdsGossip::default(),
            keypair: RwLock::new(keypair),
            entrypoints: RwLock::default(),
            outbound_budget: DataBudget::default(),
            my_contact_info: RwLock::new(contact_info),
            ping_cache: Mutex::new(PingCache::new(
                GOSSIP_PING_CACHE_TTL,
                GOSSIP_PING_CACHE_CAPACITY,
            )),
            stats: GossipStats::default(),
            socket: UdpSocket::bind("0.0.0.0:0").unwrap(),
            local_message_pending_push_queue: Mutex::default(),
            contact_debug_interval: DEFAULT_CONTACT_DEBUG_INTERVAL_MILLIS,
            instance: RwLock::new(NodeInstance::new(&mut thread_rng(), id, timestamp())),
            contact_info_path: PathBuf::default(),
            contact_save_interval: 0, // disabled
            socket_addr_space,
        };
        me.insert_self();
        me.push_self(&HashMap::new(), None);
        me
    }

    // Should only be used by tests and simulations
    // pub fn clone_with_id(&self, new_id: &Pubkey) -> Self {     //remove
    //     let mut my_contact_info = self.my_contact_info.read().unwrap().clone();
    //     my_contact_info.id = *new_id;
    //     ClusterInfo {
    //         gossip: self.gossip.mock_clone(),
    //         keypair: RwLock::new(self.keypair.read().unwrap().clone()),
    //         entrypoints: RwLock::new(self.entrypoints.read().unwrap().clone()),
    //         outbound_budget: self.outbound_budget.clone_non_atomic(),
    //         my_contact_info: RwLock::new(my_contact_info),
    //         ping_cache: Mutex::new(self.ping_cache.lock().unwrap().mock_clone()),
    //         stats: GossipStats::default(),
    //         socket: UdpSocket::bind("0.0.0.0:0").unwrap(),
    //         local_message_pending_push_queue: Mutex::new(
    //             self.local_message_pending_push_queue
    //                 .lock()
    //                 .unwrap()
    //                 .clone(),
    //         ),
    //         contact_debug_interval: self.contact_debug_interval,
    //         instance: RwLock::new(NodeInstance::new(&mut thread_rng(), *new_id, timestamp())),
    //         contact_info_path: PathBuf::default(),
    //         contact_save_interval: 0, // disabled
    //         ..*self
    //     }
    // }

    pub fn set_contact_debug_interval(&mut self, new: u64) {
        self.contact_debug_interval = new;
    }

    pub fn socket_addr_space(&self) -> &SocketAddrSpace {
        &self.socket_addr_space
    }

    fn push_self(
        &self,
        stakes: &HashMap<Pubkey, u64>,
        gossip_validators: Option<&HashSet<Pubkey>>,
    ) {
        let now = timestamp();
        self.my_contact_info.write().unwrap().wallclock = now;
        let entries: Vec<_> = vec![
            CrdsData::ContactInfo(self.my_contact_info()),
            CrdsData::NodeInstance(self.instance.read().unwrap().with_wallclock(now)),
        ]
        .into_iter()
        .map(|v| CrdsValue::new_signed(v, &self.keypair()))
        .collect();
        self.local_message_pending_push_queue
            .lock()
            .unwrap()
            .extend(entries);
        let ContactInfo {
            id: self_pubkey,
            shred_version,
            ..
        } = *self.my_contact_info.read().unwrap();
        self.gossip.refresh_push_active_set(
            &self_pubkey,
            shred_version,
            stakes,
            gossip_validators,
            &self.socket_addr_space,
        );
    }

    // TODO kill insert_info, only used by tests
    // pub fn insert_info(&self, contact_info: ContactInfo) {    //remove
    //     let value = CrdsValue::new_signed(CrdsData::ContactInfo(contact_info), &self.keypair());
    //     let mut gossip_crds = self.gossip.crds.write().unwrap();
    //     let _ = gossip_crds.insert(value, timestamp(), GossipRoute::LocalMessage);
    // }

    pub fn set_entrypoint(&self, entrypoint: ContactInfo) {
        self.set_entrypoints(vec![entrypoint]);
    }

    pub fn set_entrypoints(&self, entrypoints: Vec<ContactInfo>) {
        *self.entrypoints.write().unwrap() = entrypoints;
    }

    pub fn save_contact_info(&self) {
        let nodes = {
            let entrypoint_gossip_addrs = self
                .entrypoints
                .read()
                .unwrap()
                .iter()
                .map(|contact_info| contact_info.gossip)
                .collect::<HashSet<_>>();
            let self_pubkey = self.id();
            let gossip_crds = self.gossip.crds.read().unwrap();
            gossip_crds
                .get_nodes()
                .filter_map(|v| {
                    // Don't save:
                    // 1. Our ContactInfo. No point
                    // 2. Entrypoint ContactInfo. This will avoid adopting the incorrect shred
                    //    version on restart if the entrypoint shred version changes.  Also
                    //    there's not much point in saving entrypoint ContactInfo since by
                    //    definition that information is already available
                    let contact_info = v.value.contact_info().unwrap();
                    if contact_info.id != self_pubkey
                        && !entrypoint_gossip_addrs.contains(&contact_info.gossip)
                    {
                        return Some(v.value.clone());
                    }
                    None
                })
                .collect::<Vec<_>>()
        };

        if nodes.is_empty() {
            return;
        }

        let filename = self.contact_info_path.join("contact-info.bin");
        let tmp_filename = &filename.with_extension("tmp");

        match File::create(tmp_filename) {
            Ok(mut file) => {
                if let Err(err) = bincode::serialize_into(&mut file, &nodes) {
                    warn!(
                        "Failed to serialize contact info info {}: {}",
                        tmp_filename.display(),
                        err
                    );
                    return;
                }
            }
            Err(err) => {
                warn!("Failed to create {}: {}", tmp_filename.display(), err);
                return;
            }
        }

        match fs::rename(tmp_filename, &filename) {
            Ok(()) => {
                info!(
                    "Saved contact info for {} nodes into {}",
                    nodes.len(),
                    filename.display()
                );
            }
            Err(err) => {
                warn!(
                    "Failed to rename {} to {}: {}",
                    tmp_filename.display(),
                    filename.display(),
                    err
                );
            }
        }
    }

    pub fn restore_contact_info(&mut self, contact_info_path: &Path, contact_save_interval: u64) {
        self.contact_info_path = contact_info_path.into();
        self.contact_save_interval = contact_save_interval;

        let filename = contact_info_path.join("contact-info.bin");
        if !filename.exists() {
            return;
        }

        let nodes: Vec<CrdsValue> = match File::open(&filename) {
            Ok(file) => {
                bincode::deserialize_from(&mut BufReader::new(file)).unwrap_or_else(|err| {
                    warn!("Failed to deserialize {}: {}", filename.display(), err);
                    vec![]
                })
            }
            Err(err) => {
                warn!("Failed to open {}: {}", filename.display(), err);
                vec![]
            }
        };

        info!(
            "Loaded contact info for {} nodes from {}",
            nodes.len(),
            filename.display()
        );
        let now = timestamp();
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        for node in nodes {
            if let Err(err) = gossip_crds.insert(node, now, GossipRoute::LocalMessage) {
                warn!("crds insert failed {:?}", err);
            }
        }
    }

    pub fn id(&self) -> Pubkey {
        self.my_contact_info.read().unwrap().id
    }

    pub fn keypair(&self) -> RwLockReadGuard<Arc<Keypair>> {
        self.keypair.read().unwrap()
    }

    pub fn set_keypair(&self, new_keypair: Arc<Keypair>) {
        let id = new_keypair.pubkey();
        {
            let mut instance = self.instance.write().unwrap();
            *instance = NodeInstance::new(&mut thread_rng(), id, timestamp());
        }
        *self.keypair.write().unwrap() = new_keypair;
        self.my_contact_info.write().unwrap().id = id;

        self.insert_self();
        self.push_message(CrdsValue::new_signed(
            CrdsData::Version(Version::new(self.id())),
            &self.keypair(),
        ));
        self.push_self(&HashMap::new(), None);
    }

    pub fn lookup_contact_info<F, Y>(&self, id: &Pubkey, map: F) -> Option<Y>
    where
        F: FnOnce(&ContactInfo) -> Y,
    {
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds.get(*id).map(map)
    }

    pub fn lookup_contact_info_by_gossip_addr(
        &self,
        gossip_addr: &SocketAddr,
    ) -> Option<ContactInfo> {
        let gossip_crds = self.gossip.crds.read().unwrap();
        let mut nodes = gossip_crds.get_nodes_contact_info();
        nodes.find(|node| node.gossip == *gossip_addr).cloned()
    }

    pub fn my_contact_info(&self) -> ContactInfo {
        self.my_contact_info.read().unwrap().clone()
    }

    pub fn my_shred_version(&self) -> u16 {
        self.my_contact_info.read().unwrap().shred_version
    }

    fn lookup_epoch_slots(&self, ix: EpochSlotsIndex) -> EpochSlots {
        let self_pubkey = self.id();
        let label = CrdsValueLabel::EpochSlots(ix, self_pubkey);
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get::<&CrdsValue>(&label)
            .and_then(|v| v.epoch_slots())
            .cloned()
            .unwrap_or_else(|| EpochSlots::new(self_pubkey, timestamp()))
    }

    pub fn rpc_info_trace(&self) -> String {
        let now = timestamp();
        let my_pubkey = self.id();
        let my_shred_version = self.my_shred_version();
        let nodes: Vec<_> = self
            .all_peers()
            .into_iter()
            .filter_map(|(node, last_updated)| {
                if !ContactInfo::is_valid_address(&node.rpc, &self.socket_addr_space) {
                    return None;
                }

                let node_version = self.get_node_version(&node.id);
                if my_shred_version != 0
                    && (node.shred_version != 0 && node.shred_version != my_shred_version)
                {
                    return None;
                }

                let addr_to_string = |default_ip: &IpAddr, addr: &SocketAddr| -> String {
                    if ContactInfo::is_valid_address(addr, &self.socket_addr_space) {
                        if &addr.ip() == default_ip {
                            addr.port().to_string()
                        } else {
                            addr.to_string()
                        }
                    } else {
                        "none".to_string()
                    }
                };

                let rpc_addr = node.rpc.ip();
                Some(format!(
                    "{:15} {:2}| {:5} | {:44} |{:^9}| {:5}| {:5}| {}\n",
                    rpc_addr.to_string(),
                    if node.id == my_pubkey { "me" } else { "" },
                    now.saturating_sub(last_updated),
                    node.id,
                    if let Some(node_version) = node_version {
                        node_version.to_string()
                    } else {
                        "-".to_string()
                    },
                    addr_to_string(&rpc_addr, &node.rpc),
                    addr_to_string(&rpc_addr, &node.rpc_pubsub),
                    node.shred_version,
                ))
            })
            .collect();

        format!(
            "RPC Address       |Age(ms)| Node identifier                              \
             | Version | RPC  |PubSub|ShredVer\n\
             ------------------+-------+----------------------------------------------+---------+\
             ------+------+--------\n\
             {}\
             RPC Enabled Nodes: {}",
            nodes.join(""),
            nodes.len(),
        )
    }

    pub fn contact_info_trace(&self) -> String {
        let now = timestamp();
        let mut shred_spy_nodes = 0usize;
        let mut total_spy_nodes = 0usize;
        let mut different_shred_nodes = 0usize;
        let my_pubkey = self.id();
        let my_shred_version = self.my_shred_version();
        let mut nodes_sorted: Vec<_> = self
            .all_peers()
            .into_iter()
            .filter_map(|(node, last_updated)| {
                let is_spy_node = Self::is_spy_node(&node, &self.socket_addr_space);
                if is_spy_node {
                    total_spy_nodes = total_spy_nodes.saturating_add(1);
                }

                let node_version = self.get_node_version(&node.id);
                if my_shred_version != 0
                    && (node.shred_version != 0 && node.shred_version != my_shred_version)
                {
                    different_shred_nodes = different_shred_nodes.saturating_add(1);
                    None
                } else {
                    if is_spy_node {
                        shred_spy_nodes = shred_spy_nodes.saturating_add(1);
                    }
                    let ip_addr = node.gossip.ip();
                    let slot = self
                        .gossip
                        .crds
                        .read()
                        .unwrap()
                        .get::<&SnapshotHashes>(node.id)
                        .and_then(|x| x.hashes.iter().map(|(s, _)| *s).max());
                    Some((slot, ip_addr, node, node_version, last_updated))
                }
            })
            .collect();
        nodes_sorted.sort_by_key(|(slot, ..)| slot.unwrap_or_default());

        let nodes: Vec<_> = nodes_sorted.iter()
            .map(|(slot, ip_addr, node, node_version , last_updated)| {
                let addr_to_string = |default_ip: &IpAddr, addr: &SocketAddr| -> String {
                    if ContactInfo::is_valid_address(addr, &self.socket_addr_space) {
                        if &addr.ip() == default_ip {
                            addr.port().to_string()
                        } else {
                            addr.to_string()
                        }
                    } else {
                        "none".to_string()
                    }
                };
                format!(
                    "{:15} {:2}| {:5} | {:44} |{:^9}| {:5}| {:6}| {:5}| {:5}| {:5}| {:5}| {:5}| {:5}| {:7}| {}\n",
                    if ContactInfo::is_valid_address(&node.gossip, &self.socket_addr_space) {
                        ip_addr.to_string()
                    } else {
                        "none".to_string()
                    },
                    if node.id == my_pubkey { "me" } else { "" },
                    now.saturating_sub(*last_updated),
                    node.id,
                    if let Some(node_version) = node_version {
                        node_version.to_string()
                    } else {
                        "-".to_string()
                    },
                    addr_to_string(ip_addr, &node.gossip),
                    addr_to_string(ip_addr, &node.tpu_vote),
                    addr_to_string(ip_addr, &node.tpu),
                    addr_to_string(ip_addr, &node.tpu_forwards),
                    addr_to_string(ip_addr, &node.tvu),
                    addr_to_string(ip_addr, &node.tvu_forwards),
                    addr_to_string(ip_addr, &node.repair),
                    addr_to_string(ip_addr, &node.serve_repair),
                    node.shred_version,
                    slot.map(|x|x.to_string()).unwrap_or_default(),
                )})
            .collect();

        format!(
            "IP Address        |Age(ms)| Node identifier                              \
             | Version |Gossip|TPUvote| TPU  |TPUfwd| TVU  |TVUfwd|Repair|ServeR|ShredVer|LastSnapshot\n\
             ------------------+-------+----------------------------------------------+---------+\
             ------+-------+------+------+------+------+------+------+--------+--------\n\
             {}\
             Nodes: {}{}{}",
            nodes.join(""),
            nodes.len().saturating_sub(shred_spy_nodes),
            if total_spy_nodes > 0 {
                format!("\nSpies: {}", total_spy_nodes)
            } else {
                "".to_string()
            },
            if different_shred_nodes > 0 {
                format!(
                    "\nNodes with different shred version: {}",
                    different_shred_nodes
                )
            } else {
                "".to_string()
            }
        )
    }

    // TODO: This has a race condition if called from more than one thread.
    pub fn push_lowest_slot(&self, min: Slot) {
        let self_pubkey = self.id();
        let last = {
            let gossip_crds = self.gossip.crds.read().unwrap();
            gossip_crds
                .get::<&LowestSlot>(self_pubkey)
                .map(|x| x.lowest)
                .unwrap_or_default()
        };
        if min > last {
            let now = timestamp();
            let entry = CrdsValue::new_signed(
                CrdsData::LowestSlot(0, LowestSlot::new(self_pubkey, min, now)),
                &self.keypair(),
            );
            self.local_message_pending_push_queue
                .lock()
                .unwrap()
                .push(entry);
        }
    }

    // TODO: If two threads call into this function then epoch_slot_index has a
    // race condition and the threads will overwrite each other in crds table.
    pub fn push_epoch_slots(&self, mut update: &[Slot]) {
        let self_pubkey = self.id();
        let current_slots: Vec<_> = {
            let gossip_crds =
                self.time_gossip_read_lock("lookup_epoch_slots", &self.stats.epoch_slots_lookup);
            (0..crds_value::MAX_EPOCH_SLOTS)
                .filter_map(|ix| {
                    let label = CrdsValueLabel::EpochSlots(ix, self_pubkey);
                    let epoch_slots = gossip_crds.get::<&CrdsValue>(&label)?.epoch_slots()?;
                    let first_slot = epoch_slots.first_slot()?;
                    Some((epoch_slots.wallclock, first_slot, ix))
                })
                .collect()
        };
        let min_slot: Slot = current_slots
            .iter()
            .map(|(_wallclock, slot, _index)| *slot)
            .min()
            .unwrap_or_default();
        let max_slot: Slot = update.iter().max().cloned().unwrap_or(0);
        let total_slots = max_slot as isize - min_slot as isize;
        // WARN if CRDS is not storing at least a full epoch worth of slots
        if DEFAULT_SLOTS_PER_EPOCH as isize > total_slots
            && crds_value::MAX_EPOCH_SLOTS as usize <= current_slots.len()
        {
            inc_new_counter_warn!("cluster_info-epoch_slots-filled", 1);
            warn!(
                "EPOCH_SLOTS are filling up FAST {}/{}",
                total_slots,
                current_slots.len()
            );
        }
        let mut reset = false;
        let mut epoch_slot_index = match current_slots.iter().max() {
            Some((_wallclock, _slot, index)) => *index,
            None => 0,
        };
        let mut entries = Vec::default();
        let keypair = self.keypair();
        while !update.is_empty() {
            let ix = epoch_slot_index % crds_value::MAX_EPOCH_SLOTS;
            let now = timestamp();
            let mut slots = if !reset {
                self.lookup_epoch_slots(ix)
            } else {
                EpochSlots::new(self_pubkey, now)
            };
            let n = slots.fill(update, now);
            update = &update[n..];
            if n > 0 {
                let epoch_slots = CrdsData::EpochSlots(ix, slots);
                let entry = CrdsValue::new_signed(epoch_slots, &keypair);
                entries.push(entry);
            }
            epoch_slot_index += 1;
            reset = true;
        }
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        let now = timestamp();
        for entry in entries {
            if let Err(err) = gossip_crds.insert(entry, now, GossipRoute::LocalMessage) {
                error!("push_epoch_slots failed: {:?}", err);
            }
        }
    }

    fn time_gossip_read_lock<'a>(
        &'a self,
        label: &'static str,
        counter: &'a Counter,
    ) -> TimedGuard<'a, RwLockReadGuard<Crds>> {
        TimedGuard::new(self.gossip.crds.read().unwrap(), label, counter)
    }

    pub fn push_message(&self, message: CrdsValue) {
        self.local_message_pending_push_queue
            .lock()
            .unwrap()
            .push(message);
    }

    pub fn push_accounts_hashes(&self, accounts_hashes: Vec<(Slot, Hash)>) {
        if accounts_hashes.len() > MAX_SNAPSHOT_HASHES {
            warn!(
                "accounts hashes too large, ignored: {}",
                accounts_hashes.len(),
            );
            return;
        }

        let message = CrdsData::AccountsHashes(SnapshotHashes::new(self.id(), accounts_hashes));
        self.push_message(CrdsValue::new_signed(message, &self.keypair()));
    }

    pub fn push_snapshot_hashes(&self, snapshot_hashes: Vec<(Slot, Hash)>) {
        if snapshot_hashes.len() > MAX_SNAPSHOT_HASHES {
            warn!(
                "snapshot hashes too large, ignored: {}",
                snapshot_hashes.len(),
            );
            return;
        }

        let message = CrdsData::SnapshotHashes(SnapshotHashes::new(self.id(), snapshot_hashes));
        self.push_message(CrdsValue::new_signed(message, &self.keypair()));
    }

    pub fn push_incremental_snapshot_hashes(
        &self,
        base: (Slot, Hash),
        hashes: Vec<(Slot, Hash)>,
    ) -> Result<(), ClusterInfoError> {
        if hashes.len() > MAX_INCREMENTAL_SNAPSHOT_HASHES {
            return Err(ClusterInfoError::TooManyIncrementalSnapshotHashes);
        }

        let message = CrdsData::IncrementalSnapshotHashes(IncrementalSnapshotHashes {
            from: self.id(),
            base,
            hashes,
            wallclock: timestamp(),
        });
        self.push_message(CrdsValue::new_signed(message, &self.keypair()));

        Ok(())
    }

    pub fn push_vote_at_index(&self, vote: Transaction, vote_index: u8) {
        assert!((vote_index as usize) < MAX_LOCKOUT_HISTORY);
        let self_pubkey = self.id();
        let now = timestamp();
        let vote = Vote::new(self_pubkey, vote, now).unwrap();
        let vote = CrdsData::Vote(vote_index, vote);
        let vote = CrdsValue::new_signed(vote, &self.keypair());
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        if let Err(err) = gossip_crds.insert(vote, now, GossipRoute::LocalMessage) {
            error!("push_vote failed: {:?}", err);
        }
    }

    pub fn push_vote(&self, tower: &[Slot], vote: Transaction) {
        debug_assert!(tower.iter().tuple_windows().all(|(a, b)| a < b));
        // Find a crds vote which is evicted from the tower, and recycle its
        // vote-index. This can be either an old vote which is popped off the
        // deque, or recent vote which has expired before getting enough
        // confirmations.
        // If all votes are still in the tower, add a new vote-index. If more
        // than one vote is evicted, the oldest one by wallclock is returned in
        // order to allow more recent votes more time to propagate through
        // gossip.
        // TODO: When there are more than one vote evicted from the tower, only
        // one crds vote is overwritten here. Decide what to do with the rest.
        let mut num_crds_votes = 0;
        let self_pubkey = self.id();
        // Returns true if the tower does not contain the vote.slot.
        let should_evict_vote = |vote: &Vote| -> bool {
            match vote.slot() {
                Some(slot) => !tower.contains(&slot),
                None => {
                    error!("crds vote with no slots!");
                    true
                }
            }
        };
        let vote_index = {
            let gossip_crds =
                self.time_gossip_read_lock("gossip_read_push_vote", &self.stats.push_vote_read);
            (0..MAX_LOCKOUT_HISTORY as u8)
                .filter_map(|ix| {
                    let vote = CrdsValueLabel::Vote(ix, self_pubkey);
                    let vote: &CrdsData = gossip_crds.get(&vote)?;
                    num_crds_votes += 1;
                    match &vote {
                        CrdsData::Vote(_, vote) if should_evict_vote(vote) => {
                            Some((vote.wallclock, ix))
                        }
                        CrdsData::Vote(_, _) => None,
                        _ => panic!("this should not happen!"),
                    }
                })
                .min() // Boot the oldest evicted vote by wallclock.
                .map(|(_ /*wallclock*/, ix)| ix)
        };
        let vote_index = vote_index.unwrap_or(num_crds_votes);
        if (vote_index as usize) >= MAX_LOCKOUT_HISTORY {
            let (_, vote, hash) = vote_parser::parse_vote_transaction(&vote).unwrap();
            panic!(
                "invalid vote index: {}, switch: {}, vote slots: {:?}, tower: {:?}",
                vote_index,
                hash.is_some(),
                vote.slots,
                tower
            );
        }
        self.push_vote_at_index(vote, vote_index);
    }

    pub fn refresh_vote(&self, vote: Transaction, vote_slot: Slot) {
        let vote_index = {
            let self_pubkey = self.id();
            let gossip_crds =
                self.time_gossip_read_lock("gossip_read_push_vote", &self.stats.push_vote_read);
            (0..MAX_LOCKOUT_HISTORY as u8).find(|ix| {
                let vote = CrdsValueLabel::Vote(*ix, self_pubkey);
                if let Some(vote) = gossip_crds.get::<&CrdsData>(&vote) {
                    match &vote {
                        CrdsData::Vote(_, prev_vote) => match prev_vote.slot() {
                            Some(prev_vote_slot) => prev_vote_slot == vote_slot,
                            None => {
                                error!("crds vote with no slots!");
                                false
                            }
                        },
                        _ => panic!("this should not happen!"),
                    }
                } else {
                    false
                }
            })
        };

        // If you don't see a vote with the same slot yet, this means you probably
        // restarted, and need to wait for your oldest vote to propagate back to you.
        //
        // We don't write to an arbitrary index, because it may replace one of this validator's
        // existing votes on the network.
        if let Some(vote_index) = vote_index {
            self.push_vote_at_index(vote, vote_index);
        }
    }

    pub fn send_transaction(
        &self,
        transaction: &Transaction,
        tpu: Option<SocketAddr>,
    ) -> Result<(), GossipError> {
        let tpu = tpu.unwrap_or_else(|| self.my_contact_info().tpu);
        let buf = serialize(transaction)?;
        self.socket.send_to(&buf, tpu)?;
        Ok(())
    }

    /// Returns votes inserted since the given cursor.
    pub fn get_votes(&self, cursor: &mut Cursor) -> Vec<Transaction> {
        let txs: Vec<Transaction> = self
            .time_gossip_read_lock("get_votes", &self.stats.get_votes)
            .get_votes(cursor)
            .map(|vote| {
                let transaction = match &vote.value.data {
                    CrdsData::Vote(_, vote) => vote.transaction().clone(),
                    _ => panic!("this should not happen!"),
                };
                transaction
            })
            .collect();
        inc_new_counter_info!("cluster_info-get_votes-count", txs.len());
        txs
    }

    /// Returns votes and the associated labels inserted since the given cursor.
    pub fn get_votes_with_labels(
        &self,
        cursor: &mut Cursor,
    ) -> (Vec<CrdsValueLabel>, Vec<Transaction>) {
        let (labels, txs): (_, Vec<_>) = self
            .time_gossip_read_lock("get_votes", &self.stats.get_votes)
            .get_votes(cursor)
            .map(|vote| {
                let transaction = match &vote.value.data {
                    CrdsData::Vote(_, vote) => vote.transaction().clone(),
                    _ => panic!("this should not happen!"),
                };
                (vote.value.label(), transaction)
            })
            .unzip();
        inc_new_counter_info!("cluster_info-get_votes-count", txs.len());
        (labels, txs)
    }

    pub fn push_duplicate_shred(
        &self,
        shred: &Shred,
        other_payload: &[u8],
    ) -> Result<(), GossipError> {
        self.gossip.push_duplicate_shred(
            &self.keypair(),
            shred,
            other_payload,
            None::<fn(Slot) -> Option<Pubkey>>, // Leader schedule
            DUPLICATE_SHRED_MAX_PAYLOAD_SIZE,
        )?;
        Ok(())
    }

    pub fn get_accounts_hash_for_node<F, Y>(&self, pubkey: &Pubkey, map: F) -> Option<Y>
    where
        F: FnOnce(&Vec<(Slot, Hash)>) -> Y,
    {
        self.time_gossip_read_lock("get_accounts_hash", &self.stats.get_accounts_hash)
            .get::<&CrdsValue>(&CrdsValueLabel::AccountsHashes(*pubkey))
            .map(|x| &x.accounts_hash().unwrap().hashes)
            .map(map)
    }

    pub fn get_snapshot_hash_for_node<F, Y>(&self, pubkey: &Pubkey, map: F) -> Option<Y>
    where
        F: FnOnce(&Vec<(Slot, Hash)>) -> Y,
    {
        let gossip_crds = self.gossip.crds.read().unwrap();
        let hashes = &gossip_crds.get::<&SnapshotHashes>(*pubkey)?.hashes;
        Some(map(hashes))
    }

    pub fn get_incremental_snapshot_hashes_for_node(
        &self,
        pubkey: &Pubkey,
    ) -> Option<IncrementalSnapshotHashes> {
        self.gossip
            .crds
            .read()
            .unwrap()
            .get::<&IncrementalSnapshotHashes>(*pubkey)
            .cloned()
    }

    /// Returns epoch-slots inserted since the given cursor.
    /// Excludes entries from nodes with unkown or different shred version.
    pub fn get_epoch_slots(&self, cursor: &mut Cursor) -> Vec<EpochSlots> {
        let self_shred_version = Some(self.my_shred_version());
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_epoch_slots(cursor)
            .filter(|entry| {
                let origin = entry.value.pubkey();
                gossip_crds.get_shred_version(&origin) == self_shred_version
            })
            .map(|entry| match &entry.value.data {
                CrdsData::EpochSlots(_, slots) => slots.clone(),
                _ => panic!("this should not happen!"),
            })
            .collect()
    }

    pub fn get_node_version(&self, pubkey: &Pubkey) -> Option<sino_version::Version> {
        let gossip_crds = self.gossip.crds.read().unwrap();
        if let Some(version) = gossip_crds.get::<&Version>(*pubkey) {
            return Some(version.version.clone());
        }
        let version: &crds_value::LegacyVersion = gossip_crds.get(*pubkey)?;
        Some(version.version.clone().into())
    }

    /// all validators that have a valid rpc port regardless of `shred_version`.
    pub fn all_rpc_peers(&self) -> Vec<ContactInfo> {
        let self_pubkey = self.id();
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_nodes_contact_info()
            .filter(|x| {
                x.id != self_pubkey
                    && ContactInfo::is_valid_address(&x.rpc, &self.socket_addr_space)
            })
            .cloned()
            .collect()
    }

    // All nodes in gossip (including spy nodes) and the last time we heard about them
    pub fn all_peers(&self) -> Vec<(ContactInfo, u64)> {
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_nodes()
            .map(|x| (x.value.contact_info().unwrap().clone(), x.local_timestamp))
            .collect()
    }

    pub fn gossip_peers(&self) -> Vec<ContactInfo> {
        let me = self.id();
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_nodes_contact_info()
            // shred_version not considered for gossip peers (ie, spy nodes do not set shred_version)
            .filter(|x| {
                x.id != me && ContactInfo::is_valid_address(&x.gossip, &self.socket_addr_space)
            })
            .cloned()
            .collect()
    }

    /// all validators that have a valid tvu port regardless of `shred_version`.
    pub fn all_tvu_peers(&self) -> Vec<ContactInfo> {
        let self_pubkey = self.id();
        self.time_gossip_read_lock("all_tvu_peers", &self.stats.all_tvu_peers)
            .get_nodes_contact_info()
            .filter(|x| {
                ContactInfo::is_valid_address(&x.tvu, &self.socket_addr_space)
                    && x.id != self_pubkey
            })
            .cloned()
            .collect()
    }

    /// all validators that have a valid tvu port and are on the same `shred_version`.
    pub fn tvu_peers(&self) -> Vec<ContactInfo> {
        let self_pubkey = self.id();
        let self_shred_version = self.my_shred_version();
        self.time_gossip_read_lock("tvu_peers", &self.stats.tvu_peers)
            .get_nodes_contact_info()
            .filter(|node| {
                node.id != self_pubkey
                    && node.shred_version == self_shred_version
                    && ContactInfo::is_valid_tvu_address(&node.tvu)
            })
            .cloned()
            .collect()
    }

    /// all tvu peers with valid gossip addrs that likely have the slot being requested
    pub fn repair_peers(&self, slot: Slot) -> Vec<ContactInfo> {
        let _st = ScopedTimer::from(&self.stats.repair_peers);
        let self_pubkey = self.id();
        let self_shred_version = self.my_shred_version();
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_nodes_contact_info()
            .filter(|node| {
                node.id != self_pubkey
                    && node.shred_version == self_shred_version
                    && ContactInfo::is_valid_tvu_address(&node.tvu)
                    && ContactInfo::is_valid_address(&node.serve_repair, &self.socket_addr_space)
                    && match gossip_crds.get::<&LowestSlot>(node.id) {
                        None => true, // fallback to legacy behavior
                        Some(lowest_slot) => lowest_slot.lowest <= slot,
                    }
            })
            .cloned()
            .collect()
    }

    fn is_spy_node(contact_info: &ContactInfo, socket_addr_space: &SocketAddrSpace) -> bool {
        !ContactInfo::is_valid_address(&contact_info.tpu, socket_addr_space)
            || !ContactInfo::is_valid_address(&contact_info.gossip, socket_addr_space)
            || !ContactInfo::is_valid_address(&contact_info.tvu, socket_addr_space)
    }

    /// compute broadcast table
    pub fn tpu_peers(&self) -> Vec<ContactInfo> {
        let self_pubkey = self.id();
        let gossip_crds = self.gossip.crds.read().unwrap();
        gossip_crds
            .get_nodes_contact_info()
            .filter(|x| {
                x.id != self_pubkey
                    && ContactInfo::is_valid_address(&x.tpu, &self.socket_addr_space)
            })
            .cloned()
            .collect()
    }

    /// retransmit messages to a list of nodes
    /// # Remarks
    /// We need to avoid having obj locked while doing a io, such as the `send_to`
    pub fn retransmit_to(
        peers: &[&ContactInfo],
        data: &[u8],
        s: &UdpSocket,
        forwarded: bool,
        socket_addr_space: &SocketAddrSpace,
    ) {
        trace!("retransmit orders {}", peers.len());
        let dests: Vec<_> = if forwarded {
            peers
                .iter()
                .map(|peer| peer.tvu_forwards)
                .filter(|addr| ContactInfo::is_valid_address(addr, socket_addr_space))
                .collect()
        } else {
            peers
                .iter()
                .map(|peer| peer.tvu)
                .filter(|addr| socket_addr_space.check(addr))
                .collect()
        };
        if let Err(SendPktsError::IoError(ioerr, num_failed)) = multi_target_send(s, data, &dests) {
            inc_new_counter_info!("cluster_info-retransmit-packets", dests.len(), 1);
            inc_new_counter_error!("cluster_info-retransmit-error", num_failed, 1);
            error!(
                "retransmit_to multi_target_send error: {:?}, {}/{} packets failed",
                ioerr,
                num_failed,
                dests.len(),
            );
        }
    }

    fn insert_self(&self) {
        let value = CrdsValue::new_signed(
            CrdsData::ContactInfo(self.my_contact_info()),
            &self.keypair(),
        );
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        let _ = gossip_crds.insert(value, timestamp(), GossipRoute::LocalMessage);
    }

    // If the network entrypoint hasn't been discovered yet, add it to the crds table
    fn append_entrypoint_to_pulls(
        &self,
        thread_pool: &ThreadPool,
        pulls: &mut Vec<(ContactInfo, Vec<CrdsFilter>)>,
    ) {
        const THROTTLE_DELAY: u64 = CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS / 2;
        let entrypoint = {
            let mut entrypoints = self.entrypoints.write().unwrap();
            let entrypoint = match entrypoints.choose_mut(&mut rand::thread_rng()) {
                Some(entrypoint) => entrypoint,
                None => return,
            };
            if !pulls.is_empty() {
                let now = timestamp();
                if now <= entrypoint.wallclock.saturating_add(THROTTLE_DELAY) {
                    return;
                }
                entrypoint.wallclock = now;
                if self
                    .time_gossip_read_lock("entrypoint", &self.stats.entrypoint)
                    .get_nodes_contact_info()
                    .any(|node| node.gossip == entrypoint.gossip)
                {
                    return; // Found the entrypoint, no need to pull from it
                }
            }
            entrypoint.clone()
        };
        let filters = match pulls.first() {
            Some((_, filters)) => filters.clone(),
            None => {
                let _st = ScopedTimer::from(&self.stats.entrypoint2);
                self.gossip
                    .pull
                    .build_crds_filters(thread_pool, &self.gossip.crds, MAX_BLOOM_SIZE)
            }
        };
        self.stats.pull_from_entrypoint_count.add_relaxed(1);
        pulls.push((entrypoint, filters));
    }

    /// Splits an input feed of serializable data into chunks where the sum of
    /// serialized size of values within each chunk is no larger than
    /// max_chunk_size.
    /// Note: some messages cannot be contained within that size so in the worst case this returns
    /// N nested Vecs with 1 item each.
    fn split_gossip_messages<I, T>(
        max_chunk_size: usize,
        data_feed: I,
    ) -> impl Iterator<Item = Vec<T>>
    where
        T: Serialize + Debug,
        I: IntoIterator<Item = T>,
    {
        let mut data_feed = data_feed.into_iter().fuse();
        let mut buffer = vec![];
        let mut buffer_size = 0; // Serialized size of buffered values.
        std::iter::from_fn(move || loop {
            match data_feed.next() {
                None => {
                    return if buffer.is_empty() {
                        None
                    } else {
                        Some(std::mem::take(&mut buffer))
                    };
                }
                Some(data) => {
                    let data_size = match serialized_size(&data) {
                        Ok(size) => size as usize,
                        Err(err) => {
                            error!("serialized_size failed: {}", err);
                            continue;
                        }
                    };
                    if buffer_size + data_size <= max_chunk_size {
                        buffer_size += data_size;
                        buffer.push(data);
                    } else if data_size <= max_chunk_size {
                        buffer_size = data_size;
                        return Some(std::mem::replace(&mut buffer, vec![data]));
                    } else {
                        error!(
                            "dropping data larger than the maximum chunk size {:?}",
                            data
                        );
                    }
                }
            }
        })
    }

    #[allow(clippy::type_complexity)]
    fn new_pull_requests(
        &self,
        thread_pool: &ThreadPool,
        gossip_validators: Option<&HashSet<Pubkey>>,
        stakes: &HashMap<Pubkey, u64>,
    ) -> (
        Vec<(SocketAddr, Ping)>,     // Ping packets.
        Vec<(SocketAddr, Protocol)>, // Pull requests
    ) {
        let now = timestamp();
        let mut pings = Vec::new();
        let mut pulls: Vec<_> = {
            let _st = ScopedTimer::from(&self.stats.new_pull_requests);
            match self.gossip.new_pull_request(
                thread_pool,
                self.keypair().deref(),
                self.my_shred_version(),
                now,
                gossip_validators,
                stakes,
                MAX_BLOOM_SIZE,
                &self.ping_cache,
                &mut pings,
                &self.socket_addr_space,
            ) {
                Err(_) => Vec::default(),
                Ok((peer, filters)) => vec![(peer, filters)],
            }
        };
        self.append_entrypoint_to_pulls(thread_pool, &mut pulls);
        let num_requests = pulls.iter().map(|(_, filters)| filters.len() as u64).sum();
        self.stats.new_pull_requests_count.add_relaxed(num_requests);
        {
            let _st = ScopedTimer::from(&self.stats.mark_pull_request);
            for (peer, _) in &pulls {
                self.gossip.mark_pull_request_creation_time(peer.id, now);
            }
        }
        let self_info = CrdsData::ContactInfo(self.my_contact_info());
        let self_info = CrdsValue::new_signed(self_info, &self.keypair());
        let pulls = pulls
            .into_iter()
            .flat_map(|(peer, filters)| repeat(peer.gossip).zip(filters))
            .map(|(gossip_addr, filter)| {
                let request = Protocol::PullRequest(filter, self_info.clone());
                (gossip_addr, request)
            });
        self.stats
            .new_pull_requests_pings_count
            .add_relaxed(pings.len() as u64);
        (pings, pulls.collect())
    }

    fn drain_push_queue(&self) -> Vec<CrdsValue> {
        let mut push_queue = self.local_message_pending_push_queue.lock().unwrap();
        std::mem::take(&mut *push_queue)
    }
    // Used in tests
    pub fn flush_push_queue(&self) {
        let pending_push_messages = self.drain_push_queue();
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        let now = timestamp();
        for entry in pending_push_messages {
            let _ = gossip_crds.insert(entry, now, GossipRoute::LocalMessage);
        }
    }
    fn new_push_requests(&self, stakes: &HashMap<Pubkey, u64>) -> Vec<(SocketAddr, Protocol)> {
        let self_id = self.id();
        let mut push_messages = {
            let _st = ScopedTimer::from(&self.stats.new_push_requests);
            self.gossip
                .new_push_messages(self.drain_push_queue(), timestamp())
        };
        if self.require_stake_for_gossip(stakes) {
            push_messages.retain(|_, data| {
                retain_staked(data, stakes);
                !data.is_empty()
            })
        }
        let push_messages: Vec<_> = {
            let gossip_crds =
                self.time_gossip_read_lock("push_req_lookup", &self.stats.new_push_requests2);
            push_messages
                .into_iter()
                .filter_map(|(pubkey, messages)| {
                    let peer: &ContactInfo = gossip_crds.get(pubkey)?;
                    Some((peer.gossip, messages))
                })
                .collect()
        };
        let messages: Vec<_> = push_messages
            .into_iter()
            .flat_map(|(peer, msgs)| {
                Self::split_gossip_messages(PUSH_MESSAGE_MAX_PAYLOAD_SIZE, msgs)
                    .map(move |payload| (peer, Protocol::PushMessage(self_id, payload)))
            })
            .collect();
        self.stats
            .new_push_requests_num
            .add_relaxed(messages.len() as u64);
        messages
    }

    // Generate new push and pull requests
    fn generate_new_gossip_requests(
        &self,
        thread_pool: &ThreadPool,
        gossip_validators: Option<&HashSet<Pubkey>>,
        stakes: &HashMap<Pubkey, u64>,
        generate_pull_requests: bool,
    ) -> Vec<(SocketAddr, Protocol)> {
        self.trim_crds_table(CRDS_UNIQUE_PUBKEY_CAPACITY, stakes);
        // This will flush local pending push messages before generating
        // pull-request bloom filters, preventing pull responses to return the
        // same values back to the node itself. Note that packets will arrive
        // and are processed out of order.
        let mut out: Vec<_> = self.new_push_requests(stakes);
        self.stats
            .packets_sent_push_messages_count
            .add_relaxed(out.len() as u64);
        if generate_pull_requests {
            let (pings, pull_requests) =
                self.new_pull_requests(thread_pool, gossip_validators, stakes);
            self.stats
                .packets_sent_pull_requests_count
                .add_relaxed(pull_requests.len() as u64);
            let pings = pings
                .into_iter()
                .map(|(addr, ping)| (addr, Protocol::PingMessage(ping)));
            out.extend(pull_requests);
            out.extend(pings);
        }
        out
    }

    /// At random pick a node and try to get updated changes from them
    fn run_gossip(
        &self,
        thread_pool: &ThreadPool,
        gossip_validators: Option<&HashSet<Pubkey>>,
        recycler: &PacketBatchRecycler,
        stakes: &HashMap<Pubkey, u64>,
        sender: &PacketBatchSender,
        generate_pull_requests: bool,
    ) -> Result<(), GossipError> {
        let reqs = self.generate_new_gossip_requests(
            thread_pool,
            gossip_validators,
            stakes,
            generate_pull_requests,
        );
        if !reqs.is_empty() {
            let packet_batch = to_packet_batch_with_destination(recycler.clone(), &reqs);
            self.stats
                .packets_sent_gossip_requests_count
                .add_relaxed(packet_batch.packets.len() as u64);
            sender.send(packet_batch)?;
        }
        Ok(())
    }

    fn process_entrypoints(&self) -> bool {
        let mut entrypoints = self.entrypoints.write().unwrap();
        if entrypoints.is_empty() {
            // No entrypoint specified.  Nothing more to process
            return true;
        }
        for entrypoint in entrypoints.iter_mut() {
            if entrypoint.id == Pubkey::default() {
                // If a pull from the entrypoint was successful it should exist in the CRDS table
                if let Some(entrypoint_from_gossip) =
                    self.lookup_contact_info_by_gossip_addr(&entrypoint.gossip)
                {
                    // Update the entrypoint's id so future entrypoint pulls correctly reference it
                    *entrypoint = entrypoint_from_gossip;
                }
            }
        }
        // Adopt an entrypoint's `shred_version` if ours is unset
        if self.my_shred_version() == 0 {
            if let Some(entrypoint) = entrypoints
                .iter()
                .find(|entrypoint| entrypoint.shred_version != 0)
            {
                info!(
                    "Setting shred version to {:?} from entrypoint {:?}",
                    entrypoint.shred_version, entrypoint.id
                );
                self.my_contact_info.write().unwrap().shred_version = entrypoint.shred_version;
            }
        }
        self.my_shred_version() != 0
            && entrypoints
                .iter()
                .all(|entrypoint| entrypoint.id != Pubkey::default())
    }

    fn handle_purge(
        &self,
        thread_pool: &ThreadPool,
        bank_forks: Option<&RwLock<BankForks>>,
        stakes: &HashMap<Pubkey, u64>,
    ) {
        let self_pubkey = self.id();
        let epoch_duration = get_epoch_duration(bank_forks);
        let timeouts = self
            .gossip
            .make_timeouts(self_pubkey, stakes, epoch_duration);
        let num_purged = {
            let _st = ScopedTimer::from(&self.stats.purge);
            self.gossip
                .purge(&self_pubkey, thread_pool, timestamp(), &timeouts)
        };
        inc_new_counter_info!("cluster_info-purge-count", num_purged);
    }

    // Trims the CRDS table by dropping all values associated with the pubkeys
    // with the lowest stake, so that the number of unique pubkeys are bounded.
    fn trim_crds_table(&self, cap: usize, stakes: &HashMap<Pubkey, u64>) {
        if !self.gossip.crds.read().unwrap().should_trim(cap) {
            return;
        }
        let keep: Vec<_> = self
            .entrypoints
            .read()
            .unwrap()
            .iter()
            .map(|k| k.id)
            .chain(std::iter::once(self.id()))
            .collect();
        self.stats.trim_crds_table.add_relaxed(1);
        let mut gossip_crds = self.gossip.crds.write().unwrap();
        match gossip_crds.trim(cap, &keep, stakes, timestamp()) {
            Err(err) => {
                self.stats.trim_crds_table_failed.add_relaxed(1);
                // TODO: Stakes are comming from the root-bank. Debug why/when
                // they are empty/zero.
                debug!("crds table trim failed: {:?}", err);
            }
            Ok(num_purged) => {
                self.stats
                    .trim_crds_table_purged_values_count
                    .add_relaxed(num_purged as u64);
            }
        }
    }

    /// randomly pick a node and ask them for updates asynchronously
    pub fn gossip(
        self: Arc<Self>,
        bank_forks: Option<Arc<RwLock<BankForks>>>,
        sender: PacketBatchSender,
        gossip_validators: Option<HashSet<Pubkey>>,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(std::cmp::min(get_thread_count(), 8))
            .thread_name(|i| format!("ClusterInfo::gossip-{}", i))
            .build()
            .unwrap();
        Builder::new()
            .name("gossip".to_string())
            .spawn(move || {
                let mut last_push = timestamp();
                let mut last_contact_info_trace = timestamp();
                let mut last_contact_info_save = timestamp();
                let mut entrypoints_processed = false;
                let recycler = PacketBatchRecycler::default();
                let crds_data = vec![
                    CrdsData::Version(Version::new(self.id())),
                    CrdsData::NodeInstance(
                        self.instance.read().unwrap().with_wallclock(timestamp()),
                    ),
                ];
                for value in crds_data {
                    let value = CrdsValue::new_signed(value, &self.keypair());
                    self.push_message(value);
                }
                let mut generate_pull_requests = true;
                loop {
                    let start = timestamp();
                    if self.contact_debug_interval != 0
                        && start - last_contact_info_trace > self.contact_debug_interval
                    {
                        // Log contact info
                        info!(
                            "\n{}\n\n{}",
                            self.contact_info_trace(),
                            self.rpc_info_trace()
                        );
                        last_contact_info_trace = start;
                    }

                    if self.contact_save_interval != 0
                        && start - last_contact_info_save > self.contact_save_interval
                    {
                        self.save_contact_info();
                        last_contact_info_save = start;
                    }

                    let (stakes, _feature_set) = match bank_forks {
                        Some(ref bank_forks) => {
                            let root_bank = bank_forks.read().unwrap().root_bank();
                            (
                                root_bank.staked_nodes(),
                                Some(root_bank.feature_set.clone()),
                            )
                        }
                        None => (Arc::default(), None),
                    };
                    let _ = self.run_gossip(
                        &thread_pool,
                        gossip_validators.as_ref(),
                        &recycler,
                        &stakes,
                        &sender,
                        generate_pull_requests,
                    );
                    if exit.load(Ordering::Relaxed) {
                        return;
                    }
                    self.handle_purge(&thread_pool, bank_forks.as_deref(), &stakes);
                    entrypoints_processed = entrypoints_processed || self.process_entrypoints();
                    //TODO: possibly tune this parameter
                    //we saw a deadlock passing an self.read().unwrap().timeout into sleep
                    if start - last_push > CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS / 2 {
                        self.push_self(&stakes, gossip_validators.as_ref());
                        last_push = timestamp();
                    }
                    let elapsed = timestamp() - start;
                    if GOSSIP_SLEEP_MILLIS > elapsed {
                        let time_left = GOSSIP_SLEEP_MILLIS - elapsed;
                        sleep(Duration::from_millis(time_left));
                    }
                    generate_pull_requests = !generate_pull_requests;
                }
            })
            .unwrap()
    }

    fn handle_batch_prune_messages(&self, messages: Vec<(Pubkey, PruneData)>) {
        let _st = ScopedTimer::from(&self.stats.handle_batch_prune_messages_time);
        if messages.is_empty() {
            return;
        }
        self.stats
            .prune_message_count
            .add_relaxed(messages.len() as u64);
        self.stats.prune_message_len.add_relaxed(
            messages
                .iter()
                .map(|(_, data)| data.prunes.len() as u64)
                .sum(),
        );
        let mut prune_message_timeout = 0;
        let mut bad_prune_destination = 0;
        let self_pubkey = self.id();
        {
            let _st = ScopedTimer::from(&self.stats.process_prune);
            let now = timestamp();
            for (from, data) in messages {
                match self.gossip.process_prune_msg(
                    &self_pubkey,
                    &from,
                    &data.destination,
                    &data.prunes,
                    data.wallclock,
                    now,
                ) {
                    Err(CrdsGossipError::PruneMessageTimeout) => {
                        prune_message_timeout += 1;
                    }
                    Err(CrdsGossipError::BadPruneDestination) => {
                        bad_prune_destination += 1;
                    }
                    _ => (),
                }
            }
        }
        if prune_message_timeout != 0 {
            inc_new_counter_debug!("cluster_info-prune_message_timeout", prune_message_timeout);
        }
        if bad_prune_destination != 0 {
            inc_new_counter_debug!("cluster_info-bad_prune_destination", bad_prune_destination);
        }
    }

    fn handle_batch_pull_requests(
        &self,
        // from address, crds filter, caller contact info
        requests: Vec<(SocketAddr, CrdsFilter, CrdsValue)>,
        thread_pool: &ThreadPool,
        recycler: &PacketBatchRecycler,
        stakes: &HashMap<Pubkey, u64>,
        response_sender: &PacketBatchSender,
    ) {
        let _st = ScopedTimer::from(&self.stats.handle_batch_pull_requests_time);
        if requests.is_empty() {
            return;
        }
        let self_pubkey = self.id();
        let requests: Vec<_> = thread_pool.install(|| {
            requests
                .into_par_iter()
                .with_min_len(1024)
                .filter(|(_, _, caller)| match caller.contact_info() {
                    None => false,
                    Some(caller) if caller.id == self_pubkey => {
                        warn!("PullRequest ignored, I'm talking to myself");
                        inc_new_counter_debug!("cluster_info-window-request-loopback", 1);
                        false
                    }
                    Some(_) => true,
                })
                .map(|(from_addr, filter, caller)| PullData {
                    from_addr,
                    caller,
                    filter,
                })
                .collect()
        });
        if !requests.is_empty() {
            self.stats
                .pull_requests_count
                .add_relaxed(requests.len() as u64);
            let response = self.handle_pull_requests(thread_pool, recycler, requests, stakes);
            if !response.is_empty() {
                self.stats
                    .packets_sent_pull_responses_count
                    .add_relaxed(response.packets.len() as u64);
                let _ = response_sender.send(response);
            }
        }
    }

    fn update_data_budget(&self, num_staked: usize) -> usize {
        const INTERVAL_MS: u64 = 100;
        // allow 50kBps per staked validator, epoch slots + votes ~= 1.5kB/slot ~= 4kB/s
        const BYTES_PER_INTERVAL: usize = 5000;
        const MAX_BUDGET_MULTIPLE: usize = 5; // allow budget build-up to 5x the interval default
        let num_staked = num_staked.max(2);
        self.outbound_budget.update(INTERVAL_MS, |bytes| {
            std::cmp::min(
                bytes + num_staked * BYTES_PER_INTERVAL,
                MAX_BUDGET_MULTIPLE * num_staked * BYTES_PER_INTERVAL,
            )
        })
    }

    // Returns a predicate checking if the pull request is from a valid
    // address, and if the address have responded to a ping request. Also
    // appends ping packets for the addresses which need to be (re)verified.
    fn check_pull_request<'a, R>(
        &'a self,
        now: Instant,
        mut rng: &'a mut R,
        packet_batch: &'a mut PacketBatch,
    ) -> impl FnMut(&PullData) -> bool + 'a
    where
        R: Rng + CryptoRng,
    {
        let mut cache = HashMap::<(Pubkey, SocketAddr), bool>::new();
        let mut pingf = move || Ping::new_rand(&mut rng, &self.keypair()).ok();
        let mut ping_cache = self.ping_cache.lock().unwrap();
        let mut hard_check = move |node| {
            let (check, ping) = ping_cache.check(now, node, &mut pingf);
            if let Some(ping) = ping {
                let ping = Protocol::PingMessage(ping);
                match Packet::from_data(Some(&node.1), ping) {
                    Ok(packet) => packet_batch.packets.push(packet),
                    Err(err) => error!("failed to write ping packet: {:?}", err),
                };
            }
            if !check {
                self.stats
                    .pull_request_ping_pong_check_failed_count
                    .add_relaxed(1)
            }
            check
        };
        // Because pull-responses are sent back to packet.meta.addr() of
        // incoming pull-requests, pings are also sent to request.from_addr (as
        // opposed to caller.gossip address).
        move |request| {
            ContactInfo::is_valid_address(&request.from_addr, &self.socket_addr_space) && {
                let node = (request.caller.pubkey(), request.from_addr);
                *cache.entry(node).or_insert_with(|| hard_check(node))
            }
        }
    }

    // Pull requests take an incoming bloom filter of contained entries from a node
    // and tries to send back to them the values it detects are missing.
    fn handle_pull_requests(
        &self,
        thread_pool: &ThreadPool,
        recycler: &PacketBatchRecycler,
        requests: Vec<PullData>,
        stakes: &HashMap<Pubkey, u64>,
    ) -> PacketBatch {
        const DEFAULT_EPOCH_DURATION_MS: u64 = DEFAULT_SLOTS_PER_EPOCH * DEFAULT_MS_PER_SLOT;
        let mut time = Measure::start("handle_pull_requests");
        let callers = crds_value::filter_current(requests.iter().map(|r| &r.caller));
        {
            let _st = ScopedTimer::from(&self.stats.process_pull_requests);
            self.gossip
                .process_pull_requests(callers.cloned(), timestamp());
        }
        let output_size_limit =
            self.update_data_budget(stakes.len()) / PULL_RESPONSE_MIN_SERIALIZED_SIZE;
        let mut packet_batch =
            PacketBatch::new_unpinned_with_recycler(recycler.clone(), 64, "handle_pull_requests");
        let (caller_and_filters, addrs): (Vec<_>, Vec<_>) = {
            let mut rng = rand::thread_rng();
            let check_pull_request =
                self.check_pull_request(Instant::now(), &mut rng, &mut packet_batch);
            requests
                .into_iter()
                .filter(check_pull_request)
                .map(|r| ((r.caller, r.filter), r.from_addr))
                .unzip()
        };
        let now = timestamp();
        let self_id = self.id();
        let mut pull_responses = {
            let _st = ScopedTimer::from(&self.stats.generate_pull_responses);
            self.gossip.generate_pull_responses(
                thread_pool,
                &caller_and_filters,
                output_size_limit,
                now,
            )
        };
        if self.require_stake_for_gossip(stakes) {
            for resp in &mut pull_responses {
                retain_staked(resp, stakes);
            }
        }
        let (responses, scores): (Vec<_>, Vec<_>) = addrs
            .iter()
            .zip(pull_responses)
            .flat_map(|(addr, responses)| repeat(addr).zip(responses))
            .map(|(addr, response)| {
                let age = now.saturating_sub(response.wallclock());
                let score = DEFAULT_EPOCH_DURATION_MS
                    .saturating_sub(age)
                    .div(CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS)
                    .max(1);
                let score = if stakes.contains_key(&response.pubkey()) {
                    2 * score
                } else {
                    score
                };
                let score = match response.data {
                    CrdsData::ContactInfo(_) => 2 * score,
                    _ => score,
                };
                ((addr, response), score)
            })
            .unzip();
        if responses.is_empty() {
            return packet_batch;
        }
        let mut rng = rand::thread_rng();
        let shuffle = WeightedShuffle::new("handle-pull-requests", &scores).shuffle(&mut rng);
        let mut total_bytes = 0;
        let mut sent = 0;
        for (addr, response) in shuffle.map(|i| &responses[i]) {
            let response = vec![response.clone()];
            let response = Protocol::PullResponse(self_id, response);
            match Packet::from_data(Some(addr), response) {
                Err(err) => error!("failed to write pull-response packet: {:?}", err),
                Ok(packet) => {
                    if self.outbound_budget.take(packet.meta.size) {
                        total_bytes += packet.meta.size;
                        packet_batch.packets.push(packet);
                        sent += 1;
                    } else {
                        inc_new_counter_info!("gossip_pull_request-no_budget", 1);
                        break;
                    }
                }
            }
        }
        time.stop();
        let dropped_responses = responses.len() - sent;
        inc_new_counter_info!("gossip_pull_request-sent_requests", sent);
        inc_new_counter_info!("gossip_pull_request-dropped_requests", dropped_responses);
        debug!(
            "handle_pull_requests: {} sent: {} total: {} total_bytes: {}",
            time,
            sent,
            responses.len(),
            total_bytes
        );
        packet_batch
    }

    fn handle_batch_pull_responses(
        &self,
        responses: Vec<(Pubkey, Vec<CrdsValue>)>,
        thread_pool: &ThreadPool,
        stakes: &HashMap<Pubkey, u64>,
        epoch_duration: Duration,
    ) {
        let _st = ScopedTimer::from(&self.stats.handle_batch_pull_responses_time);
        if responses.is_empty() {
            return;
        }
        fn extend<K, V>(hash_map: &mut HashMap<K, Vec<V>>, (key, mut value): (K, Vec<V>))
        where
            K: Eq + std::hash::Hash,
        {
            match hash_map.entry(key) {
                Entry::Occupied(mut entry) => {
                    let entry_value = entry.get_mut();
                    if entry_value.len() < value.len() {
                        std::mem::swap(entry_value, &mut value);
                    }
                    entry_value.extend(value);
                }
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
            }
        }
        fn merge<K, V>(
            mut hash_map: HashMap<K, Vec<V>>,
            other: HashMap<K, Vec<V>>,
        ) -> HashMap<K, Vec<V>>
        where
            K: Eq + std::hash::Hash,
        {
            if hash_map.len() < other.len() {
                return merge(other, hash_map);
            }
            for kv in other {
                extend(&mut hash_map, kv);
            }
            hash_map
        }
        let responses = thread_pool.install(|| {
            responses
                .into_par_iter()
                .with_min_len(1024)
                .fold(HashMap::new, |mut hash_map, kv| {
                    extend(&mut hash_map, kv);
                    hash_map
                })
                .reduce(HashMap::new, merge)
        });
        if !responses.is_empty() {
            let self_pubkey = self.id();
            let timeouts = self
                .gossip
                .make_timeouts(self_pubkey, stakes, epoch_duration);
            for (from, data) in responses {
                self.handle_pull_response(&from, data, &timeouts);
            }
        }
    }

    // Returns (failed, timeout, success)
    fn handle_pull_response(
        &self,
        from: &Pubkey,
        crds_values: Vec<CrdsValue>,
        timeouts: &HashMap<Pubkey, u64>,
    ) -> (usize, usize, usize) {
        let len = crds_values.len();
        trace!("PullResponse me: {} from: {} len={}", self.id(), from, len);
        let mut pull_stats = ProcessPullStats::default();
        let (filtered_pulls, filtered_pulls_expired_timeout, failed_inserts) = {
            let _st = ScopedTimer::from(&self.stats.filter_pull_response);
            self.gossip
                .filter_pull_responses(timeouts, crds_values, timestamp(), &mut pull_stats)
        };
        if !filtered_pulls.is_empty()
            || !filtered_pulls_expired_timeout.is_empty()
            || !failed_inserts.is_empty()
        {
            let _st = ScopedTimer::from(&self.stats.process_pull_response);
            self.gossip.process_pull_responses(
                from,
                filtered_pulls,
                filtered_pulls_expired_timeout,
                failed_inserts,
                timestamp(),
                &mut pull_stats,
            );
        }
        self.stats.process_pull_response_count.add_relaxed(1);
        self.stats.process_pull_response_len.add_relaxed(len as u64);
        self.stats
            .process_pull_response_timeout
            .add_relaxed(pull_stats.timeout_count as u64);
        self.stats
            .process_pull_response_fail_insert
            .add_relaxed(pull_stats.failed_insert as u64);
        self.stats
            .process_pull_response_fail_timeout
            .add_relaxed(pull_stats.failed_timeout as u64);
        self.stats
            .process_pull_response_success
            .add_relaxed(pull_stats.success as u64);

        (
            pull_stats.failed_insert + pull_stats.failed_timeout,
            pull_stats.timeout_count,
            pull_stats.success,
        )
    }

    fn handle_batch_ping_messages<I>(
        &self,
        pings: I,
        recycler: &PacketBatchRecycler,
        response_sender: &PacketBatchSender,
    ) where
        I: IntoIterator<Item = (SocketAddr, Ping)>,
    {
        let _st = ScopedTimer::from(&self.stats.handle_batch_ping_messages_time);
        if let Some(response) = self.handle_ping_messages(pings, recycler) {
            let _ = response_sender.send(response);
        }
    }

    fn handle_ping_messages<I>(
        &self,
        pings: I,
        recycler: &PacketBatchRecycler,
    ) -> Option<PacketBatch>
    where
        I: IntoIterator<Item = (SocketAddr, Ping)>,
    {
        let keypair = self.keypair();
        let packets: Vec<_> = pings
            .into_iter()
            .filter_map(|(addr, ping)| {
                let pong = Pong::new(&ping, &keypair).ok()?;
                let pong = Protocol::PongMessage(pong);
                match Packet::from_data(Some(&addr), pong) {
                    Ok(packet) => Some(packet),
                    Err(err) => {
                        error!("failed to write pong packet: {:?}", err);
                        None
                    }
                }
            })
            .collect();
        if packets.is_empty() {
            None
        } else {
            let packet_batch = PacketBatch::new_unpinned_with_recycler_data(
                recycler,
                "handle_ping_messages",
                packets,
            );
            Some(packet_batch)
        }
    }

    fn handle_batch_pong_messages<I>(&self, pongs: I, now: Instant)
    where
        I: IntoIterator<Item = (SocketAddr, Pong)>,
    {
        let _st = ScopedTimer::from(&self.stats.handle_batch_pong_messages_time);
        let mut pongs = pongs.into_iter().peekable();
        if pongs.peek().is_some() {
            let mut ping_cache = self.ping_cache.lock().unwrap();
            for (addr, pong) in pongs {
                ping_cache.add(&pong, addr, now);
            }
        }
    }

    #[allow(clippy::needless_collect)]
    fn handle_batch_push_messages(
        &self,
        messages: Vec<(Pubkey, Vec<CrdsValue>)>,
        thread_pool: &ThreadPool,
        recycler: &PacketBatchRecycler,
        stakes: &HashMap<Pubkey, u64>,
        response_sender: &PacketBatchSender,
    ) {
        let _st = ScopedTimer::from(&self.stats.handle_batch_push_messages_time);
        if messages.is_empty() {
            return;
        }
        self.stats
            .push_message_count
            .add_relaxed(messages.len() as u64);
        let num_crds_values: u64 = messages.iter().map(|(_, data)| data.len() as u64).sum();
        self.stats
            .push_message_value_count
            .add_relaxed(num_crds_values);
        // Origins' pubkeys of upserted crds values.
        let origins: HashSet<_> = {
            let _st = ScopedTimer::from(&self.stats.process_push_message);
            let now = timestamp();
            messages
                .into_iter()
                .flat_map(|(from, crds_values)| {
                    let (num_success, origins) =
                        self.gossip.process_push_message(&from, crds_values, now);
                    self.stats
                        .process_push_success
                        .add_relaxed(num_success as u64);
                    origins
                })
                .collect()
        };
        // Generate prune messages.
        let self_pubkey = self.id();
        let prunes = {
            let _st = ScopedTimer::from(&self.stats.prune_received_cache);
            self.gossip
                .prune_received_cache(&self_pubkey, origins, stakes)
        };
        let prunes: Vec<(Pubkey /*from*/, Vec<Pubkey> /*origins*/)> = prunes
            .into_iter()
            .flat_map(|(from, prunes)| {
                repeat(from).zip(
                    prunes
                        .into_iter()
                        .chunks(MAX_PRUNE_DATA_NODES)
                        .into_iter()
                        .map(Iterator::collect)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        let prune_messages: Vec<_> = {
            let gossip_crds = self.gossip.crds.read().unwrap();
            let wallclock = timestamp();
            let self_pubkey = self.id();
            thread_pool.install(|| {
                prunes
                    .into_par_iter()
                    .with_min_len(256)
                    .filter_map(|(from, prunes)| {
                        let peer: &ContactInfo = gossip_crds.get(from)?;
                        let mut prune_data = PruneData {
                            pubkey: self_pubkey,
                            prunes,
                            signature: Signature::default(),
                            destination: from,
                            wallclock,
                        };
                        prune_data.sign(&self.keypair());
                        let prune_message = Protocol::PruneMessage(self_pubkey, prune_data);
                        Some((peer.gossip, prune_message))
                    })
                    .collect()
            })
        };
        if prune_messages.is_empty() {
            return;
        }
        let mut packet_batch = to_packet_batch_with_destination(recycler.clone(), &prune_messages);
        let num_prune_packets = packet_batch.packets.len();
        self.stats
            .push_response_count
            .add_relaxed(packet_batch.packets.len() as u64);
        let new_push_requests = self.new_push_requests(stakes);
        inc_new_counter_debug!("cluster_info-push_message-pushes", new_push_requests.len());
        for (address, request) in new_push_requests {
            if ContactInfo::is_valid_address(&address, &self.socket_addr_space) {
                match Packet::from_data(Some(&address), &request) {
                    Ok(packet) => packet_batch.packets.push(packet),
                    Err(err) => error!("failed to write push-request packet: {:?}", err),
                }
            } else {
                trace!("Dropping Gossip push response, as destination is unknown");
            }
        }
        self.stats
            .packets_sent_prune_messages_count
            .add_relaxed(num_prune_packets as u64);
        self.stats
            .packets_sent_push_messages_count
            .add_relaxed((packet_batch.packets.len() - num_prune_packets) as u64);
        let _ = response_sender.send(packet_batch);
    }

    fn require_stake_for_gossip(&self, stakes: &HashMap<Pubkey, u64>) -> bool {
        if stakes.len() < MIN_NUM_STAKED_NODES {
            self.stats
                .require_stake_for_gossip_unknown_stakes
                .add_relaxed(1);
            false
        } else {
            true
        }
    }

    fn process_packets(
        &self,
        packets: VecDeque<(/*from:*/ SocketAddr, Protocol)>,
        thread_pool: &ThreadPool,
        recycler: &PacketBatchRecycler,
        response_sender: &PacketBatchSender,
        stakes: &HashMap<Pubkey, u64>,
        _feature_set: Option<&FeatureSet>,
        epoch_duration: Duration,
        should_check_duplicate_instance: bool,
    ) -> Result<(), GossipError> {
        let _st = ScopedTimer::from(&self.stats.process_gossip_packets_time);
        // Filter out values if the shred-versions are different.
        let self_shred_version = self.my_shred_version();
        let packets = if self_shred_version == 0 {
            packets
        } else {
            let gossip_crds = self.gossip.crds.read().unwrap();
            thread_pool.install(|| {
                packets
                    .into_par_iter()
                    .with_min_len(1024)
                    .filter_map(|(from, msg)| {
                        let msg = filter_on_shred_version(
                            msg,
                            self_shred_version,
                            &gossip_crds,
                            &self.stats,
                        )?;
                        Some((from, msg))
                    })
                    .collect()
            })
        };

        // Check if there is a duplicate instance of
        // this node with more recent timestamp.
        let instance = self.instance.read().unwrap();
        let check_duplicate_instance = |values: &[CrdsValue]| {
            if should_check_duplicate_instance {
                for value in values {
                    if instance.check_duplicate(value) {
                        return Err(GossipError::DuplicateNodeInstance);
                    }
                }
            }
            Ok(())
        };
        // Split packets based on their types.
        let mut pull_requests = vec![];
        let mut pull_responses = vec![];
        let mut push_messages = vec![];
        let mut prune_messages = vec![];
        let mut ping_messages = vec![];
        let mut pong_messages = vec![];
        for (from_addr, packet) in packets {
            match packet {
                Protocol::PullRequest(filter, caller) => {
                    pull_requests.push((from_addr, filter, caller))
                }
                Protocol::PullResponse(from, data) => {
                    check_duplicate_instance(&data)?;
                    pull_responses.push((from, data));
                }
                Protocol::PushMessage(from, data) => {
                    check_duplicate_instance(&data)?;
                    push_messages.push((from, data));
                }
                Protocol::PruneMessage(from, data) => prune_messages.push((from, data)),
                Protocol::PingMessage(ping) => ping_messages.push((from_addr, ping)),
                Protocol::PongMessage(pong) => pong_messages.push((from_addr, pong)),
            }
        }
        self.stats
            .packets_received_pull_requests_count
            .add_relaxed(pull_requests.len() as u64);
        self.stats
            .packets_received_pull_responses_count
            .add_relaxed(pull_responses.len() as u64);
        self.stats
            .packets_received_push_messages_count
            .add_relaxed(push_messages.len() as u64);
        self.stats
            .packets_received_prune_messages_count
            .add_relaxed(prune_messages.len() as u64);
        if self.require_stake_for_gossip(stakes) {
            for (_, data) in &mut pull_responses {
                retain_staked(data, stakes);
            }
            for (_, data) in &mut push_messages {
                retain_staked(data, stakes);
            }
            pull_responses.retain(|(_, data)| !data.is_empty());
            push_messages.retain(|(_, data)| !data.is_empty());
        }
        self.handle_batch_ping_messages(ping_messages, recycler, response_sender);
        self.handle_batch_prune_messages(prune_messages);
        self.handle_batch_push_messages(
            push_messages,
            thread_pool,
            recycler,
            stakes,
            response_sender,
        );
        self.handle_batch_pull_responses(pull_responses, thread_pool, stakes, epoch_duration);
        self.trim_crds_table(CRDS_UNIQUE_PUBKEY_CAPACITY, stakes);
        self.handle_batch_pong_messages(pong_messages, Instant::now());
        self.handle_batch_pull_requests(
            pull_requests,
            thread_pool,
            recycler,
            stakes,
            response_sender,
        );
        Ok(())
    }

    // Consumes packets received from the socket, deserializing, sanitizing and
    // verifying them and then sending them down the channel for the actual
    // handling of requests/messages.
    fn run_socket_consume(
        &self,
        receiver: &PacketBatchReceiver,
        sender: &Sender<Vec<(/*from:*/ SocketAddr, Protocol)>>,
        thread_pool: &ThreadPool,
    ) -> Result<(), GossipError> {
        const RECV_TIMEOUT: Duration = Duration::from_secs(1);
        let packets: Vec<_> = receiver.recv_timeout(RECV_TIMEOUT)?.packets.into();
        let mut packets = VecDeque::from(packets);
        for packet_batch in receiver.try_iter() {
            packets.extend(packet_batch.packets.iter().cloned());
            let excess_count = packets.len().saturating_sub(MAX_GOSSIP_TRAFFIC);
            if excess_count > 0 {
                packets.drain(0..excess_count);
                self.stats
                    .gossip_packets_dropped_count
                    .add_relaxed(excess_count as u64);
            }
        }
        self.stats
            .packets_received_count
            .add_relaxed(packets.len() as u64);
        let verify_packet = |packet: Packet| {
            let protocol: Protocol = packet.deserialize_slice(..).ok()?;
            protocol.sanitize().ok()?;
            let protocol = protocol.par_verify()?;
            Some((packet.meta.addr(), protocol))
        };
        let packets: Vec<_> = {
            let _st = ScopedTimer::from(&self.stats.verify_gossip_packets_time);
            thread_pool.install(|| packets.into_par_iter().filter_map(verify_packet).collect())
        };
        self.stats
            .packets_received_verified_count
            .add_relaxed(packets.len() as u64);
        Ok(sender.send(packets)?)
    }

    /// Process messages from the network
    fn run_listen(
        &self,
        recycler: &PacketBatchRecycler,
        bank_forks: Option<&RwLock<BankForks>>,
        receiver: &Receiver<Vec<(/*from:*/ SocketAddr, Protocol)>>,
        response_sender: &PacketBatchSender,
        thread_pool: &ThreadPool,
        last_print: &mut Instant,
        should_check_duplicate_instance: bool,
    ) -> Result<(), GossipError> {
        const RECV_TIMEOUT: Duration = Duration::from_secs(1);
        const SUBMIT_GOSSIP_STATS_INTERVAL: Duration = Duration::from_secs(2);
        let mut packets = VecDeque::from(receiver.recv_timeout(RECV_TIMEOUT)?);
        for payload in receiver.try_iter() {
            packets.extend(payload);
            let excess_count = packets.len().saturating_sub(MAX_GOSSIP_TRAFFIC);
            if excess_count > 0 {
                packets.drain(0..excess_count);
                self.stats
                    .gossip_packets_dropped_count
                    .add_relaxed(excess_count as u64);
            }
        }
        // Using root_bank instead of working_bank here so that an enbaled
        // feature does not roll back (if the feature happens to get enabled in
        // a minority fork).
        let (feature_set, stakes) = match bank_forks {
            None => (None, Arc::default()),
            Some(bank_forks) => {
                let bank = bank_forks.read().unwrap().root_bank();
                let feature_set = bank.feature_set.clone();
                (Some(feature_set), bank.staked_nodes())
            }
        };
        self.process_packets(
            packets,
            thread_pool,
            recycler,
            response_sender,
            &stakes,
            feature_set.as_deref(),
            get_epoch_duration(bank_forks),
            should_check_duplicate_instance,
        )?;
        if last_print.elapsed() > SUBMIT_GOSSIP_STATS_INTERVAL {
            submit_gossip_stats(&self.stats, &self.gossip, &stakes);
            *last_print = Instant::now();
        }
        Ok(())
    }

    pub(crate) fn start_socket_consume_thread(
        self: Arc<Self>,
        receiver: PacketBatchReceiver,
        sender: Sender<Vec<(/*from:*/ SocketAddr, Protocol)>>,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(get_thread_count().min(8))
            .thread_name(|i| format!("gossip-consume-{}", i))
            .build()
            .unwrap();
        let run_consume = move || {
            while !exit.load(Ordering::Relaxed) {
                match self.run_socket_consume(&receiver, &sender, &thread_pool) {
                    Err(GossipError::RecvTimeoutError(RecvTimeoutError::Disconnected)) => break,
                    Err(GossipError::RecvTimeoutError(RecvTimeoutError::Timeout)) => (),
                    // A send operation can only fail if the receiving end of a
                    // channel is disconnected.
                    Err(GossipError::SendError) => break,
                    Err(err) => error!("gossip consume: {}", err),
                    Ok(()) => (),
                }
            }
        };
        let thread_name = String::from("gossip-consume");
        Builder::new().name(thread_name).spawn(run_consume).unwrap()
    }

    pub(crate) fn listen(
        self: Arc<Self>,
        bank_forks: Option<Arc<RwLock<BankForks>>>,
        requests_receiver: Receiver<Vec<(/*from:*/ SocketAddr, Protocol)>>,
        response_sender: PacketBatchSender,
        should_check_duplicate_instance: bool,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let mut last_print = Instant::now();
        let recycler = PacketBatchRecycler::default();
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(get_thread_count().min(8))
            .thread_name(|i| format!("sor-gossip-work-{}", i))
            .build()
            .unwrap();
        Builder::new()
            .name("sino-listen".to_string())
            .spawn(move || {
                while !exit.load(Ordering::Relaxed) {
                    if let Err(err) = self.run_listen(
                        &recycler,
                        bank_forks.as_deref(),
                        &requests_receiver,
                        &response_sender,
                        &thread_pool,
                        &mut last_print,
                        should_check_duplicate_instance,
                    ) {
                        match err {
                            GossipError::RecvTimeoutError(RecvTimeoutError::Disconnected) => break,
                            GossipError::RecvTimeoutError(RecvTimeoutError::Timeout) => {
                                let table_size = self.gossip.crds.read().unwrap().len();
                                debug!(
                                    "{}: run_listen timeout, table size: {}",
                                    self.id(),
                                    table_size,
                                );
                            }
                            GossipError::DuplicateNodeInstance => {
                                error!(
                                    "duplicate running instances of the same validator node: {}",
                                    self.id()
                                );
                                exit.store(true, Ordering::Relaxed);
                                // TODO: Pass through Exit here so
                                // that this will exit cleanly.
                                std::process::exit(1);
                            }
                            _ => error!("gossip run_listen failed: {}", err),
                        }
                    }
                }
            })
            .unwrap()
    }

    pub fn gossip_contact_info(id: Pubkey, gossip: SocketAddr, shred_version: u16) -> ContactInfo {
        ContactInfo {
            id,
            gossip,
            wallclock: timestamp(),
            shred_version,
            ..ContactInfo::default()
        }
    }

    /// An alternative to Spy Node that has a valid gossip address and fully participate in Gossip.
    pub fn gossip_node(   
        id: Pubkey,
        gossip_addr: &SocketAddr,
        shred_version: u16,
    ) -> (ContactInfo, UdpSocket, Option<TcpListener>) {
        let bind_ip_addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let (port, (gossip_socket, ip_echo)) =
            Node::get_gossip_port(gossip_addr, VALIDATOR_PORT_RANGE, bind_ip_addr);
        let contact_info =
            Self::gossip_contact_info(id, SocketAddr::new(gossip_addr.ip(), port), shred_version);

        (contact_info, gossip_socket, Some(ip_echo))
    }

    /// A Node with dummy ports to spy on gossip via pull requests
    pub fn spy_node(
        id: Pubkey,
        shred_version: u16,
    ) -> (ContactInfo, UdpSocket, Option<TcpListener>) {
        let bind_ip_addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let (_, gossip_socket) = bind_in_range(bind_ip_addr, VALIDATOR_PORT_RANGE).unwrap();
        let contact_info = Self::gossip_contact_info(id, socketaddr_any!(), shred_version);

        (contact_info, gossip_socket, None)
    }
}

// Returns root bank's epoch duration. Falls back on
//     DEFAULT_SLOTS_PER_EPOCH * DEFAULT_MS_PER_SLOT
// if there are no working banks.
fn get_epoch_duration(bank_forks: Option<&RwLock<BankForks>>) -> Duration {
    let num_slots = match bank_forks {
        None => {
            inc_new_counter_info!("cluster_info-purge-no_working_bank", 1);
            DEFAULT_SLOTS_PER_EPOCH
        }
        Some(bank_forks) => {
            let bank = bank_forks.read().unwrap().root_bank();
            bank.get_slots_in_epoch(bank.epoch())
        }
    };
    Duration::from_millis(num_slots * DEFAULT_MS_PER_SLOT)
}

/// Turbine logic
/// 1 - For the current node find out if it is in layer 1
/// 1.1 - If yes, then broadcast to all layer 1 nodes
///      1 - using the layer 1 index, broadcast to all layer 2 nodes assuming you know neighborhood size
/// 1.2 - If no, then figure out what layer the node is in and who the neighbors are and only broadcast to them
///      1 - also check if there are nodes in the next layer and repeat the layer 1 to layer 2 logic

/// Returns Neighbor Nodes and Children Nodes `(neighbors, children)` for a given node based on its stake
pub fn compute_retransmit_peers<T: Copy>(
    fanout: usize,
    index: usize, // Local node's index withing the nodes slice.
    nodes: &[T],
) -> (Vec<T> /*neighbors*/, Vec<T> /*children*/) {
    // 1st layer: fanout    nodes starting at 0
    // 2nd layer: fanout**2 nodes starting at fanout
    // 3rd layer: fanout**3 nodes starting at fanout + fanout**2
    // ...
    // Each layer is divided into neighborhoods of fanout nodes each.
    let offset = index % fanout; // Node's index within its neighborhood.
    let anchor = index - offset; // First node in the neighborhood.
    let neighbors = (anchor..)
        .take(fanout)
        .map(|i| nodes.get(i).copied())
        .while_some()
        .collect();
    let children = ((anchor + 1) * fanout + offset..)
        .step_by(fanout)
        .take(fanout)
        .map(|i| nodes.get(i).copied())
        .while_some()
        .collect();
    (neighbors, children)
}

#[derive(Debug)]
pub struct Sockets {
    pub gossip: UdpSocket,
    pub ip_echo: Option<TcpListener>,
    pub tvu: Vec<UdpSocket>,
    pub tvu_forwards: Vec<UdpSocket>,
    pub tpu: Vec<UdpSocket>,
    pub tpu_forwards: Vec<UdpSocket>,
    pub tpu_vote: Vec<UdpSocket>,
    pub broadcast: Vec<UdpSocket>,
    pub repair: UdpSocket,
    pub retransmit_sockets: Vec<UdpSocket>,
    pub serve_repair: UdpSocket,
    pub ancestor_hashes_requests: UdpSocket,
    pub tpu_quic: UdpSocket,
}

#[derive(Debug)]
pub struct Node {
    pub info: ContactInfo,
    pub sockets: Sockets,
}

impl Node {
    pub fn new_localhost() -> Self {
        let pubkey = sdk::pubkey::new_rand();
        Self::new_localhost_with_pubkey(&pubkey)
    }
    pub fn new_localhost_with_pubkey(pubkey: &Pubkey) -> Self {
        let bind_ip_addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let ((_tpu_port, tpu), (_tpu_quic_port, tpu_quic)) =
            bind_two_consecutive_in_range(bind_ip_addr, (1024, 65535)).unwrap();
        let (gossip_port, (gossip, ip_echo)) =
            bind_common_in_range(bind_ip_addr, (1024, 65535)).unwrap();
        let gossip_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), gossip_port);
        let tvu = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tvu_forwards = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tpu_forwards = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tpu_vote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let repair = UdpSocket::bind("127.0.0.1:0").unwrap();
        let rpc_port = find_available_port_in_range(bind_ip_addr, (1024, 65535)).unwrap();
        let rpc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), rpc_port);
        let rpc_pubsub_port = find_available_port_in_range(bind_ip_addr, (1024, 65535)).unwrap();
        let rpc_pubsub_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), rpc_pubsub_port);

        let broadcast = vec![UdpSocket::bind("0.0.0.0:0").unwrap()];
        let retransmit_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let serve_repair = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ancestor_hashes_requests = UdpSocket::bind("0.0.0.0:0").unwrap();

        let info = ContactInfo {
            id: *pubkey,
            gossip: gossip_addr,
            tvu: tvu.local_addr().unwrap(),
            tvu_forwards: tvu_forwards.local_addr().unwrap(),
            repair: repair.local_addr().unwrap(),
            tpu: tpu.local_addr().unwrap(),
            tpu_forwards: tpu_forwards.local_addr().unwrap(),
            tpu_vote: tpu_vote.local_addr().unwrap(),
            rpc: rpc_addr,
            rpc_pubsub: rpc_pubsub_addr,
            serve_repair: serve_repair.local_addr().unwrap(),
            wallclock: timestamp(),
            shred_version: 0,
        };
        Node {
            info,
            sockets: Sockets {
                gossip,
                ip_echo: Some(ip_echo),
                tvu: vec![tvu],
                tvu_forwards: vec![tvu_forwards],
                tpu: vec![tpu],
                tpu_forwards: vec![tpu_forwards],
                tpu_vote: vec![tpu_vote],
                broadcast,
                repair,
                retransmit_sockets: vec![retransmit_socket],
                serve_repair,
                ancestor_hashes_requests,
                tpu_quic,
            },
        }
    }

    fn get_gossip_port(
        gossip_addr: &SocketAddr,
        port_range: PortRange,
        bind_ip_addr: IpAddr,
    ) -> (u16, (UdpSocket, TcpListener)) {
        if gossip_addr.port() != 0 {
            (
                gossip_addr.port(),
                bind_common(bind_ip_addr, gossip_addr.port(), false).unwrap_or_else(|e| {
                    panic!("gossip_addr bind_to port {}: {}", gossip_addr.port(), e)
                }),
            )
        } else {
            bind_common_in_range(bind_ip_addr, port_range).expect("Failed to bind")
        }
    }
    fn bind(bind_ip_addr: IpAddr, port_range: PortRange) -> (u16, UdpSocket) {
        bind_in_range(bind_ip_addr, port_range).expect("Failed to bind")
    }

    pub fn new_single_bind(        //remove
        pubkey: &Pubkey,
        gossip_addr: &SocketAddr,
        port_range: PortRange,
        bind_ip_addr: IpAddr,
    ) -> Self {
        let (gossip_port, (gossip, ip_echo)) =
            Self::get_gossip_port(gossip_addr, port_range, bind_ip_addr);
        let (tvu_port, tvu) = Self::bind(bind_ip_addr, port_range);
        let (tvu_forwards_port, tvu_forwards) = Self::bind(bind_ip_addr, port_range);
        let ((tpu_port, tpu), (_tpu_quic_port, tpu_quic)) =
            bind_two_consecutive_in_range(bind_ip_addr, port_range).unwrap();
        let (tpu_forwards_port, tpu_forwards) = Self::bind(bind_ip_addr, port_range);
        let (tpu_vote_port, tpu_vote) = Self::bind(bind_ip_addr, port_range);
        let (_, retransmit_socket) = Self::bind(bind_ip_addr, port_range);
        let (repair_port, repair) = Self::bind(bind_ip_addr, port_range);
        let (serve_repair_port, serve_repair) = Self::bind(bind_ip_addr, port_range);
        let (_, broadcast) = Self::bind(bind_ip_addr, port_range);
        let (_, ancestor_hashes_requests) = Self::bind(bind_ip_addr, port_range);

        let rpc_port = find_available_port_in_range(bind_ip_addr, port_range).unwrap();
        let rpc_pubsub_port = find_available_port_in_range(bind_ip_addr, port_range).unwrap();

        let info = ContactInfo {
            id: *pubkey,
            gossip: SocketAddr::new(gossip_addr.ip(), gossip_port),
            tvu: SocketAddr::new(gossip_addr.ip(), tvu_port),
            tvu_forwards: SocketAddr::new(gossip_addr.ip(), tvu_forwards_port),
            repair: SocketAddr::new(gossip_addr.ip(), repair_port),
            tpu: SocketAddr::new(gossip_addr.ip(), tpu_port),
            tpu_forwards: SocketAddr::new(gossip_addr.ip(), tpu_forwards_port),
            tpu_vote: SocketAddr::new(gossip_addr.ip(), tpu_vote_port),
            rpc: SocketAddr::new(gossip_addr.ip(), rpc_port),
            rpc_pubsub: SocketAddr::new(gossip_addr.ip(), rpc_pubsub_port),
            serve_repair: SocketAddr::new(gossip_addr.ip(), serve_repair_port),
            wallclock: timestamp(),
            shred_version: 0,
        };
        trace!("new ContactInfo: {:?}", info);

        Node {
            info,
            sockets: Sockets {
                gossip,
                ip_echo: Some(ip_echo),
                tvu: vec![tvu],
                tvu_forwards: vec![tvu_forwards],
                tpu: vec![tpu],
                tpu_forwards: vec![tpu_forwards],
                tpu_vote: vec![tpu_vote],
                broadcast: vec![broadcast],
                repair,
                retransmit_sockets: vec![retransmit_socket],
                serve_repair,
                ancestor_hashes_requests,
                tpu_quic,
            },
        }
    }

    pub fn new_with_external_ip(           
        pubkey: &Pubkey,
        gossip_addr: &SocketAddr,
        port_range: PortRange,
        bind_ip_addr: IpAddr,
    ) -> Node {
        let (gossip_port, (gossip, ip_echo)) =
            Self::get_gossip_port(gossip_addr, port_range, bind_ip_addr);

        let (tvu_port, tvu_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 8).expect("tvu multi_bind");

        let (tvu_forwards_port, tvu_forwards_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 8).expect("tvu_forwards multi_bind");

        let (tpu_port, tpu_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 32).expect("tpu multi_bind");

        let (_tpu_port_quic, tpu_quic) = Self::bind(
            bind_ip_addr,
            (tpu_port + QUIC_PORT_OFFSET, tpu_port + QUIC_PORT_OFFSET + 1),
        );

        let (tpu_forwards_port, tpu_forwards_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 8).expect("tpu_forwards multi_bind");

        let (tpu_vote_port, tpu_vote_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 1).expect("tpu_vote multi_bind");

        let (_, retransmit_sockets) =
            multi_bind_in_range(bind_ip_addr, port_range, 8).expect("retransmit multi_bind");

        let (repair_port, repair) = Self::bind(bind_ip_addr, port_range);
        let (serve_repair_port, serve_repair) = Self::bind(bind_ip_addr, port_range);

        let (_, broadcast) =
            multi_bind_in_range(bind_ip_addr, port_range, 4).expect("broadcast multi_bind");

        let (_, ancestor_hashes_requests) = Self::bind(bind_ip_addr, port_range);

        let info = ContactInfo {
            id: *pubkey,
            gossip: SocketAddr::new(gossip_addr.ip(), gossip_port),
            tvu: SocketAddr::new(gossip_addr.ip(), tvu_port),
            tvu_forwards: SocketAddr::new(gossip_addr.ip(), tvu_forwards_port),
            repair: SocketAddr::new(gossip_addr.ip(), repair_port),
            tpu: SocketAddr::new(gossip_addr.ip(), tpu_port),
            tpu_forwards: SocketAddr::new(gossip_addr.ip(), tpu_forwards_port),
            tpu_vote: SocketAddr::new(gossip_addr.ip(), tpu_vote_port),
            rpc: socketaddr_any!(),
            rpc_pubsub: socketaddr_any!(),
            serve_repair: SocketAddr::new(gossip_addr.ip(), serve_repair_port),
            wallclock: 0,
            shred_version: 0,
        };
        trace!("new ContactInfo: {:?}", info);

        Node {
            info,
            sockets: Sockets {
                gossip,
                tvu: tvu_sockets,
                tvu_forwards: tvu_forwards_sockets,
                tpu: tpu_sockets,
                tpu_forwards: tpu_forwards_sockets,
                tpu_vote: tpu_vote_sockets,
                broadcast,
                repair,
                retransmit_sockets,
                serve_repair,
                ip_echo: Some(ip_echo),
                ancestor_hashes_requests,
                tpu_quic,
            },
        }
    }
}

pub fn push_messages_to_peer(
    messages: Vec<CrdsValue>,
    self_id: Pubkey,
    peer_gossip: SocketAddr,
    socket_addr_space: &SocketAddrSpace,
) -> Result<(), GossipError> {
    let reqs: Vec<_> = ClusterInfo::split_gossip_messages(PUSH_MESSAGE_MAX_PAYLOAD_SIZE, messages)
        .map(move |payload| (peer_gossip, Protocol::PushMessage(self_id, payload)))
        .collect();
    let packet_batch = to_packet_batch_with_destination(PacketBatchRecycler::default(), &reqs);
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    packet::send_to(&packet_batch, &sock, socket_addr_space)?;
    Ok(())
}

// Filters out values from nodes with different shred-version.
fn filter_on_shred_version(
    mut msg: Protocol,
    self_shred_version: u16,
    crds: &Crds,
    stats: &GossipStats,
) -> Option<Protocol> {
    let filter_values = |from: &Pubkey, values: &mut Vec<CrdsValue>, skipped_counter: &Counter| {
        let num_values = values.len();
        // Node-instances are always exempted from shred-version check so that:
        // * their propagation across cluster is expedited.
        // * prevent two running instances of the same identity key cross
        //   contaminate gossip between clusters.
        if crds.get_shred_version(from) == Some(self_shred_version) {
            values.retain(|value| match &value.data {
                // Allow contact-infos so that shred-versions are updated.
                CrdsData::ContactInfo(_) => true,
                CrdsData::NodeInstance(_) => true,
                // Only retain values with the same shred version.
                _ => crds.get_shred_version(&value.pubkey()) == Some(self_shred_version),
            })
        } else {
            values.retain(|value| match &value.data {
                // Allow node to update its own contact info in case their
                // shred-version changes
                CrdsData::ContactInfo(node) => node.id == *from,
                CrdsData::NodeInstance(_) => true,
                _ => false,
            })
        }
        let num_skipped = num_values - values.len();
        if num_skipped != 0 {
            skipped_counter.add_relaxed(num_skipped as u64);
        }
    };
    match &mut msg {
        Protocol::PullRequest(_, caller) => match &caller.data {
            // Allow spy nodes with shred-verion == 0 to pull from other nodes.
            CrdsData::ContactInfo(node)
                if node.shred_version == 0 || node.shred_version == self_shred_version =>
            {
                Some(msg)
            }
            _ => {
                stats.skip_pull_shred_version.add_relaxed(1);
                None
            }
        },
        Protocol::PullResponse(from, values) => {
            filter_values(from, values, &stats.skip_pull_response_shred_version);
            if values.is_empty() {
                None
            } else {
                Some(msg)
            }
        }
        Protocol::PushMessage(from, values) => {
            filter_values(from, values, &stats.skip_push_message_shred_version);
            if values.is_empty() {
                None
            } else {
                Some(msg)
            }
        }
        Protocol::PruneMessage(_, _) | Protocol::PingMessage(_) | Protocol::PongMessage(_) => {
            Some(msg)
        }
    }
}

