//! The `gossip_service` module implements the network control plane.

use {
    crate::{
        cluster_info::{ClusterInfo, VALIDATOR_PORT_RANGE},
        contact_info::ContactInfo,
    },
    rand::{thread_rng, Rng},
    client::thin_client::{create_client, ThinClient},
    perf::recycler::Recycler,
    runtime::bank_forks::BankForks,
    sdk::{
        pubkey::Pubkey,
        signature::{Keypair, Signer},
    },
    streamer::{
        socket::SocketAddrSpace,
        streamer::{self, StreamerReceiveStats},
    },
    std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc::channel,
            Arc, RwLock,
        },
        thread::{self, sleep, JoinHandle},
        time::{Duration, Instant},
    },
};

pub struct GossipService {
    thread_hdls: Vec<JoinHandle<()>>,
}

impl GossipService {
    pub fn new(
        cluster_info: &Arc<ClusterInfo>,
        bank_forks: Option<Arc<RwLock<BankForks>>>,
        gossip_socket: UdpSocket,
        gossip_validators: Option<HashSet<Pubkey>>,
        should_check_duplicate_instance: bool,
        exit: &Arc<AtomicBool>,
    ) -> Self {
        let (request_sender, request_receiver) = channel();
        let gossip_socket = Arc::new(gossip_socket);
        trace!(
            "GossipService: id: {}, listening on: {:?}",
            &cluster_info.id(),
            gossip_socket.local_addr().unwrap()
        );
        let socket_addr_space = *cluster_info.socket_addr_space();
        let t_receiver = streamer::receiver(
            gossip_socket.clone(),
            exit.clone(),
            request_sender,
            Recycler::default(),
            Arc::new(StreamerReceiveStats::new("gossip_receiver")),
            1,
            false,
            None,
        );
        let (consume_sender, listen_receiver) = channel();
        // https://github.com/rust-lang/rust/issues/39364#issuecomment-634545136
        let _consume_sender = consume_sender.clone();
        let t_socket_consume = cluster_info.clone().start_socket_consume_thread(
            request_receiver,
            consume_sender,
            exit.clone(),
        );
        let (response_sender, response_receiver) = channel();
        let t_listen = cluster_info.clone().listen(
            bank_forks.clone(),
            listen_receiver,
            response_sender.clone(),
            should_check_duplicate_instance,
            exit.clone(),
        );
        let t_gossip = cluster_info.clone().gossip(
            bank_forks,
            response_sender,
            gossip_validators,
            exit.clone(),
        );
        // To work around:
        // https://github.com/rust-lang/rust/issues/54267
        // responder thread should start after response_sender.clone(). see:
        // https://github.com/rust-lang/rust/issues/39364#issuecomment-381446873
        let t_responder = streamer::responder(
            "gossip",
            gossip_socket,
            response_receiver,
            socket_addr_space,
        );
        let thread_hdls = vec![
            t_receiver,
            t_responder,
            t_socket_consume,
            t_listen,
            t_gossip,
        ];
        Self { thread_hdls }
    }

    pub fn join(self) -> thread::Result<()> {
        for thread_hdl in self.thread_hdls {
            thread_hdl.join()?;
        }
        Ok(())
    }
}

/// Discover Validators in a cluster
pub fn discover_cluster(
    entrypoint: &SocketAddr,
    num_nodes: usize,
    socket_addr_space: SocketAddrSpace,
) -> std::io::Result<Vec<ContactInfo>> {
    const DISCOVER_CLUSTER_TIMEOUT: Duration = Duration::from_secs(120);
    let (_all_peers, validators) = discover(
        None, // keypair
        Some(entrypoint),
        Some(num_nodes),
        DISCOVER_CLUSTER_TIMEOUT,
        None, // find_node_by_pubkey
        None, // find_node_by_gossip_addr
        None, // my_gossip_addr
        0,    // my_shred_version
        socket_addr_space,
    )?;
    Ok(validators)
}

pub fn discover(
    keypair: Option<Keypair>,
    entrypoint: Option<&SocketAddr>,
    num_nodes: Option<usize>, // num_nodes only counts validators, excludes spy nodes
    timeout: Duration,
    find_node_by_pubkey: Option<Pubkey>,
    find_node_by_gossip_addr: Option<&SocketAddr>,
    my_gossip_addr: Option<&SocketAddr>,
    my_shred_version: u16,
    socket_addr_space: SocketAddrSpace,
) -> std::io::Result<(
    Vec<ContactInfo>, // all gossip peers
    Vec<ContactInfo>, // tvu peers (validators)
)> {
    let keypair = keypair.unwrap_or_else(Keypair::new);
    let exit = Arc::new(AtomicBool::new(false));
    let (gossip_service, ip_echo, spy_ref) = make_gossip_node(
        keypair,
        entrypoint,
        &exit,
        my_gossip_addr,
        my_shred_version,
        true, // should_check_duplicate_instance,
        socket_addr_space,
    );

    let id = spy_ref.id();
    info!("Entrypoint: {:?}", entrypoint);
    info!("Node Id: {:?}", id);
    if let Some(my_gossip_addr) = my_gossip_addr {
        info!("Gossip Address: {:?}", my_gossip_addr);
    }
    let _ip_echo_server = ip_echo
        .map(|tcp_listener| solana_net_utils::ip_echo_server(tcp_listener, Some(my_shred_version)));
    let (met_criteria, elapsed, all_peers, tvu_peers) = spy(
        spy_ref.clone(),
        num_nodes,
        timeout,
        find_node_by_pubkey,
        find_node_by_gossip_addr,
    );

    exit.store(true, Ordering::Relaxed);
    gossip_service.join().unwrap();

    if met_criteria {
        info!(
            "discover success in {}s...\n{}",
            elapsed.as_secs(),
            spy_ref.contact_info_trace()
        );
        return Ok((all_peers, tvu_peers));
    }

    if !tvu_peers.is_empty() {
        info!(
            "discover failed to match criteria by timeout...\n{}",
            spy_ref.contact_info_trace()
        );
        return Ok((all_peers, tvu_peers));
    }

    info!("discover failed...\n{}", spy_ref.contact_info_trace());
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Discover failed",
    ))
}

/// Creates a ThinClient per valid node
// pub fn get_clients(nodes: &[ContactInfo], socket_addr_space: &SocketAddrSpace) -> Vec<ThinClient> {
//     nodes
//         .iter()
//         .filter_map(|node| ContactInfo::valid_client_facing_addr(node, socket_addr_space))
//         .map(|addrs| create_client(addrs, VALIDATOR_PORT_RANGE))
//         .collect()
// }

/// Creates a ThinClient by selecting a valid node at random
pub fn get_client(nodes: &[ContactInfo], socket_addr_space: &SocketAddrSpace) -> ThinClient {
    let nodes: Vec<_> = nodes
        .iter()
        .filter_map(|node| ContactInfo::valid_client_facing_addr(node, socket_addr_space))
        .collect();
    let select = thread_rng().gen_range(0, nodes.len());
    create_client(nodes[select], VALIDATOR_PORT_RANGE)
}

pub fn get_multi_client(
    nodes: &[ContactInfo],
    socket_addr_space: &SocketAddrSpace,
) -> (ThinClient, usize) {
    let addrs: Vec<_> = nodes
        .iter()
        .filter_map(|node| ContactInfo::valid_client_facing_addr(node, socket_addr_space))
        .collect();
    let rpc_addrs: Vec<_> = addrs.iter().map(|addr| addr.0).collect();
    let tpu_addrs: Vec<_> = addrs.iter().map(|addr| addr.1).collect();
    let (_, transactions_socket) = solana_net_utils::bind_in_range(
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        VALIDATOR_PORT_RANGE,
    )
    .unwrap();
    let num_nodes = tpu_addrs.len();
    (
        ThinClient::new_from_addrs(rpc_addrs, tpu_addrs, transactions_socket),
        num_nodes,
    )
}

fn spy(
    spy_ref: Arc<ClusterInfo>,
    num_nodes: Option<usize>,
    timeout: Duration,
    find_node_by_pubkey: Option<Pubkey>,
    find_node_by_gossip_addr: Option<&SocketAddr>,
) -> (
    bool,             // if found the specified nodes
    Duration,         // elapsed time until found the nodes or timed-out
    Vec<ContactInfo>, // all gossip peers
    Vec<ContactInfo>, // tvu peers (validators)
) {
    let now = Instant::now();
    let mut met_criteria = false;
    let mut all_peers: Vec<ContactInfo> = Vec::new();
    let mut tvu_peers: Vec<ContactInfo> = Vec::new();
    let mut i = 1;
    while !met_criteria && now.elapsed() < timeout {
        all_peers = spy_ref
            .all_peers()
            .into_iter()
            .map(|x| x.0)
            .collect::<Vec<_>>();
        tvu_peers = spy_ref.all_tvu_peers();

        let found_node_by_pubkey = if let Some(pubkey) = find_node_by_pubkey {
            all_peers.iter().any(|x| x.id == pubkey)
        } else {
            false
        };

        let found_node_by_gossip_addr = if let Some(gossip_addr) = find_node_by_gossip_addr {
            all_peers.iter().any(|x| x.gossip == *gossip_addr)
        } else {
            false
        };

        if let Some(num) = num_nodes {
            // Only consider validators and archives for `num_nodes`
            let mut nodes: Vec<_> = tvu_peers.iter().collect();
            nodes.sort();
            nodes.dedup();

            if nodes.len() >= num {
                if found_node_by_pubkey || found_node_by_gossip_addr {
                    met_criteria = true;
                }

                if find_node_by_pubkey.is_none() && find_node_by_gossip_addr.is_none() {
                    met_criteria = true;
                }
            }
        } else if found_node_by_pubkey || found_node_by_gossip_addr {
            met_criteria = true;
        }
        if i % 20 == 0 {
            info!("discovering...\n{}", spy_ref.contact_info_trace());
        }
        sleep(Duration::from_millis(
            crate::cluster_info::GOSSIP_SLEEP_MILLIS,
        ));
        i += 1;
    }
    (met_criteria, now.elapsed(), all_peers, tvu_peers)
}

/// Makes a spy or gossip node based on whether or not a gossip_addr was passed in
/// Pass in a gossip addr to fully participate in gossip instead of relying on just pulls
pub fn make_gossip_node(
    keypair: Keypair,
    entrypoint: Option<&SocketAddr>,
    exit: &Arc<AtomicBool>,
    gossip_addr: Option<&SocketAddr>,
    shred_version: u16,
    should_check_duplicate_instance: bool,
    socket_addr_space: SocketAddrSpace,
) -> (GossipService, Option<TcpListener>, Arc<ClusterInfo>) {
    let (node, gossip_socket, ip_echo) = if let Some(gossip_addr) = gossip_addr {
        ClusterInfo::gossip_node(keypair.pubkey(), gossip_addr, shred_version)
    } else {
        ClusterInfo::spy_node(keypair.pubkey(), shred_version)
    };
    let cluster_info = ClusterInfo::new(node, Arc::new(keypair), socket_addr_space);
    if let Some(entrypoint) = entrypoint {
        cluster_info.set_entrypoint(ContactInfo::new_gossip_entry_point(entrypoint));
    }
    let cluster_info = Arc::new(cluster_info);
    let gossip_service = GossipService::new(
        &cluster_info,
        None,
        gossip_socket,
        None,
        should_check_duplicate_instance,
        exit,
    );
    (gossip_service, ip_echo, cluster_info)
}