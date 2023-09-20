use {
    crate::crds_value::MAX_WALLCLOCK,
    sdk::{
        pubkey::Pubkey,
        //rpc_port,
        sanitize::{Sanitize, SanitizeError},
        //signature,
        timing::timestamp,
    },
    sino_streamer::socket::SocketAddrSpace,
    std::net::{IpAddr, SocketAddr},
};

/// Structure representing a node on the network
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, AbiExample, Deserialize, Serialize)]
pub struct ContactInfo {
    pub id: Pubkey,
    /// gossip address
    pub gossip: SocketAddr,
    /// address to connect to for replication
    pub tvu: SocketAddr,
    /// address to forward shreds to
    pub tvu_forwards: SocketAddr,
    /// address to send repair responses to
    pub repair: SocketAddr,
    /// transactions address
    pub tpu: SocketAddr,
    /// address to forward unprocessed transactions to
    pub tpu_forwards: SocketAddr,
    /// address to which to send bank state requests
    pub tpu_vote: SocketAddr,
    /// address to which to send JSON-RPC requests
    pub rpc: SocketAddr,
    /// websocket for JSON-RPC push notifications
    pub rpc_pubsub: SocketAddr,
    /// address to send repair requests to
    pub serve_repair: SocketAddr,
    /// latest wallclock picked
    pub wallclock: u64,
    /// node shred version
    pub shred_version: u16,
}

impl Sanitize for ContactInfo {
    fn sanitize(&self) -> std::result::Result<(), SanitizeError> {
        if self.wallclock >= MAX_WALLCLOCK {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! socketaddr {
    ($ip:expr, $port:expr) => {
        std::net::SocketAddr::from((std::net::Ipv4Addr::from($ip), $port))
    };
    ($str:expr) => {{
        $str.parse::<std::net::SocketAddr>().unwrap()
    }};
}
#[macro_export]
macro_rules! socketaddr_any {
    () => {
        socketaddr!(0, 0)
    };
}

impl Default for ContactInfo {
    fn default() -> Self {
        ContactInfo {
            id: Pubkey::default(),
            gossip: socketaddr_any!(),
            tvu: socketaddr_any!(),
            tvu_forwards: socketaddr_any!(),
            repair: socketaddr_any!(),
            tpu: socketaddr_any!(),
            tpu_forwards: socketaddr_any!(),
            tpu_vote: socketaddr_any!(),
            rpc: socketaddr_any!(),
            rpc_pubsub: socketaddr_any!(),
            serve_repair: socketaddr_any!(),
            wallclock: 0,
            shred_version: 0,
        }
    }
}

impl ContactInfo {
    pub fn new_localhost(id: &Pubkey, now: u64) -> Self {
        Self {
            id: *id,
            gossip: socketaddr!("127.0.0.1:1234"),
            tvu: socketaddr!("127.0.0.1:1235"),
            tvu_forwards: socketaddr!("127.0.0.1:1236"),
            repair: socketaddr!("127.0.0.1:1237"),
            tpu: socketaddr!("127.0.0.1:1238"),
            tpu_forwards: socketaddr!("127.0.0.1:1239"),
            tpu_vote: socketaddr!("127.0.0.1:1240"),
            rpc: socketaddr!("127.0.0.1:1241"),
            rpc_pubsub: socketaddr!("127.0.0.1:1242"),
            serve_repair: socketaddr!("127.0.0.1:1243"),
            wallclock: now,
            shred_version: 0,
        }
    }

    /// New random ContactInfo for tests and simulations.
    pub fn new_rand<R: rand::Rng>(rng: &mut R, pubkey: Option<Pubkey>) -> Self {
        let delay = 10 * 60 * 1000; // 10 minutes
        let now = timestamp() - delay + rng.gen_range(0, 2 * delay);
        let pubkey = pubkey.unwrap_or_else(sdk::pubkey::new_rand);
        ContactInfo::new_localhost(&pubkey, now)
    }

    // #[cfg(test)]
    // /// ContactInfo with multicast addresses for adversarial testing.
    // pub fn new_multicast() -> Self {
    //     let addr = socketaddr!("224.0.1.255:1000");
    //     assert!(addr.ip().is_multicast());
    //     Self {
    //         id: sdk::pubkey::new_rand(),
    //         gossip: addr,
    //         tvu: addr,
    //         tvu_forwards: addr,
    //         repair: addr,
    //         tpu: addr,
    //         tpu_forwards: addr,
    //         tpu_vote: addr,
    //         rpc: addr,
    //         rpc_pubsub: addr,
    //         serve_repair: addr,
    //         wallclock: 0,
    //         shred_version: 0,
    //     }
    // }

    // Used in tests
    // pub fn new_with_pubkey_socketaddr(pubkey: &Pubkey, bind_addr: &SocketAddr) -> Self {
    //     fn next_port(addr: &SocketAddr, nxt: u16) -> SocketAddr {
    //         let mut nxt_addr = *addr;
    //         nxt_addr.set_port(addr.port() + nxt);
    //         nxt_addr
    //     }

    //     let tpu = *bind_addr;
    //     let gossip = next_port(bind_addr, 1);
    //     let tvu = next_port(bind_addr, 2);
    //     let tpu_forwards = next_port(bind_addr, 3);
    //     let tvu_forwards = next_port(bind_addr, 4);
    //     let repair = next_port(bind_addr, 5);
    //     let rpc = SocketAddr::new(bind_addr.ip(), rpc_port::DEFAULT_RPC_PORT);
    //     let rpc_pubsub = SocketAddr::new(bind_addr.ip(), rpc_port::DEFAULT_RPC_PUBSUB_PORT);
    //     let serve_repair = next_port(bind_addr, 6);
    //     let tpu_vote = next_port(bind_addr, 7);
    //     Self {
    //         id: *pubkey,
    //         gossip,
    //         tvu,
    //         tvu_forwards,
    //         repair,
    //         tpu,
    //         tpu_forwards,
    //         tpu_vote,
    //         rpc,
    //         rpc_pubsub,
    //         serve_repair,
    //         wallclock: timestamp(),
    //         shred_version: 0,
    //     }
    // }

    // Used in tests
    // pub fn new_with_socketaddr(bind_addr: &SocketAddr) -> Self {
    //     let keypair = Keypair::new();
    //     Self::new_with_pubkey_socketaddr(&keypair.pubkey(), bind_addr)
    // }

    // Construct a ContactInfo that's only usable for gossip
    pub fn new_gossip_entry_point(gossip_addr: &SocketAddr) -> Self {
        Self {
            id: Pubkey::default(),
            gossip: *gossip_addr,
            wallclock: timestamp(),
            ..ContactInfo::default()
        }
    }

    fn is_valid_ip(addr: IpAddr) -> bool {
        !(addr.is_unspecified() || addr.is_multicast())
        // || (addr.is_loopback() && !cfg_test))
        // TODO: boot loopback in production networks
    }

    /// port must not be 0
    /// ip must be specified and not multicast
    /// loopback ip is only allowed in tests
    // Keeping this for now not to break tvu-peers and turbine shuffle order of
    // nodes when arranging nodes on retransmit tree. Private IP addresses in
    // turbine are filtered out just before sending packets.
    pub(crate) fn is_valid_tvu_address(addr: &SocketAddr) -> bool {
        (addr.port() != 0) && Self::is_valid_ip(addr.ip())
    }

    // TODO: Replace this entirely with streamer SocketAddrSpace.
    pub fn is_valid_address(addr: &SocketAddr, socket_addr_space: &SocketAddrSpace) -> bool {
        Self::is_valid_tvu_address(addr) && socket_addr_space.check(addr)
    }

    pub fn client_facing_addr(&self) -> (SocketAddr, SocketAddr) {
        (self.rpc, self.tpu)
    }

    pub fn valid_client_facing_addr(
        &self,
        socket_addr_space: &SocketAddrSpace,
    ) -> Option<(SocketAddr, SocketAddr)> {
        if ContactInfo::is_valid_address(&self.rpc, socket_addr_space)
            && ContactInfo::is_valid_address(&self.tpu, socket_addr_space)
        {
            Some((self.rpc, self.tpu))
        } else {
            None
        }
    }
}

