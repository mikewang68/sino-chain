use {
    crate::serve_repair::ServeRepair,
    ledger::blockstore::Blockstore,
    perf::recycler::Recycler,
    streamer::{
        socket::SocketAddrSpace,
        streamer::{self, StreamerReceiveStats},
    },
    std::{
        net::UdpSocket,
        sync::{atomic::AtomicBool, mpsc::channel, Arc, RwLock},
        thread::{self, JoinHandle},
    },
};

pub struct ServeRepairService {
    thread_hdls: Vec<JoinHandle<()>>,
}

impl ServeRepairService {
    pub fn new(
        serve_repair: &Arc<RwLock<ServeRepair>>,
        blockstore: Option<Arc<Blockstore>>,
        serve_repair_socket: UdpSocket,
        socket_addr_space: SocketAddrSpace,
        exit: &Arc<AtomicBool>,
    ) -> Self {
        let (request_sender, request_receiver) = channel();
        let serve_repair_socket = Arc::new(serve_repair_socket);
        trace!(
            "ServeRepairService: id: {}, listening on: {:?}",
            &serve_repair.read().unwrap().my_id(),
            serve_repair_socket.local_addr().unwrap()
        );
        let t_receiver = streamer::receiver(
            serve_repair_socket.clone(),
            exit.clone(),
            request_sender,
            Recycler::default(),
            Arc::new(StreamerReceiveStats::new("serve_repair_receiver")),
            1,
            false,
            None,
        );
        let (response_sender, response_receiver) = channel();
        let t_responder = streamer::responder(
            "serve-repairs",
            serve_repair_socket,
            response_receiver,
            socket_addr_space,
        );
        let t_listen = ServeRepair::listen(
            serve_repair.clone(),
            blockstore,
            request_receiver,
            response_sender,
            exit,
        );

        let thread_hdls = vec![t_receiver, t_responder, t_listen];
        Self { thread_hdls }
    }

    pub fn join(self) -> thread::Result<()> {
        for thread_hdl in self.thread_hdls {
            thread_hdl.join()?;
        }
        Ok(())
    }
}
