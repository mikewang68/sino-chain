//! The `streamer` module defines a set of services for efficiently pulling data from UDP sockets.
//!

use {
    crate::{
        packet::{self, PacketBatch, PacketBatchRecycler, PACKETS_PER_BATCH},
        sendmmsg::{batch_send, SendPktsError},
        socket::SocketAddrSpace,
    },
    sdk::timing::timestamp,
    std::{
        net::UdpSocket,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc::{Receiver, RecvTimeoutError, SendError, Sender},
            Arc,
        },
        thread::{sleep, Builder, JoinHandle},
        time::{Duration, Instant},
    },
    thiserror::Error,
};

pub type PacketBatchReceiver = Receiver<PacketBatch>;
pub type PacketBatchSender = Sender<PacketBatch>;

#[derive(Error, Debug)]
pub enum StreamerError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("receive timeout error")]
    RecvTimeout(#[from] RecvTimeoutError),

    #[error("send packets error")]
    Send(#[from] SendError<PacketBatch>),

    #[error(transparent)]
    SendPktsError(#[from] SendPktsError),
}

pub struct StreamerReceiveStats {
    pub name: &'static str,
    pub packets_count: AtomicUsize,
    pub packet_batches_count: AtomicUsize,
    pub full_packet_batches_count: AtomicUsize,
    pub max_channel_len: AtomicUsize,
}

impl StreamerReceiveStats {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            packets_count: AtomicUsize::default(),
            packet_batches_count: AtomicUsize::default(),
            full_packet_batches_count: AtomicUsize::default(),
            max_channel_len: AtomicUsize::default(),
        }
    }

    pub fn report(&self) {
        datapoint_info!(
            self.name,
            (
                "packets_count",
                self.packets_count.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "packet_batches_count",
                self.packet_batches_count.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "full_packet_batches_count",
                self.full_packet_batches_count.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
            (
                "channel_len",
                self.max_channel_len.swap(0, Ordering::Relaxed) as i64,
                i64
            ),
        );
    }
}

pub type Result<T> = std::result::Result<T, StreamerError>;

fn recv_loop(
    socket: &UdpSocket,
    exit: Arc<AtomicBool>,
    packet_batch_sender: &PacketBatchSender,
    recycler: &PacketBatchRecycler,
    stats: &StreamerReceiveStats,
    coalesce_ms: u64,
    use_pinned_memory: bool,
    in_vote_only_mode: Option<Arc<AtomicBool>>,
) -> Result<()> {
    loop {
        let mut packet_batch = if use_pinned_memory {
            PacketBatch::new_with_recycler(recycler.clone(), PACKETS_PER_BATCH, stats.name)
        } else {
            PacketBatch::with_capacity(PACKETS_PER_BATCH)
        };
        loop {
            // Check for exit signal, even if socket is busy
            // (for instance the leader transaction socket)
            if exit.load(Ordering::Relaxed) {
                return Ok(());
            }

            if let Some(ref in_vote_only_mode) = in_vote_only_mode {
                if in_vote_only_mode.load(Ordering::Relaxed) {
                    sleep(Duration::from_millis(1));
                    continue;
                }
            }

            if let Ok(len) = packet::recv_from(&mut packet_batch, socket, coalesce_ms) {
                if len > 0 {
                    let StreamerReceiveStats {
                        packets_count,
                        packet_batches_count,
                        full_packet_batches_count,
                        ..
                    } = stats;

                    packets_count.fetch_add(len, Ordering::Relaxed);
                    packet_batches_count.fetch_add(1, Ordering::Relaxed);
                    if len == PACKETS_PER_BATCH {
                        full_packet_batches_count.fetch_add(1, Ordering::Relaxed);
                    }

                    packet_batch_sender.send(packet_batch)?;
                }
                break;
            }
        }
    }
}

pub fn receiver(
    socket: Arc<UdpSocket>,
    exit: Arc<AtomicBool>,
    packet_batch_sender: PacketBatchSender,
    recycler: PacketBatchRecycler,
    stats: Arc<StreamerReceiveStats>,
    coalesce_ms: u64,
    use_pinned_memory: bool,
    in_vote_only_mode: Option<Arc<AtomicBool>>,
) -> JoinHandle<()> {
    let res = socket.set_read_timeout(Some(Duration::new(1, 0)));
    assert!(res.is_ok(), "streamer::receiver set_read_timeout error");
    Builder::new()
        .name("sino-receiver".to_string())
        .spawn(move || {
            let _ = recv_loop(
                &socket,
                exit,
                &packet_batch_sender,
                &recycler,
                &stats,
                coalesce_ms,
                use_pinned_memory,
                in_vote_only_mode,
            );
        })
        .unwrap()
}

fn recv_send(
    sock: &UdpSocket,
    r: &PacketBatchReceiver,
    socket_addr_space: &SocketAddrSpace,
) -> Result<()> {
    let timer = Duration::new(1, 0);
    let packet_batch = r.recv_timeout(timer)?;
    let packets = packet_batch.packets.iter().filter_map(|pkt| {
        let addr = pkt.meta.addr();
        socket_addr_space
            .check(&addr)
            .then(|| (&pkt.data[..pkt.meta.size], addr))
    });
    batch_send(sock, &packets.collect::<Vec<_>>())?;
    Ok(())
}

pub fn recv_packet_batches(
    recvr: &PacketBatchReceiver,
) -> Result<(Vec<PacketBatch>, usize, Duration)> {
    let timer = Duration::new(1, 0);
    let packet_batch = recvr.recv_timeout(timer)?;
    let recv_start = Instant::now();
    trace!("got packets");
    let mut num_packets = packet_batch.packets.len();
    let mut packet_batches = vec![packet_batch];
    while let Ok(packet_batch) = recvr.try_recv() {
        trace!("got more packets");
        num_packets += packet_batch.packets.len();
        packet_batches.push(packet_batch);
    }
    let recv_duration = recv_start.elapsed();
    trace!(
        "packet batches len: {}, num packets: {}",
        packet_batches.len(),
        num_packets
    );
    Ok((packet_batches, num_packets, recv_duration))
}

pub fn responder(
    name: &'static str,
    sock: Arc<UdpSocket>,
    r: PacketBatchReceiver,
    socket_addr_space: SocketAddrSpace,
) -> JoinHandle<()> {
    Builder::new()
        .name(format!("sino-responder-{}", name))
        .spawn(move || {
            let mut errors = 0;
            let mut last_error = None;
            let mut last_print = 0;
            loop {
                if let Err(e) = recv_send(&sock, &r, &socket_addr_space) {
                    match e {
                        StreamerError::RecvTimeout(RecvTimeoutError::Disconnected) => break,
                        StreamerError::RecvTimeout(RecvTimeoutError::Timeout) => (),
                        _ => {
                            errors += 1;
                            last_error = Some(e);
                        }
                    }
                }
                let now = timestamp();
                if now - last_print > 1000 && errors != 0 {
                    datapoint_info!(name, ("errors", errors, i64),);
                    info!("{} last-error: {:?} count: {}", name, last_error, errors);
                    last_print = now;
                    errors = 0;
                }
            }
        })
        .unwrap()
}