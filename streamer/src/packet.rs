//! The `packet` module defines data structures and methods to pull data from the network.
use {
    crate::{
        recvmmsg::{recv_mmsg, NUM_RCVMMSGS},
        socket::SocketAddrSpace,
    },
    metrics::inc_new_counter_debug,
    std::{io::Result, net::UdpSocket, time::Instant},
};
pub use {
    perf::packet::{
        to_packet_batches, PacketBatch, PacketBatchRecycler, NUM_PACKETS, PACKETS_PER_BATCH,
    },
    sdk::packet::{Meta, Packet, PACKET_DATA_SIZE},
};

pub fn recv_from(batch: &mut PacketBatch, socket: &UdpSocket, max_wait_ms: u64) -> Result<usize> {
    let mut i = 0;
    //DOCUMENTED SIDE-EFFECT
    //Performance out of the IO without poll
    //  * block on the socket until it's readable
    //  * set the socket to non blocking
    //  * read until it fails
    //  * set it back to blocking before returning
    socket.set_nonblocking(false)?;
    trace!("receiving on {}", socket.local_addr().unwrap());
    let start = Instant::now();
    loop {
        batch.packets.resize(
            std::cmp::min(i + NUM_RCVMMSGS, PACKETS_PER_BATCH),
            Packet::default(),
        );
        match recv_mmsg(socket, &mut batch.packets[i..]) {
            Err(_) if i > 0 => {
                if Instant::now()
                    .checked_duration_since(start)
                    .unwrap_or_default()
                    .as_millis() as u64
                    > max_wait_ms
                {
                    break;
                }
            }
            Err(e) => {
                trace!("recv_from err {:?}", e);
                return Err(e);
            }
            Ok(npkts) => {
                if i == 0 {
                    socket.set_nonblocking(true)?;
                }
                trace!("got {} packets", npkts);
                i += npkts;
                // Try to batch into big enough buffers
                // will cause less re-shuffling later on.
                if Instant::now()
                    .checked_duration_since(start)
                    .unwrap_or_default()
                    .as_millis() as u64
                    > max_wait_ms
                    || i >= PACKETS_PER_BATCH
                {
                    break;
                }
            }
        }
    }
    batch.packets.truncate(i);
    inc_new_counter_debug!("packets-recv_count", i);
    Ok(i)
}

pub fn send_to(
    batch: &PacketBatch,
    socket: &UdpSocket,
    socket_addr_space: &SocketAddrSpace,
) -> Result<()> {
    for p in &batch.packets {
        let addr = p.meta.addr();
        if socket_addr_space.check(&addr) {
            socket.send_to(&p.data[..p.meta.size], addr)?;
        }
    }
    Ok(())
}