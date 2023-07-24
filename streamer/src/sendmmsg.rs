//! The `sendmmsg` module provides sendmmsg() API implementation

#[cfg(target_os = "linux")]
use {
    itertools::izip,
    libc::{iovec, mmsghdr, sockaddr_in, sockaddr_in6, sockaddr_storage},
    nix::sys::socket::InetAddr,
    std::os::unix::io::AsRawFd,
};
use {
    std::{
        borrow::Borrow,
        io,
        iter::repeat,
        net::{SocketAddr, UdpSocket},
    },
    thiserror::Error,
};

#[derive(Debug, Error)]
pub enum SendPktsError {
    /// IO Error during send: first error, num failed packets
    #[error("IO Error, some packets could not be sent")]
    IoError(io::Error, usize),
}

#[cfg(not(target_os = "linux"))]
pub fn batch_send<S, T>(sock: &UdpSocket, packets: &[(T, S)]) -> Result<(), SendPktsError>
where
    S: Borrow<SocketAddr>,
    T: AsRef<[u8]>,
{
    let mut num_failed = 0;
    let mut erropt = None;
    for (p, a) in packets {
        if let Err(e) = sock.send_to(p.as_ref(), a.borrow()) {
            num_failed += 1;
            if erropt.is_none() {
                erropt = Some(e);
            }
        }
    }

    if let Some(err) = erropt {
        Err(SendPktsError::IoError(err, num_failed))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn mmsghdr_for_packet(
    packet: &[u8],
    dest: &SocketAddr,
    iov: &mut iovec,
    addr: &mut sockaddr_storage,
    hdr: &mut mmsghdr,
) {
    const SIZE_OF_SOCKADDR_IN: usize = std::mem::size_of::<sockaddr_in>();
    const SIZE_OF_SOCKADDR_IN6: usize = std::mem::size_of::<sockaddr_in6>();

    *iov = iovec {
        iov_base: packet.as_ptr() as *mut libc::c_void,
        iov_len: packet.len(),
    };
    hdr.msg_hdr.msg_iov = iov;
    hdr.msg_hdr.msg_iovlen = 1;
    hdr.msg_hdr.msg_name = addr as *mut _ as *mut _;

    match InetAddr::from_std(dest) {
        InetAddr::V4(dest) => {
            unsafe {
                std::ptr::write(addr as *mut _ as *mut _, dest);
            }
            hdr.msg_hdr.msg_namelen = SIZE_OF_SOCKADDR_IN as u32;
        }
        InetAddr::V6(dest) => {
            unsafe {
                std::ptr::write(addr as *mut _ as *mut _, dest);
            }
            hdr.msg_hdr.msg_namelen = SIZE_OF_SOCKADDR_IN6 as u32;
        }
    };
}

#[cfg(target_os = "linux")]
fn sendmmsg_retry(sock: &UdpSocket, hdrs: &mut Vec<mmsghdr>) -> Result<(), SendPktsError> {
    let sock_fd = sock.as_raw_fd();
    let mut total_sent = 0;
    let mut erropt = None;

    let mut pkts = &mut hdrs[..];
    while !pkts.is_empty() {
        let npkts = match unsafe { libc::sendmmsg(sock_fd, &mut pkts[0], pkts.len() as u32, 0) } {
            -1 => {
                if erropt.is_none() {
                    erropt = Some(io::Error::last_os_error());
                }
                // skip over the failing packet
                1_usize
            }
            n => {
                // if we fail to send all packets we advance to the failing
                // packet and retry in order to capture the error code
                total_sent += n as usize;
                n as usize
            }
        };
        pkts = &mut pkts[npkts..];
    }

    if let Some(err) = erropt {
        Err(SendPktsError::IoError(err, hdrs.len() - total_sent))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn batch_send<S, T>(sock: &UdpSocket, packets: &[(T, S)]) -> Result<(), SendPktsError>
where
    S: Borrow<SocketAddr>,
    T: AsRef<[u8]>,
{
    let size = packets.len();
    #[allow(clippy::uninit_assumed_init)]
    let iovec = std::mem::MaybeUninit::<iovec>::uninit();
    let mut iovs = vec![unsafe { iovec.assume_init() }; size];
    let mut addrs = vec![unsafe { std::mem::zeroed() }; size];
    let mut hdrs = vec![unsafe { std::mem::zeroed() }; size];
    for ((pkt, dest), hdr, iov, addr) in izip!(packets, &mut hdrs, &mut iovs, &mut addrs) {
        mmsghdr_for_packet(pkt.as_ref(), dest.borrow(), iov, addr, hdr);
    }
    sendmmsg_retry(sock, &mut hdrs)
}

pub fn multi_target_send<S, T>(
    sock: &UdpSocket,
    packet: T,
    dests: &[S],
) -> Result<(), SendPktsError>
where
    S: Borrow<SocketAddr>,
    T: AsRef<[u8]>,
{
    let dests = dests.iter().map(Borrow::borrow);
    let pkts: Vec<_> = repeat(&packet).zip(dests).collect();
    batch_send(sock, &pkts)
}