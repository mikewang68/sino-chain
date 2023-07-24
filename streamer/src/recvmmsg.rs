//! The `recvmmsg` module provides recvmmsg() API implementation

pub use perf::packet::NUM_RCVMMSGS;
use {
    crate::packet::{Meta, Packet},
    std::{cmp, io, net::UdpSocket},
};
#[cfg(target_os = "linux")]
use {
    itertools::izip,
    libc::{iovec, mmsghdr, sockaddr_storage, socklen_t, AF_INET, AF_INET6, MSG_WAITFORONE},
    nix::sys::socket::InetAddr,
    std::{mem, os::unix::io::AsRawFd},
};

#[cfg(not(target_os = "linux"))]
pub fn recv_mmsg(socket: &UdpSocket, packets: &mut [Packet]) -> io::Result</*num packets:*/ usize> {
    debug_assert!(packets.iter().all(|pkt| pkt.meta == Meta::default()));
    let mut i = 0;
    let count = cmp::min(NUM_RCVMMSGS, packets.len());
    for p in packets.iter_mut().take(count) {
        p.meta.size = 0;
        match socket.recv_from(&mut p.data) {
            Err(_) if i > 0 => {
                break;
            }
            Err(e) => {
                return Err(e);
            }
            Ok((nrecv, from)) => {
                p.meta.size = nrecv;
                p.meta.set_addr(&from);
                if i == 0 {
                    socket.set_nonblocking(true)?;
                }
            }
        }
        i += 1;
    }
    Ok(i)
}

#[cfg(target_os = "linux")]
fn cast_socket_addr(addr: &sockaddr_storage, hdr: &mmsghdr) -> Option<InetAddr> {
    use libc::{sa_family_t, sockaddr_in, sockaddr_in6};
    const SOCKADDR_IN_SIZE: usize = std::mem::size_of::<sockaddr_in>();
    const SOCKADDR_IN6_SIZE: usize = std::mem::size_of::<sockaddr_in6>();
    if addr.ss_family == AF_INET as sa_family_t
        && hdr.msg_hdr.msg_namelen == SOCKADDR_IN_SIZE as socklen_t
    {
        let addr = addr as *const _ as *const sockaddr_in;
        return Some(unsafe { InetAddr::V4(*addr) });
    }
    if addr.ss_family == AF_INET6 as sa_family_t
        && hdr.msg_hdr.msg_namelen == SOCKADDR_IN6_SIZE as socklen_t
    {
        let addr = addr as *const _ as *const sockaddr_in6;
        return Some(unsafe { InetAddr::V6(*addr) });
    }
    error!(
        "recvmmsg unexpected ss_family:{} msg_namelen:{}",
        addr.ss_family, hdr.msg_hdr.msg_namelen
    );
    None
}

#[cfg(target_os = "linux")]
#[allow(clippy::uninit_assumed_init)]
pub fn recv_mmsg(sock: &UdpSocket, packets: &mut [Packet]) -> io::Result</*num packets:*/ usize> {
    // Assert that there are no leftovers in packets.
    debug_assert!(packets.iter().all(|pkt| pkt.meta == Meta::default()));
    const SOCKADDR_STORAGE_SIZE: usize = mem::size_of::<sockaddr_storage>();

    let mut hdrs: [mmsghdr; NUM_RCVMMSGS] = unsafe { mem::zeroed() };
    let iovs = mem::MaybeUninit::<[iovec; NUM_RCVMMSGS]>::uninit();
    let mut iovs: [iovec; NUM_RCVMMSGS] = unsafe { iovs.assume_init() };
    let mut addrs: [sockaddr_storage; NUM_RCVMMSGS] = unsafe { mem::zeroed() };

    let sock_fd = sock.as_raw_fd();
    let count = cmp::min(iovs.len(), packets.len());

    for (packet, hdr, iov, addr) in
        izip!(packets.iter_mut(), &mut hdrs, &mut iovs, &mut addrs).take(count)
    {
        *iov = iovec {
            iov_base: packet.data.as_mut_ptr() as *mut libc::c_void,
            iov_len: packet.data.len(),
        };
        hdr.msg_hdr.msg_name = addr as *mut _ as *mut _;
        hdr.msg_hdr.msg_namelen = SOCKADDR_STORAGE_SIZE as socklen_t;
        hdr.msg_hdr.msg_iov = iov;
        hdr.msg_hdr.msg_iovlen = 1;
    }
    let mut ts = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let nrecv =
        unsafe { libc::recvmmsg(sock_fd, &mut hdrs[0], count as u32, MSG_WAITFORONE, &mut ts) };
    let nrecv = if nrecv < 0 {
        return Err(io::Error::last_os_error());
    } else {
        usize::try_from(nrecv).unwrap()
    };
    for (addr, hdr, pkt) in izip!(addrs, hdrs, packets.iter_mut()).take(nrecv) {
        pkt.meta.size = hdr.msg_len as usize;
        if let Some(addr) = cast_socket_addr(&addr, &hdr) {
            pkt.meta.set_addr(&addr.to_std());
        }
    }
    Ok(nrecv)
}