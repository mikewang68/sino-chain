#[cfg(target_os = "linux")]
use std::{fs::File, io::BufReader, path::Path};
use {
    sdk::timing::AtomicInterval,
    std::{
        collections::HashMap,
        io::BufRead,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, sleep, Builder, JoinHandle},
        time::Duration,
    },
};

const MS_PER_S: u64 = 1_000;
const SAMPLE_INTERVAL_UDP_MS: u64 = 2 * MS_PER_S;
const SAMPLE_INTERVAL_MEM_MS: u64 = MS_PER_S;
const SLEEP_INTERVAL: Duration = Duration::from_millis(500);

#[cfg(target_os = "linux")]
const PROC_NET_SNMP_PATH: &str = "/proc/net/snmp";

pub struct SystemMonitorService {
    thread_hdl: JoinHandle<()>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct UdpStats {
    in_datagrams: usize,
    no_ports: usize,
    in_errors: usize,
    out_datagrams: usize,
    rcvbuf_errors: usize,
    sndbuf_errors: usize,
    in_csum_errors: usize,
    ignored_multi: usize,
}

#[cfg(target_os = "linux")]
fn read_udp_stats(file_path: impl AsRef<Path>) -> Result<UdpStats, String> {
    let file = File::open(file_path).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(file);
    parse_udp_stats(&mut reader)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_udp_stats(reader: &mut impl BufRead) -> Result<UdpStats, String> {
    let mut udp_lines = Vec::default();
    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.starts_with("Udp:") {
            udp_lines.push(line);
            if udp_lines.len() == 2 {
                break;
            }
        }
    }
    if udp_lines.len() != 2 {
        return Err(format!(
            "parse error, expected 2 lines, num lines: {}",
            udp_lines.len()
        ));
    }

    let pairs: Vec<_> = udp_lines[0]
        .split_ascii_whitespace()
        .zip(udp_lines[1].split_ascii_whitespace())
        .collect();
    let udp_stats: HashMap<String, usize> = pairs[1..]
        .iter()
        .map(|(label, val)| (label.to_string(), val.parse::<usize>().unwrap()))
        .collect();

    let stats = UdpStats {
        in_datagrams: *udp_stats.get("InDatagrams").unwrap_or(&0),
        no_ports: *udp_stats.get("NoPorts").unwrap_or(&0),
        in_errors: *udp_stats.get("InErrors").unwrap_or(&0),
        out_datagrams: *udp_stats.get("OutDatagrams").unwrap_or(&0),
        rcvbuf_errors: *udp_stats.get("RcvbufErrors").unwrap_or(&0),
        sndbuf_errors: *udp_stats.get("SndbufErrors").unwrap_or(&0),
        in_csum_errors: *udp_stats.get("InCsumErrors").unwrap_or(&0),
        ignored_multi: *udp_stats.get("IgnoredMulti").unwrap_or(&0),
    };

    Ok(stats)
}

#[cfg(target_os = "linux")]
pub fn verify_udp_stats_access() -> Result<(), String> {
    read_udp_stats(PROC_NET_SNMP_PATH)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn verify_udp_stats_access() -> Result<(), String> {
    Ok(())
}

impl SystemMonitorService {
    pub fn new(exit: Arc<AtomicBool>, report_os_network_stats: bool) -> Self {
        info!("Starting SystemMonitorService");
        let thread_hdl = Builder::new()
            .name("system-monitor".to_string())
            .spawn(move || {
                Self::run(exit, report_os_network_stats);
            })
            .unwrap();

        Self { thread_hdl }
    }

    #[cfg(target_os = "linux")]
    fn process_udp_stats(udp_stats: &mut Option<UdpStats>) {
        match read_udp_stats(PROC_NET_SNMP_PATH) {
            Ok(new_stats) => {
                if let Some(old_stats) = udp_stats {
                    SystemMonitorService::report_udp_stats(old_stats, &new_stats);
                }
                *udp_stats = Some(new_stats);
            }
            Err(e) => warn!("read_udp_stats: {}", e),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn process_udp_stats(_udp_stats: &mut Option<UdpStats>) {}

    #[cfg(target_os = "linux")]
    fn report_udp_stats(old_stats: &UdpStats, new_stats: &UdpStats) {
        datapoint_info!(
            "net-stats-validator",
            (
                "in_datagrams_delta",
                new_stats.in_datagrams - old_stats.in_datagrams,
                i64
            ),
            (
                "no_ports_delta",
                new_stats.no_ports - old_stats.no_ports,
                i64
            ),
            (
                "in_errors_delta",
                new_stats.in_errors - old_stats.in_errors,
                i64
            ),
            (
                "out_datagrams_delta",
                new_stats.out_datagrams - old_stats.out_datagrams,
                i64
            ),
            (
                "rcvbuf_errors_delta",
                new_stats.rcvbuf_errors - old_stats.rcvbuf_errors,
                i64
            ),
            (
                "sndbuf_errors_delta",
                new_stats.sndbuf_errors - old_stats.sndbuf_errors,
                i64
            ),
            (
                "in_csum_errors_delta",
                new_stats.in_csum_errors - old_stats.in_csum_errors,
                i64
            ),
            (
                "ignored_multi_delta",
                new_stats.ignored_multi - old_stats.ignored_multi,
                i64
            ),
            ("in_errors", new_stats.in_errors, i64),
            ("rcvbuf_errors", new_stats.rcvbuf_errors, i64),
            ("sndbuf_errors", new_stats.sndbuf_errors, i64),
        );
    }

    fn calc_percent(numerator: u64, denom: u64) -> f64 {
        if denom == 0 {
            0.0
        } else {
            (numerator as f64 / denom as f64) * 100.0
        }
    }

    fn report_mem_stats() {
        if let Ok(info) = sys_info::mem_info() {
            // stats are returned in kb.
            const KB: u64 = 1_024;
            datapoint_info!(
                "memory-stats",
                ("total", info.total * KB, i64),
                ("swap_total", info.swap_total, i64),
                (
                    "free_percent",
                    Self::calc_percent(info.free, info.total),
                    f64
                ),
                (
                    "used_bytes",
                    info.total.saturating_sub(info.avail) * KB,
                    i64
                ),
                (
                    "avail_percent",
                    Self::calc_percent(info.avail, info.total),
                    f64
                ),
                (
                    "buffers_percent",
                    Self::calc_percent(info.buffers, info.total),
                    f64
                ),
                (
                    "cached_percent",
                    Self::calc_percent(info.cached, info.total),
                    f64
                ),
                (
                    "swap_free_percent",
                    Self::calc_percent(info.swap_free, info.swap_total),
                    f64
                ),
            )
        }
    }

    pub fn run(exit: Arc<AtomicBool>, report_os_network_stats: bool) {
        let mut udp_stats = None;

        let udp_timer = AtomicInterval::default();
        let mem_timer = AtomicInterval::default();
        loop {
            if exit.load(Ordering::Relaxed) {
                break;
            }

            if report_os_network_stats && udp_timer.should_update(SAMPLE_INTERVAL_UDP_MS) {
                SystemMonitorService::process_udp_stats(&mut udp_stats);
            }

            if mem_timer.should_update(SAMPLE_INTERVAL_MEM_MS) {
                SystemMonitorService::report_mem_stats();
            }

            sleep(SLEEP_INTERVAL);
        }
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_udp_stats() {
        let mut mock_snmp =
b"Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates
Ip: 1 64 357 0 2 0 0 0 355 315 0 6 0 0 0 0 0 0 0
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps
Icmp: 3 0 0 3 0 0 0 0 0 0 0 0 0 0 7 0 7 0 0 0 0 0 0 0 0 0 0
IcmpMsg: InType3 OutType3
IcmpMsg: 3 7
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 29 1 0 0 5 318 279 0 0 4 0
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti
Udp: 27 7 0 30 0 0 0 0
UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti
UdpLite: 0 0 0 0 0 0 0 0" as &[u8];
        let stats = parse_udp_stats(&mut mock_snmp).unwrap();
        assert_eq!(stats.out_datagrams, 30);
        assert_eq!(stats.no_ports, 7);

        let mut mock_snmp = b"unexpected data" as &[u8];
        let stats = parse_udp_stats(&mut mock_snmp);
        assert!(stats.is_err());
    }

    #[test]
    fn test_calc_percent() {
        assert!(SystemMonitorService::calc_percent(99, 100) < 100.0);
        let one_tb_as_kb = (1u64 << 40) >> 10;
        assert!(SystemMonitorService::calc_percent(one_tb_as_kb - 1, one_tb_as_kb) < 100.0);
    }
}
