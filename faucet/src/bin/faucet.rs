use {
    clap::{crate_description, crate_name, values_t, App, Arg},
    log::*,
    clap_utils::input_parsers::{wens_of_sor, value_of},
    faucet::{
        faucet::{run_faucet, Faucet, FAUCET_PORT},
        socketaddr,
    },
    sdk::signature::read_keypair_file,
    std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
        thread,
    },
};

#[tokio::main]
async fn main() {
    let default_keypair = cli_config::Config::default().keypair_path;

    sino_logger::setup_with_default("solana=info");
    metrics::set_panic_hook("faucet", /*version:*/ None);
    let matches = App::new(crate_name!())
        .about(crate_description!())
        .version(sino_version::version!())
        .arg(
            Arg::with_name("keypair")
                .short("k")
                .long("keypair")
                .value_name("PATH")
                .takes_value(true)
                .required(true)
                .default_value(&default_keypair)
                .help("File from which to read the faucet's keypair"),
        )
        .arg(
            Arg::with_name("slice")
                .long("slice")
                .value_name("SECS")
                .takes_value(true)
                .help("Time slice over which to limit requests to faucet"),
        )
        .arg(
            Arg::with_name("per_time_cap")
                .long("per-time-cap")
                .alias("cap")
                .value_name("NUM")
                .takes_value(true)
                .help("Request limit for time slice, in SOR"),
        )
        .arg(
            Arg::with_name("per_request_cap")
                .long("per-request-cap")
                .value_name("NUM")
                .takes_value(true)
                .help("Request limit for a single request, in SOR"),
        )
        .arg(
            Arg::with_name("allowed_ip")
                .long("allow-ip")
                .value_name("IP_ADDRESS")
                .takes_value(true)
                .multiple(true)
                .help(
                    "Allow requests from a particular IP address without request limit; \
                    recipient address will be used to check request limits instead",
                ),
        )
        .get_matches();

    let faucet_keypair = read_keypair_file(matches.value_of("keypair").unwrap())
        .expect("failed to read client keypair");

    let time_slice = value_of(&matches, "slice");
    let per_time_cap = wens_of_sor(&matches, "per_time_cap");
    let per_request_cap = wens_of_sor(&matches, "per_request_cap");

    let allowed_ips: HashSet<_> = values_t!(matches.values_of("allowed_ip"), IpAddr)
        .unwrap_or_default()
        .into_iter()
        .collect();

    let faucet_addr = socketaddr!(0, FAUCET_PORT);

    let faucet = Arc::new(Mutex::new(Faucet::new_with_allowed_ips(
        faucet_keypair,
        time_slice,
        per_time_cap,
        per_request_cap,
        allowed_ips,
    )));

    let faucet1 = faucet.clone();
    thread::spawn(move || loop {
        let time = faucet1.lock().unwrap().time_slice;
        thread::sleep(time);
        debug!("clearing ip cache");
        faucet1.lock().unwrap().clear_caches();
    });

    run_faucet(faucet, faucet_addr, None).await;
}
