use {
    clap::{App, Arg},
    std::net::{SocketAddr, TcpListener},
    sino_logger
};

fn main() {
    sino_logger::setup();
    let matches = App::new("sino-ip-address-server")
        .version(sino_version::version!())
        .arg(
            Arg::with_name("port")
                .index(1)
                .required(true)
                .help("TCP port to bind to"),
        )
        .get_matches();

    let port = matches.value_of("port").unwrap();
    let port = port
        .parse()
        .unwrap_or_else(|_| panic!("Unable to parse {}", port));
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], port));
    let tcp_listener = TcpListener::bind(bind_addr).expect("unable to start tcp listener");
    let _runtime = sino_net_utils::ip_echo_server(tcp_listener, /*shred_version=*/ None);
    loop {
        std::thread::park();
    }
}
