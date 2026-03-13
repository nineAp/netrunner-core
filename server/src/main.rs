use netrunner_core::{
    logger_init,
    proxy::{connection::connection::ConnectionRole, network::Network},
};

use clap::Parser;
#[derive(Parser, Debug)]
#[command(author, version, about = "Netrunner Proxy Server")]
struct Args {
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    host: String,
}

fn main() {
    logger_init();
    let args = Args::parse();
    let net = Network::new(args.host, args.port, ConnectionRole::Server, None);

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    rt.block_on(async {
        net.run().await;
    });
}
