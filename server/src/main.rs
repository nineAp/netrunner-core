use clap::Parser;
use netrunner_core::net::{network::Network, ConnectionRole};
use netrunner_logger::Logger;
use tokio_util::sync::CancellationToken;
#[derive(Parser, Debug)]
#[command(author, version, about = "Netrunner Proxy Server")]
struct Args {
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    host: String,
}

fn main() {
    Logger::init("./logs".into());
    Logger::global().set_level("error");
    let args = Args::parse();
    let net = Network::new(args.host, args.port, ConnectionRole::Server);

    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

    rt.block_on(async {
        net.run(CancellationToken::new()).await;
    });
}
