mod auth;
mod mobileconfig;
mod server;
mod target;

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "netrunner-masque-edge",
    version,
    about = "Netrunner MASQUE edge prototype"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the HTTP/3 CONNECT and CONNECT-UDP proxy.
    Serve(ServeArgs),
    /// Generate a manually installable iOS Network Relay profile.
    Profile(ProfileArgs),
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// UDP socket used by HTTP/3 / QUIC.
    #[arg(long, default_value = "0.0.0.0:443")]
    bind: SocketAddr,

    /// PEM certificate chain for the relay hostname.
    #[arg(long)]
    cert: PathBuf,

    /// PEM private key for the relay hostname.
    #[arg(long)]
    key: PathBuf,

    /// Bearer token accepted from the iOS relay profile. MASQUE_TOKEN is used when omitted.
    #[arg(long)]
    token: Option<String>,

    /// Explicitly run as an open proxy. Intended only for isolated local tests.
    #[arg(long, default_value_t = false)]
    allow_anonymous: bool,

    /// Permit loopback, private, link-local and other non-public destinations.
    #[arg(long, default_value_t = false)]
    allow_private_targets: bool,
}

#[derive(Debug, Args)]
struct ProfileArgs {
    /// Relay URL or RFC 9298 URI template, for example
    /// https://relay.example.com/.well-known/masque/udp/{target_host}/{target_port}/
    #[arg(long)]
    http3_url: String,

    /// Optional HTTP/2 fallback URL. Do not set this until an H2 listener is deployed.
    #[arg(long)]
    http2_url: Option<String>,

    /// Bearer token embedded into the per-device profile.
    #[arg(long)]
    token: String,

    /// Human-readable profile name shown by iOS.
    #[arg(long, default_value = "Netrunner Relay")]
    name: String,

    /// Route only these domains. When omitted, iOS routes all eligible TCP/UDP flows.
    #[arg(long = "match-domain")]
    match_domains: Vec<String>,

    /// Write to this path instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // The root release image builds this binary together with netrunner-server.
    // Cargo feature unification can therefore compile rustls with both Ring and
    // AWS-LC providers, in which case rustls deliberately refuses to guess at
    // runtime. MASQUE is configured for Ring, so select it explicitly before
    // parsing certificates or accepting QUIC connections.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "netrunner_masque_edge=info".into()),
        )
        .with_target(false)
        .compact()
        .init();

    match Cli::parse().command {
        Command::Serve(args) => {
            let token = args
                .token
                .or_else(|| std::env::var("MASQUE_TOKEN").ok())
                .filter(|token| !token.trim().is_empty());

            if token.is_none() && !args.allow_anonymous {
                bail!("--token or MASQUE_TOKEN is required unless --allow-anonymous is explicit");
            }

            server::run(server::Config {
                bind: args.bind,
                cert: args.cert,
                key: args.key,
                auth: auth::BearerAuth::new(token),
                allow_private_targets: args.allow_private_targets,
            })
            .await
        }
        Command::Profile(args) => {
            let profile = mobileconfig::render(&mobileconfig::ProfileOptions {
                name: args.name,
                http3_url: args.http3_url,
                http2_url: args.http2_url,
                bearer_token: args.token,
                match_domains: args.match_domains,
            });

            if let Some(output) = args.output {
                std::fs::write(&output, profile)
                    .with_context(|| format!("failed to write {}", output.display()))?;
            } else {
                print!("{profile}");
            }
            Ok(())
        }
    }
}
