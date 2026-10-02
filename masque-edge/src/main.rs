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

    /// Control-plane endpoint which validates per-device tokens.
    /// MASQUE_AUTH_URL is used when omitted.
    #[arg(long)]
    auth_url: Option<String>,

    /// Control-plane endpoint for traffic accounting. MASQUE_USAGE_URL is
    /// used when omitted, then it is derived from the validation URL.
    #[arg(long)]
    usage_url: Option<String>,

    /// Per-node X-Internal-Secret for the control-plane auth endpoint.
    /// MASQUE_AUTH_SECRET (or PROXY_INTERNAL_SECRET) is used when omitted.
    #[arg(long)]
    auth_secret: Option<String>,

    /// Explicitly run as an open proxy. Intended only for isolated local tests.
    #[arg(long, default_value_t = false)]
    allow_anonymous: bool,

    /// Permit loopback, private, link-local and other non-public destinations.
    #[arg(long, default_value_t = false)]
    allow_private_targets: bool,

    /// Maximum simultaneous QUIC connections. MASQUE_MAX_CONNECTIONS is
    /// used when omitted.
    #[arg(long)]
    max_connections: Option<usize>,
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
    // Провайдер выбирается до разбора сертификатов и приёма QUIC — см.
    // `server::install_crypto_provider`, там же разбор, почему это нужно.
    server::install_crypto_provider();

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
            let auth_url = args
                .auth_url
                .or_else(|| std::env::var("MASQUE_AUTH_URL").ok())
                .filter(|value| !value.trim().is_empty());
            let auth_secret = args
                .auth_secret
                .or_else(|| std::env::var("MASQUE_AUTH_SECRET").ok())
                .or_else(|| std::env::var("PROXY_INTERNAL_SECRET").ok())
                .filter(|value| !value.trim().is_empty());
            let usage_url = args
                .usage_url
                .or_else(|| std::env::var("MASQUE_USAGE_URL").ok())
                .filter(|value| !value.trim().is_empty());
            let mesh_enabled = std::env::var("MESH_ENABLED")
                .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
                .unwrap_or(false);
            let mesh = if mesh_enabled {
                let node_id = std::env::var("PROXY_NODE_ID")
                    .context("MESH_ENABLED requires PROXY_NODE_ID")?;
                let backend_url =
                    std::env::var("BACKEND_URL").context("MESH_ENABLED requires BACKEND_URL")?;
                let internal_secret = std::env::var("PROXY_INTERNAL_SECRET")
                    .or_else(|_| std::env::var("MASQUE_AUTH_SECRET"))
                    .context("MESH_ENABLED requires PROXY_INTERNAL_SECRET")?;
                Some(server::MeshConfig {
                    node_id,
                    backend_url,
                    internal_secret,
                })
            } else {
                None
            };
            let max_connections = args
                .max_connections
                .or_else(|| {
                    std::env::var("MASQUE_MAX_CONNECTIONS")
                        .ok()
                        .and_then(|value| value.parse().ok())
                })
                .unwrap_or(4096);
            if max_connections == 0 || max_connections > 100_000 {
                bail!("MASQUE_MAX_CONNECTIONS must be between 1 and 100000");
            }

            let auth = match (auth_url, auth_secret, token, args.allow_anonymous) {
                (Some(url), Some(secret), None, false) => {
                    let usage_url = usage_url.unwrap_or_else(|| {
                        url.strip_suffix("/validate")
                            .map(|prefix| format!("{prefix}/usage"))
                            .unwrap_or_else(|| format!("{url}/usage"))
                    });
                    auth::BearerAuth::remote(url, usage_url, secret)?
                }
                (None, None, Some(token), false) => auth::BearerAuth::new(Some(token)),
                (None, None, None, true) => auth::BearerAuth::new(None),
                (Some(_), None, _, _) | (None, Some(_), _, _) => {
                    bail!("MASQUE_AUTH_URL and MASQUE_AUTH_SECRET must be configured together")
                }
                (Some(_), Some(_), Some(_), _) => {
                    bail!("remote auth and a static MASQUE_TOKEN cannot be enabled together")
                }
                _ => bail!(
                    "remote auth or --token/MASQUE_TOKEN is required unless --allow-anonymous is explicit"
                ),
            };

            server::run(server::Config {
                bind: args.bind,
                cert: args.cert,
                key: args.key,
                auth,
                allow_private_targets: args.allow_private_targets,
                max_connections,
                mesh,
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
