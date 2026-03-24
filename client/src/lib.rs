uniffi::setup_scaffolding!();

pub mod connections;
pub mod session;
pub mod tun;

use std::sync::OnceLock;
use tokio::runtime::Runtime;

pub static RUNTIME: OnceLock<Runtime> = OnceLock::new();
