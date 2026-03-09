uniffi::setup_scaffolding!();
pub mod connections;
pub mod tun;
use std::sync::{Arc, Mutex};

use netrunner_core::proxy::{connection::connection::ConnectionRole, network::Network};
use smoltcp::{iface::Config, phy::DeviceCapabilities};
use std::net::Ipv4Addr;
use std::sync::OnceLock;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tracing::info;

use crate::tun::{engine::Engine, tun::Tun};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
    })
}
// --- Обертка для Session ---
#[derive(uniffi::Object)]
pub struct Session {
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

#[uniffi::export]
impl Session {
    pub fn stop(&self) {
        let mut guard = self.shutdown_tx.lock().unwrap();
        if let Some(tx) = guard.take() {
            let _ = tx.send(());
        }
    }
}

// --- Фабрика (SessionManager) ---
#[derive(uniffi::Object)]
pub struct SessionManager;

#[uniffi::constructor]
impl SessionManager {
    pub fn new() -> Self {
        Self
    }
}

#[uniffi::export]
impl SessionManager {
    pub fn start(&self, remote_address: String, tun_fd: Option<i32>) -> Arc<Session> {
        let (tx, rx) = oneshot::channel();
        let runtime = get_runtime();
        runtime.spawn(async move {
            info!("Starting VPN session...");

            let tun_device = if let Some(fd) = tun_fd {
                info!("Using provided FD for TUN: {}", fd);
                Tun::from_android_fd(fd).expect("Failed to init TUN from FD")
            } else {
                info!("Creating TUN device manually");
                Tun::create(|config| {
                    config
                        .tun_name("tun0")
                        .address((10, 0, 0, 1))
                        // ... настройки ...
                        .up();
                })
                .expect("Failed to init TUN")
            };

            tun_device.setup_routing();
            tun_device.setup_dns_redirection();

            // 2. Инициализация сети
            let config = Config::new(smoltcp::wire::HardwareAddress::Ip);
            let mut caps = DeviceCapabilities::default();
            caps.max_transmission_unit = 1500;
            caps.medium = smoltcp::phy::Medium::Ip;

            let network = Network::new(
                "0.0.0.0".into(),
                8080,
                ConnectionRole::Client,
                Some(remote_address),
            );

            let proxy_ip = network.get_self_local_address();

            // Запускаем сетевой поток
            let net_handle = tokio::spawn(async move {
                network.run().await;
            });

            // 3. Инициализация Engine
            let mut engine = Engine::new(config, caps, proxy_ip);
            engine.set_any_ip(true);
            engine.set_transparent_mode();
            engine.set_default_gateway(Ipv4Addr::new(10, 0, 0, 2));
            engine.activate();

            // 4. Главный цикл с поддержкой остановки
            tokio::select! {
                _ = engine.run(tun_device) => {
                    info!("Engine loop finished naturally.");
                }
                _ = rx => {
                    info!("Shutdown signal received. Cleaning up...");
                }
            }

            net_handle.abort();
            info!("VPN session stopped.");
        });

        Arc::new(Session {
            shutdown_tx: Mutex::new(Some(tx)),
        })
    }
}
