//! Проверка «пачка одновременных Connect на одной сессии» (так открывает соединения браузер).
//!
//! Поднимает реальный `netrunner-server` отдельным процессом и локальный echo-таргет, один клиент (`ClientHandler::connect`)
//! открывает `--streams` потоков сразу, в каждый шлёт короткое сообщение и ждёт эхо. Печатает одну JSON-строку:
//! сколько потоков получили эхо (`echoed`) и сколько повисли (`hung`: Connect потерян, байта не пришло).
//!
//! Использует только публичный API клиента, поэтому собирается и со старым ядром — для сравнения «до/после» правки
//! доставки Connect-кадров (muxer: Connect — критичный кадр, идёт через `send().await`, а не `try_send`).

use clap::Parser;
use netrunner_core::net::{ClientHandler, NetworkConfig};
use netrunner_core::rawcast::{LocalProtocol, RawCastEvent, RawCastFrame};
use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
struct Args {
    /// Бинарник `netrunner-server`.
    #[arg(long)]
    server_bin: String,
    /// Сколько потоков открыть одновременно.
    #[arg(long, default_value_t = 64)]
    streams: u64,
    /// Сколько раундов (каждый — новая сессия клиента).
    #[arg(long, default_value_t = 3)]
    rounds: u32,
    /// Сколько секунд ждать эхо после отправки.
    #[arg(long, default_value_t = 15)]
    wait_secs: u64,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn echo_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    NetworkConfig::init_global(1450);
    let echo = echo_server().await;
    let std::net::IpAddr::V4(ip) = echo.ip() else {
        unreachable!()
    };

    let port = free_port();
    let mut server = Command::new(&args.server_bin)
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--decoy-host",
            "example.com",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("не удалось запустить сервер");
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(&addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let (mut echoed_total, mut hung_total) = (0u64, 0u64);
    for _ in 0..args.rounds {
        let (to_tunnel, rx_from_engine) = mpsc::channel::<RawCastFrame>(1024);
        let (tx_to_engine, mut from_tunnel) = mpsc::channel::<RawCastFrame>(1024);
        let muxer = ClientHandler::connect(&addr, "example.com", None, None, rx_from_engine, tx_to_engine)
            .await
            .expect("connect");
        let deadline = Instant::now() + Duration::from_secs(10);
        while muxer.active_legs_count() == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(muxer.active_legs_count() > 0, "ни одна нога не поднялась");

        // Все Connect — одной пачкой, без пауз.
        for id in 1..=args.streams {
            let mut connect = RawCastFrame::connect(LocalProtocol::Tcp, id, ip, echo.port());
            connect.payload = bytes::Bytes::from(echo.to_string());
            to_tunnel.send(connect).await.unwrap();
            to_tunnel
                .send(RawCastFrame::data(
                    LocalProtocol::Tcp,
                    id,
                    ip,
                    echo.port(),
                    bytes::Bytes::from_static(b"ping"),
                ))
                .await
                .unwrap();
        }
        let mut seen: HashSet<u64> = HashSet::new();
        let end = tokio::time::Instant::now() + Duration::from_secs(args.wait_secs);
        while (seen.len() as u64) < args.streams {
            match tokio::time::timeout_at(end, from_tunnel.recv()).await {
                Ok(Some(frame)) if frame.event == RawCastEvent::Data => {
                    seen.insert(frame.socket_id);
                }
                Ok(Some(_)) => {}
                _ => break,
            }
        }
        echoed_total += seen.len() as u64;
        hung_total += args.streams - seen.len() as u64;
        drop(to_tunnel);
        drop(muxer);
    }
    let _ = server.kill();
    println!(
        "{{\"streams\":{},\"rounds\":{},\"echoed\":{},\"hung\":{}}}",
        args.streams, args.rounds, echoed_total, hung_total
    );
}
