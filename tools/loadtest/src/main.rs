//! Нагрузочный тест `netrunner-server` для сайзинга прод-серверов.
//!
//! Одна инвокация = один уровень конкурентности = один изолированный прогон:
//! поднимает свежий сервер (реальный скомпилированный бинарник, отдельным
//! процессом — чтобы мерить именно ЕГО ресурсы, не путая с нагрузочным
//! генератором) + локальный echo-таргет, гоняет `--concurrency` параллельных
//! "виртуальных пользователей" через настоящий клиентский стек
//! (`ClientHandler::connect` + `RawCastFrame`, тот же публичный API, что и
//! реальное приложение) в течение `--duration-secs`, снимает RSS/CPU процесса
//! сервера из `/proc`, печатает результат одной JSON-строкой в stdout.
//!
//! Почему процесс на уровень, а не один долгоживущий процесс на все уровни:
//! `ClientHandler::connect` — это "fire and forget" (спавнит фоновые задачи и
//! возвращается сразу же, ещё до реального хендшейка), и они не имеют чистого
//! способа самоостановки извне. Гонять по процессу на уровень — самый простой
//! и надёжный способ гарантировать отсутствие "хвостов" из предыдущего уровня.
//!
//! Каждый пользователь поднимает `MAX_TUNNEL_LEGS` (сейчас 4) TCP-соединений к
//! серверу — это сознательный выбор реального протокола (избыточность/
//! multipath), не артефакт теста. Держи это в уме при интерпретации: N
//! "пользователей" ⇒ примерно 4N настоящих TCP-соединений на сервере.

use clap::Parser;
use netrunner_core::net::{ClientHandler, NetworkConfig};
use netrunner_core::rawcast::{LocalProtocol, RawCastEvent, RawCastFrame};
use serde::Serialize;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(about = "Нагрузочный тест netrunner-server: один запуск = один уровень конкурентности")]
struct Args {
    /// Путь к скомпилированному бинарнику netrunner-server.
    #[arg(long, default_value = "../../target/release/netrunner-server")]
    server_bin: String,

    /// Сколько параллельных "виртуальных пользователей" (каждый — полноценный
    /// клиентский туннель через ClientHandler::connect, т.е. до 4 TCP-соединений).
    #[arg(long, default_value_t = 100)]
    concurrency: usize,

    /// Сколько секунд сустейнить трафик на каждом пользователе.
    #[arg(long, default_value_t = 15)]
    duration_secs: u64,

    /// Целевая скорость на одного пользователя, байт/сек, в каждую сторону
    /// (echo отражает обратно столько же). 0 — слать максимально быстро без пауз.
    #[arg(long, default_value_t = 32 * 1024)]
    rate_bps: u64,

    /// Размер одного Data-кадра полезной нагрузки.
    #[arg(long, default_value_t = 4096)]
    chunk_size: usize,

    /// Сколько секунд ждать, пока сервер поднимется и начнёт слушать порт.
    #[arg(long, default_value_t = 10)]
    startup_timeout_secs: u64,
}

#[derive(Default)]
struct UserStats {
    handshake_successes: AtomicU64,
    handshake_failures: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    first_byte_latency_ms: Mutex<Vec<u64>>,
}

#[derive(Serialize)]
struct LoadTestResult {
    concurrency: usize,
    duration_secs: u64,
    rate_bps_target: u64,
    chunk_size: usize,
    handshake_successes: u64,
    handshake_failures: u64,
    handshake_success_rate: f64,
    bytes_sent: u64,
    bytes_received: u64,
    aggregate_mbps_down: f64,
    aggregate_mbps_up: f64,
    first_byte_latency_ms_p50: u64,
    first_byte_latency_ms_p95: u64,
    first_byte_latency_ms_max: u64,
    server_rss_mb: f64,
    server_cpu_cores: f64,
    server_open_fds: u64,
    loadtest_cpu_cores_self: f64,
    wall_elapsed_secs: f64,
}

fn find_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind for free port probe")
        .local_addr()
        .unwrap()
        .port()
}

/// `VmRSS` из `/proc/<pid>/status`, в КБ.
fn read_rss_kb(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.trim().split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// `utime + stime` (в тиках) из `/proc/<pid>/stat`. `comm` (2-е поле) в скобках
/// и может содержать пробелы — ищем последнюю `)` и считаем поля от неё.
fn read_cpu_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // Поля после ')' начинаются с исходного поля #3 (state) под индексом 0.
    // utime = поле #14 -> индекс 11; stime = поле #15 -> индекс 12.
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

fn read_open_fds(pid: u32) -> u64 {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map(|d| d.count() as u64)
        .unwrap_or(0)
}

fn clk_tck() -> f64 {
    let tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if tck > 0 {
        tck as f64
    } else {
        100.0
    }
}

async fn wait_for_server(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Локальный echo-таргет: то, во что сервер реально проксирует туннельный
/// трафик виртуальных пользователей (имитирует "интернет" без сети).
async fn spawn_echo_server() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn run_virtual_user(
    server_addr: String,
    echo_addr: SocketAddr,
    duration: Duration,
    chunk_size: usize,
    rate_bps: u64,
    stats: Arc<UserStats>,
) {
    let (app_tx, rx_from_engine) = mpsc::channel::<RawCastFrame>(256);
    let (tx_to_engine, mut app_rx) = mpsc::channel::<RawCastFrame>(256);

    let started = Instant::now();

    let muxer =
        match ClientHandler::connect(&server_addr, "example.com", rx_from_engine, tx_to_engine)
            .await
        {
            Ok(m) => m,
            Err(_) => {
                stats.handshake_failures.fetch_add(1, Relaxed);
                return;
            }
        };

    // connect() возвращается сразу же, спавнит фоновые задачи и не ждёт, пока
    // реально поднимется хоть одна нога — Connect-кадр, отправленный раньше,
    // чем select_leg() найдёт живую ногу, молча теряется (send_control по
    // FrameType::Connect идёт через try_send, ошибка отбрасывается вызывающим
    // кодом внутри connect()). Настоящий TUN-трафик почти никогда не бьёт по
    // этой гонке (первый пакет юзера обычно приходит куда позже, чем
    // устанавливается первая нога), но синтетический генератор нагрузки бьёт
    // в неё гарантированно — поэтому ждём здесь явно.
    let leg_deadline = Instant::now() + Duration::from_secs(5);
    while muxer.active_legs_count() == 0 && Instant::now() < leg_deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    if muxer.active_legs_count() == 0 {
        stats.handshake_failures.fetch_add(1, Relaxed);
        return;
    }

    let ip = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => unreachable!("echo server is always bound on 127.0.0.1"),
    };
    let port = echo_addr.port();
    let socket_id: u64 = 1;

    if app_tx
        .send(RawCastFrame::connect(
            LocalProtocol::Tcp,
            socket_id,
            ip,
            port,
        ))
        .await
        .is_err()
    {
        stats.handshake_failures.fetch_add(1, Relaxed);
        return;
    }

    let stats_reader = stats.clone();
    let reader = tokio::spawn(async move {
        let mut recorded = false;
        while let Some(frame) = app_rx.recv().await {
            if frame.event == RawCastEvent::Data {
                stats_reader
                    .bytes_received
                    .fetch_add(frame.payload.len() as u64, Relaxed);
                if !recorded {
                    recorded = true;
                    stats_reader.handshake_successes.fetch_add(1, Relaxed);
                    stats_reader
                        .first_byte_latency_ms
                        .lock()
                        .unwrap()
                        .push(started.elapsed().as_millis() as u64);
                }
            }
        }
    });

    let payload = bytes::Bytes::from(vec![0xABu8; chunk_size]);
    let interval = if rate_bps == 0 {
        None
    } else {
        Some(Duration::from_millis(
            (chunk_size as u64 * 1000 / rate_bps).max(1),
        ))
    };

    let end = Instant::now() + duration;
    while Instant::now() < end {
        let frame = RawCastFrame::data(LocalProtocol::Tcp, socket_id, ip, port, payload.clone());
        if app_tx.send(frame).await.is_err() {
            break;
        }
        stats.bytes_sent.fetch_add(chunk_size as u64, Relaxed);
        if let Some(iv) = interval {
            tokio::time::sleep(iv).await;
        }
    }

    drop(app_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), reader).await;
}

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * pct).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    NetworkConfig::init_global(1450); // тот же MTU, что и у реального клиента

    let echo_addr = spawn_echo_server().await;
    let server_port = find_free_port();
    let server_addr_str = format!("127.0.0.1:{server_port}");

    let mut server_child = Command::new(&args.server_bin)
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &server_port.to_string(),
            "--decoy-host",
            "example.com",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "не удалось запустить {} — собери сервер (cargo build --release -p netrunner-server) и укажи путь через --server-bin: {e}",
                args.server_bin
            )
        });
    let server_pid = server_child.id();

    let ready = wait_for_server(
        server_addr_str.parse().unwrap(),
        Duration::from_secs(args.startup_timeout_secs),
    )
    .await;
    if !ready {
        eprintln!("сервер не поднялся за {}с", args.startup_timeout_secs);
        let _ = server_child.kill();
        std::process::exit(1);
    }
    // Дать серверу устаканиться после старта (аллокации рантайма и т.п. не
    // должны попасть в измеряемый CPU-дельту).
    tokio::time::sleep(Duration::from_millis(300)).await;

    let cpu_start = read_cpu_ticks(server_pid).unwrap_or(0);
    let self_cpu_start = read_cpu_ticks(std::process::id()).unwrap_or(0);
    let wall_start = Instant::now();

    let stats = Arc::new(UserStats::default());
    let mut handles = Vec::with_capacity(args.concurrency);
    for _ in 0..args.concurrency {
        let s = server_addr_str.clone();
        let st = stats.clone();
        handles.push(tokio::spawn(run_virtual_user(
            s,
            echo_addr,
            Duration::from_secs(args.duration_secs),
            args.chunk_size,
            args.rate_bps,
            st,
        )));
        tokio::time::sleep(Duration::from_micros(200)).await;
    }

    for h in handles {
        let _ = h.await;
    }

    let wall_elapsed = wall_start.elapsed().as_secs_f64();
    let cpu_end = read_cpu_ticks(server_pid).unwrap_or(cpu_start);
    let self_cpu_end = read_cpu_ticks(std::process::id()).unwrap_or(self_cpu_start);
    let rss_kb = read_rss_kb(server_pid).unwrap_or(0);
    let open_fds = read_open_fds(server_pid);
    let clk = clk_tck();

    let mut latencies = stats.first_byte_latency_ms.lock().unwrap().clone();
    latencies.sort_unstable();

    let successes = stats.handshake_successes.load(Relaxed);
    let failures = stats.handshake_failures.load(Relaxed);
    let bytes_sent = stats.bytes_sent.load(Relaxed);
    let bytes_received = stats.bytes_received.load(Relaxed);

    let result = LoadTestResult {
        concurrency: args.concurrency,
        duration_secs: args.duration_secs,
        rate_bps_target: args.rate_bps,
        chunk_size: args.chunk_size,
        handshake_successes: successes,
        handshake_failures: failures,
        handshake_success_rate: if args.concurrency > 0 {
            successes as f64 / args.concurrency as f64
        } else {
            0.0
        },
        bytes_sent,
        bytes_received,
        aggregate_mbps_down: (bytes_received as f64 * 8.0 / 1_000_000.0) / wall_elapsed,
        aggregate_mbps_up: (bytes_sent as f64 * 8.0 / 1_000_000.0) / wall_elapsed,
        first_byte_latency_ms_p50: percentile(&latencies, 0.50),
        first_byte_latency_ms_p95: percentile(&latencies, 0.95),
        first_byte_latency_ms_max: latencies.last().copied().unwrap_or(0),
        server_rss_mb: rss_kb as f64 / 1024.0,
        server_cpu_cores: ((cpu_end - cpu_start) as f64 / clk) / wall_elapsed,
        server_open_fds: open_fds,
        loadtest_cpu_cores_self: ((self_cpu_end - self_cpu_start) as f64 / clk) / wall_elapsed,
        wall_elapsed_secs: wall_elapsed,
    };

    println!("{}", serde_json::to_string(&result).unwrap());

    let _ = server_child.kill();
    let _ = server_child.wait();
}
