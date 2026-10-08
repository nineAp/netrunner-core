//! Живой захват трафика (Linux, `AF_PACKET`) — запись прямо из бинаря,
//! без `tcpdump`.
//!
//! Идея: пользователь запускает запись, сёрфит в браузере, останавливает
//! (Ctrl+C / по таймеру / когда набралось достаточно соединений) — и получает
//! данные для сборки профиля. Захват хранит **только начало** каждого
//! TCP-соединения на заданных портах (по умолчанию 443): этого хватает для
//! `ClientHello` и первого flight'а сервера, а память остаётся ограниченной.
//!
//! Нужны права на сырой сокет: `root` либо `CAP_NET_RAW`
//! (`sudo setcap cap_net_raw+ep ./netrunner-client`). Запись следует делать
//! **без включённого VPN** — иначе в захвате окажется наш собственный туннель,
//! а не браузер.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::net::{decode, Transport};
use super::{analyze_packets, write_pcap, Analysis, Packet};

/// Параметры записи.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Интерфейс (`eth0`, `wlan0`, `lo`); `None` — все.
    pub iface: Option<String>,
    /// TCP-порты, чей трафик интересен (источник или получатель).
    pub ports: Vec<u16>,
    /// Остановиться через столько времени.
    pub max_duration: Option<Duration>,
    /// Остановиться, когда набрано столько `ClientHello` одного (самого
    /// частого) отпечатка.
    pub stop_after_hellos: Option<usize>,
    /// Сколько байт полезной нагрузки хранить на направление соединения.
    pub bytes_per_flow: usize,
    /// Общий предел памяти под захват.
    pub max_total_bytes: usize,
    /// Как часто пересчитывать прогресс.
    pub progress_every: Duration,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            iface: None,
            ports: vec![443],
            max_duration: Some(Duration::from_secs(120)),
            stop_after_hellos: None,
            bytes_per_flow: 48 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            progress_every: Duration::from_millis(700),
        }
    }
}

/// Срез состояния для вывода пользователю.
#[derive(Debug, Clone, Default)]
pub struct Progress {
    pub elapsed: Duration,
    pub packets_seen: u64,
    pub packets_kept: u64,
    pub tcp_flows: usize,
    pub client_hellos: usize,
    /// Число `ClientHello` у самого частого отпечатка.
    pub best_group_hellos: usize,
    /// Различных отпечатков (JA4) пока видно.
    pub groups: usize,
}

/// Ошибки записи.
#[derive(Debug)]
pub enum CaptureError {
    /// Нет прав на сырой сокет.
    Permission,
    /// Интерфейс не найден.
    NoSuchInterface(String),
    Io(io::Error),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Permission => write!(
                f,
                "no permission to open a raw packet socket: run as root or grant the binary \
                 CAP_NET_RAW (sudo setcap cap_net_raw+ep <binary>)"
            ),
            Self::NoSuchInterface(i) => write!(f, "network interface {i:?} not found"),
            Self::Io(e) => write!(f, "capture I/O error: {e}"),
        }
    }
}

impl std::error::Error for CaptureError {}

/// Что записано.
pub struct Recording {
    /// Захваченные кадры (владеющие копии) и тип канального уровня каждого.
    frames: Vec<(u64, u32, Vec<u8>)>,
    pub progress: Progress,
}

impl Recording {
    fn packets(&self) -> Vec<Packet<'_>> {
        self.frames
            .iter()
            .map(|(ts, link, d)| Packet {
                ts_nanos: *ts,
                link_type: *link,
                orig_len: d.len() as u32,
                data: d,
            })
            .collect()
    }

    /// Разбор записи.
    pub fn analyze(&self) -> Analysis {
        analyze_packets(&self.packets())
    }

    /// Классический `pcap` (для сохранения/повторного разбора/Wireshark).
    /// Кадры с разными типами канального уровня (`-i any` на смеси
    /// Ethernet/raw) пишутся как есть: первый определяет заголовок файла, поэтому
    /// несовместимые отбрасываются.
    pub fn to_pcap(&self) -> Vec<u8> {
        let all = self.packets();
        let link = all.first().map_or(1, |p| p.link_type);
        let same: Vec<Packet<'_>> = all.into_iter().filter(|p| p.link_type == link).collect();
        write_pcap(&same)
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

// ARPHRD_* → LINKTYPE_*
fn link_type_for_hatype(hatype: u16) -> Option<u32> {
    match hatype {
        1 | 772 => Some(1),              // ETHER, LOOPBACK (Ethernet-заголовок)
        65534 | 512 | 768 | 776 => Some(101), // NONE (tun), PPP, IPIP, SIT → raw IP
        _ => None,
    }
}

#[derive(Default)]
struct FlowCount {
    a_to_b: usize,
    b_to_a: usize,
}

/// Решает, сохранять ли кадр, и учитывает объём потока.
struct Filter {
    ports: Vec<u16>,
    per_flow: usize,
    flows: HashMap<(std::net::IpAddr, u16, std::net::IpAddr, u16), FlowCount>,
}

impl Filter {
    fn keep(&mut self, link: u32, data: &[u8]) -> bool {
        let Some(Transport::Tcp(s)) = decode(link, data) else {
            return false;
        };
        if !(self.ports.contains(&s.sport) || self.ports.contains(&s.dport)) {
            return false;
        }
        // Служебные кадры (SYN/FIN/RST, пустые ACK) нужны для определения
        // клиента и границ — они малы, храним.
        if s.payload.is_empty() {
            return true;
        }
        let fwd = (s.src, s.sport) <= (s.dst, s.dport);
        let key = if fwd {
            (s.src, s.sport, s.dst, s.dport)
        } else {
            (s.dst, s.dport, s.src, s.sport)
        };
        let c = self.flows.entry(key).or_default();
        let slot = if fwd { &mut c.a_to_b } else { &mut c.b_to_a };
        if *slot >= self.per_flow {
            return false;
        }
        *slot += s.payload.len();
        true
    }
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// Записывает трафик, пока не сработает условие остановки.
///
/// `stop` — внешний флаг (обработчик Ctrl+C). `on_progress` вызывается
/// примерно раз в `progress_every`.
pub fn record(
    cfg: &CaptureConfig,
    stop: &AtomicBool,
    on_progress: &mut dyn FnMut(&Progress),
) -> Result<Recording, CaptureError> {
    let fd = open_socket(cfg.iface.as_deref())?;
    let mut buf = vec![0u8; 65_536 + 256];
    let started = Instant::now();
    let mut last_progress = Instant::now();
    let mut filter = Filter {
        ports: cfg.ports.clone(),
        per_flow: cfg.bytes_per_flow,
        flows: HashMap::new(),
    };
    let mut rec = Recording {
        frames: Vec::new(),
        progress: Progress::default(),
    };
    let mut kept_bytes = 0usize;
    let mut seen = 0u64;

    let result = loop {
        if stop.load(Ordering::Relaxed) {
            break Ok(());
        }
        if cfg.max_duration.is_some_and(|d| started.elapsed() >= d) {
            break Ok(());
        }
        match recv_one(fd, &mut buf) {
            Ok(Some((n, hatype))) => {
                seen += 1;
                let Some(link) = link_type_for_hatype(hatype) else {
                    continue;
                };
                let data = &buf[..n];
                if filter.keep(link, data) && kept_bytes + n <= cfg.max_total_bytes {
                    kept_bytes += n;
                    rec.frames.push((now_nanos(), link, data.to_vec()));
                }
            }
            Ok(None) => {} // таймаут чтения: проверим условия остановки
            Err(e) => break Err(CaptureError::Io(e)),
        }
        if last_progress.elapsed() >= cfg.progress_every {
            last_progress = Instant::now();
            let p = progress_of(&rec, seen, started.elapsed());
            on_progress(&p);
            if cfg.stop_after_hellos.is_some_and(|n| p.best_group_hellos >= n) {
                break Ok(());
            }
        }
    };
    // SAFETY: fd получен из socket() выше и больше не используется.
    unsafe { libc::close(fd) };
    result?;
    rec.progress = progress_of(&rec, seen, started.elapsed());
    on_progress(&rec.progress);
    Ok(rec)
}

fn progress_of(rec: &Recording, seen: u64, elapsed: Duration) -> Progress {
    let a = rec.analyze();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for h in &a.client_hellos {
        *counts.entry(super::ja4(h)).or_default() += 1;
    }
    Progress {
        elapsed,
        packets_seen: seen,
        packets_kept: rec.frames.len() as u64,
        tcp_flows: a.tcp_flows,
        client_hellos: a.client_hellos.len(),
        best_group_hellos: counts.values().copied().max().unwrap_or(0),
        groups: counts.len(),
    }
}

// ─────────────────────────────── сырой сокет ────────────────────────────────

fn open_socket(iface: Option<&str>) -> Result<libc::c_int, CaptureError> {
    // SAFETY: обычные вызовы libc с корректно инициализированными аргументами.
    unsafe {
        let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto);
        if fd < 0 {
            let e = io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::EPERM) | Some(libc::EACCES) => CaptureError::Permission,
                _ => CaptureError::Io(e),
            });
        }
        if let Some(name) = iface {
            let cname = std::ffi::CString::new(name)
                .map_err(|_| CaptureError::NoSuchInterface(name.to_string()))?;
            let idx = libc::if_nametoindex(cname.as_ptr());
            if idx == 0 {
                libc::close(fd);
                return Err(CaptureError::NoSuchInterface(name.to_string()));
            }
            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
            sll.sll_ifindex = idx as i32;
            if libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            ) < 0
            {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(CaptureError::Io(e));
            }
        }
        // Таймаут чтения: цикл регулярно проверяет флаг остановки.
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 200_000,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as u32,
        );
        Ok(fd)
    }
}

/// Читает один кадр: `Some((длина, ARPHRD_*))`, `None` по таймауту.
fn recv_one(fd: libc::c_int, buf: &mut [u8]) -> io::Result<Option<(usize, u16)>> {
    // SAFETY: buf валиден на всю длину; sll — выходной параметр нужного размера.
    unsafe {
        let mut sll: libc::sockaddr_ll = std::mem::zeroed();
        let mut slen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        let n = libc::recvfrom(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            &mut sll as *mut _ as *mut libc::sockaddr,
            &mut slen,
        );
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => {
                    Ok(None)
                }
                _ => Err(e),
            };
        }
        Ok(Some((n as usize, sll.sll_hatype)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::net::build::*;
    use super::super::net::TCP_ACK;
    use super::*;

    #[test]
    fn hatype_mapping() {
        assert_eq!(link_type_for_hatype(1), Some(1));
        assert_eq!(link_type_for_hatype(772), Some(1));
        assert_eq!(link_type_for_hatype(65534), Some(101));
        assert_eq!(link_type_for_hatype(9999), None);
    }

    #[test]
    fn filter_keeps_only_the_start_of_port_443_flows() {
        let mut f = Filter {
            ports: vec![443],
            per_flow: 100,
            flows: HashMap::new(),
        };
        let c = [10, 0, 0, 1];
        let s = [10, 0, 0, 2];
        let big = vec![7u8; 60];
        let up = |seq| ethernet(&tcp_v4(c, s, 5000, 443, seq, TCP_ACK, &big));
        assert!(f.keep(1, &up(1)));
        assert!(f.keep(1, &up(61))); // 120 > 100: этот ещё берём (порог по уже набранному)
        assert!(!f.keep(1, &up(121))); // дальше — нет
        // обратное направление считается отдельно
        let down = ethernet(&tcp_v4(s, c, 443, 5000, 1, TCP_ACK, &big));
        assert!(f.keep(1, &down));
        // чужой порт и пустой ACK
        assert!(!f.keep(1, &ethernet(&tcp_v4(c, s, 5000, 80, 1, TCP_ACK, &big))));
        assert!(f.keep(1, &ethernet(&tcp_v4(c, s, 5000, 443, 1, TCP_ACK, b""))));
        // не TCP
        assert!(!f.keep(1, &[0u8; 10]));
    }

    #[test]
    fn missing_interface_is_reported_or_permission_denied() {
        // Без прав — Permission, с правами — NoSuchInterface; в обоих случаях
        // это внятная ошибка, а не паника.
        let cfg = CaptureConfig {
            iface: Some("definitely-not-an-iface0".into()),
            ..Default::default()
        };
        let stop = AtomicBool::new(true);
        match record(&cfg, &stop, &mut |_| {}) {
            Err(CaptureError::Permission) | Err(CaptureError::NoSuchInterface(_)) => {}
            other => panic!("unexpected: {:?}", other.map(|_| ())),
        }
    }
}
