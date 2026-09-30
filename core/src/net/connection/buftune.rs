//! Adaptive OS socket buffers for tunnel legs: keep them near 2×BDP.
//!
//! A fixed `SO_RCVBUF`/`SO_SNDBUF` is wrong in both directions. Too small (the old
//! 256 KB receive buffer) and the leg can never carry more than `buffer / RTT`
//! (~65 Mbit/s at 31 ms, regardless of the link). Too large (autotune up to
//! megabytes, or the old 1 MB send buffer plus a 4 MB channel) and a bulk flow
//! parks seconds of data in front of every interactive packet (bufferbloat).
//!
//! [`BufTuner`] measures the leg's goodput and propagation RTT and steers the
//! buffer to about twice the bandwidth-delay product: enough headroom for full
//! rate, but bounded queueing (at most ~2× the RTT of extra delay).
//!
//! The decision logic ([`decide`]) is pure and unit-tested; the tuner only adds
//! measurement and the `setsockopt` plumbing.

use std::time::{Duration, Instant};

use tokio::net::TcpStream;

/// Never shrink below this: interactive flows and slow start need some room.
pub const BUF_FLOOR: usize = 256 * 1024;
/// Applied right after the handshake, before any rate is known.
pub const BUF_INITIAL: usize = 512 * 1024;
/// Hard ceiling (also the pre-connect value so the TCP window scale is large
/// enough to ever use it; a window scale is fixed at the handshake).
pub const BUF_CAP: usize = 8 * 1024 * 1024;

/// Measurement/decision interval.
const INTERVAL: Duration = Duration::from_millis(250);
/// Span over which the minimum RTT is held (older minima expire).
const RTT_MIN_WINDOW: Duration = Duration::from_secs(10);
/// The buffer counts as a limit once the measured BDP exceeds this share of it.
const GROW_THRESHOLD: f64 = 0.6;
/// Only resize down when the target is below this share of the current size.
const SHRINK_RATIO: f64 = 0.7;
/// Per-interval decay of the rate estimate, so a finished burst fades out.
const RATE_DECAY: f64 = 0.85;

/// Which direction of the leg a tuner steers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// `SO_RCVBUF`: limits the download window the peer may use.
    Recv,
    /// `SO_SNDBUF`: limits what can sit unacknowledged/unsent on our side.
    Send,
}

/// Next buffer size given the measured bandwidth-delay product (`bdp`, bytes) and
/// the current size. Returns `cur` when no change is worthwhile.
///
/// - BDP above [`GROW_THRESHOLD`] of the buffer means the buffer is (nearly) the
///   limit: double it, so a small start reaches the real rate in a few steps.
/// - Otherwise aim for 2×BDP, and only shrink when that is well below `cur`
///   (hysteresis against flapping).
pub fn decide(cur: usize, bdp: f64, floor: usize, cap: usize) -> usize {
    let target = if bdp > cur as f64 * GROW_THRESHOLD {
        cur.saturating_mul(2)
    } else {
        (bdp * 2.0) as usize
    };
    let target = target.clamp(floor, cap);
    if target > cur || (target as f64) < cur as f64 * SHRINK_RATIO {
        target
    } else {
        cur
    }
}

/// Measures goodput + min RTT for one direction of one leg and proposes sizes.
pub struct BufTuner {
    dir: Dir,
    cur: usize,
    win_start: Instant,
    win_bytes: u64,
    rate_est: f64,
    rtt_min_ms: Option<u32>,
    rtt_min_at: Instant,
    /// Set after a forced (privileged) `setsockopt` failed, so we stop retrying.
    force_failed: bool,
}

impl BufTuner {
    pub fn new(dir: Dir) -> Self {
        let now = Instant::now();
        Self {
            dir,
            cur: BUF_INITIAL,
            win_start: now,
            win_bytes: 0,
            rate_est: 0.0,
            rtt_min_ms: None,
            rtt_min_at: now,
            force_failed: false,
        }
    }

    /// Account bytes moved in this direction.
    pub fn on_bytes(&mut self, n: usize) {
        self.win_bytes += n as u64;
    }

    /// True once a measurement interval has elapsed (cheap; call per I/O).
    pub fn due(&self, now: Instant) -> bool {
        now.duration_since(self.win_start) >= INTERVAL
    }

    /// Close the interval and return a new size if it should change. `rtt_ms` is
    /// an RTT sample for this leg; it feeds the windowed minimum.
    pub fn tick(&mut self, now: Instant, rtt_ms: Option<u32>) -> Option<usize> {
        if let Some(s) = rtt_ms.filter(|&s| s > 0) {
            let expired = now.duration_since(self.rtt_min_at) > RTT_MIN_WINDOW;
            if self.rtt_min_ms.is_none_or(|m| s <= m) || expired {
                self.rtt_min_ms = Some(s);
                self.rtt_min_at = now;
            }
        }

        let elapsed = now.duration_since(self.win_start).as_secs_f64();
        if elapsed < INTERVAL.as_secs_f64() {
            return None;
        }
        let rate = self.win_bytes as f64 / elapsed;
        self.win_start = now;
        self.win_bytes = 0;
        self.rate_est = rate.max(self.rate_est * RATE_DECAY);

        let rtt_s = self.rtt_min_ms? as f64 / 1000.0;
        let next = decide(self.cur, self.rate_est * rtt_s, BUF_FLOOR, BUF_CAP);
        (next != self.cur).then(|| {
            self.cur = next;
            next
        })
    }

    /// The size currently in force (what the last apply asked for).
    pub fn current(&self) -> usize {
        self.cur
    }

    /// Apply the initial size right after the handshake.
    pub fn apply_initial(&mut self, stream: &TcpStream) {
        self.apply(stream, BUF_INITIAL);
    }

    /// Set the OS buffer. Best effort: errors are ignored, and on Linux a value
    /// clamped by `net.core.{r,w}mem_max` is retried once with the privileged
    /// `SO_*BUFFORCE` (works with `CAP_NET_ADMIN`, silently skipped otherwise).
    pub fn apply(&mut self, stream: &TcpStream, size: usize) {
        self.cur = size;
        let sock = socket2::SockRef::from(stream);
        let _ = match self.dir {
            Dir::Recv => sock.set_recv_buffer_size(size),
            Dir::Send => sock.set_send_buffer_size(size),
        };
        #[cfg(target_os = "linux")]
        if !self.force_failed {
            let effective = match self.dir {
                Dir::Recv => sock.recv_buffer_size(),
                Dir::Send => sock.send_buffer_size(),
            }
            .unwrap_or(usize::MAX);
            // The kernel stores twice the requested value; less means a clamp.
            if effective < size.saturating_mul(2).saturating_sub(size / 10) {
                self.force_failed = !force_linux(stream, self.dir, size);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn force_linux(stream: &TcpStream, dir: Dir, size: usize) -> bool {
    use std::os::fd::AsRawFd;
    let opt = match dir {
        Dir::Recv => libc::SO_RCVBUFFORCE,
        Dir::Send => libc::SO_SNDBUFFORCE,
    };
    let val = size.min(i32::MAX as usize) as libc::c_int;
    // SAFETY: valid fd for the lifetime of `stream`, `val` outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            opt,
            (&val as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Smoothed RTT of the leg in milliseconds, from the kernel where available.
#[cfg(target_os = "linux")]
pub fn kernel_rtt_ms(stream: &TcpStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut info = std::mem::MaybeUninit::<libc::tcp_info>::zeroed();
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    // SAFETY: valid fd, `info`/`len` describe a writable tcp_info.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    let info = unsafe { info.assume_init() };
    (info.tcpi_rtt > 0).then(|| (info.tcpi_rtt / 1000).max(1))
}

#[cfg(not(target_os = "linux"))]
pub fn kernel_rtt_ms(_stream: &TcpStream) -> Option<u32> {
    None
}

/// RTT sample for a leg: the kernel's own when available (works on the server,
/// which has no heartbeat-derived global), else the client's global estimate.
pub fn leg_rtt_ms(stream: &TcpStream) -> Option<u32> {
    use crate::net::{GLOBAL_MIN_RTT, INITIAL_RTT_MS};
    use std::sync::atomic::Ordering;
    kernel_rtt_ms(stream).or_else(|| {
        let g = GLOBAL_MIN_RTT.load(Ordering::Relaxed);
        (g != 0 && g != INITIAL_RTT_MS).then_some(g)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KB: usize = 1024;

    #[test]
    fn grows_by_doubling_while_buffer_is_the_limit() {
        // BDP equal to the buffer (window-limited flow): double.
        assert_eq!(
            decide(512 * KB, 512.0 * KB as f64, BUF_FLOOR, BUF_CAP),
            1024 * KB
        );
        // Never beyond the cap.
        assert_eq!(decide(6 * 1024 * KB, 6.0e6, BUF_FLOOR, BUF_CAP), BUF_CAP);
    }

    #[test]
    fn settles_near_twice_the_bdp() {
        // 300 KB BDP in a 1 MB buffer: 2*BDP = 600 KB < 0.7*1 MB -> shrink to it.
        let next = decide(1024 * KB, 300.0 * KB as f64, BUF_FLOOR, BUF_CAP);
        assert_eq!(next, 600 * KB);
        // And 600 KB is stable for that BDP (no flapping).
        assert_eq!(decide(next, 300.0 * KB as f64, BUF_FLOOR, BUF_CAP), next);
    }

    #[test]
    fn small_changes_are_ignored_and_floor_holds() {
        // Target within the hysteresis band: unchanged.
        assert_eq!(
            decide(1000 * KB, 450.0 * KB as f64, BUF_FLOOR, BUF_CAP),
            1000 * KB
        );
        // Idle leg falls back to the floor, never below.
        assert_eq!(decide(4096 * KB, 0.0, BUF_FLOOR, BUF_CAP), BUF_FLOOR);
        assert_eq!(decide(BUF_FLOOR, 0.0, BUF_FLOOR, BUF_CAP), BUF_FLOOR);
    }

    #[test]
    fn tuner_converges_from_window_limited_start() {
        // A 100 Mbit/s path at 30 ms (BDP 375 KB) starting from BUF_INITIAL.
        // While window-limited, goodput ~ buffer/RTT; afterwards it is link-bound.
        let mut t = BufTuner::new(Dir::Recv);
        let start = Instant::now();
        let link = 12.5e6_f64; // bytes/s
        let rtt = 0.030_f64;
        for step in 1..=40u32 {
            let now = start + INTERVAL * step;
            let rate = (t.current() as f64 / rtt).min(link);
            t.on_bytes((rate * INTERVAL.as_secs_f64()) as usize);
            t.tick(now, Some(30));
        }
        let bdp = link * rtt;
        let cur = t.current() as f64;
        assert!(cur >= bdp * 1.5, "too small: {cur} vs BDP {bdp}");
        assert!(cur <= bdp * 3.2, "too large: {cur} vs BDP {bdp}");
    }

    #[test]
    fn tuner_shrinks_after_load_ends() {
        let mut t = BufTuner::new(Dir::Send);
        let start = Instant::now();
        for step in 1..=20u32 {
            t.on_bytes((50.0e6 * INTERVAL.as_secs_f64()) as usize);
            t.tick(start + INTERVAL * step, Some(40));
        }
        assert!(t.current() > 2 * 1024 * KB);
        for step in 21..=80u32 {
            t.tick(start + INTERVAL * step, Some(40)); // idle
        }
        assert_eq!(t.current(), BUF_FLOOR);
    }
}
