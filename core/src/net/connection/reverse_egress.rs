//! Reverse egress: a node behind NAT dials OUT to an ingress and then serves as the exit
//! for the flows of that ingress's own clients. The data-plane role follows
//! `StreamHandler::opener`, not who dialed: the dialer's handler has a `RemoteOpener`
//! (it opens targets), the acceptor keeps `opener == None` for that session and opens
//! flows toward the dialer through a [`MeshPeerSession`] — the same pattern mesh uses
//! for peer hops.
//!
//! Auth token of the dialer: `egress:<label>:<token>`. The label is informational.
//!
//! Safety: the dialing side applies an [`EgressPolicy`] — by default it refuses to
//! connect to loopback/private/link-local/metadata addresses, otherwise a page opened
//! by a client of the ingress could scan the home LAN of the egress.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::TcpStream;

use super::MeshPeerSession;

/// Auth token prefix that marks a reverse-egress dialer.
pub const EGRESS_TOKEN_PREFIX: &str = "egress:";

/// What the dialing egress is allowed to reach.
#[derive(Clone, Debug, Default)]
pub struct EgressPolicy {
    /// Allow loopback/private/link-local targets (the egress's own LAN). Off by default.
    pub allow_private: bool,
    /// Maximum number of flows this egress serves at the same time; further flows are refused. `None` means unlimited.
    pub max_streams: Option<usize>,
}

/// An [`EgressPolicy`] plus the live flow counter shared by all legs of one egress session.
pub(crate) struct EgressRuntime {
    pub(crate) policy: EgressPolicy,
    active: AtomicUsize,
}

/// One flow slot; released on drop.
pub(crate) struct StreamSlot(Arc<EgressRuntime>);

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl EgressRuntime {
    pub(crate) fn new(policy: EgressPolicy) -> Arc<Self> {
        Arc::new(Self {
            policy,
            active: AtomicUsize::new(0),
        })
    }

    /// `None` when the flow limit is reached.
    pub(crate) fn try_acquire(self: &Arc<Self>) -> Option<StreamSlot> {
        let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        if self.policy.max_streams.is_some_and(|max| now > max) {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(StreamSlot(self.clone()))
    }
}

impl EgressPolicy {
    pub fn address_allowed(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        if ip.is_unspecified() || ip.is_multicast() {
            return false;
        }
        if self.allow_private {
            return true;
        }
        match ip {
            IpAddr::V4(v4) => !is_private_v4(v4),
            IpAddr::V6(v6) => !is_private_v6(v6),
        }
    }

    /// Resolves `target` (`host:port`) here, on the egress, keeps only allowed addresses and
    /// connects to one of them — the address that was checked is the address that is used
    /// (no second resolution, so DNS rebinding cannot swap it).
    pub(crate) async fn connect(&self, target: &str) -> io::Result<TcpStream> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target).await?.collect();
        let mut last = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target is not allowed by the egress policy",
        );
        for addr in addrs.into_iter().filter(|a| self.address_allowed(a.ip())) {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last = error,
            }
        }
        Err(last)
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // 169.254/16, includes cloud metadata
        || ip.is_broadcast()
        || (a == 100 && (64..128).contains(&b)) // CGNAT
        || a == 0
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_loopback()
        || (first & 0xfe00) == 0xfc00 // unique local
        || (first & 0xffc0) == 0xfe80 // link-local
}

/// Per-client routing decision of an [`ExitPolicy`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitChoice {
    /// Follow the registry's [`ExitMode`].
    Default,
    /// This client always exits from the ingress itself.
    Local,
    /// This client exits only through the egress with this label; without it the flow is refused.
    Egress(String),
}

/// Maps a client (the validator's `user_id`) to its exit; implemented by the node, e.g. from its device registry.
pub trait ExitPolicy: Send + Sync {
    fn choice_for(&self, user_id: Option<&str>) -> ExitChoice;
}

/// Where one flow goes.
pub(crate) enum Pick {
    Local,
    Via(Arc<MeshPeerSession>),
    /// A remote exit is required but unavailable: refuse, never fall back to the ingress.
    Refuse,
}

/// Where flows of the ingress's own clients exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitMode {
    /// Exit from the ingress itself (the default, as before).
    Local,
    /// Exit through a connected reverse egress; with none connected, fall back to local.
    Prefer,
    /// Exit only through a reverse egress; with none connected, flows fail (no fallback).
    Require,
}

struct Entry {
    session_id: String,
    label: String,
    session: Arc<MeshPeerSession>,
}

struct Inner {
    mode: ExitMode,
    sessions: Vec<Entry>,
    policy: Option<Arc<dyn ExitPolicy>>,
}

/// Live reverse-egress sessions of one ingress.
pub struct ReverseEgressRegistry {
    inner: Mutex<Inner>,
}

impl ReverseEgressRegistry {
    pub fn new(mode: ExitMode) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                mode,
                sessions: Vec::new(),
                policy: None,
            }),
        })
    }

    pub fn mode(&self) -> ExitMode {
        self.inner.lock().unwrap().mode
    }

    pub fn set_mode(&self, mode: ExitMode) {
        self.inner.lock().unwrap().mode = mode;
    }

    /// Per-client exit policy, consulted for every new flow. `None`: everybody follows the mode.
    pub fn set_policy(&self, policy: Option<Arc<dyn ExitPolicy>>) {
        self.inner.lock().unwrap().policy = policy;
    }

    /// Decides where a flow of `user_id` goes.
    pub(crate) fn pick_for(&self, user_id: Option<&str>) -> Pick {
        let (mode, policy) = {
            let inner = self.inner.lock().unwrap();
            (inner.mode, inner.policy.clone())
        };
        match policy.map_or(ExitChoice::Default, |p| p.choice_for(user_id)) {
            ExitChoice::Local => Pick::Local,
            ExitChoice::Egress(label) => self.pick_labeled(&label).map_or(Pick::Refuse, Pick::Via),
            ExitChoice::Default => match (mode, self.pick()) {
                (ExitMode::Local, _) | (ExitMode::Prefer, None) => Pick::Local,
                (_, Some(session)) => Pick::Via(session),
                (ExitMode::Require, None) => Pick::Refuse,
            },
        }
    }

    /// The most recent usable session with this label.
    fn pick_labeled(&self, label: &str) -> Option<Arc<MeshPeerSession>> {
        self.inner
            .lock()
            .unwrap()
            .sessions
            .iter()
            .rev()
            .find(|e| e.label == label && e.session.is_usable())
            .map(|e| e.session.clone())
    }

    /// Labels of the sessions that can carry flows right now.
    pub fn live(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap()
            .sessions
            .iter()
            .filter(|e| e.session.is_usable())
            .map(|e| e.label.clone())
            .collect()
    }

    /// Idempotent per session: every leg of a session calls this.
    pub(crate) fn register(&self, session_id: &str, label: &str, session: Arc<MeshPeerSession>) {
        let mut inner = self.inner.lock().unwrap();
        if inner.sessions.iter().any(|e| e.session_id == session_id) {
            return;
        }
        inner.sessions.push(Entry {
            session_id: session_id.to_owned(),
            label: label.to_owned(),
            session,
        });
    }

    pub(crate) fn unregister(&self, session_id: &str) {
        self.inner
            .lock()
            .unwrap()
            .sessions
            .retain(|e| e.session_id != session_id);
    }

    /// The most recently connected usable session.
    pub(crate) fn pick(&self) -> Option<Arc<MeshPeerSession>> {
        self.inner
            .lock()
            .unwrap()
            .sessions
            .iter()
            .rev()
            .find(|e| e.session.is_usable())
            .map(|e| e.session.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn default_policy_refuses_private_and_special_targets() {
        let policy = EgressPolicy::default();
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.0.1",
        ] {
            assert!(!policy.address_allowed(ip(blocked)), "{blocked}");
        }
        for allowed in ["1.1.1.1", "93.184.216.34", "2606:4700::1111", "172.32.0.1"] {
            assert!(policy.address_allowed(ip(allowed)), "{allowed}");
        }
    }

    #[test]
    fn lan_opt_in_allows_private_but_not_unspecified_or_multicast() {
        let policy = EgressPolicy {
            allow_private: true,

            ..Default::default()
        };
        assert!(policy.address_allowed(ip("192.168.1.1")));
        assert!(policy.address_allowed(ip("127.0.0.1")));
        assert!(!policy.address_allowed(ip("0.0.0.0")));
        assert!(!policy.address_allowed(ip("ff02::1")));
    }
}
