//! Server-to-server QUIC transport for mesh sessions.
//!
//! Client-to-ingress transport remains the existing NRXP transport and its
//! `quiceng` datagram camouflage. This module is only enabled by the proxy
//! server's `mesh-quic` feature. QUIC TLS certificates are ephemeral; the
//! inner NRXP handshake authenticates the node identity before a mesh session
//! is accepted, so the TLS certificate is not used as node identity.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

const ALPN: &[u8] = b"nrxp-mesh/1";
// A bounded per-connection queue limits memory consumed by unauthenticated
// peers before the inner NRXP identity handshake completes.
const QUIC_DATAGRAM_BUFFER: usize = 256 * 1024;
// Keep only a short burst of outgoing UDP in flight. The default is 1 MiB,
// which can represent many seconds of stale packets on a slow mobile path.
const QUIC_DATAGRAM_SEND_BUFFER: usize = 64 * 1024;

pub(crate) fn client_endpoint(bind_addr: SocketAddr) -> io::Result<Endpoint> {
    let mut endpoint = Endpoint::client(bind_addr)?;
    let verifier = Arc::new(SkipCertificateVerification::new());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| io::Error::other(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(mesh_transport_config());
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

pub fn server_endpoint(addr: SocketAddr) -> io::Result<Endpoint> {
    let certificate = rcgen::generate_simple_self_signed(vec!["mesh.netrunner".to_owned()])
        .map_err(|error| io::Error::other(error.to_string()))?;
    let cert_der: CertificateDer<'static> = certificate.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| io::Error::other(error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .map_err(|error| io::Error::other(error.to_string()))?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| io::Error::other(error.to_string()))?;

    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport = mesh_transport_config();
    Endpoint::server(config, addr)
}

/// Packets that may overtake an unacknowledged one before it is declared lost
/// (quinn/RFC 9002 default: 3).
///
/// Node-to-node paths reorder packets: jitter of 1 ms was enough for the default
/// to read reordering as loss, cut the congestion window and overflow the small
/// datagram queue below, so 15-45% of UDP flows silently vanished while nothing
/// was really lost (isolated test: `quic_datagram_jitter_probe`). 30 packets /
/// 2 RTT of tolerance keeps delivery at 97-100% there; genuine loss is still
/// detected, a little later.
const PACKET_REORDER_THRESHOLD: u32 = 30;
const TIME_REORDER_THRESHOLD: f32 = 2.0;

/// `MESH_QUIC_CC=bbr` switches the inter-node congestion controller from Cubic to
/// BBR, which does not treat reordering or sparse loss as congestion (99-100%
/// delivery at 7 Mbit with 10 ms jitter and 0.3% loss, where tuned Cubic keeps
/// 33-62%). Opt-in: it changes how every inter-node flow shares the link.
fn mesh_transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.keep_alive_interval(Some(Duration::from_secs(15)));
    config.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_BUFFER));
    config.datagram_send_buffer_size(QUIC_DATAGRAM_SEND_BUFFER);
    config.max_concurrent_bidi_streams(VarInt::from_u32(128));
    config.packet_threshold(PACKET_REORDER_THRESHOLD);
    config.time_threshold(TIME_REORDER_THRESHOLD);
    if std::env::var("MESH_QUIC_CC").is_ok_and(|value| value.eq_ignore_ascii_case("bbr")) {
        config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    Arc::new(config)
}

#[derive(Debug)]
struct SkipCertificateVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipCertificateVerification {
    fn new() -> Self {
        Self(Arc::new(rustls::crypto::ring::default_provider()))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // The application handshake inside the QUIC stream authenticates the
        // remote node using its provisioned NRXP static key. QUIC TLS provides
        // transport encryption and congestion control, not the node identity.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::{client_endpoint, server_endpoint, QUIC_DATAGRAM_SEND_BUFFER};
    use bytes::Bytes;
    use tokio::sync::oneshot;

    /// Delivery of an unreliable datagram flow over the mesh transport when the
    /// path reorders packets. Needs jitter on loopback, so it only runs on
    /// request, inside a network namespace:
    ///
    /// ```text
    /// unshare -Urn sh -c 'ip link set lo up; tc qdisc add dev lo root netem delay 60ms 10ms;
    ///   cargo test -p netrunner-core --features mesh-quic --lib quic_datagram_jitter_probe -- --ignored --nocapture'
    /// ```
    ///
    /// With quinn's default loss detection (reordering threshold 3) 1 ms of
    /// jitter already lost 15-45% of the datagrams.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "diagnostic: needs netem on loopback"]
    async fn quic_datagram_jitter_probe() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let env = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
        let (pps, size, secs) = (env("PPS", 200), env("SIZE", 900) as usize, env("SECS", 15));

        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let received = std::sync::Arc::new(AtomicU64::new(0));
        let counter = received.clone();
        tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let _stream = connection.accept_bi().await.unwrap();
            while connection.read_datagram().await.is_ok() {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
        let connection = client.connect(addr, "mesh.netrunner").unwrap().await.unwrap();
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        send.write_all(b"hi").await.unwrap();

        let payload = bytes::Bytes::from(vec![0xA5u8; size]);
        let mut tick = tokio::time::interval(std::time::Duration::from_micros(1_000_000 / pps));
        let mut sent = 0u64;
        for _ in 0..pps * secs {
            tick.tick().await;
            if connection.send_datagram(payload.clone()).is_ok() {
                sent += 1;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let stats = connection.stats();
        println!(
            "sent={sent} received={} ({}%) | cwnd={} rtt={:?} lost_packets={} congestion_events={} sent_packets={} black_holes={} | send_buffer_space_end={}",
            received.load(Ordering::Relaxed),
            received.load(Ordering::Relaxed) * 100 / sent.max(1),
            stats.path.cwnd,
            stats.path.rtt,
            stats.path.lost_packets,
            stats.path.congestion_events,
            stats.path.sent_packets,
            stats.path.black_holes_detected,
            connection.datagram_send_buffer_space(),
        );
        assert!(
            received.load(Ordering::Relaxed) * 100 / sent.max(1) >= 90,
            "datagram delivery collapsed under jitter"
        );
    }

    #[tokio::test]
    async fn mesh_quic_negotiates_streams_and_datagrams_with_ephemeral_tls() {
        let server = server_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
        let (received_tx, received_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("incoming QUIC connection");
            let connection = incoming.await.expect("QUIC handshake");
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let mut request = [0; 4];
            recv.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            send.write_all(b"pong").await.unwrap();
            connection
                .send_datagram(Bytes::from_static(b"datagram-ok"))
                .unwrap();
            received_rx.await.unwrap();
        });

        let connection = client
            .connect(server_addr, "mesh.netrunner")
            .unwrap()
            .await
            .unwrap();

        assert_eq!(
            connection.datagram_send_buffer_space(),
            QUIC_DATAGRAM_SEND_BUFFER,
            "mesh QUIC send queue must stay latency-bounded"
        );
        // Saturate the outgoing queue synchronously. `send_datagram` must
        // remain non-blocking and keep accepting fresh UDP packets by dropping
        // stale queued packets once the configured limit is reached.
        let packet = Bytes::from(vec![0u8; 900]);
        for _ in 0..(QUIC_DATAGRAM_SEND_BUFFER / packet.len() + 32) {
            connection
                .send_datagram(packet.clone())
                .expect("UDP send should not wait for congestion buffer space");
        }
        assert!(
            connection.datagram_send_buffer_space() < packet.len(),
            "burst should exercise the bounded outgoing datagram queue"
        );

        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        recv.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        assert_eq!(
            connection.read_datagram().await.unwrap().as_ref(),
            b"datagram-ok"
        );
        received_tx.send(()).unwrap();
        server_task.await.unwrap();
    }
}
