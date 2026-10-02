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
const QUIC_DATAGRAM_BUFFER: usize = 1024 * 1024;

pub(crate) fn client_endpoint(bind_addr: SocketAddr) -> io::Result<Endpoint> {
    let mut endpoint = Endpoint::client(bind_addr)?;
    let verifier = Arc::new(SkipCertificateVerification::new());
    let mut tls = rustls::ClientConfig::builder()
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

    let mut tls = rustls::ServerConfig::builder()
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

fn mesh_transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();
    config.keep_alive_interval(Some(Duration::from_secs(15)));
    config.datagram_receive_buffer_size(Some(QUIC_DATAGRAM_BUFFER));
    config.max_concurrent_bidi_streams(VarInt::from_u32(128));
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
