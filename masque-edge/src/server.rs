use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use h3::{ext::Protocol, quic::StreamId, server::RequestStream};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::{Method, Request, Response, StatusCode};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::RwLock,
};
use tracing::{debug, info, warn};

use crate::{auth::BearerAuth, target};

type Sessions = Arc<RwLock<HashMap<StreamId, Arc<UdpSocket>>>>;

/// Выбирает Ring как криптопровайдер rustls — ровно один раз на процесс.
///
/// Корневой релизный образ собирает этот бинарь вместе с `netrunner-server`, а
/// тот через `reqwest`/`hyper-rustls` тянет AWS-LC. Из-за унификации фич
/// Cargo rustls оказывается собран сразу с двумя провайдерами, и тогда он
/// принципиально отказывается угадывать нужный в рантайме — падает с «no
/// process-level CryptoProvider available».
///
/// MASQUE настроен на Ring, поэтому выбор делается явно. Вызывать обязаны и
/// `main`, и тесты: тесты `main` не исполняют, и без этого вызова любой тест,
/// поднимающий QUIC, падает — но только при сборке всего воркспейса, а по
/// отдельности крейт собирается с одним провайдером и проходит. Такое
/// расхождение между `cargo test -p` и `cargo test --workspace` дороже всего
/// искать, поэтому точка входа одна.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Ошибка здесь означает, что провайдер уже кем-то установлен — для
        // нашей цели это тот же успех.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub struct Config {
    pub bind: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub auth: BearerAuth,
    pub allow_private_targets: bool,
}

pub async fn run(config: Config) -> Result<()> {
    let server_config = build_server_config(&config.cert, &config.key)?;
    let endpoint = quinn::Endpoint::server(server_config, config.bind)
        .with_context(|| format!("failed to bind HTTP/3 endpoint at {}", config.bind))?;

    info!(bind = %config.bind, "MASQUE HTTP/3 edge listening");
    while let Some(incoming) = endpoint.accept().await {
        let auth = config.auth.clone();
        let allow_private_targets = config.allow_private_targets;
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let remote = connection.remote_address();
                    if let Err(error) =
                        handle_connection(connection, auth, allow_private_targets).await
                    {
                        warn!(%remote, %error, "HTTP/3 connection failed");
                    }
                }
                Err(error) => warn!(%error, "QUIC handshake failed"),
            }
        });
    }
    Ok(())
}

fn build_server_config(cert_path: &PathBuf, key_path: &PathBuf) -> Result<quinn::ServerConfig> {
    let mut cert_reader = BufReader::new(
        File::open(cert_path)
            .with_context(|| format!("failed to open certificate {}", cert_path.display()))?,
    );
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse PEM certificate chain")?;
    if certs.is_empty() {
        bail!("certificate chain is empty");
    }

    let mut key_reader = BufReader::new(
        File::open(key_path)
            .with_context(|| format!("failed to open private key {}", key_path.display()))?,
    );
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("failed to parse PEM private key")?
        .context("private key file contains no supported key")?;

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("certificate and private key do not match")?;
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .context("failed to create QUIC TLS config")?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let transport = Arc::get_mut(&mut config.transport)
        .context("QUIC transport config is unexpectedly shared")?;
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    transport.max_concurrent_bidi_streams(256_u32.into());
    transport.max_concurrent_uni_streams(16_u32.into());
    Ok(config)
}

async fn handle_connection(
    connection: quinn::Connection,
    auth: BearerAuth,
    allow_private_targets: bool,
) -> Result<()> {
    let remote = connection.remote_address();
    let quinn_connection = h3_quinn::Connection::new(connection);
    let mut builder = h3::server::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let mut h3 = builder
        .build(quinn_connection)
        .await
        .context("failed to establish HTTP/3")?;

    let sessions: Sessions = Arc::new(RwLock::new(HashMap::new()));
    let mut datagram_reader = h3.get_datagram_reader();
    let uplink_sessions = Arc::clone(&sessions);
    let datagram_task = tokio::spawn(async move {
        loop {
            let datagram = datagram_reader
                .read_datagram()
                .await
                .context("failed to read HTTP/3 datagram")?;
            let stream_id = datagram.stream_id();
            let payload = datagram.into_payload();
            let Some(payload) = strip_context_zero(payload) else {
                warn!(
                    ?stream_id,
                    "ignoring CONNECT-UDP datagram with non-zero context ID"
                );
                continue;
            };
            let socket = uplink_sessions.read().await.get(&stream_id).cloned();
            if let Some(socket) = socket {
                socket
                    .send(&payload)
                    .await
                    .context("failed to forward CONNECT-UDP datagram")?;
            } else {
                debug!(
                    ?stream_id,
                    "datagram arrived before its UDP session was ready"
                );
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    info!(%remote, "HTTP/3 connection established");
    while let Some(resolver) = h3
        .accept()
        .await
        .context("failed to accept HTTP/3 request")?
    {
        let (request, stream) = match resolver.resolve_request().await {
            Ok(request) => request,
            Err(error) => {
                warn!(%remote, %error, "invalid HTTP/3 request");
                continue;
            }
        };
        let datagram_sender = h3.get_datagram_sender(stream.id());
        let request_auth = auth.clone();
        let request_sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            let stream_id = stream.id();
            if let Err(error) = handle_request(
                request,
                stream,
                datagram_sender,
                request_sessions,
                request_auth,
                allow_private_targets,
            )
            .await
            {
                warn!(?stream_id, %error, "MASQUE request failed");
            }
        });
    }

    datagram_task.abort();
    Ok(())
}

async fn handle_request(
    request: Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    datagram_sender: h3_datagram::datagram_handler::DatagramSender<
        h3_quinn::datagram::SendDatagramHandler,
        Bytes,
    >,
    sessions: Sessions,
    auth: BearerAuth,
    allow_private_targets: bool,
) -> Result<()> {
    if !auth.authorize(&request) {
        send_status(&mut stream, StatusCode::UNAUTHORIZED).await?;
        return Ok(());
    }
    if request.method() != Method::CONNECT {
        send_status(&mut stream, StatusCode::METHOD_NOT_ALLOWED).await?;
        return Ok(());
    }

    match request.extensions().get::<Protocol>() {
        Some(protocol) if protocol == &Protocol::CONNECT_UDP => {
            handle_connect_udp(
                request,
                stream,
                datagram_sender,
                sessions,
                allow_private_targets,
            )
            .await
        }
        Some(protocol) => {
            warn!(?protocol, "unsupported extended CONNECT protocol");
            send_status(&mut stream, StatusCode::NOT_IMPLEMENTED).await
        }
        None => handle_connect_tcp(request, stream, allow_private_targets).await,
    }
}

async fn handle_connect_tcp(
    request: Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    allow_private_targets: bool,
) -> Result<()> {
    let authority = request
        .uri()
        .authority()
        .context("TCP CONNECT request has no :authority")?;
    let target = target::from_authority(authority.as_str())?;
    let resolved = target.resolve(allow_private_targets).await?;
    let tcp = TcpStream::connect(resolved)
        .await
        .with_context(|| format!("TCP connect to {} failed", target))?;
    tcp.set_nodelay(true)?;

    stream
        .send_response(Response::builder().status(StatusCode::OK).body(())?)
        .await
        .context("failed to accept TCP CONNECT")?;
    info!(%target, "TCP CONNECT established");

    let (mut h3_send, mut h3_recv) = stream.split();
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let upload = async {
        while let Some(mut data) = h3_recv.recv_data().await? {
            while data.has_remaining() {
                let chunk = data.chunk();
                tcp_write.write_all(chunk).await?;
                let len = chunk.len();
                data.advance(len);
            }
        }
        tcp_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };

    let download = async {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let read = tcp_read.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            h3_send
                .send_data(Bytes::copy_from_slice(&buffer[..read]))
                .await?;
        }
        h3_send.finish().await?;
        Ok::<(), anyhow::Error>(())
    };

    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn handle_connect_udp(
    request: Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut datagram_sender: h3_datagram::datagram_handler::DatagramSender<
        h3_quinn::datagram::SendDatagramHandler,
        Bytes,
    >,
    sessions: Sessions,
    allow_private_targets: bool,
) -> Result<()> {
    let target = target::from_connect_udp_path(request.uri().path())?;
    let resolved = target.resolve(allow_private_targets).await?;
    let bind = match resolved.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    socket
        .connect(resolved)
        .await
        .with_context(|| format!("UDP connect to {} failed", target))?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("capsule-protocol", "?1")
        .body(())?;
    stream
        .send_response(response)
        .await
        .context("failed to accept CONNECT-UDP")?;

    let stream_id = stream.id();
    sessions
        .write()
        .await
        .insert(stream_id, Arc::clone(&socket));
    info!(%target, ?stream_id, "CONNECT-UDP established");

    let result = async {
        let mut buffer = vec![0_u8; 65_535];
        loop {
            tokio::select! {
                received = socket.recv(&mut buffer) => {
                    let received = received?;
                    let mut payload = BytesMut::with_capacity(received + 1);
                    payload.put_u8(0); // RFC 9298 context ID 0.
                    payload.put_slice(&buffer[..received]);
                    if let Err(error) = datagram_sender.send_datagram(payload.freeze()) {
                        warn!(?stream_id, %error, "dropping UDP response datagram");
                    }
                }
                body = stream.recv_data() => {
                    match body? {
                        Some(_) => debug!(?stream_id, "ignoring capsule body on HTTP/3 datagram tunnel"),
                        None => break,
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;

    sessions.write().await.remove(&stream_id);
    let _ = stream.finish().await;
    result
}

async fn send_status(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
) -> Result<()> {
    stream
        .send_response(Response::builder().status(status).body(())?)
        .await?;
    stream.finish().await?;
    Ok(())
}

fn strip_context_zero(mut payload: Bytes) -> Option<Bytes> {
    if !payload.has_remaining() {
        return None;
    }
    let first = payload.get_u8();
    if first != 0 {
        return None;
    }
    Some(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;

    use h3_datagram::datagram_handler::HandleDatagramsExt;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use tempfile::TempDir;
    use tokio::{task::JoinHandle, time::timeout};

    struct TestServer {
        address: SocketAddr,
        client_config: quinn::ClientConfig,
        task: JoinHandle<Result<()>>,
        _directory: TempDir,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn start_test_server() -> Result<TestServer> {
        // Без этого тесты падают при `cargo test --workspace` — см.
        // `install_crypto_provider`.
        install_crypto_provider();

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let directory = tempfile::tempdir()?;
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem())?;
        std::fs::write(&key_path, signing_key.serialize_pem())?;

        let probe = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let address = probe.local_addr()?;
        drop(probe);

        let task = tokio::spawn(run(Config {
            bind: address,
            cert: cert_path,
            key: key_path,
            auth: BearerAuth::new(Some("test-token".into())),
            allow_private_targets: true,
        }));
        tokio::time::sleep(Duration::from_millis(30)).await;

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone())?;
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let client_config = quinn::ClientConfig::new(Arc::new(crypto));

        Ok(TestServer {
            address,
            client_config,
            task,
            _directory: directory,
        })
    }

    async fn connect_test_client(
        server: &TestServer,
    ) -> Result<(
        quinn::Endpoint,
        h3::client::Connection<h3_quinn::Connection, Bytes>,
        h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    )> {
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        endpoint.set_default_client_config(server.client_config.clone());
        let connection = endpoint.connect(server.address, "localhost")?.await?;
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true).enable_datagram(true);
        let (driver, sender) = builder.build(h3_quinn::Connection::new(connection)).await?;
        Ok((endpoint, driver, sender))
    }

    #[test]
    fn strips_zero_context_id() {
        let payload = strip_context_zero(Bytes::from_static(b"\0hello")).unwrap();
        assert_eq!(payload, Bytes::from_static(b"hello"));
        assert!(strip_context_zero(Bytes::from_static(b"\x01hello")).is_none());
        assert!(strip_context_zero(Bytes::new()).is_none());
    }

    #[tokio::test]
    async fn proxies_tcp_connect_over_http3() -> Result<()> {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let echo_address = echo.local_addr()?;
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await?;
            let (mut read, mut write) = stream.split();
            tokio::io::copy(&mut read, &mut write).await?;
            Ok::<(), std::io::Error>(())
        });

        let server = start_test_server().await?;
        let (_endpoint, mut driver, mut sender) = connect_test_client(&server).await?;
        let driver_task = tokio::spawn(async move {
            let error = poll_fn(|context| driver.poll_close(context)).await;
            Err::<(), _>(error)
        });

        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{echo_address}"))
            .header("authorization", "Bearer test-token")
            .body(())?;
        let mut stream = sender.send_request(request).await?;
        let response = timeout(Duration::from_secs(3), stream.recv_response()).await??;
        assert_eq!(response.status(), StatusCode::OK);

        stream
            .send_data(Bytes::from_static(b"hello over h3"))
            .await?;
        stream.finish().await?;
        let mut response_data = stream.recv_data().await?.context("missing echo body")?;
        assert_eq!(
            response_data.copy_to_bytes(response_data.remaining()),
            b"hello over h3"[..]
        );

        driver_task.abort();
        echo_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn proxies_connect_udp_datagrams_over_http3() -> Result<()> {
        let echo = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let echo_address = echo.local_addr()?;
        let echo_task = {
            let echo = Arc::clone(&echo);
            tokio::spawn(async move {
                let mut buffer = [0_u8; 1024];
                let (read, peer) = echo.recv_from(&mut buffer).await?;
                echo.send_to(&buffer[..read], peer).await?;
                Ok::<(), std::io::Error>(())
            })
        };

        let server = start_test_server().await?;
        let (_endpoint, mut driver, mut sender) = connect_test_client(&server).await?;
        let mut datagram_reader = driver.get_datagram_reader();
        let (stream_id_tx, mut stream_id_rx) = tokio::sync::mpsc::channel(1);
        let (datagram_tx, mut datagram_rx) = tokio::sync::mpsc::channel(1);
        let driver_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    error = poll_fn(|context| driver.poll_close(context)) => {
                        return Err::<(), anyhow::Error>(error.into());
                    }
                    stream_id = stream_id_rx.recv() => {
                        let Some(stream_id) = stream_id else { return Ok(()); };
                        datagram_tx.send(driver.get_datagram_sender(stream_id)).await
                            .context("datagram sender receiver closed")?;
                    }
                }
            }
        });

        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!(
                "https://localhost/.well-known/masque/udp/{}/{}/",
                echo_address.ip(),
                echo_address.port()
            ))
            .header("authorization", "Bearer test-token")
            .extension(Protocol::CONNECT_UDP)
            .body(())?;
        let mut stream = sender.send_request(request).await?;
        stream_id_tx.send(stream.id()).await?;
        let mut datagram_sender = datagram_rx
            .recv()
            .await
            .context("missing datagram sender")?;
        let response = timeout(Duration::from_secs(3), stream.recv_response()).await??;
        assert_eq!(response.status(), StatusCode::OK);

        datagram_sender.send_datagram(Bytes::from_static(b"\0ping"))?;
        let datagram = timeout(Duration::from_secs(3), datagram_reader.read_datagram()).await??;
        assert_eq!(
            strip_context_zero(datagram.into_payload()).unwrap(),
            b"ping"[..]
        );

        stream.finish().await?;
        driver_task.abort();
        echo_task.await??;
        Ok(())
    }
}
