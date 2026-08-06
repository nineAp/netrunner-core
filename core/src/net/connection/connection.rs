//! Точки входа туннеля: установка соединений на стороне клиента и сервера.
//!
//! Здесь собирается всё ядро в две роли:
//!
//! - [`ClientHandler`] — клиентская сторона. [`connect`](ClientHandler::connect)
//!   поднимает [`MAX_TUNNEL_LEGS`] ног (с разбежкой по времени), сторожит смену
//!   сети и переводит локальный трафик ([`RawCastFrame`]) в потоки туннеля.
//!   Каждая нога делает [`perform_handshake`](ClientHandler::perform_handshake)
//!   (поддельный TLS + обмен ключами + auth-кадр) и крутится в [`TunnelEngine`].
//! - [`ServerHandler`] — серверная сторона. Принимает соединение, проверяет, что
//!   это валидный Netrunner-`ClientHello`; если нет — **stealth-fallback**:
//!   прозрачно проксирует трафик на безобидный хост (`decoy_host:443`, атрибут
//!   ноды — задаётся при старте, не константа), маскируясь под обычный TLS и
//!   не выдавая себя сканерам/DPI.
//! - [`SessionManager`] — реестр сессий сервера (одна сессия = один [`Muxer`],
//!   несколько ног).
//!
//! Обе роли сходятся на [`TunnelEngine`]: клиент задаёт `remote_addr`
//! (реконнектит), сервер оставляет его пустым (нога просто завершается).

use std::{net::Ipv4Addr, sync::Arc, time::Instant};

use crate::{
    crypto::{ChaChaCipher, SessionKeys},
    net::{
        connection::{
            engine::TunnelEngine,
            handler::{RemoteOpener, StreamHandler},
            muxer::{MuxMessage, Muxer},
        },
        NetworkConfig, DNS_LOOKUP_TIMEOUT, FALLBACK_CONNECT_TIMEOUT, HTTPS_PORT,
        LEG_RECONNECT_DELAY, LEG_STAGGER_DELAY, MAX_TUNNEL_LEGS, NETWORK_WATCHER_INTERVAL,
        SECURE_HANDSHAKE_TIMEOUT, SESSION_CLEANUP_DELAY, STREAM_PAUSE_BUDGET, STREAM_PAUSE_RETRY,
        TLS_HELLO_TIMEOUT, TOPOLOGY_PRINT_INTERVAL,
    },
    nrxp::{Codec, Frame, FrameType, TlsBridge},
    rawcast::{LocalProtocol, RawCastAdapter, RawCastFrame},
    tlseng::{BrowserProfile, ServerProfile},
};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use netrunner_logger::{
    debug, error, info, warn, AppError, ERR_AUTH_FAILED, ERR_INFRA_TIMEOUT, ERR_NET_TLS_TAMPER,
};
use rand::{Rng, RngExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::mpsc,
};

/// Реестр активных сессий сервера: `session_id` → общий на сессию [`Muxer`].
pub struct SessionManager {
    sessions: DashMap<String, Arc<Muxer>>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    pub fn generate_id() -> String {
        let mut rng = rand::rng();
        format!("{:016x}{:016x}", rng.next_u64(), rng.next_u64())
    }

    pub fn get_session(&self) -> &DashMap<String, Arc<Muxer>> {
        &self.sessions
    }

    /// Возвращает muxer сессии, создавая его при первом обращении. Так вторая и
    /// последующие ноги одной сессии цепляются к тому же мультиплексору.
    pub fn get_or_create(&self, session_id: &str) -> Arc<Muxer> {
        self.sessions
            .entry(session_id.to_string())
            .or_insert_with(|| Arc::new(Muxer::new(false, session_id.to_string())))
            .clone()
    }

    pub fn remove(&self, session_id: &str) {
        if self.sessions.remove(session_id).is_some() {
            info!("🧹 Session {} completely closed and cleaned up", session_id);
        }
    }

    pub fn print_all_sessions(&self) {
        if self.sessions.is_empty() {
            return;
        }

        info!("📊 --- SERVER GLOBAL SESSIONS REPORT ---");
        for entry in self.sessions.iter() {
            let muxer = entry.value();
            muxer.print_topology_tree();
        }
        info!("📊 ---------------------------------------");
    }
}

/// Общий контракт обработчика входящего туннельного соединения (реализует сервер).
#[async_trait::async_trait]
pub trait TunnelHandler {
    /// Обрабатывает соединение до его завершения.
    async fn run(self) -> Result<(), AppError>;
}

/// Обёртка над TCP-соединением: половинки сокета + накопительный буфер чтения.
pub struct Connection {
    pub(crate) inbound: OwnedReadHalf,
    pub(crate) outbound: OwnedWriteHalf,
    pub(crate) read_buf: BytesMut,
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        let (inbound, outbound) = stream.into_split();
        Self {
            inbound,
            outbound,
            read_buf: BytesMut::with_capacity(NetworkConfig::global().connection_buf_size),
        }
    }
}

/// Грубая синтаксическая проверка SNI-хоста перед тем, как вообще пытаться
/// его резолвить для stealth-fallback. Отсеивает: пустую строку, аномально
/// длинные значения (реальные hostname не длиннее 253 байт по RFC 1035), и
/// буквальные IP-адреса — SNI по стандарту несёт hostname, а не IP; разрешать
/// IP-литерал означал бы дать удалённой стороне впрямую выбрать адрес нашего
/// исходящего соединения безо всякого DNS-резолва между ними.
fn is_plausible_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// `true`, если по этому IP безопасно пустить исходящее TCP-соединение сервера
/// в ответ на данные, присланные недоверенной удалённой стороной (SNI из
/// невалидного `ClientHello`). Блокирует loopback/private/link-local (в т.ч.
/// `169.254.169.254` — облачный metadata-эндпоинт)/multicast/unspecified —
/// защита от SSRF на внутреннюю сеть ноды через подставной SNI.
fn is_safe_decoy_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation())
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            let is_unique_local = (segments[0] & 0xfe00) == 0xfc00; // fc00::/7
            let is_link_local = (segments[0] & 0xffc0) == 0xfe80; // fe80::/10
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || is_unique_local
                || is_link_local)
        }
    }
}

/// Резолвит `host:port` и возвращает первый адрес, прошедший
/// [`is_safe_decoy_ip`] — `None`, если хост не резолвится вовсе или резолвится
/// только в небезопасные (внутренние/локальные) адреса.
async fn resolve_safe_decoy_addr(host: &str, port: u16) -> Option<std::net::SocketAddr> {
    let addrs = tokio::time::timeout(
        FALLBACK_CONNECT_TIMEOUT,
        tokio::net::lookup_host((host, port)),
    )
    .await
    .ok()?
    .ok()?;
    addrs.into_iter().find(|a| is_safe_decoy_ip(&a.ip()))
}

/// Дожидается и вырезает из буфера фиктивную запись `ChangeCipherSpec`,
/// которую наш пир (мы же на другом конце — клиент или сервер) всегда шлёт
/// сразу вслед за своим Hello (см. [`TlsBridge::build_middlebox_ccs`]) ради
/// middlebox-совместимости TLS 1.3. Переиспользуется и клиентской, и
/// серверной стороной хендшейка — обе ждут её одинаково.
async fn consume_middlebox_ccs(
    inbound: &mut OwnedReadHalf,
    read_buf: &mut BytesMut,
) -> Result<(), AppError> {
    loop {
        match TlsBridge::unpack_middlebox_ccs(read_buf) {
            Ok(Some(())) => return Ok(()),
            Ok(None) => {
                let res = tokio::time::timeout(TLS_HELLO_TIMEOUT, inbound.read_buf(read_buf)).await;
                match res {
                    Ok(Ok(0)) => {
                        return Err(AppError::new(
                            ERR_INFRA_TIMEOUT,
                            "Разрыв соединения",
                            "EOF while waiting for ChangeCipherSpec",
                        ))
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(e)) => {
                        return Err(AppError::new(
                            ERR_INFRA_TIMEOUT,
                            "Ошибка чтения",
                            e.to_string(),
                        ))
                    }
                    Err(_) => {
                        return Err(AppError::new(
                            ERR_INFRA_TIMEOUT,
                            "Таймаут handshake",
                            "Timeout waiting for ChangeCipherSpec",
                        ))
                    }
                }
            }
            Err(e) => {
                return Err(AppError::new(
                    ERR_NET_TLS_TAMPER,
                    "Ошибка TLS",
                    format!("TLS error while reading ChangeCipherSpec: {:?}", e.stage),
                ))
            }
        }
    }
}

/// Клиентская сторона туннеля (набор статических операций).
pub struct ClientHandler;
impl ClientHandler {
    /// Узнаёт локальный IP «трюком с UDP-connect»: соединение к 8.8.8.8 без
    /// отправки заставляет ОС выбрать исходящий интерфейс, чей адрес мы и читаем.
    /// Нужно для детектора смены сети (Wi-Fi↔LTE).
    fn get_local_ip() -> Option<std::net::IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        socket.local_addr().ok().map(|a| a.ip())
    }

    /// Проводит полный клиентский хендшейк по уже установленному TCP-сокету.
    ///
    /// Шаги: послать поддельный `ClientHello` (профиль браузера по `profile`,
    /// SNI=`decoy_sni`) → дождаться `ServerHello` и вывести ключи → зарядить
    /// шифр и кодек → отправить первый зашифрованный auth-кадр `Heartbeat` с
    /// `"session_id:leg_id:auth_token"` (третий сегмент может быть пустым).
    /// Возвращает половинки сокета и готовые кодеки.
    pub(crate) async fn perform_handshake(
        stream: tokio::net::TcpStream,
        session_id: &str,
        leg_id: u32,
        profile: &BrowserProfile,
        decoy_sni: &str,
        auth_token: &str,
    ) -> Result<
        (
            OwnedReadHalf,
            OwnedWriteHalf,
            crate::nrxp::RxCodec,
            crate::nrxp::TxCodec,
        ),
        AppError,
    > {
        stream.set_nodelay(true).unwrap_or_default();
        let mut conn = Connection::new(stream);
        let mut session_keys = SessionKeys::new(true);
        let ch = TlsBridge::wrap_client_hello(profile, decoy_sni, &session_keys);

        conn.outbound
            .write_all(&ch)
            .await
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сбой сети", e.to_string()))?;

        // Реальные браузеры шлют фиктивный ChangeCipherSpec сразу после
        // ClientHello (RFC 8446 Appendix D.4) — повторяем и это, не только сам
        // хендшейк, иначе последовательность типов TLS-записей выдаёт
        // нестандартный стек даже при идеальном JA3/JA4-отпечатке ClientHello.
        conn.outbound
            .write_all(&TlsBridge::build_middlebox_ccs())
            .await
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сбой сети", e.to_string()))?;

        loop {
            match TlsBridge::unpack_handshake(&mut conn.read_buf) {
                Ok(Some(msg)) => {
                    session_keys.update_keys(msg.random(), msg.extensions(), false)?;
                    break;
                }
                Ok(None) => {
                    let res = tokio::time::timeout(
                        TLS_HELLO_TIMEOUT,
                        conn.inbound.read_buf(&mut conn.read_buf),
                    )
                    .await;
                    match res {
                        Ok(Ok(0)) => {
                            return Err(AppError::new(
                                ERR_INFRA_TIMEOUT,
                                "Разрыв соединения",
                                "EOF on handshake".to_string(),
                            ))
                        }
                        Ok(Ok(_)) => continue,
                        Ok(Err(e)) => {
                            return Err(AppError::new(
                                ERR_INFRA_TIMEOUT,
                                "Ошибка чтения",
                                e.to_string(),
                            ))
                        }
                        Err(_) => {
                            return Err(AppError::new(
                                ERR_INFRA_TIMEOUT,
                                "Таймаут handshake",
                                "Handshake read timeout",
                            ))
                        }
                    }
                }
                Err(e) => {
                    return Err(AppError::new(
                        ERR_NET_TLS_TAMPER,
                        "Ошибка TLS",
                        format!("TLS error: {:?}", e.stage),
                    ))
                }
            }
        }

        // Сервер тоже шлёт фиктивный ChangeCipherSpec сразу после ServerHello —
        // вычитываем и отбрасываем её здесь же, до перехода в data-фазу.
        consume_middlebox_ccs(&mut conn.inbound, &mut conn.read_buf).await?;

        let (tx_key, tx_iv, rx_key, rx_iv) = session_keys.get_aead_parameters();
        let mut cipher = ChaChaCipher::new();
        cipher.set_keys(tx_key, tx_iv, rx_key, rx_iv);
        let codec = Codec::new(cipher, session_keys.get_auth_key());
        let (rx_codec, mut tx_codec) = codec.split();

        // Третий сегмент — Bearer-токен клиента (пусто, если `--require-auth`
        // выключен на этом развёртывании или приложение ещё не залогинено).
        // Сервер игнорирует его целиком, если сам не запущен с `--require-auth`.
        let auth_payload = Bytes::from(format!("{}:{}:{}", session_id, leg_id, auth_token));
        let encrypted_auth = tx_codec
            .encode_frame(0, FrameType::Heartbeat, auth_payload)
            .map_err(|e| {
                AppError::new(
                    ERR_NET_TLS_TAMPER,
                    "Сбой шифрования",
                    format!("Failed to encrypt Auth: {:?}", e),
                )
            })?;

        conn.outbound
            .write_all(&encrypted_auth)
            .await
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сбой отправки", e.to_string()))?;

        Ok((conn.inbound, conn.outbound, rx_codec, tx_codec))
    }

    /// Устанавливает одну ногу и крутит её движок до остановки.
    ///
    /// Резолвит адрес (с тайм-аутом), создаёт TCP-сокет с анти-bufferbloat
    /// тюнингом буферов, делает хендшейк, регистрирует ногу в muxer и запускает
    /// [`TunnelEngine::run`]. Возвращается только при остановке движка; снаружи
    /// (в [`connect`](ClientHandler::connect)) это уводит ногу на переподключение.
    ///
    /// Профиль браузера выбирается через [`BrowserProfile::for_session`] —
    /// один стабильный отпечаток на всю туннельную сессию (все ноги, все
    /// переподключения), а не по номеру попытки: см. doc на `for_session` про
    /// то, почему ротация профиля между ретраями одной и той же ноги была
    /// хуже, чем константный отпечаток.
    async fn establish_leg(
        remote_proxy_addr: &str,
        leg_id: u32,
        muxer: Arc<Muxer>,
        session_id: &str,
        decoy_sni: &Arc<str>,
        auth_token: &Arc<str>,
    ) -> Result<(), AppError> {
        let leg_name = format!("TCP-Leg-{}", leg_id);

        let addrs_future = tokio::net::lookup_host(remote_proxy_addr);
        let mut addrs = tokio::time::timeout(DNS_LOOKUP_TIMEOUT, addrs_future)
            .await
            .map_err(|_| {
                AppError::new(ERR_INFRA_TIMEOUT, "Сервер недоступен", "DNS Lookup Timeout")
            })?
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Ошибка DNS", e.to_string()))?;

        let addr = addrs.next().ok_or_else(|| {
            AppError::new(
                ERR_INFRA_TIMEOUT,
                "Ошибка сети",
                format!("No IPs found for {}", remote_proxy_addr),
            )
        })?;

        let socket = (if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        })
        .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сбой сокета", e.to_string()))?;
        // Limit OS TCP send buffer to reduce bufferbloat on the tunnel leg.
        // Default buffers (4–8 MB) can hold seconds of data at mobile speeds.
        let _ = socket.set_send_buffer_size(crate::net::TUNNEL_SOCKET_SNDBUF);
        let _ = socket.set_recv_buffer_size(crate::net::TUNNEL_SOCKET_RCVBUF);

        let stream = tokio::time::timeout(FALLBACK_CONNECT_TIMEOUT, socket.connect(addr))
            .await
            .map_err(|_| {
                AppError::new(
                    ERR_INFRA_TIMEOUT,
                    "Таймаут подключения",
                    "Connection timeout",
                )
            })?
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Сбой сокета", e.to_string()))?;

        let profile = BrowserProfile::for_session(session_id);
        let (inbound, outbound, rx_codec, tx_codec) =
            Self::perform_handshake(stream, session_id, leg_id, profile, decoy_sni, auth_token)
                .await?;

        let cap = NetworkConfig::global().channel_capacity;
        let (control_tx, control_rx) = mpsc::channel::<MuxMessage>(cap);
        let (data_tx, data_rx) = mpsc::channel::<MuxMessage>(cap);

        muxer.add_leg(leg_id, control_tx, data_tx);

        let handler = Arc::new(StreamHandler::new(muxer.clone(), None));
        let engine = TunnelEngine {
            leg_id,
            inbound: Some(inbound),
            outbound: Some(outbound),
            // 💡 ИЗМЕНЕНО: Передаем кодеки без Arc<Mutex>
            rx_codec: Some(rx_codec),
            tx_codec: Some(tx_codec),
            read_buf: BytesMut::with_capacity(NetworkConfig::global().connection_buf_size),
            control_rx: Some(control_rx),
            data_rx: Some(data_rx),
            handler,
            muxer: muxer.clone(),
            remote_addr: remote_proxy_addr.to_string(),
            session_id: session_id.to_string(),
            leg_status: crate::net::connection::engine::LegStatus::Active,
            decoy_sni: decoy_sni.clone(),
            auth_token: auth_token.clone(),
        };

        let run_result = engine.run().await;
        // Use force_remove because the engine may have re-registered the leg internally
        // (via reconnect + add_leg), making control_tx_clone stale for same_channel comparison.
        muxer.force_remove_leg(leg_id);

        run_result?;
        Err(AppError::new(
            ERR_INFRA_TIMEOUT,
            "Движок остановлен",
            format!("{} Engine stopped", leg_name),
        ))
    }

    /// Точка входа клиента: поднимает весь туннель и возвращает его [`Muxer`].
    ///
    /// Запускает три группы фоновых задач:
    /// 1. **Ноги** — [`MAX_TUNNEL_LEGS`] задач, каждая в вечном цикле
    ///    establish→disconnect→reconnect (со сдвигом старта [`LEG_STAGGER_DELAY`]).
    /// 2. **Сторож сети** — следит за сменой локального IP и при переключении
    ///    сети сбрасывает все ноги (быстрый реконнект вместо зависших сокетов).
    /// 3. **Здоровье/топология** — периодический health-check и печать топологии.
    ///
    /// Плюс главный цикл, который переводит локальные [`RawCastFrame`]
    /// (`rx_from_engine`) в потоки/данные туннеля и возвращает ответы обратно
    /// (`tx_to_engine`), с пер-сокетными буферами выгрузки против HOL-блокировки.
    ///
    /// `decoy_sni` — хост, под который маскируется наш `ClientHello` (SNI).
    /// Сейчас это статическое значение атрибута конфигурации вызывающей
    /// стороны (см. `EngineConfig::decoy_sni` в `client`); в перспективе будет
    /// приходить динамически со списком серверов, чтобы не расходиться с тем,
    /// на какой decoy-хост настроен конкретный сервер (`--decoy-host`).
    pub async fn connect(
        remote_proxy_addr: &str,
        decoy_sni: impl Into<Arc<str>>,
        auth_token: Option<String>,
        mut rx_from_engine: mpsc::Receiver<RawCastFrame>,
        tx_to_engine: mpsc::Sender<RawCastFrame>,
    ) -> Result<Arc<Muxer>, AppError> {
        let decoy_sni: Arc<str> = decoy_sni.into();
        let auth_token: Arc<str> = auth_token.unwrap_or_default().into();
        let session_id = SessionManager::generate_id();
        let muxer = Arc::new(Muxer::new(true, session_id.clone()));
        let registry: Arc<DashMap<u32, (u64, Ipv4Addr, u16, LocalProtocol)>> =
            Arc::new(DashMap::new());
        let local_to_global: Arc<DashMap<u64, u32>> = Arc::new(DashMap::new());
        let local_to_upload_tx: Arc<DashMap<u64, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());

        let watcher_muxer = muxer.clone();
        tokio::spawn(async move {
            let mut last_ip = Self::get_local_ip();
            let mut interval = tokio::time::interval(NETWORK_WATCHER_INTERVAL);
            loop {
                interval.tick().await;
                let current_ip = Self::get_local_ip();
                if current_ip != last_ip {
                    if current_ip.is_some() && last_ip.is_some() {
                        netrunner_logger::warn!(
                            "🌐 Network Change Detected: {:?} -> {:?}",
                            last_ip,
                            current_ip
                        );
                        watcher_muxer.remove_all_legs();
                    }
                    last_ip = current_ip;
                }
            }
        });

        for id in 0..MAX_TUNNEL_LEGS {
            let addr = remote_proxy_addr.to_string();
            let m = muxer.clone();
            let sid = session_id.clone();
            let decoy_sni = decoy_sni.clone();
            let auth_token = auth_token.clone();
            tokio::spawn(async move {
                tokio::time::sleep(LEG_STAGGER_DELAY * id).await;
                let mut attempt: u32 = 0;
                loop {
                    if m.is_fatal() {
                        // Другая нога уже поймала ERR_AUTH_FAILED (тот же токен
                        // невалиден для всех ног одинаково) — не долбимся дальше.
                        info!("Leg {} stopping: session marked fatal", id);
                        return;
                    }
                    if let Err(e) =
                        Self::establish_leg(&addr, id, m.clone(), &sid, &decoy_sni, &auth_token)
                            .await
                    {
                        if e.code == ERR_AUTH_FAILED {
                            // Сервер безоговорочно отверг токен (см. `validate`
                            // в establish_leg) — это не сетевой сбой, повторные
                            // попытки с тем же токеном обречены (аккаунт
                            // удалён/забанен/подписка истекла). Останавливаем
                            // ЭТУ ногу и просим верхний движок клиента
                            // (`Engine::run`, видит `Muxer::is_fatal`) завершить
                            // сессию целиком, а не висеть в "connected" вечно.
                            error!("Leg {} auth rejected by server, giving up: {}", id, e);
                            m.mark_fatal();
                            return;
                        }

                        attempt += 1;
                        error!("Leg {} disconnected: {}. Reconnecting in 2s...", id, e);
                        let rtt =
                            crate::net::GLOBAL_MIN_RTT.load(std::sync::atomic::Ordering::Relaxed);
                        crate::net::diagnostics::DIAG_COUNTERS
                            .leg_disconnects
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        crate::net::diagnostics::send_diag_event(
                            crate::net::diagnostics::DiagnosticsEvent::LegDisconnected {
                                leg_id: id,
                                rtt_ms: rtt,
                                reason: e.to_string(),
                            },
                        );
                        tokio::time::sleep(LEG_RECONNECT_DELAY).await;
                        crate::net::diagnostics::send_diag_event(
                            crate::net::diagnostics::DiagnosticsEvent::LegReconnecting {
                                leg_id: id,
                                attempt,
                            },
                        );
                    } else {
                        attempt = 0;
                    }
                }
            });
        }

        let m_weak = Arc::downgrade(&muxer);
        tokio::spawn(async move {
            while let Some(m_stats) = m_weak.upgrade() {
                tokio::time::sleep(TOPOLOGY_PRINT_INTERVAL).await;
                if m_stats.active_legs_count() == 0 {
                    continue;
                }
                m_stats.perform_health_check().await;
                m_stats.print_topology_tree();
            }
        });

        let muxer_inner = muxer.clone();
        tokio::spawn(async move {
            // Per-socket upload backlog. When a stream's up_tx is momentarily full we
            // stash the frame here and KEEP PROCESSING other streams — so one slow
            // upload can no longer head-of-line-block the shared loop, and we never
            // kill a healthy stream. Only a single stream sustaining more than
            // UPLOAD_PENDING_CAP buffered frames triggers bounded back-pressure
            // (a one-frame blocking send) to keep memory bounded.
            const UPLOAD_PENDING_CAP: usize = 64;
            let mut pending_upload: std::collections::HashMap<
                u64,
                std::collections::VecDeque<Bytes>,
            > = std::collections::HashMap::new();

            loop {
                // Flush existing per-socket backlogs first (fully non-blocking).
                if !pending_upload.is_empty() {
                    pending_upload.retain(|sid, q| {
                        match local_to_upload_tx.get(sid).map(|r| r.value().clone()) {
                            Some(up_tx) => {
                                while let Some(front) = q.pop_front() {
                                    match up_tx.try_send(front) {
                                        Ok(_) => {}
                                        Err(mpsc::error::TrySendError::Full(p)) => {
                                            q.push_front(p);
                                            break;
                                        }
                                        Err(mpsc::error::TrySendError::Closed(_)) => {
                                            q.clear();
                                            break;
                                        }
                                    }
                                }
                                !q.is_empty() // keep the entry only if still backlogged
                            }
                            None => false, // socket gone — drop its backlog
                        }
                    });
                }

                // Wait for the next frame; while backlogged, also wake on a short timer
                // to retry the flush as the uplink drains.
                let raw_frame = if pending_upload.is_empty() {
                    match rx_from_engine.recv().await {
                        Some(f) => f,
                        None => break,
                    }
                } else {
                    tokio::select! {
                        f = rx_from_engine.recv() => match f {
                            Some(f) => f,
                            None => break,
                        },
                        _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => continue,
                    }
                };

                if let Ok(nrxp_frame) = RawCastAdapter::to_nrxp(raw_frame.clone()) {
                    let local_socket_id = raw_frame.socket_id;
                    let f_type = nrxp_frame.header.frame_type;
                    let payload = nrxp_frame.payload;

                    match f_type {
                        FrameType::Connect | FrameType::UdpConnect => {
                            let global_stream_id = muxer_inner.next_stream_id();
                            local_to_global.insert(local_socket_id, global_stream_id);
                            registry.insert(
                                global_stream_id,
                                (
                                    local_socket_id,
                                    raw_frame.dst_ip,
                                    raw_frame.dst_port,
                                    raw_frame.protocol,
                                ),
                            );

                            let cap = NetworkConfig::global().channel_capacity;

                            let (v_tx, mut v_rx) = mpsc::channel::<Bytes>(cap);
                            let cancel_token = muxer_inner.register_stream(global_stream_id, v_tx);

                            let tx_to_tun = tx_to_engine.clone();
                            let reg = registry.clone();
                            let l2g = local_to_global.clone();
                            let up_tx_map = local_to_upload_tx.clone();

                            tokio::spawn(async move {
                                while let Some(back_payload) = v_rx.recv().await {
                                    let route_info = reg.get(&global_stream_id).map(|r| *r);

                                    if let Some((orig_local_id, ip, port, proto)) = route_info {
                                        let out_f_type = if proto == LocalProtocol::Udp {
                                            FrameType::UdpData
                                        } else {
                                            FrameType::Data
                                        };
                                        let mock_nrxp = Frame::new(
                                            orig_local_id as u32,
                                            out_f_type,
                                            back_payload,
                                        );
                                        if let Ok(raw) = RawCastAdapter::from_nrxp(
                                            mock_nrxp,
                                            ip,
                                            port,
                                            proto == LocalProtocol::Udp,
                                        ) {
                                            let _ = tx_to_tun.send(raw).await;
                                        }
                                    }
                                }

                                if let Some((_, (orig_local_id, _, _, _))) =
                                    reg.remove(&global_stream_id)
                                {
                                    l2g.remove(&orig_local_id);
                                    up_tx_map.remove(&orig_local_id);
                                    debug!(
                                        global_stream_id,
                                        "🧹 Garbage Collector: Cleaned up dead registry stream"
                                    );
                                }
                            });

                            // Per-stream upload buffer, kept deeper than the (deliberately
                            // small, anti-bufferbloat) default so upload bursts — e.g. a
                            // speedtest over a slow uplink — are absorbed here and the shared
                            // rx_from_engine loop rarely has to apply back-pressure on it.
                            let (up_tx, mut up_rx) = mpsc::channel::<Bytes>(cap.max(32));
                            local_to_upload_tx.insert(local_socket_id, up_tx);

                            let m_clone = muxer_inner.clone();
                            let is_udp = raw_frame.protocol == LocalProtocol::Udp;

                            tokio::spawn(async move {
                                let _ = m_clone
                                    .send_control(global_stream_id, f_type, payload)
                                    .await;

                                while let Some(data_payload) = up_rx.recv().await {
                                    if is_udp {
                                        // UDP has no delivery guarantee — best-effort like
                                        // run_udp_bridge: drop on a dead tunnel, don't pause.
                                        let _ = m_clone
                                            .send_data_safe(global_stream_id, data_payload, true)
                                            .await;
                                        continue;
                                    }

                                    // 🔥 GRACEFUL PAUSE (anti-domino), symmetric to
                                    // run_tcp_bridge's upload half on the server. send_data_safe
                                    // already fails over between live legs; it only errors when
                                    // EVERY leg is down. That used to be silently ignored here
                                    // (`let _ = ...await`), permanently dropping the chunk and
                                    // corrupting the upload mid-stream. Now we hold the chunk and
                                    // retry while the engine reconnects, bounded by
                                    // STREAM_PAUSE_BUDGET, and bail out immediately if the stream
                                    // gets torn down from elsewhere (peer Close, backlog
                                    // eviction) meanwhile.
                                    let deadline = Instant::now() + STREAM_PAUSE_BUDGET;
                                    let mut delivered = false;
                                    loop {
                                        if m_clone
                                            .send_data_safe(
                                                global_stream_id,
                                                data_payload.clone(),
                                                false,
                                            )
                                            .await
                                            .is_ok()
                                        {
                                            delivered = true;
                                            break;
                                        }
                                        if Instant::now() >= deadline {
                                            break;
                                        }
                                        tokio::select! {
                                            biased;
                                            _ = cancel_token.cancelled() => break,
                                            _ = tokio::time::sleep(STREAM_PAUSE_RETRY) => {}
                                        }
                                    }
                                    if !delivered {
                                        warn!(
                                            global_stream_id,
                                            "Upload stream pause budget exceeded — no leg recovered, dropping stream"
                                        );
                                        m_clone.remove_stream(global_stream_id);
                                        break;
                                    }
                                }
                            });
                        }
                        FrameType::Data | FrameType::UdpData => {
                            if let Some(up_tx) = local_to_upload_tx
                                .get(&local_socket_id)
                                .map(|r| r.value().clone())
                            {
                                // PER-STREAM, no shared-loop HOL: if this stream already has a
                                // backlog, queue behind it (preserve order). Otherwise try a
                                // non-blocking send; on full, START a backlog and keep serving
                                // OTHER streams. (Replaces the old 2 s blocking grace that
                                // stalled the whole loop and then killed healthy streams.)
                                if let Some(q) = pending_upload.get_mut(&local_socket_id) {
                                    q.push_back(payload);
                                } else {
                                    match up_tx.try_send(payload) {
                                        Ok(_) => {}
                                        Err(mpsc::error::TrySendError::Closed(_)) => {}
                                        Err(mpsc::error::TrySendError::Full(p)) => {
                                            let mut q =
                                                std::collections::VecDeque::with_capacity(16);
                                            q.push_back(p);
                                            pending_upload.insert(local_socket_id, q);
                                        }
                                    }
                                }

                                // Bounded back-pressure: only if THIS stream's backlog exceeds
                                // the cap (sustained uplink-bound overload) do we block on a
                                // single frame, so memory stays bounded. Never closes the
                                // stream; other streams were already flushed at the loop top.
                                let over_cap = pending_upload
                                    .get(&local_socket_id)
                                    .is_some_and(|q| q.len() > UPLOAD_PENDING_CAP);
                                if over_cap {
                                    let front = pending_upload
                                        .get_mut(&local_socket_id)
                                        .and_then(|q| q.pop_front());
                                    if let Some(front) = front {
                                        let _ = up_tx.send(front).await;
                                    }
                                }
                            }
                        }
                        FrameType::Close => {
                            pending_upload.remove(&local_socket_id);
                            if let Some(kv) = local_to_global.remove(&local_socket_id) {
                                let global_stream_id = kv.1;

                                let m_clone = muxer_inner.clone();
                                tokio::spawn(async move {
                                    let _ = m_clone
                                        .send_control(
                                            global_stream_id,
                                            FrameType::Close,
                                            Bytes::new(),
                                        )
                                        .await;
                                    m_clone.remove_stream(global_stream_id);
                                });

                                registry.remove(&global_stream_id);
                                local_to_upload_tx.remove(&local_socket_id);
                            }
                        }
                        _ => {}
                    }
                }
            }
        });

        Ok(muxer)
    }
}

/// Серверная сторона: обрабатывает одно входящее соединение.
pub struct ServerHandler {
    pub(crate) conn: Connection,
    pub(crate) session_manager: Arc<SessionManager>,
    /// Домен-декой для stealth-fallback (атрибут ноды, задаётся при старте
    /// сервера через `--decoy-host`; раньше был захардкожен на `ubuntu.com`).
    pub(crate) decoy_host: Arc<str>,
    /// `None` — авторизация выключена на этом инстансе (`--require-auth` не
    /// передан), поведение как до этой фичи. `Some` — токен клиента
    /// обязателен и проверяется бэкендом при установке первой ноги сессии.
    pub(crate) auth: Option<Arc<dyn crate::net::AuthValidator>>,
}

impl ServerHandler {
    pub fn new(
        connection: Connection,
        session_manager: Arc<SessionManager>,
        decoy_host: Arc<str>,
        auth: Option<Arc<dyn crate::net::AuthValidator>>,
    ) -> Self {
        Self {
            conn: connection,
            session_manager,
            decoy_host,
            auth,
        }
    }

    /// Stealth-fallback: прозрачно проксирует соединение на безобидный хост,
    /// когда клиент оказался «не наш».
    ///
    /// `requested_sni` — hostname из SNI невалидного `ClientHello`, если он
    /// удалось разобрать (`None`, если хендшейк вообще не распарсился/не
    /// дождались данных). Раньше fallback всегда шёл на один и тот же
    /// фиксированный `decoy_host` независимо от того, какой SNI прислал
    /// зонд — активное зондирование с разными SNI на один и тот же IP всегда
    /// получало одинаковый ответ, что само по себе выдавало нестандартный
    /// прокси. Теперь при валидном `requested_sni` проксируем именно на него
    /// (резолвится и проверяется через [`resolve_safe_decoy_addr`] — только
    /// публичные IP, чтобы SNI, присланный атакующим, не мог заставить ноду
    /// самой законнектиться на внутреннюю инфраструктуру, SSRF), а на
    /// `decoy_host` — только если SNI нет, невалиден или резолвится
    /// небезопасно.
    ///
    /// Уже прочитанные байты (`initial_data`) пересылаются первыми, затем
    /// соединение склеивается в обе стороны через `tokio::io::copy`. Снаружи это
    /// выглядит как обычный визит на публичный сайт — сервер не выдаёт себя
    /// сканерам и активным пробам DPI.
    async fn handle_stealth_fallback(
        mut client_inbound: OwnedReadHalf,
        mut client_outbound: OwnedWriteHalf,
        initial_data: Bytes,
        decoy_host: &str,
        requested_sni: Option<&str>,
    ) {
        // Единая точка для всех трёх причин fallback (невалидный ClientHello,
        // TLS_HELLO_TIMEOUT, парсинг не удался) — та, кто сюда попал, ПО
        // ОПРЕДЕЛЕНИЮ не наш клиент (не собрал корректный Netrunner-хендшейк),
        // отсюда и метрика: любой TCP-коннект на 443, не ставший
        // `netrunner_vpn_established_total`, либо сюда, либо в
        // `netrunner_auth_failed_total` (см. ниже в `run`) — граница между
        // "реальный VPN-трафик" и "сканеры/DPI-пробы, долбящиеся на порт".
        metrics::counter!("netrunner_scanner_fallback_total").increment(1);
        let sni_target = requested_sni.filter(|h| is_plausible_hostname(h));

        // Приватность: не логируем ни запрошенный SNI, ни разрешённый адрес —
        // это то же самое "куда идёт клиент", просто на пути анти-DPI decoy'я,
        // а не обычного туннеля. Достаточно знать, свой ли SNI использован или
        // пришлось падать на decoy_host.
        let target_addr = match sni_target {
            Some(host) => match resolve_safe_decoy_addr(host, HTTPS_PORT).await {
                Some(addr) => {
                    debug!("Stealth fallback: bridging to requested SNI");
                    Some(addr)
                }
                None => {
                    debug!("Stealth fallback: SNI resolved unsafely or failed, using decoy_host");
                    resolve_safe_decoy_addr(decoy_host, HTTPS_PORT).await
                }
            },
            None => resolve_safe_decoy_addr(decoy_host, HTTPS_PORT).await,
        };

        let Some(target_addr) = target_addr else {
            warn!("Stealth fallback: no safe target address available, dropping connection.");
            return;
        };

        debug!("Stealth fallback: bridging to decoy target");
        let target_stream =
            tokio::time::timeout(FALLBACK_CONNECT_TIMEOUT, TcpStream::connect(target_addr)).await;

        if let Ok(Ok(target_server)) = target_stream {
            let (mut server_read, mut server_write) = target_server.into_split();

            if !initial_data.is_empty() && server_write.write_all(&initial_data).await.is_err() {
                return;
            }

            let client_to_server = tokio::io::copy(&mut client_inbound, &mut server_write);
            let server_to_client = tokio::io::copy(&mut server_read, &mut client_outbound);

            let _ = tokio::join!(client_to_server, server_to_client);
            debug!("Stealth fallback connection closed.");
        } else {
            warn!("Failed to connect to fallback host.");
        }
    }
}

/// Серверный жизненный цикл соединения: хендшейк → аутентификация → движок.
///
/// Три фазы, на каждой при малейшем несоответствии — stealth-fallback или отказ:
/// 1. Принять `ClientHello` и собрать `ServerHello`; невалидный/чужой → fallback.
/// 2. Расшифровать первый кадр и проверить auth-payload `"session_id:leg_id"`;
///    неверный → [`ERR_AUTH_FAILED`].
/// 3. Прицепить ногу к muxer сессии и крутить [`TunnelEngine`]; по завершении —
///    эвикт ноги и отложенная уборка сессии, если ног не осталось.
#[async_trait::async_trait]
impl TunnelHandler for ServerHandler {
    async fn run(self) -> Result<(), AppError> {
        debug!("Acting as TLS Server with Stealth Fallback");

        let decoy_host = self.decoy_host;
        let Connection {
            mut inbound,
            mut outbound,
            mut read_buf,
        } = self.conn;
        let mut session_keys = SessionKeys::new(false);

        let (hello, peer_version) = loop {
            let buf_snapshot = read_buf.clone().freeze();

            match TlsBridge::unpack_handshake(&mut read_buf) {
                Ok(Some(client_msg)) => {
                    match TlsBridge::wrap_server_hello(
                        &client_msg,
                        &mut session_keys,
                        &ServerProfile::MODERN,
                    ) {
                        Ok((sh, peer_version)) => {
                            debug!(peer_version, "✅ Valid Netrunner ClientHello detected");
                            break (sh, peer_version);
                        }
                        Err(e) => {
                            warn!("❌ Unauthorized/Invalid ClientHello. Triggering Stealth Fallback. Reason: {:?}", e.stage);
                            // Невалидный (например, чужой) ClientHello всё равно разобрался
                            // синтаксически — достаём его SNI, чтобы fallback проксировал
                            // именно на запрошенный хост, а не всегда на один и тот же decoy.
                            let requested_sni = client_msg.extensions().server_name();
                            Self::handle_stealth_fallback(
                                inbound,
                                outbound,
                                buf_snapshot,
                                &decoy_host,
                                requested_sni.as_deref(),
                            )
                            .await;
                            return Ok(());
                        }
                    }
                }
                Ok(None) => {
                    let res =
                        tokio::time::timeout(TLS_HELLO_TIMEOUT, inbound.read_buf(&mut read_buf))
                            .await;
                    match res {
                        Ok(Ok(0)) => {
                            return Err(AppError::new(
                                ERR_INFRA_TIMEOUT,
                                "Клиент отключился",
                                "Client closed connection",
                            ))
                        }
                        Ok(Ok(_)) => continue,
                        _ => {
                            warn!("⏰ TLS_HELLO_TIMEOUT reached. Triggering fallback...");
                            Self::handle_stealth_fallback(
                                inbound,
                                outbound,
                                buf_snapshot,
                                &decoy_host,
                                None,
                            )
                            .await;
                            return Ok(());
                        }
                    }
                }
                Err(_) => {
                    warn!("❌ Handshake parse failed (Not a valid TLS probe). Triggering Stealth Fallback.");
                    Self::handle_stealth_fallback(
                        inbound,
                        outbound,
                        buf_snapshot,
                        &decoy_host,
                        None,
                    )
                    .await;
                    return Ok(());
                }
            }
        };

        // Обмен CCS — только с клиентами, заявившими версию протокола, которая
        // его понимает (crate::MIN_VERSION_FOR_CCS). Старый клиент (версия ниже)
        // ничего не знает про CCS и с обеих сторон получает досемверсионное
        // поведение — иначе апгрейд сервера порвал бы соединения с ещё не
        // обновлёнными клиентскими сборками.
        let use_ccs = peer_version >= crate::MIN_VERSION_FOR_CCS;

        if use_ccs {
            // Клиент шлёт свой ChangeCipherSpec сразу после ClientHello —
            // вычитываем и отбрасываем её здесь же (см. TlsBridge::build_middlebox_ccs).
            consume_middlebox_ccs(&mut inbound, &mut read_buf).await?;
        }

        // Небольшой случайный джиттер перед ответом: мгновенный, идеально
        // детерминированный ServerHello сам по себе отличает наш стек от
        // бэкенда настоящего сайта с обычным серверным временем обработки.
        let jitter_ms = rand::rng().random_range(5..=40u64);
        tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;

        outbound
            .write_all(&hello)
            .await
            .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Ошибка отправки", e.to_string()))?;

        if use_ccs {
            // ...и сами отвечаем своим ChangeCipherSpec сразу после ServerHello —
            // по той же причине, что и клиент.
            outbound
                .write_all(&TlsBridge::build_middlebox_ccs())
                .await
                .map_err(|e| AppError::new(ERR_INFRA_TIMEOUT, "Ошибка отправки", e.to_string()))?;
        }

        let (tx_key, tx_iv, rx_key, rx_iv) = session_keys.get_aead_parameters();
        let mut cipher = ChaChaCipher::new();
        cipher.set_keys(tx_key, tx_iv, rx_key, rx_iv);

        let codec = Codec::new(cipher, session_keys.get_auth_key());
        let (mut rx_codec, mut tx_codec) = codec.split();

        let (session_id, leg_id, auth_token) = loop {
            match rx_codec.decode_inbound(&mut read_buf) {
                Ok(Some(frame)) => {
                    if frame.header.frame_type == FrameType::Heartbeat {
                        let payload_str = std::str::from_utf8(&frame.payload).unwrap_or("");
                        let parts: Vec<&str> = payload_str.splitn(3, ':').collect();
                        if parts.len() == 3 && parts[1].parse::<u32>().is_ok() {
                            let sid = parts[0].to_string();
                            let lid: u32 = parts[1].parse().unwrap();
                            let token = parts[2].to_string();
                            debug!("🤝 Secure Auth verified! Session: {}, Leg: {}", sid, lid);
                            break (sid, lid, token);
                        }
                    }
                    // Собрал корректный Netrunner-хендшейк (не сканер — тот
                    // отсеялся бы ещё в handle_stealth_fallback), но не смог
                    // пройти auth-фрейм — тот же счётчик, что уже копится в
                    // backend_client.rs::validate() при отказе бэкенда (тот же
                    // Grafana-панель "Auth failures/sec", см.
                    // netrunner-data/observability/grafana-dashboards/proxy-nodes.json) —
                    // просто ещё один источник событий "auth провалился", на
                    // фрейм-уровне, ДО похода к бэкенду.
                    metrics::counter!("netrunner_auth_failures_total").increment(1);
                    return Err(AppError::new(
                        ERR_AUTH_FAILED,
                        "Ошибка авторизации",
                        "Expected Auth payload in first Heartbeat frame",
                    ));
                }
                Ok(None) => {
                    let n = tokio::time::timeout(
                        SECURE_HANDSHAKE_TIMEOUT,
                        inbound.read_buf(&mut read_buf),
                    )
                    .await
                    .map_err(|_| {
                        AppError::new(
                            ERR_INFRA_TIMEOUT,
                            "Таймаут авторизации",
                            "Timeout waiting for Auth",
                        )
                    })?
                    .map_err(|e| {
                        AppError::new(ERR_INFRA_TIMEOUT, "Ошибка сокета", e.to_string())
                    })?;
                    if n == 0 {
                        metrics::counter!("netrunner_auth_failures_total").increment(1);
                        return Err(AppError::new(
                            ERR_AUTH_FAILED,
                            "Отказ",
                            "Client closed connection before Auth",
                        ));
                    }
                }
                Err(e) => {
                    error!("❌ Secure Auth Failed: {:?}", e.stage);
                    metrics::counter!("netrunner_auth_failures_total").increment(1);
                    return Err(AppError::new(
                        ERR_AUTH_FAILED,
                        "Доступ запрещен",
                        "Dropped by security strategy (Auth Phase)",
                    ));
                }
            }
        };

        let muxer = self.session_manager.get_or_create(&session_id);

        // Проверка личности клиента у бэкенда — только если этот инстанс
        // запущен с `--require-auth`. До этой точки соединение прошло
        // Netrunner-хендшейк (не сканер/чужой TLS-клиент), поэтому отказ здесь
        // — обычный разрыв, а не stealth-fallback (светить уже нечего).
        if let Some(validator) = &self.auth {
            match validator.validate(&auth_token).await {
                Ok(quota) => muxer.set_quota_user(quota.user_id),
                Err(e) => {
                    // Не дублируем счётчик — `BackendClient::validate` (см.
                    // server/src/backend_client.rs) уже инкрементит тот же
                    // `netrunner_auth_failures_total` сам, на обеих своих
                    // ветках отказа (пустой токен / бэкенд отклонил).
                    warn!("❌ Backend rejected client token: {}", e.internal_msg);
                    // Раньше клиент видел только голый TCP EOF на отказ — неотличимо
                    // от сбоя сети/недоступной цели (см. client-edge: "vpn node
                    // closed the tunnel leg" без единой подсказки, почему). Шлём
                    // явный сигнал ДО закрытия: Close-кадр на служебном stream_id=0
                    // (0 уже зарезервирован под heartbeat/diag — см. muxer.rs,
                    // ни один реальный Connect-поток туда никогда не попадает), с
                    // текстовой причиной. Crypto-хендшейк уже завершён, поэтому
                    // кадр кодируется тем же codec'ом, что и всё остальное — клиент
                    // (edge и толстый) видит его как обычный кадр в своём цикле чтения.
                    if let Ok(reject_frame) = tx_codec.encode_frame(
                        0,
                        FrameType::Close,
                        Bytes::from(format!("auth_rejected: {}", e.internal_msg)),
                    ) {
                        let _ = outbound.write_all(&reject_frame).await;
                    }
                    return Err(AppError::new(
                        ERR_AUTH_FAILED,
                        "Доступ запрещен",
                        e.internal_msg,
                    ));
                }
            }
        }

        let cap = NetworkConfig::global().channel_capacity;
        let (control_tx, control_rx) = mpsc::channel::<MuxMessage>(cap);
        let (data_tx, data_rx) = mpsc::channel::<MuxMessage>(cap);

        let control_tx_clone = control_tx.clone();
        muxer.add_leg(leg_id, control_tx, data_tx);
        // Прошли все три фазы (валидный хендшейк → auth-фрейм → токен принят
        // бэкендом, если --require-auth включён) — вот теперь это реальное
        // "подключение к моему VPN", не просто TCP-коннект на 443. См.
        // netrunner_scanner_fallback_total/netrunner_auth_failed_total выше за
        // тем, как выглядят остальные две категории.
        metrics::counter!("netrunner_vpn_established_total").increment(1);

        let opener = Arc::new(RemoteOpener {
            muxer: muxer.clone(),
        });
        let handler = Arc::new(StreamHandler::new(muxer.clone(), Some(opener)));

        let log_session_id = session_id.clone();

        let engine = TunnelEngine {
            leg_id,
            inbound: Some(inbound),
            outbound: Some(outbound),
            // 💡 ИЗМЕНЕНО: Передаем кодеки без Arc<Mutex>
            rx_codec: Some(rx_codec),
            tx_codec: Some(tx_codec),
            read_buf,
            control_rx: Some(control_rx),
            data_rx: Some(data_rx),
            handler,
            muxer: muxer.clone(),
            remote_addr: String::new(),
            session_id,
            leg_status: crate::net::connection::engine::LegStatus::Active,
            // Сервер никогда не реконнектит (см. `attempt_reconnect`'s early
            // return on empty `remote_addr`), поэтому SNI/токен здесь не используются.
            decoy_sni: Arc::from(""),
            auth_token: Arc::from(""),
        };

        let res = engine.run().await;

        muxer.remove_leg(leg_id, &control_tx_clone);

        if muxer.active_legs_count() == 0 {
            let sm = self.session_manager.clone();
            let sid = log_session_id;
            let m = muxer.clone();
            tokio::spawn(async move {
                tokio::time::sleep(SESSION_CLEANUP_DELAY).await;
                if m.active_legs_count() == 0 {
                    sm.remove(&sid);
                }
            });
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- is_plausible_hostname ----------

    #[test]
    fn plausible_hostnames_are_accepted() {
        for host in [
            "example.com",
            "dev.netrunner-vpn.com",
            "a.b.c.d.e.example.org",
            "xn--80ak6aa92e.com", // punycode — только ascii-alnum/./-
        ] {
            assert!(is_plausible_hostname(host), "{host} should be plausible");
        }
    }

    #[test]
    fn ip_literals_are_rejected() {
        for host in [
            "127.0.0.1",
            "8.8.8.8",
            "::1",
            "2001:db8::1",
            "169.254.169.254",
        ] {
            assert!(
                !is_plausible_hostname(host),
                "{host} is an IP, not a hostname"
            );
        }
    }

    #[test]
    fn empty_and_oversized_hostnames_are_rejected() {
        assert!(!is_plausible_hostname(""));
        let too_long = "a".repeat(254);
        assert!(!is_plausible_hostname(&too_long));
        let just_ok = "a".repeat(253);
        assert!(is_plausible_hostname(&just_ok));
    }

    #[test]
    fn hostnames_with_unexpected_characters_are_rejected() {
        for host in [
            "exa mple.com",
            "example.com/../etc",
            "example.com\0",
            "user@example.com",
            "example.com:8080",
            "http://example.com",
        ] {
            assert!(!is_plausible_hostname(host), "{host} has invalid chars");
        }
    }

    // ---------- is_safe_decoy_ip ----------

    #[test]
    fn public_ipv4_is_safe() {
        assert!(is_safe_decoy_ip(&"8.8.8.8".parse().unwrap()));
        assert!(is_safe_decoy_ip(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn private_and_special_ipv4_ranges_are_blocked() {
        for ip in [
            "127.0.0.1",       // loopback
            "10.0.0.1",        // private
            "172.16.0.1",      // private
            "192.168.1.1",     // private
            "169.254.169.254", // link-local / cloud metadata endpoint
            "224.0.0.1",       // multicast
            "0.0.0.0",         // unspecified
            "255.255.255.255", // broadcast
            "192.0.2.1",       // documentation (TEST-NET-1)
        ] {
            let addr: std::net::IpAddr = ip.parse().unwrap();
            assert!(!is_safe_decoy_ip(&addr), "{ip} must be blocked");
        }
    }

    #[test]
    fn public_ipv6_is_safe() {
        // 2606:4700:4700::1111 — Cloudflare public resolver.
        assert!(is_safe_decoy_ip(&"2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn private_and_special_ipv6_ranges_are_blocked() {
        for ip in [
            "::1",          // loopback
            "::",           // unspecified
            "fe80::1",      // link-local
            "fc00::1",      // unique local
            "fd12:3456::1", // unique local (fd.. subset)
            "ff02::1",      // multicast
        ] {
            let addr: std::net::IpAddr = ip.parse().unwrap();
            assert!(!is_safe_decoy_ip(&addr), "{ip} must be blocked");
        }
    }

    // ---------- resolve_safe_decoy_addr ----------

    #[tokio::test]
    async fn resolve_safe_decoy_addr_accepts_public_ip_literal() {
        let addr = resolve_safe_decoy_addr("93.184.216.34", 443).await;
        assert_eq!(addr, Some("93.184.216.34:443".parse().unwrap()));
    }

    #[tokio::test]
    async fn resolve_safe_decoy_addr_rejects_private_ip_literal() {
        // "host" здесь буквально IP из приватного диапазона — резолв тривиален
        // (без сети), но результат всё равно должен быть отфильтрован.
        let addr = resolve_safe_decoy_addr("10.0.0.5", 443).await;
        assert_eq!(addr, None);
    }

    #[tokio::test]
    async fn resolve_safe_decoy_addr_rejects_metadata_endpoint() {
        let addr = resolve_safe_decoy_addr("169.254.169.254", 443).await;
        assert_eq!(
            addr, None,
            "cloud metadata endpoint must never be reachable via decoy fallback"
        );
    }

    // ---------- полный хендшейк клиент↔сервер по настоящему TCP ----------

    /// Легитимный хендшейк: клиент шлёт настоящий ClientHello+CCS, сервер
    /// проверяет auth-тег, отвечает ServerHello+CCS, клиент шлёт auth-кадр —
    /// всё по реальному TCP-сокету (не в памяти), с реальными таймингами и
    /// разбиением на TCP-чтения. Проверяет именно то, что не покрывают чисто
    /// байтовые юнит-тесты: что CCS/версия/хендшейк действительно
    /// синхронизируются через настоящий сокет, а не только в идеальном
    /// одноразовом буфере.
    #[tokio::test]
    async fn legitimate_handshake_succeeds_over_real_tcp() {
        NetworkConfig::init_global(1500);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = Connection::new(stream);
            let handler = ServerHandler::new(
                conn,
                Arc::new(SessionManager::new()),
                Arc::from("example.com"),
                None,
            );
            // run() продолжает в muxer/engine после хендшейка и вернётся сам,
            // как только клиент закроет сокет (наш тест-клиент не шлёт
            // ничего сверх auth-кадра) — достаточно не повиснуть навсегда.
            handler.run().await
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let session_id = SessionManager::generate_id();
        let handshake = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            ClientHandler::perform_handshake(
                stream,
                &session_id,
                0,
                BrowserProfile::for_session(&session_id),
                &Arc::<str>::from("example.com"),
                "",
            ),
        )
        .await
        .expect("handshake must not hang")
        .expect("legitimate handshake must succeed");

        let (_inbound, _outbound, _rx_codec, _tx_codec) = handshake;
        drop(_inbound);
        drop(_outbound);

        // Сервер должен либо уже завершиться, либо завершиться вскоре после
        // того, как клиент уронил сокет (EOF в движке туннеля) — не повиснуть.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server_task).await;
    }

    /// Мусорный (не-NRXP) ClientHello должен уводить сервер в stealth-fallback,
    /// а не в панику/зависание. decoy_host намеренно указывает на
    /// незарезолвливаемое имя — тест офлайновый, реальный интернет не нужен;
    /// нас интересует, что сервер аккуратно завершает соединение, а не падает
    /// и не висит вечно.
    #[tokio::test]
    async fn garbage_client_hello_triggers_fallback_without_hanging() {
        NetworkConfig::init_global(1500);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let conn = Connection::new(stream);
            let handler = ServerHandler::new(
                conn,
                Arc::new(SessionManager::new()),
                Arc::from("this-host-does-not-resolve.invalid"),
                None,
            );
            handler.run().await
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Валидная по форме TLS Handshake-запись (content_type=0x16, версия,
        // длина=5, ровно 5 байт тела), но тело — мусор, не ClientHello/ServerHello.
        // Это специально ОТЛИЧАЕТСЯ от "просто разорвал соединение": здесь
        // сервер должен дойти до Err(_) в unpack_handshake (парсинг записи
        // прошёл, разбор hello — нет) и сразу уйти в fallback, а не ждать
        // TLS_HELLO_TIMEOUT из-за "недостаточно данных".
        stream
            .write_all(&[0x16, 0x03, 0x03, 0x00, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00])
            .await
            .unwrap();
        drop(stream);

        let result = tokio::time::timeout(std::time::Duration::from_secs(15), server_task).await;
        assert!(
            result.is_ok(),
            "server must not hang forever on a non-NRXP ClientHello"
        );
        // handle_stealth_fallback возвращает Ok(()) даже если decoy недостижим —
        // соединение просто тихо закрывается, как и было задумано.
        assert!(matches!(result.unwrap().unwrap(), Ok(())));
    }
}
