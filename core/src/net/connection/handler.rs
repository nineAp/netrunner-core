//! Диспетчеризация входящих кадров туннеля по их типу и `stream_id`.
//!
//! [`StreamHandler`] — это «маршрутизатор» на приёмной стороне: один кадр входит,
//! и в зависимости от типа происходит одно из:
//! - `Heartbeat` → ответить PONG / измерить RTT / переслать локально;
//! - `Connect`/`UdpConnect` → (только сервер) открыть соединение к цели;
//! - `Data`/`UdpData` → доставить данные в локальный поток (с backpressure);
//! - `Close` → закрыть поток.
//!
//! Открытием реальных соединений к целям занимается [`RemoteOpener`] (есть только
//! на сервере: у клиента `opener == None`, поэтому входящие `Connect` отвергаются).
//! Каждое открытое соединение защищено [`CancellationToken`] — при эвикте/закрытии
//! потока мост и установка соединения мгновенно обрываются.

use bytes::Bytes;
use netrunner_logger::{debug, trace, warn};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use tokio_util::sync::CancellationToken;

use crate::net::{
    connection::{
        bridge::{run_tcp_bridge, run_udp_bridge},
        muxer::Muxer,
    },
    MeshRoute, NetworkConfig,
};
use crate::nrxp::{Frame, FrameType};

/// Открыватель реальных соединений к целям (серверная сторона туннеля).
///
/// На каждый входящий `Connect`/`UdpConnect` поднимает TCP/UDP-сокет к цели и
/// запускает соответствующий мост, прокачивающий данные между туннелем и целью.
pub struct RemoteOpener {
    pub muxer: Arc<Muxer>,
    /// Present on a user/client session when this ingress must forward every
    /// destination through the configured mesh route. Mesh-peer sessions only
    /// receive a router when their authenticated route has hops remaining.
    pub mesh: Option<Arc<crate::net::NodeMesh>>,
    /// Per-flow route budget and visited-node set. This is fixed at CONNECT and
    /// carried unchanged for the lifetime of the flow.
    pub mesh_route: Option<MeshRoute>,
    /// Mesh egress sessions confirm destination CONNECTs over the control
    /// stream before their ingress acknowledges the client request.
    pub mesh_peer: bool,
    /// The authenticated peer used the mesh4 onion-capable handshake.
    pub mesh_onion_peer: bool,
}

impl RemoteOpener {
    pub async fn open_tcp_with_privacy(
        &self,
        stream_id: u32,
        target: String,
        v_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
        strong_privacy: bool,
    ) {
        if !self.mesh_peer
            && self
                .mesh_route
                .as_ref()
                .is_some_and(|route| route.remaining_hops > 1)
        {
            if let Some(mesh) = self.mesh.clone() {
                let max_hops = self
                    .mesh_route
                    .as_ref()
                    .map_or(1, |route| route.remaining_hops);
                tokio::spawn(Self::open_via_onion(
                    self.muxer.clone(),
                    mesh,
                    stream_id,
                    target,
                    v_rx,
                    token,
                    false,
                    strong_privacy,
                    max_hops,
                ));
                return;
            }
        }
        if strong_privacy {
            self.reject_stream(stream_id, token).await;
            return;
        }
        if !self.mesh_peer && self.mesh_route.is_none() {
            if let Some(mesh) = self.mesh.clone() {
                if mesh.is_direct_output() {
                    tokio::spawn(Self::open_local_tcp_with_egress_failover(
                        self.muxer.clone(),
                        mesh,
                        stream_id,
                        target,
                        v_rx,
                        token,
                    ));
                    return;
                }
            }
        }
        self.open_tcp(stream_id, target, v_rx, token).await;
    }

    pub async fn open_udp_with_privacy(
        &self,
        stream_id: u32,
        target: String,
        v_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
        strong_privacy: bool,
    ) {
        if !self.mesh_peer
            && self
                .mesh_route
                .as_ref()
                .is_some_and(|route| route.remaining_hops > 1)
        {
            if let Some(mesh) = self.mesh.clone() {
                let max_hops = self
                    .mesh_route
                    .as_ref()
                    .map_or(1, |route| route.remaining_hops);
                tokio::spawn(Self::open_via_onion(
                    self.muxer.clone(),
                    mesh,
                    stream_id,
                    target,
                    v_rx,
                    token,
                    true,
                    strong_privacy,
                    max_hops,
                ));
                return;
            }
        }
        if strong_privacy {
            self.reject_stream(stream_id, token).await;
            return;
        }
        if !self.mesh_peer && self.mesh_route.is_none() {
            if let Some(mesh) = self.mesh.clone() {
                if mesh.is_direct_output() {
                    tokio::spawn(Self::open_local_udp_with_egress_failover(
                        self.muxer.clone(),
                        mesh,
                        stream_id,
                        target,
                        v_rx,
                        token,
                    ));
                    return;
                }
            }
        }
        self.open_udp(stream_id, target, v_rx, token).await;
    }

    async fn open_local_tcp_with_egress_failover(
        muxer: Arc<Muxer>,
        mesh: Arc<crate::net::NodeMesh>,
        stream_id: u32,
        target: String,
        v_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
    ) {
        let stream = tokio::select! {
            _ = token.cancelled() => None,
            result = tokio::time::timeout(Duration::from_secs(7), TcpStream::connect(&target)) => {
                result.ok().and_then(Result::ok)
            }
        };
        if let Some(stream) = stream {
            let (reader, writer) = stream.into_split();
            // `biased` + a flag: the bridge's own guard cancels the stream token on the
            // way out, so `token.is_cancelled()` can't tell "bridge finished" from
            // "evicted". Only an eviction (cancelled while the bridge still runs) skips
            // the Close; a normal end must tell the peer, or its socket never sees EOF.
            let bridge_finished = tokio::select! {
                biased;
                _ = run_tcp_bridge(stream_id, reader, writer, muxer.clone(), v_rx) => true,
                _ = token.cancelled() => false,
            };
            if bridge_finished {
                let _ = muxer
                    .send_control(stream_id, FrameType::Close, Bytes::new())
                    .await;
            }
            muxer.remove_stream(stream_id);
            return;
        }
        if token.is_cancelled() {
            muxer.remove_stream(stream_id);
            return;
        }

        let fallback = mesh
            .build_direct_onion_fallback(&target, false, false)
            .await;
        let (fallback, failovers_left) = fallback
            .map(|(fallback, count)| (Some(fallback), count))
            .unwrap_or((None, 0));
        run_mesh_onion_failover(
            mesh,
            muxer,
            stream_id,
            v_rx,
            token,
            false,
            false,
            fallback,
            failovers_left,
            false,
        )
        .await;
    }

    async fn open_local_udp_with_egress_failover(
        muxer: Arc<Muxer>,
        mesh: Arc<crate::net::NodeMesh>,
        stream_id: u32,
        target: String,
        v_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
    ) {
        let address = tokio::select! {
            _ = token.cancelled() => None,
            result = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(&target)) => {
                result.ok().and_then(Result::ok).and_then(|mut addresses| addresses.next())
            }
        };
        if let Some(address) = address {
            let bind = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = tokio::select! {
                _ = token.cancelled() => None,
                result = UdpSocket::bind(bind) => result.ok(),
            };
            if let Some(socket) = socket {
                if socket.connect(address).await.is_ok() {
                    tokio::select! {
                        _ = token.cancelled() => {},
                        _ = run_udp_bridge(stream_id, socket, muxer.clone(), v_rx) => {},
                    }
                    muxer.remove_stream(stream_id);
                    return;
                }
            }
        }
        if token.is_cancelled() {
            muxer.remove_stream(stream_id);
            return;
        }

        let fallback = mesh.build_direct_onion_fallback(&target, true, false).await;
        let (fallback, failovers_left) = fallback
            .map(|(fallback, count)| (Some(fallback), count))
            .unwrap_or((None, 0));
        run_mesh_onion_failover(
            mesh,
            muxer,
            stream_id,
            v_rx,
            token,
            true,
            false,
            fallback,
            failovers_left,
            false,
        )
        .await;
    }

    async fn reject_stream(&self, stream_id: u32, token: CancellationToken) {
        if !token.is_cancelled() {
            let _ = self
                .muxer
                .send_control(stream_id, FrameType::Close, Bytes::new())
                .await;
        }
        self.muxer.remove_stream(stream_id);
    }

    /// Открывает TCP-соединение к `target` и запускает TCP-мост.
    ///
    /// Всё происходит в отдельной задаче. Установка соединения (тайм-аут 7 с) и
    /// сам мост обёрнуты в `select!` с `token.cancelled()` — эвикт обрывает их
    /// немедленно. При неудаче подключения шлёт `Close` обратно в туннель. По
    /// завершении всегда снимает регистрацию потока.
    pub async fn open_tcp(
        &self,
        stream_id: u32,
        target: String,
        v_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
    ) {
        let muxer = self.muxer.clone();
        let mesh = self.mesh.clone();
        let mesh_route = self.mesh_route.clone();
        let mesh_peer = self.mesh_peer;
        let self_mesh_onion_peer = self.mesh_onion_peer;
        let mesh2_peer = mesh_route.is_some();
        tokio::spawn(async move {
            if let (Some(mesh), Some(route)) = (mesh, mesh_route) {
                Self::open_via_mesh(
                    muxer, mesh, route, stream_id, target, v_rx, token, false, mesh_peer,
                )
                .await;
                return;
            }

            // Приватность: НЕ логируем `target` (хост, к которому идёт пользователь)
            // — это ровно та информация о его активности, которую прокси не должен
            // хранить нигде. `stream_id` достаточно для локальной корреляции.
            debug!(stream_id, "🌐 [Remote] Connecting");
            let start = Instant::now();

            tokio::select! {
                _ = token.cancelled() => {
                    debug!(stream_id, "🔪 Target connection cancelled by Eviction");
                    return;
                }
                connect_res = tokio::time::timeout(Duration::from_secs(7), TcpStream::connect(&target)) => {
                    match connect_res {
                        Ok(Ok(stream)) => {
                            if mesh_peer {
                                let ready = if mesh2_peer || self_mesh_onion_peer {
                                    crate::net::MESH_ROUTE_READY
                                } else {
                                    b"PONG"
                                };
                                let _ = muxer
                                    .send_control(
                                        stream_id,
                                        FrameType::Heartbeat,
                                        Bytes::from_static(ready),
                                    )
                                    .await;
                            }
                            debug!(stream_id, elapsed_ms = start.elapsed().as_millis() as u64, "✅ [Remote] Connected");
                            let (r, w) = stream.into_split();

                            // Credit-gated reads (Muxer::consume_credit) were tried here and
                            // reverted: tying read pacing to a network round-trip produced
                            // burst-then-stall downloads and jitter on the shared physical leg,
                            // on top of the local mpsc backpressure that already paced reads
                            // correctly. The Credit frame/API stays in Muxer for a possible
                            // future redesign but isn't wired up on this path anymore.

                            // 🔥 Защищаем и сам мост токеном отмены
                            tokio::select! {
                                _ = token.cancelled() => { debug!(stream_id, "🔪 TCP bridge closed by Eviction"); }
                                _ = run_tcp_bridge(stream_id, r, w, muxer.clone(), v_rx) => {}
                            }
                            // 🔥 Сообщаем клиенту, что поток завершён — неважно, из-за
                            // EOF цели, write-timeout ноги, истёкшего STREAM_PAUSE_BUDGET
                            // или нашей же эвикции по бэклогу. Раньше это отправлялось
                            // только при неудачном CONNECT: при штатном завершении моста
                            // клиент никогда не узнавал, что стрим кончился — его
                            // виртуальный TCP-сокет навсегда застревал в CloseWait (ждёт
                            // от нас Close, см. server_eof/socket.close() в клиентском
                            // TcpConnection::poll_and_process), и освобождался только
                            // 120-секундным idle-таймаутом, попутно замедляя весь движок.
                            let _ = muxer
                                .send_control(stream_id, FrameType::Close, Bytes::new())
                                .await;
                        }
                        _ => {
                            warn!(stream_id, "❌ [Remote] Target connection failed");
                            let _ = muxer.send_control(stream_id, FrameType::Close, Bytes::new()).await;
                        }
                    }
                }
            }
            muxer.remove_stream(stream_id);
        });
    }

    /// Биндит UDP-сокет, «подключает» его к `target` и запускает UDP-мост.
    /// Так же защищено токеном отмены; по завершении снимает регистрацию потока.
    pub async fn open_udp(
        &self,
        stream_id: u32,
        target: String,
        v_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
    ) {
        let muxer = self.muxer.clone();
        let mesh = self.mesh.clone();
        let mesh_route = self.mesh_route.clone();
        let mesh_peer = self.mesh_peer;
        let self_mesh_onion_peer = self.mesh_onion_peer;
        let mesh2_peer = mesh_route.is_some();
        tokio::spawn(async move {
            if let (Some(mesh), Some(route)) = (mesh, mesh_route) {
                Self::open_via_mesh(
                    muxer, mesh, route, stream_id, target, v_rx, token, true, mesh_peer,
                )
                .await;
                return;
            }

            debug!(stream_id, "🚀 [Remote] Binding UDP");
            tokio::select! {
                _ = token.cancelled() => { return; }
                _ = async {
                    let resolved = tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::net::lookup_host(&target),
                    )
                    .await
                    .ok()
                    .and_then(|result| result.ok())
                    .and_then(|mut addresses| addresses.next());
                    if let Some(address) = resolved {
                        let bind = if address.is_ipv4() {
                            "0.0.0.0:0"
                        } else {
                            "[::]:0"
                        };
                        if let Ok(socket) = UdpSocket::bind(bind).await {
                            if socket.connect(address).await.is_ok() {
                                if mesh_peer {
                                    let ready = if mesh2_peer || self_mesh_onion_peer {
                                        crate::net::MESH_ROUTE_READY
                                    } else {
                                        b"PONG"
                                    };
                                    let _ = muxer
                                        .send_control(
                                            stream_id,
                                            FrameType::Heartbeat,
                                            Bytes::from_static(ready),
                                        )
                                        .await;
                                }
                                run_udp_bridge(stream_id, socket, muxer.clone(), v_rx).await;
                            }
                        }
                    }
                } => {}
            }
            muxer.remove_stream(stream_id);
        });
    }

    async fn open_via_onion(
        ingress_muxer: Arc<Muxer>,
        mesh: Arc<crate::net::NodeMesh>,
        ingress_stream_id: u32,
        target: String,
        ingress_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
        is_udp: bool,
        strong_privacy: bool,
        max_hops: u8,
    ) {
        let started = Instant::now();
        let setup_deadline = tokio::time::Instant::now() + Duration::from_secs(65);
        let mut excluded_first_hops = Vec::new();
        let mut connected = None;
        let max_attempts = mesh
            .peer_count()
            .await
            .clamp(1, usize::from(crate::net::MAX_MESH_HOPS));
        for _ in 0..max_attempts {
            if token.is_cancelled() || tokio::time::Instant::now() >= setup_deadline {
                break;
            }
            let Some((peer, capsule)) = mesh
                .build_onion_route(
                    &target,
                    is_udp,
                    strong_privacy,
                    &excluded_first_hops,
                    max_hops,
                )
                .await
            else {
                metrics::counter!("netrunner_mesh_egress_failover_exhausted_total").increment(1);
                warn!(
                    stream_id = ingress_stream_id,
                    "mesh route setup has no unused egress candidate"
                );
                break;
            };
            let attempt_cancel = token.child_token();
            let attempt_call_cancel = attempt_cancel.clone();
            let attempt_mesh = mesh.clone();
            let attempt_peer = peer.clone();
            let mut attempt_task = tokio::spawn(async move {
                attempt_mesh
                    .connect_onion_stream(
                        &attempt_peer,
                        &capsule,
                        is_udp,
                        Some(&attempt_call_cancel),
                        Some(ingress_stream_id),
                    )
                    .await
            });
            let attempt_result = tokio::select! {
                biased;
                _ = token.cancelled() => None,
                _ = tokio::time::sleep_until(setup_deadline) => None,
                result = &mut attempt_task => Some(result),
            };
            let Some(result) = attempt_result else {
                attempt_cancel.cancel();
                if let Ok(Ok((late_session, late_stream_id, _))) = attempt_task.await {
                    let _ = late_session
                        .muxer
                        .send_control(late_stream_id, FrameType::Close, Bytes::new())
                        .await;
                    late_session.muxer.remove_stream(late_stream_id);
                }
                if !token.is_cancelled() {
                    metrics::counter!("netrunner_mesh_onion_route_failures_total").increment(1);
                    warn!(
                        stream_id = ingress_stream_id,
                        "mesh route setup deadline expired"
                    );
                }
                break;
            };
            let result = match result {
                Ok(result) => result,
                Err(_) => {
                    excluded_first_hops.push(peer.node_id);
                    metrics::counter!("netrunner_mesh_onion_route_failures_total").increment(1);
                    continue;
                }
            };
            match result {
                Ok((peer_session, peer_stream_id, peer_rx)) => {
                    connected = Some((peer_session, peer_stream_id, peer_rx));
                    break;
                }
                Err(error) if error.code == crate::net::ERR_MESH_EGRESS_EXHAUSTED => {
                    // The preselected chain's bounded egress budget is spent.
                    // Preserve the explicit exhaustion result instead of
                    // silently starting a fresh chain for the same flow.
                    warn!(
                        stream_id = ingress_stream_id,
                        "mesh egress failover chain exhausted before destination CONNECT"
                    );
                    break;
                }
                Err(error) if error.code != netrunner_logger::ERR_INFRA_TIMEOUT => {
                    break;
                }
                Err(_) => {
                    excluded_first_hops.push(peer.node_id);
                    metrics::counter!("netrunner_mesh_onion_route_failures_total").increment(1);
                }
            }
        }

        let Some((peer_session, peer_stream_id, peer_rx)) = connected else {
            if !token.is_cancelled() {
                let _ = ingress_muxer
                    .send_control(ingress_stream_id, FrameType::Close, Bytes::new())
                    .await;
            }
            ingress_muxer.remove_stream(ingress_stream_id);
            return;
        };
        metrics::counter!("netrunner_mesh_onion_streams_total").increment(1);
        metrics::histogram!("netrunner_mesh_onion_setup_seconds")
            .record(started.elapsed().as_secs_f64());
        let peer_muxer = peer_session.muxer.clone();
        run_mesh_onion_bridge(
            mesh,
            ingress_muxer,
            ingress_stream_id,
            ingress_rx,
            peer_muxer,
            peer_stream_id,
            peer_rx,
            peer_session,
            token,
            is_udp,
            strong_privacy,
        )
        .await;
    }

    pub async fn open_mesh_onion(
        &self,
        stream_id: u32,
        capsule: Bytes,
        v_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
        is_udp: bool,
    ) {
        let muxer = self.muxer.clone();
        let mesh = self.mesh.clone();
        let mesh_onion_peer = self.mesh_onion_peer;
        tokio::spawn(async move {
            let Some(mesh) = mesh.filter(|_| mesh_onion_peer) else {
                close_mesh_stream(muxer, stream_id, token).await;
                return;
            };
            let opened = match mesh.open_onion_capsule(&capsule).await {
                Ok(opened) => opened,
                Err(_) => {
                    metrics::counter!("netrunner_mesh_onion_capsule_rejections_total").increment(1);
                    close_mesh_stream(muxer, stream_id, token).await;
                    return;
                }
            };
            let strong_privacy = opened.strong_privacy;
            if opened.is_udp != is_udp {
                metrics::counter!("netrunner_mesh_onion_protocol_rejections_total").increment(1);
                close_mesh_stream(muxer, stream_id, token).await;
                return;
            }
            match opened.instruction {
                crate::net::mesh_onion::OnionInstruction::Forward {
                    next_peer,
                    next_capsule,
                } => {
                    if next_peer.node_id.eq_ignore_ascii_case(mesh.local_node_id()) {
                        metrics::counter!("netrunner_mesh_onion_loop_rejections_total")
                            .increment(1);
                        close_mesh_stream(muxer, stream_id, token).await;
                        return;
                    }
                    let (peer_session, peer_stream_id, peer_rx) = match mesh
                        .connect_onion_stream(
                            &next_peer,
                            &next_capsule,
                            is_udp,
                            Some(&token),
                            Some(stream_id),
                        )
                        .await
                    {
                        Ok(stream) => stream,
                        Err(error) if error.code == crate::net::ERR_MESH_EGRESS_EXHAUSTED => {
                            fail_mesh_stream_exhausted(muxer, stream_id, token, true).await;
                            return;
                        }
                        Err(_) => {
                            metrics::counter!("netrunner_mesh_onion_forward_failures_total")
                                .increment(1);
                            close_mesh_stream(muxer, stream_id, token).await;
                            return;
                        }
                    };
                    let peer_muxer = peer_session.muxer.clone();
                    let _ = muxer
                        .send_control(
                            stream_id,
                            FrameType::Heartbeat,
                            Bytes::from_static(crate::net::MESH_ROUTE_READY),
                        )
                        .await;
                    run_mesh_onion_bridge(
                        mesh,
                        muxer,
                        stream_id,
                        v_rx,
                        peer_muxer,
                        peer_stream_id,
                        peer_rx,
                        peer_session,
                        token,
                        is_udp,
                        strong_privacy,
                    )
                    .await;
                }
                crate::net::mesh_onion::OnionInstruction::Exit {
                    target,
                    fallback,
                    failovers_left,
                } => {
                    if fallback.as_ref().is_some_and(|next| {
                        next.peer.node_id.eq_ignore_ascii_case(mesh.local_node_id())
                    }) {
                        metrics::counter!("netrunner_mesh_onion_loop_rejections_total")
                            .increment(1);
                        close_mesh_stream(muxer, stream_id, token).await;
                        return;
                    }
                    run_mesh_onion_exit(
                        mesh,
                        muxer,
                        stream_id,
                        target,
                        v_rx,
                        token,
                        is_udp,
                        strong_privacy,
                        fallback,
                        failovers_left,
                    )
                    .await;
                }
            }
        });
    }

    /// Forwards this stream to the next route node over an ordinary NRXP leg.
    /// There is intentionally no direct-egress fallback when a route is active:
    /// that would silently shorten the configured path and expose this node.
    async fn open_via_mesh(
        ingress_muxer: Arc<Muxer>,
        mesh: Arc<crate::net::NodeMesh>,
        route: MeshRoute,
        ingress_stream_id: u32,
        target: String,
        mut ingress_rx: mpsc::Receiver<Bytes>,
        token: CancellationToken,
        is_udp: bool,
        upstream_peer: bool,
    ) {
        let route_setup_started = Instant::now();
        let Some(mut route) = mesh.route_for_flow(&route).await else {
            metrics::counter!("netrunner_mesh_route_selection_failures_total").increment(1);
            if !token.is_cancelled() {
                let _ = ingress_muxer
                    .send_control(ingress_stream_id, FrameType::Close, Bytes::new())
                    .await;
            }
            ingress_muxer.remove_stream(ingress_stream_id);
            return;
        };
        let mut failed_egress_ids: Vec<String> = Vec::new();
        let mut connected = None;
        loop {
            if let Some(egress_id) = route.egress_node_id.as_ref() {
                if !failed_egress_ids
                    .iter()
                    .any(|failed| failed.eq_ignore_ascii_case(egress_id))
                {
                    failed_egress_ids.push(egress_id.clone());
                }
            }
            for peer in mesh.peers_for_route(&route).await {
                if token.is_cancelled() {
                    break;
                }
                let Some(next_route) = mesh.route_via_peer(&route, &peer.node_id) else {
                    continue;
                };
                let auth_token = mesh.auth_token_for_route(&next_route);
                let result = mesh
                    .connect_peer_stream(&peer, &auth_token, &target, is_udp, Some(&token))
                    .await;
                match result {
                    Ok((peer_session, peer_stream_id, peer_rx)) => {
                        metrics::counter!("netrunner_mesh_egress_streams_total").increment(1);
                        connected = Some((peer_session, peer_stream_id, peer_rx));
                        break;
                    }
                    Err(_) => {
                        if token.is_cancelled() {
                            break;
                        }
                        // Keep failure detail local: peer addresses and destination
                        // data do not belong in normal connection logs.
                        metrics::counter!("netrunner_mesh_egress_connect_failures_total")
                            .increment(1);
                    }
                }
            }
            if connected.is_some() || token.is_cancelled() {
                break;
            }
            let Some(retry_route) = mesh
                .retry_with_next_egress(&route, &failed_egress_ids)
                .await
            else {
                break;
            };
            if retry_route.remaining_hops != route.remaining_hops {
                failed_egress_ids.clear();
            }
            route = retry_route;
        }

        let Some((peer_session, peer_stream_id, mut peer_rx)) = connected else {
            if !token.is_cancelled() {
                let _ = ingress_muxer
                    .send_control(ingress_stream_id, FrameType::Close, Bytes::new())
                    .await;
            }
            ingress_muxer.remove_stream(ingress_stream_id);
            return;
        };
        let peer_muxer = peer_session.muxer.clone();
        if token.is_cancelled() {
            let _ = peer_muxer
                .send_control(peer_stream_id, FrameType::Close, Bytes::new())
                .await;
            peer_muxer.remove_stream(peer_stream_id);
            ingress_muxer.remove_stream(ingress_stream_id);
            return;
        }
        metrics::histogram!("netrunner_mesh_route_setup_seconds")
            .record(route_setup_started.elapsed().as_secs_f64());
        if let Some(rtt_ms) = peer_muxer.leg_rtt_ms(0).filter(|rtt| *rtt > 0) {
            metrics::histogram!("netrunner_mesh_peer_rtt_ms").record(f64::from(rtt_ms));
        }

        // The downstream CONNECT is confirmed only after the final egress has
        // opened the destination. Propagate that acknowledgement one hop back
        // so each ingress can finish CONNECT setup before data starts flowing.
        if upstream_peer {
            let _ = ingress_muxer
                .send_control(
                    ingress_stream_id,
                    FrameType::Heartbeat,
                    Bytes::from_static(crate::net::MESH_ROUTE_READY),
                )
                .await;
        }

        let upload = async {
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    item = ingress_rx.recv() => match item {
                        None => break,
                        Some(data) if is_udp => {
                            // UDP keeps datagram semantics; an unavailable mesh
                            // leg drops this packet instead of killing the flow.
                            let _ = peer_muxer
                                .send_data_safe(peer_stream_id, data, true)
                                .await;
                        }
                        Some(data) => {
                            let deadline = tokio::time::Instant::now()
                                + crate::net::STREAM_PAUSE_BUDGET;
                            let sent = loop {
                                if peer_muxer.send_data_safe(peer_stream_id, data.clone(), false).await.is_ok() {
                                    break true;
                                }
                                if token.is_cancelled()
                                    || tokio::time::Instant::now() >= deadline
                                {
                                    break false;
                                }
                                tokio::select! {
                                    _ = token.cancelled() => break false,
                                    _ = tokio::time::sleep(crate::net::STREAM_PAUSE_RETRY) => {}
                                }
                            };
                            if !sent {
                                break;
                            }
                        }
                    }
                }
            }
        };

        let download = async {
            loop {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    item = peer_rx.recv() => match item {
                        None => break,
                        Some(data) if is_udp => {
                            let _ = ingress_muxer
                                .send_data_safe(ingress_stream_id, data, true)
                                .await;
                        }
                        Some(data) => {
                            let deadline = tokio::time::Instant::now()
                                + crate::net::STREAM_PAUSE_BUDGET;
                            let sent = loop {
                                if ingress_muxer
                                    .send_data_safe(ingress_stream_id, data.clone(), false)
                                    .await
                                    .is_ok()
                                {
                                    break true;
                                }
                                if token.is_cancelled()
                                    || tokio::time::Instant::now() >= deadline
                                {
                                    break false;
                                }
                                tokio::select! {
                                    _ = token.cancelled() => break false,
                                    _ = tokio::time::sleep(crate::net::STREAM_PAUSE_RETRY) => {}
                                }
                            };
                            if !sent {
                                break;
                            }
                        }
                    }
                }
            }
        };

        tokio::select! {
            _ = token.cancelled() => {},
            _ = upload => {},
            _ = download => {},
        }

        let _ = peer_muxer
            .send_control(peer_stream_id, FrameType::Close, Bytes::new())
            .await;
        peer_muxer.remove_stream(peer_stream_id);
        if !token.is_cancelled() {
            let _ = ingress_muxer
                .send_control(ingress_stream_id, FrameType::Close, Bytes::new())
                .await;
        }
        ingress_muxer.remove_stream(ingress_stream_id);
    }
}

async fn close_mesh_stream(muxer: Arc<Muxer>, stream_id: u32, token: CancellationToken) {
    if !token.is_cancelled() {
        let _ = muxer
            .send_control(stream_id, FrameType::Close, Bytes::new())
            .await;
    }
    muxer.remove_stream(stream_id);
}

async fn fail_mesh_stream_exhausted(
    muxer: Arc<Muxer>,
    stream_id: u32,
    token: CancellationToken,
    propagate_marker: bool,
) {
    if !token.is_cancelled() {
        if propagate_marker {
            let _ = muxer
                .send_control(
                    stream_id,
                    FrameType::Heartbeat,
                    Bytes::from_static(crate::net::MESH_EGRESS_EXHAUSTED),
                )
                .await;
        }
        metrics::counter!("netrunner_mesh_egress_failover_exhausted_total").increment(1);
    }
    close_mesh_stream(muxer, stream_id, token).await;
}

async fn send_mesh_payload(
    mesh: &Arc<crate::net::NodeMesh>,
    muxer: Arc<Muxer>,
    stream_id: u32,
    payload: Bytes,
    is_udp: bool,
    strong_privacy: bool,
    token: &CancellationToken,
) -> bool {
    if token.is_cancelled() {
        return false;
    }
    if strong_privacy {
        return tokio::select! {
            _ = token.cancelled() => false,
            result = mesh.send_mixed(muxer, stream_id, payload, is_udp, token.clone()) => result.is_ok(),
        };
    }
    if is_udp {
        let _ = muxer.send_data_safe(stream_id, payload, true).await;
        return !token.is_cancelled();
    }
    let deadline = tokio::time::Instant::now() + crate::net::STREAM_PAUSE_BUDGET;
    loop {
        if muxer
            .send_data_safe(stream_id, payload.clone(), false)
            .await
            .is_ok()
        {
            return true;
        }
        if token.is_cancelled() || tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::select! {
            _ = token.cancelled() => return false,
            _ = tokio::time::sleep(crate::net::STREAM_PAUSE_RETRY) => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_mesh_onion_bridge(
    mesh: Arc<crate::net::NodeMesh>,
    upstream_muxer: Arc<Muxer>,
    upstream_stream_id: u32,
    mut upstream_rx: mpsc::Receiver<Bytes>,
    downstream_muxer: Arc<Muxer>,
    downstream_stream_id: u32,
    mut downstream_rx: mpsc::Receiver<Bytes>,
    _peer_session: Arc<crate::net::connection::MeshPeerSession>,
    token: CancellationToken,
    is_udp: bool,
    strong_privacy: bool,
) {
    let _upstream_cover = if strong_privacy {
        Some(mesh.acquire_cover_lease(upstream_muxer.clone()).await)
    } else {
        None
    };
    let _downstream_cover = if strong_privacy {
        Some(mesh.acquire_cover_lease(downstream_muxer.clone()).await)
    } else {
        None
    };

    let upload = async {
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                packet = upstream_rx.recv() => match packet {
                    Some(packet) => {
                        if !send_mesh_payload(
                            &mesh,
                            downstream_muxer.clone(),
                            downstream_stream_id,
                            packet,
                            is_udp,
                            strong_privacy,
                            &token,
                        ).await {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    };
    let download = async {
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                packet = downstream_rx.recv() => match packet {
                    Some(packet) => {
                        if !send_mesh_payload(
                            &mesh,
                            upstream_muxer.clone(),
                            upstream_stream_id,
                            packet,
                            is_udp,
                            strong_privacy,
                            &token,
                        ).await {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    };
    tokio::select! {
        _ = token.cancelled() => {},
        _ = upload => {},
        _ = download => {},
    }

    let _ = downstream_muxer
        .send_control(downstream_stream_id, FrameType::Close, Bytes::new())
        .await;
    downstream_muxer.remove_stream(downstream_stream_id);
    if !token.is_cancelled() {
        let _ = upstream_muxer
            .send_control(upstream_stream_id, FrameType::Close, Bytes::new())
            .await;
    }
    upstream_muxer.remove_stream(upstream_stream_id);
}

#[allow(clippy::too_many_arguments)]
async fn run_mesh_onion_exit(
    mesh: Arc<crate::net::NodeMesh>,
    muxer: Arc<Muxer>,
    stream_id: u32,
    target: String,
    mut v_rx: mpsc::Receiver<Bytes>,
    token: CancellationToken,
    is_udp: bool,
    strong_privacy: bool,
    fallback: Option<crate::net::mesh_onion::OnionFallback>,
    failovers_left: u8,
) {
    if is_udp {
        let address = tokio::select! {
            _ = token.cancelled() => None,
            result = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(&target)) => {
                result.ok().and_then(Result::ok).and_then(|mut addresses| addresses.next())
            }
        };
        let Some(address) = address else {
            if token.is_cancelled() {
                close_mesh_stream(muxer, stream_id, token).await;
            } else {
                run_mesh_onion_failover(
                    mesh,
                    muxer,
                    stream_id,
                    v_rx,
                    token,
                    is_udp,
                    strong_privacy,
                    fallback,
                    failovers_left,
                    true,
                )
                .await;
            }
            return;
        };
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = tokio::select! {
            _ = token.cancelled() => None,
            result = UdpSocket::bind(bind) => result.ok(),
        };
        let Some(socket) = socket else {
            if token.is_cancelled() {
                close_mesh_stream(muxer, stream_id, token).await;
            } else {
                run_mesh_onion_failover(
                    mesh,
                    muxer,
                    stream_id,
                    v_rx,
                    token,
                    is_udp,
                    strong_privacy,
                    fallback,
                    failovers_left,
                    true,
                )
                .await;
            }
            return;
        };
        if socket.connect(address).await.is_err() {
            run_mesh_onion_failover(
                mesh,
                muxer,
                stream_id,
                v_rx,
                token,
                is_udp,
                strong_privacy,
                fallback,
                failovers_left,
                true,
            )
            .await;
            return;
        }
        if muxer
            .send_control(
                stream_id,
                FrameType::Heartbeat,
                Bytes::from_static(crate::net::MESH_ROUTE_READY),
            )
            .await
            .is_err()
        {
            close_mesh_stream(muxer, stream_id, token).await;
            return;
        }
        let _cover = if strong_privacy {
            Some(mesh.acquire_cover_lease(muxer.clone()).await)
        } else {
            None
        };
        let socket = Arc::new(socket);
        let download = async {
            let mut buffer = vec![0u8; 65_535];
            loop {
                let received = tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    result = socket.recv(&mut buffer) => match result {
                        Ok(received) => received,
                        Err(_) => break,
                    }
                };
                if !send_mesh_payload(
                    &mesh,
                    muxer.clone(),
                    stream_id,
                    Bytes::copy_from_slice(&buffer[..received]),
                    true,
                    strong_privacy,
                    &token,
                )
                .await
                {
                    break;
                }
            }
        };
        if strong_privacy {
            let (mixed_tx, mut mixed_rx) = mpsc::channel::<Bytes>(128);
            let flow_id = format!("exit-up:{}:{stream_id}", muxer.session_id());
            let upload = async {
                while let Some(packet) = tokio::select! {
                    biased;
                    _ = token.cancelled() => None,
                    packet = v_rx.recv() => packet,
                } {
                    if mesh
                        .send_mixed_to_local(
                            flow_id.clone(),
                            mixed_tx.clone(),
                            packet,
                            true,
                            token.clone(),
                        )
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            };
            let target_upload = async {
                while let Some(packet) = tokio::select! {
                    biased;
                    _ = token.cancelled() => None,
                    packet = mixed_rx.recv() => packet,
                } {
                    if socket.send(&packet).await.is_err() {
                        break;
                    }
                }
            };
            tokio::select! {
                _ = token.cancelled() => {},
                _ = upload => {},
                _ = target_upload => {},
                _ = download => {},
            }
        } else {
            let upload = async {
                while let Some(packet) = tokio::select! {
                    biased;
                    _ = token.cancelled() => None,
                    packet = v_rx.recv() => packet,
                } {
                    if socket.send(&packet).await.is_err() {
                        break;
                    }
                }
            };
            tokio::select! {
                _ = token.cancelled() => {},
                _ = upload => {},
                _ = download => {},
            }
        }
    } else {
        let stream = tokio::select! {
            _ = token.cancelled() => None,
            result = tokio::time::timeout(Duration::from_secs(7), TcpStream::connect(&target)) => {
                result.ok().and_then(Result::ok)
            }
        };
        let Some(stream) = stream else {
            if token.is_cancelled() {
                close_mesh_stream(muxer, stream_id, token).await;
            } else {
                run_mesh_onion_failover(
                    mesh,
                    muxer,
                    stream_id,
                    v_rx,
                    token,
                    is_udp,
                    strong_privacy,
                    fallback,
                    failovers_left,
                    true,
                )
                .await;
            }
            return;
        };
        if muxer
            .send_control(
                stream_id,
                FrameType::Heartbeat,
                Bytes::from_static(crate::net::MESH_ROUTE_READY),
            )
            .await
            .is_err()
        {
            close_mesh_stream(muxer, stream_id, token).await;
            return;
        }
        let _cover = if strong_privacy {
            Some(mesh.acquire_cover_lease(muxer.clone()).await)
        } else {
            None
        };
        let (mut reader, mut writer) = stream.into_split();
        let download = async {
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let received = tokio::select! {
                    biased;
                    _ = token.cancelled() => break,
                    result = reader.read(&mut buffer) => match result {
                        Ok(0) | Err(_) => break,
                        Ok(received) => received,
                    }
                };
                if !send_mesh_payload(
                    &mesh,
                    muxer.clone(),
                    stream_id,
                    Bytes::copy_from_slice(&buffer[..received]),
                    false,
                    strong_privacy,
                    &token,
                )
                .await
                {
                    break;
                }
            }
        };
        if strong_privacy {
            let (mixed_tx, mut mixed_rx) = mpsc::channel::<Bytes>(128);
            let flow_id = format!("exit-up:{}:{stream_id}", muxer.session_id());
            let upload = async {
                while let Some(packet) = tokio::select! {
                    biased;
                    _ = token.cancelled() => None,
                    packet = v_rx.recv() => packet,
                } {
                    if mesh
                        .send_mixed_to_local(
                            flow_id.clone(),
                            mixed_tx.clone(),
                            packet,
                            false,
                            token.clone(),
                        )
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            };
            let target_upload = async {
                while let Some(packet) = tokio::select! {
                    biased;
                    _ = token.cancelled() => None,
                    packet = mixed_rx.recv() => packet,
                } {
                    if writer.write_all(&packet).await.is_err() {
                        break;
                    }
                }
            };
            tokio::select! {
                _ = token.cancelled() => {},
                _ = upload => {},
                _ = target_upload => {},
                _ = download => {},
            }
        } else {
            let upload = async {
                while let Some(packet) = tokio::select! {
                    biased;
                    _ = token.cancelled() => None,
                    packet = v_rx.recv() => packet,
                } {
                    if writer.write_all(&packet).await.is_err() {
                        break;
                    }
                }
            };
            tokio::select! {
                _ = token.cancelled() => {},
                _ = upload => {},
                _ = download => {},
            }
        }
    }
    close_mesh_stream(muxer, stream_id, token).await;
}

#[allow(clippy::too_many_arguments)]
async fn run_mesh_onion_failover(
    mesh: Arc<crate::net::NodeMesh>,
    muxer: Arc<Muxer>,
    stream_id: u32,
    v_rx: mpsc::Receiver<Bytes>,
    token: CancellationToken,
    is_udp: bool,
    strong_privacy: bool,
    fallback: Option<crate::net::mesh_onion::OnionFallback>,
    failovers_left: u8,
    send_ready_to_upstream: bool,
) {
    if token.is_cancelled() {
        close_mesh_stream(muxer, stream_id, token).await;
        return;
    }
    let Some(fallback) = fallback.filter(|_| failovers_left > 0) else {
        warn!(
            stream_id,
            "mesh egress failover chain is exhausted; no unused next egress is available"
        );
        fail_mesh_stream_exhausted(muxer, stream_id, token, send_ready_to_upstream).await;
        return;
    };

    if fallback
        .peer
        .node_id
        .eq_ignore_ascii_case(mesh.local_node_id())
    {
        metrics::counter!("netrunner_mesh_onion_loop_rejections_total").increment(1);
        close_mesh_stream(muxer, stream_id, token).await;
        return;
    }
    metrics::counter!("netrunner_mesh_egress_failover_attempts_total").increment(1);
    match mesh
        .connect_onion_stream(
            &fallback.peer,
            &fallback.capsule,
            is_udp,
            Some(&token),
            Some(stream_id),
        )
        .await
    {
        Ok((peer_session, peer_stream_id, peer_rx)) => {
            let peer_muxer = peer_session.muxer.clone();
            if send_ready_to_upstream
                && muxer
                    .send_control(
                        stream_id,
                        FrameType::Heartbeat,
                        Bytes::from_static(crate::net::MESH_ROUTE_READY),
                    )
                    .await
                    .is_err()
            {
                let _ = peer_muxer
                    .send_control(peer_stream_id, FrameType::Close, Bytes::new())
                    .await;
                peer_muxer.remove_stream(peer_stream_id);
                close_mesh_stream(muxer, stream_id, token).await;
                return;
            }
            run_mesh_onion_bridge(
                mesh,
                muxer,
                stream_id,
                v_rx,
                peer_muxer,
                peer_stream_id,
                peer_rx,
                peer_session,
                token,
                is_udp,
                strong_privacy,
            )
            .await;
        }
        Err(error) if error.code == crate::net::ERR_MESH_EGRESS_EXHAUSTED => {
            fail_mesh_stream_exhausted(muxer, stream_id, token, send_ready_to_upstream).await;
        }
        Err(error) if error.code == netrunner_logger::ERR_INFRA_TIMEOUT => {
            // The preselected backup itself is unreachable. This chain cannot
            // be skipped without disclosing later peers, so report exhaustion.
            fail_mesh_stream_exhausted(muxer, stream_id, token, send_ready_to_upstream).await;
        }
        Err(_) => {
            // Authentication or protocol errors are not destination network
            // failures and must not trigger another egress.
            close_mesh_stream(muxer, stream_id, token).await;
        }
    }
}

/// Маршрутизатор входящих кадров. Наличие `opener` определяет роль:
/// `Some` — серверная сторона (умеет открывать соединения к целям),
/// `None` — клиентская (входящие `Connect` отвергаются).
pub(crate) struct StreamHandler {
    muxer: Arc<Muxer>,
    opener: Option<Arc<RemoteOpener>>,
}

impl StreamHandler {
    pub(crate) fn new(muxer: Arc<Muxer>, opener: Option<Arc<RemoteOpener>>) -> Self {
        Self { muxer, opener }
    }

    /// What an incoming heartbeat frame needs in reply, if anything: `PING` → `PONG`
    /// (or the mesh-onion readiness marker), and on the server side a plain heartbeat →
    /// an empty one. The reply to a liveness probe must go back on the leg the probe
    /// arrived on (see `Muxer::send_control_on_leg`), which is why this is separate
    /// from `handle`: the leg reader knows the leg, the handler does not.
    pub(crate) fn heartbeat_reply(&self, payload: &[u8]) -> Option<Bytes> {
        if payload == b"PING" {
            let response: &'static [u8] = if self
                .opener
                .as_ref()
                .is_some_and(|opener| opener.mesh_onion_peer)
            {
                crate::net::MESH_ONION_READY
            } else {
                b"PONG"
            };
            Some(Bytes::from_static(response))
        } else if payload == b"PONG"
            || payload == crate::net::MESH_ROUTE_READY
            || payload == crate::net::MESH_ONION_READY
            || payload == crate::net::MESH_EGRESS_EXHAUSTED
        {
            None
        } else if self.opener.is_some() {
            Some(Bytes::new())
        } else {
            None
        }
    }

    /// Диспетчеризует один кадр по типу. Для `Data`/`UdpData` доставка идёт через
    /// `await` (backpressure ради сохранения порядка), для управляющих —
    /// в отдельных задачах, чтобы не блокировать reader ноги.
    pub(crate) async fn handle(&self, frame: Frame) {
        let stream_id = frame.header.stream_id;

        match frame.header.frame_type {
            FrameType::Heartbeat => {
                let payload = frame.payload.as_ref();
                if let Some(reply) = self.heartbeat_reply(payload) {
                    trace!(stream_id, "🤝 [Tunnel] heartbeat received, replying");
                    let muxer = self.muxer.clone();
                    tokio::spawn(async move {
                        let _ = muxer
                            .send_control(stream_id, FrameType::Heartbeat, reply)
                            .await;
                    });
                } else if payload == b"PONG"
                    || payload == crate::net::MESH_ROUTE_READY
                    || payload == crate::net::MESH_ONION_READY
                    || payload == crate::net::MESH_EGRESS_EXHAUSTED
                {
                    trace!(stream_id, "🤝 [Tunnel] PONG received");
                    self.muxer.dispatch_to_local(stream_id, frame.payload);
                } else {
                    trace!(stream_id, "💓 [Client] Standard Heartbeat reply received");
                }
            }

            FrameType::Connect => {
                self.handle_conn_request(stream_id, frame.payload, false, false)
                    .await
            }
            FrameType::UdpConnect => {
                self.handle_conn_request(stream_id, frame.payload, true, false)
                    .await
            }
            FrameType::SecureConnect => {
                self.handle_conn_request(stream_id, frame.payload, false, true)
                    .await
            }
            FrameType::SecureUdpConnect => {
                self.handle_conn_request(stream_id, frame.payload, true, true)
                    .await
            }
            FrameType::MeshOnionConnect => {
                self.handle_mesh_onion_request(stream_id, frame.payload, false)
                    .await
            }
            FrameType::MeshOnionUdpConnect => {
                self.handle_mesh_onion_request(stream_id, frame.payload, true)
                    .await
            }

            FrameType::Data => {
                // Non-blocking: in-order delivery is guaranteed by the stream's
                // single persistent backlog-drainer task, not by awaiting here.
                self.muxer.dispatch_to_local(stream_id, frame.payload);
            }

            FrameType::UdpData => {
                // Как `Data`, но с коротким буфером ожидания на сервере: первый
                // `UdpData` нового потока часто обгоняет свой `UdpConnect`,
                // едущий по TCP и регистрирующий поток (bug #4). На клиенте
                // буфер не используется — поток там уже зарегистрирован.
                self.muxer.dispatch_to_local_udp(stream_id, frame.payload);
            }

            FrameType::Close => {
                // stream_id=0 зарезервирован под heartbeat/diag (см. doc-
                // комментарий модуля и `connection.rs`, откуда сервер шлёт
                // "auth_rejected: <причина>" именно на этот id при
                // безоговорочном отказе токена) — ни один реальный
                // Connect-поток туда никогда не попадает, так что здесь можно
                // безопасно читать payload как текстовый сигнал, не путая его
                // с закрытием прикладного потока.
                //
                // РАНЬШЕ этот кадр обрабатывался наравне со всеми остальными
                // Close — payload не читался вообще, поэтому сервер честно
                // слал "auth_rejected", а клиент это никогда не видел:
                // `establish_leg` (connection.rs) в итоге всегда получал
                // общую ошибку "Движок остановлен" вместо ERR_AUTH_FAILED, и
                // `Muxer::mark_fatal` (единственное, что останавливает
                // бесконечный реконнект с тем же мёртвым токеном) не
                // вызывался НИКОГДА. На практике это годами держало клиента
                // с просроченным токеном в цикле "переподключение через 2с"
                // навечно — 4 ноги (MAX_TUNNEL_LEGS) × раз в LEG_RECONNECT_DELAY
                // дают устойчивые ~2 запроса/сек на internal/validate без
                // единого шанса самостоятельно остановиться.
                if stream_id == 0 {
                    if let Ok(reason) = std::str::from_utf8(frame.payload.as_ref()) {
                        if reason.starts_with("auth_rejected") {
                            warn!(
                                reason,
                                "🚫 [Tunnel] Server rejected auth token, marking session fatal"
                            );
                            self.muxer.mark_fatal();
                        }
                    }
                }
                debug!(stream_id, "🏁 [Tunnel] Peer closed stream");
                if stream_id == 0 {
                    self.muxer.remove_stream(stream_id);
                } else {
                    // Graceful: whatever the peer sent before closing is still
                    // delivered to the local consumer, which then sees EOF.
                    self.muxer.finish_stream(stream_id);
                }
            }

            FrameType::Credit => {
                // Сквозной flow control (см. Muxer::consume_credit/grant_credit):
                // приёмник шлёт "можешь прислать ещё N байт". Синхронно и дёшево —
                // просто прибавляет к атомарному счётчику и будит ждущего отправителя.
                if let Ok(bytes) = frame.payload.as_ref().try_into().map(u32::from_be_bytes) {
                    trace!(stream_id, bytes, "💳 [Tunnel] Credit received");
                    self.muxer.grant_credit(stream_id, bytes);
                } else {
                    warn!(stream_id, "Malformed Credit frame payload, ignoring");
                }
            }

            FrameType::Diag => {
                // Диагностика клиента, доставленная по туннелю. Осмысленна только
                // на сервере: пересылаем в сток вместе с id сессии (берём из
                // muxer'а — на сервере это сессия этой ноги). На клиенте сток не
                // поднят, поэтому отчёт просто отбрасывается. Никогда не идёт в
                // локальные сокеты и не маршрутизируется как данные.
                let session_id = self.muxer.session_id().to_string();
                let json_line = String::from_utf8_lossy(&frame.payload).into_owned();
                trace!(
                    session_id = %session_id,
                    bytes = json_line.len(),
                    "🩺 [Tunnel] Client diagnostics report received"
                );
                crate::net::diagnostics::report_client_diag(
                    crate::net::diagnostics::ClientDiagReport {
                        session_id,
                        json_line,
                    },
                );
            }

            FrameType::Cover => {
                // Набивка ради формы трафика (см. cover-flight в
                // `ServerHandler::run`): данных в таком кадре нет, у него нет
                // ни потока, ни адресата. Молча отбрасываем.
                //
                // Отдельная ветка нужна не только ради полноты `match`:
                // reader ноги отдаёт сюда КАЖДЫЙ разобранный кадр (см.
                // `TunnelEngine::run`), фильтра перед `handle` нет, так что
                // cover-кадры сюда доходят штатно на каждом хендшейке.
                trace!(stream_id, "🎭 [Tunnel] Cover frame discarded");
            }
        }
    }

    /// Обрабатывает `Connect`/`UdpConnect`: регистрирует поток (получая токен
    /// отмены) и просит [`RemoteOpener`] открыть соединение. На клиенте (нет
    /// opener) — отказ с `Close`. `payload` несёт адрес цели строкой `"ip:port"`.
    async fn handle_conn_request(
        &self,
        stream_id: u32,
        payload: Bytes,
        is_udp: bool,
        strong_privacy: bool,
    ) {
        let target = String::from_utf8_lossy(&payload).to_string();

        if let Some(opener) = &self.opener {
            let cap = NetworkConfig::global().channel_capacity;
            let (v_tx, v_rx) = mpsc::channel::<Bytes>(cap);

            // 🔥 Собираем токен для мгновенного обрыва связи при Eviction.
            // Больший бэклог, чем клиентский дефолт: реальная цель в интернете
            // медленнее и капризнее локального TUN — аплоаду нужен запас (см.
            // SERVER_STREAM_BACKLOG_MAX_BYTES).
            let cancel_token = self.muxer.register_stream_with_backlog_cap(
                stream_id,
                v_tx,
                crate::net::SERVER_STREAM_BACKLOG_MAX_BYTES,
            );

            if is_udp {
                opener
                    .open_udp_with_privacy(stream_id, target, v_rx, cancel_token, strong_privacy)
                    .await;
            } else {
                opener
                    .open_tcp_with_privacy(stream_id, target, v_rx, cancel_token, strong_privacy)
                    .await;
            }
        } else {
            warn!(
                stream_id,
                "⚠️ [Tunnel] Rejected incoming connection to {} (Client mode)", target
            );
            let muxer = self.muxer.clone();
            tokio::spawn(async move {
                let _ = muxer
                    .send_control(stream_id, FrameType::Close, Bytes::new())
                    .await;
            });
        }
    }

    async fn handle_mesh_onion_request(&self, stream_id: u32, capsule: Bytes, is_udp: bool) {
        if let Some(opener) = &self.opener {
            let cap = NetworkConfig::global().channel_capacity;
            let (v_tx, v_rx) = mpsc::channel::<Bytes>(cap);
            let cancel_token = self.muxer.register_stream_with_backlog_cap(
                stream_id,
                v_tx,
                crate::net::SERVER_STREAM_BACKLOG_MAX_BYTES,
            );
            opener
                .open_mesh_onion(stream_id, capsule, v_rx, cancel_token, is_udp)
                .await;
        } else {
            let muxer = self.muxer.clone();
            tokio::spawn(async move {
                let _ = muxer
                    .send_control(stream_id, FrameType::Close, Bytes::new())
                    .await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_handler() -> (StreamHandler, Arc<Muxer>) {
        let muxer = Arc::new(Muxer::new(true, "test-session".into()));
        (StreamHandler::new(muxer.clone(), None), muxer)
    }

    /// Регрессия на сам баг: сервер шлёт "auth_rejected: ..." Close-кадром на
    /// stream_id=0 при безоговорочном отказе токена (см. `connection.rs`), но
    /// раньше payload здесь вообще не читался — `mark_fatal()` не вызывался
    /// НИКОГДА, и клиент с мёртвым токеном реконнектился раз в
    /// LEG_RECONNECT_DELAY вечно (наблюдалось на проде: 4 ноги (MAX_TUNNEL_LEGS)
    /// держали ~2 запроса/сек на /internal/validate часами).
    #[tokio::test]
    async fn close_frame_with_auth_rejected_reason_marks_session_fatal() {
        let (handler, muxer) = client_handler();
        assert!(!muxer.is_fatal());

        let frame = Frame::new(
            0,
            FrameType::Close,
            Bytes::from_static(b"auth_rejected: account banned"),
        );
        handler.handle(frame).await;

        assert!(
            muxer.is_fatal(),
            "Close(stream_id=0, \"auth_rejected: ...\") обязан пометить сессию как фатальную"
        );
    }

    /// Обычное закрытие прикладного потока (stream_id != 0) не имеет отношения
    /// к авторизации — не должно гасить всю сессию.
    #[tokio::test]
    async fn close_frame_on_application_stream_does_not_mark_fatal() {
        let (handler, muxer) = client_handler();

        let frame = Frame::new(
            42,
            FrameType::Close,
            Bytes::from_static(b"auth_rejected: this text on the wrong stream_id doesn't count"),
        );
        handler.handle(frame).await;

        assert!(!muxer.is_fatal());
    }

    /// Пустой/обычный Close на служебном stream_id=0 (например, эвикт при
    /// закрытии сокета) — тоже не должен ложно триггерить фатальное состояние.
    #[tokio::test]
    async fn close_frame_on_control_stream_without_auth_rejected_text_does_not_mark_fatal() {
        let (handler, muxer) = client_handler();

        let frame = Frame::new(0, FrameType::Close, Bytes::new());
        handler.handle(frame).await;

        assert!(!muxer.is_fatal());
    }
}
