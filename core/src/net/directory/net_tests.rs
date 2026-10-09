//! Сквозные тесты: настоящие узлы на loopback обмениваются записями по
//! аутентифицированным mesh-сессиям (TCP + NRXP), без панели.

use std::sync::Arc;

use super::*;
use crate::crypto::LocalIdentity;
use crate::net::{AuthValidator, Connection, NodeMesh, ServerHandler, SessionManager, TunnelHandler};
use crate::Identity;

struct Node {
    dir: Arc<Directory>,
    mesh: Arc<NodeMesh>,
}

async fn spawn(seed: u8, swarm: &SwarmKey) -> Node {
    crate::net::NetworkConfig::init_global(1500);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let identity = SwarmIdentity::from_static_private([seed; 32]);
    let secret = swarm.node_secret(&identity.node_id);
    let local = LocalIdentity::from_hex(&secret, &hex::encode(identity.static_private), true).unwrap();
    let dir = Arc::new(Directory::new(
        identity,
        swarm.clone(),
        DirectoryConfig {
            store: StoreConfig { allow_private: true, ..Default::default() },
            advertise: vec![Endpoint { kind: EndpointKind::Tcp, host: "127.0.0.1".into(), port }],
            decoy_sni: "example.com".into(),
            ..Default::default()
        },
        unix_now(),
    ));
    let mesh = Arc::new(NodeMesh::with_max_hops(dir.node_id_hex(), secret, 2));
    mesh.set_onion_identity(local.clone());
    mesh.set_directory(dir.clone());

    let validator: Arc<dyn AuthValidator> = Arc::new(DirectoryValidator::new(dir.clone(), None));
    let sessions = Arc::new(SessionManager::new());
    let node_mesh = mesh.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let handler = ServerHandler::new(
                Connection::new(stream),
                sessions.clone(),
                Arc::from("example.com"),
                Some(validator.clone()),
                Some(Identity::Local(local.clone())),
                crate::decoy::CoverFlight::node_default().records.into(),
                true,
            )
            .with_mesh_policy(false, true, Some(node_mesh.clone()));
            tokio::spawn(async move {
                let _ = handler.run().await;
            });
        }
    });
    Node { dir, mesh }
}

/// Записи по одной: «seed» — это самоописание соседа, переданное оператором.
fn seed(into: &Node, from: &Node) {
    let d = from.dir.own(unix_now());
    assert_eq!(into.dir.insert(d, unix_now()), Insert::Added);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_real_nodes_discover_each_other_without_a_panel() {
    let sw = SwarmKey::from_bytes([5u8; 32]);
    let a = spawn(1, &sw).await;
    let b = spawn(2, &sw).await;
    let c = spawn(3, &sw).await;

    // Топология знакомств — цепочка: A знает B, B знает C. A о C не знает.
    seed(&a, &b);
    seed(&b, &c);
    assert_eq!(a.dir.len(), 1);
    assert!(a.dir.peers(unix_now()).iter().all(|p| p.node_id != c.dir.node_id_hex()));

    // Несколько раундов реального обмена по mesh-сессиям.
    let nodes = [&a, &b, &c];
    for _ in 0..6 {
        for n in nodes {
            n.mesh.gossip_round(2).await;
        }
        if nodes.iter().all(|n| n.dir.len() == 2) {
            break;
        }
    }
    for (i, n) in nodes.iter().enumerate() {
        assert_eq!(n.dir.len(), 2, "node {i} knows {} peers", n.dir.len());
    }

    // A теперь видит C в виде, пригодном для маршрутизации: адрес, ключ, барьер.
    let peers = a.dir.peers(unix_now());
    let pc = peers.iter().find(|p| p.node_id == c.dir.node_id_hex()).expect("A learned C");
    assert_eq!(pc.nrxp_secret, sw.node_secret(&c.dir.node_id()));
    assert_eq!(pc.nrxp_static_public, hex::encode(c.dir.identity().static_pub));
    a.mesh.update_peers(peers).await;
    assert_eq!(a.mesh.peer_count().await, 2, "каталог подаётся в NodeMesh вместо списка панели");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_with_a_different_swarm_key_learns_nothing_and_teaches_nothing() {
    let sw = SwarmKey::from_bytes([5u8; 32]);
    let other = SwarmKey::from_bytes([6u8; 32]);
    let a = spawn(1, &sw).await;
    let outsider = spawn(9, &other).await;

    // Посторонний знает адрес и ключи A (запись публична), но не ключ роя.
    outsider.dir.insert(a.dir.own(unix_now()), unix_now());
    let before_a = a.dir.len();
    for _ in 0..2 {
        let (ok, learned) = outsider.mesh.gossip_round(2).await;
        assert_eq!((ok, learned), (0, 0), "хендшейк с неверным входным секретом не проходит");
    }
    assert_eq!(a.dir.len(), before_a, "и в каталог A ничего не попало");
    assert!(a.dir.peers(unix_now()).iter().all(|p| p.node_id != outsider.dir.node_id_hex()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridges_are_not_spread_by_gossip_between_real_nodes() {
    let sw = SwarmKey::from_bytes([5u8; 32]);
    let a = spawn(1, &sw).await;
    let b = spawn(2, &sw).await;
    seed(&a, &b);
    seed(&b, &a);

    // Мост известен A локально (например, импортом), но соседям не пересказывается.
    let id = SwarmIdentity::from_static_private([77; 32]);
    let bridge = NodeDescriptor::sign(
        &id.signing, id.static_pub, Roles(Roles::BRIDGE), features::GOSSIP, (2, 6), 1,
        unix_now(), 3600, String::new(),
        vec![Endpoint { kind: EndpointKind::Tcp, host: "10.77.0.1".into(), port: 443 }],
    );
    assert_eq!(a.dir.insert(bridge.clone(), unix_now()), Insert::Added);
    for _ in 0..3 {
        a.mesh.gossip_round(2).await;
        b.mesh.gossip_round(2).await;
    }
    assert!(
        b.dir.gossip_peers(unix_now()).iter().all(|p| p.node_id != node_id_hex(&bridge.node_id)),
        "адрес моста не должен покинуть узел через gossip"
    );
}

/// Узел роя остаётся обычным VPN-узлом: клиент с `node_secret`/`node_public_key`
/// (их печатает `--print-descriptor`) поднимает туннель, а панели у узла нет.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_swarm_node_still_serves_ordinary_clients() {
    use crate::crypto::PeerIdentity;
    use crate::net::ClientHandler;
    use tokio::sync::mpsc;

    let sw = SwarmKey::from_bytes([5u8; 32]);
    let node = spawn(1, &sw).await;
    let own = node.dir.own(unix_now());
    let tcp = own.endpoint(EndpointKind::Tcp).unwrap();
    let addr = format!("{}:{}", tcp.host, tcp.port);

    let peer = PeerIdentity::from_hex(&sw.node_secret(&node.dir.node_id()), &hex::encode(own.static_pub)).unwrap();
    let (tx_to_engine, rx_keep) = mpsc::channel(64);
    let (tx_keep, rx_from_engine) = mpsc::channel(64);
    std::mem::forget((rx_keep, tx_keep));
    let muxer = ClientHandler::connect(
        &addr,
        "example.com",
        None,
        Some(Identity::Peer(peer)),
        rx_from_engine,
        tx_to_engine,
    )
    .await
    .unwrap();
    for _ in 0..100 {
        if muxer.active_legs_count() >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(muxer.active_legs_count() >= 1, "клиент подключился к узлу без панели");
}
