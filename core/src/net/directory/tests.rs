//! Тесты каталога: формат, правила допуска, обмен и поведение сети из десятков
//! узлов под атакой (подделки, повторы, засорение с одной сети, мосты).

use super::*;
use rand::{RngExt, SeedableRng};

const T0: u64 = 1_800_000_000;

fn cfg(host: &str) -> DirectoryConfig {
    DirectoryConfig {
        store: StoreConfig {
            allow_private: true,
            ..Default::default()
        },
        advertise: vec![Endpoint {
            kind: EndpointKind::Tcp,
            host: host.into(),
            port: 443,
        }],
        decoy_sni: "www.example.org".into(),
        ..Default::default()
    }
}

fn dir_with(seed: u8, host: &str, swarm: &SwarmKey, mutate: impl FnOnce(&mut DirectoryConfig)) -> Directory {
    let mut c = cfg(host);
    mutate(&mut c);
    Directory::new(SwarmIdentity::from_static_private([seed; 32]), swarm.clone(), c, T0)
}

fn dir(seed: u8, host: &str, swarm: &SwarmKey) -> Directory {
    dir_with(seed, host, swarm, |_| {})
}

fn swarm() -> SwarmKey {
    SwarmKey::from_bytes([9u8; 32])
}

/// Один полный обмен A → B (байты, как по проводу).
fn exchange(a: &Directory, b: &Directory, now: u64) -> (Stats, Stats) {
    let digest = a.begin_exchange(now);
    let Ok(Handled::Reply(reply)) = b.handle_incoming(&digest, now) else {
        panic!("responder must reply to a digest")
    };
    let (sa, push) = a.complete_exchange(&reply, now).expect("reply is valid");
    let sb = match push {
        Some(p) => match b.handle_incoming(&p, now).expect("push accepted") {
            Handled::Absorbed(s) => s,
            Handled::Reply(_) => panic!("a push has no reply"),
        },
        None => Stats::default(),
    };
    (sa, sb)
}

// ───────────────────────────── descriptor ──────────────────────────────────

fn sample(seed: u8, host: &str) -> NodeDescriptor {
    dir(seed, host, &swarm()).own(T0)
}

#[test]
fn descriptor_round_trips_and_verifies() {
    let d = sample(1, "10.0.0.1");
    let bytes = d.encode();
    let back = NodeDescriptor::decode(&bytes).unwrap();
    assert_eq!(back, d);
    assert_eq!(back.verify(T0 + 1, true), Ok(()));
    assert_eq!(d.node_id, derive_node_id(&d.sign_pub, &d.static_pub));
}

#[test]
fn every_signed_field_is_protected() {
    let d = sample(1, "10.0.0.1");
    let bytes = d.encode();
    // Меняем по одному байту везде, кроме самой подписи: запись либо не разбирается,
    // либо не проходит проверку (подпись/личность/сроки/адрес).
    let sig_start = bytes.len() - 64;
    for i in 0..sig_start {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        if let Ok(x) = NodeDescriptor::decode(&b) {
            assert!(x.verify(T0 + 1, true).is_err(), "byte {i} is not covered by the signature");
        }
    }
    // и подпись
    for i in sig_start..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x80;
        let x = NodeDescriptor::decode(&b).unwrap();
        assert_eq!(x.verify(T0 + 1, true), Err(DescriptorError::BadSignature));
    }
}

#[test]
fn identity_binds_both_keys() {
    let mut d = sample(1, "10.0.0.1");
    d.static_pub = sample(2, "10.0.0.2").static_pub; // чужой статический ключ под своей подписью
    assert_eq!(d.verify(T0 + 1, true), Err(DescriptorError::BadNodeId));
}

#[test]
fn validity_rules() {
    let id = SwarmIdentity::from_static_private([3; 32]);
    let ep = vec![Endpoint { kind: EndpointKind::Tcp, host: "10.0.0.3".into(), port: 443 }];
    let mk = |issued: u64, secs: u64| {
        NodeDescriptor::sign(&id.signing, id.static_pub, Roles(Roles::RELAY), 1, (2, 6), 1, issued, secs, String::new(), ep.clone())
    };
    // истекла
    assert_eq!(mk(T0, 100).verify(T0 + 101, true), Err(DescriptorError::Expired));
    // выпущена в будущем
    assert_eq!(mk(T0 + 10_000, 100).verify(T0, true), Err(DescriptorError::FromTheFuture));
    // слегка из будущего (расхождение часов) допустимо
    assert_eq!(mk(T0 + 60, 100).verify(T0, true), Ok(()));
    // срок обрезается до максимума при выпуске
    let long = mk(T0, 10 * MAX_VALIDITY_SECS);
    assert_eq!(long.valid_until - long.issued_at, MAX_VALIDITY_SECS);
    // а подделанная запись с большим сроком не пройдёт (подпись/срок)
    let mut forged = long.clone();
    forged.valid_until = forged.issued_at + 10 * MAX_VALIDITY_SECS;
    assert!(forged.verify(T0 + 1, true).is_err());
}

#[test]
fn endpoints_are_validated() {
    let id = SwarmIdentity::from_static_private([4; 32]);
    let sign = |eps: Vec<Endpoint>, sni: &str| {
        NodeDescriptor::sign(&id.signing, id.static_pub, Roles(Roles::RELAY), 1, (2, 6), 1, T0, 3600, sni.into(), eps)
    };
    let ep = |h: &str, p: u16| Endpoint { kind: EndpointKind::Tcp, host: h.into(), port: p };
    assert!(sign(vec![], "").verify(T0, true).is_err());
    assert!(sign(vec![ep("a b", 443)], "").verify(T0, true).is_err());
    assert!(sign(vec![ep("", 443)], "").verify(T0, true).is_err());
    assert!(sign(vec![ep("host", 0)], "").verify(T0, true).is_err());
    assert!(sign(vec![ep("-bad", 443)], "").verify(T0, true).is_err());
    assert!(sign((0..5).map(|i| ep(&format!("h{i}.example"), 443)).collect(), "").verify(T0, true).is_err());
    assert!(sign(vec![ep("ok.example", 443)], "bad sni!").verify(T0, true).is_err());
    assert_eq!(sign(vec![ep("ok.example", 443)], "").verify(T0, true), Ok(()));
    // публичность
    for private in ["10.1.2.3", "192.168.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1", "fd00::1", "fe80::1", "localhost", "printer.local"] {
        assert_eq!(
            sign(vec![ep(private, 443)], "").verify(T0, false),
            Err(DescriptorError::NonPublicAddress),
            "{private}"
        );
    }
    for public in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "node.example.org"] {
        assert_eq!(sign(vec![ep(public, 443)], "").verify(T0, false), Ok(()), "{public}");
    }
}

#[test]
fn decoding_never_panics_on_garbage() {
    let good = sample(1, "10.0.0.1").encode();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    for _ in 0..3000 {
        let mut b = good.clone();
        match rng.random_range(0..3) {
            0 => b.truncate(rng.random_range(0..b.len())),
            1 => {
                for _ in 0..rng.random_range(1..8) {
                    let i = rng.random_range(0..b.len());
                    b[i] = rng.random();
                }
            }
            _ => b.extend((0..rng.random_range(1..20)).map(|_| rng.random::<u8>())),
        }
        if let Ok(d) = NodeDescriptor::decode(&b) {
            let _ = d.verify(T0, true);
        }
    }
    for len in 0..200 {
        let junk: Vec<u8> = (0..len).map(|_| rng.random()).collect();
        let _ = NodeDescriptor::decode(&junk);
        let _ = Message::decode(&junk);
    }
}

// ─────────────────────────────── store ─────────────────────────────────────

fn store() -> DescriptorStore {
    DescriptorStore::new(StoreConfig { allow_private: true, ..Default::default() }, None)
}

fn desc_with(seed: u8, host: &str, seq: u64, roles: u8, issued: u64, valid: u64) -> NodeDescriptor {
    let id = SwarmIdentity::from_static_private([seed; 32]);
    NodeDescriptor::sign(
        &id.signing,
        id.static_pub,
        Roles(roles),
        features::GOSSIP,
        (2, 6),
        seq,
        issued,
        valid,
        String::new(),
        vec![Endpoint { kind: EndpointKind::Tcp, host: host.into(), port: 443 }],
    )
}

#[test]
fn store_prefers_higher_seq_and_ignores_replays() {
    let mut s = store();
    let v1 = desc_with(1, "10.0.0.1", 5, Roles::RELAY, T0, 3600);
    let v2 = desc_with(1, "10.0.0.9", 6, Roles::RELAY, T0, 3600); // переехал
    let old = desc_with(1, "10.0.0.7", 4, Roles::RELAY, T0, 3600);
    assert_eq!(s.insert(v1.clone(), T0), Insert::Added);
    assert_eq!(s.insert(v1.clone(), T0), Insert::Stale);
    assert_eq!(s.insert(v2.clone(), T0), Insert::Updated);
    assert_eq!(s.insert(old, T0), Insert::Stale, "откат адреса запрещён");
    assert_eq!(s.insert(v1, T0), Insert::Stale, "повтор старой записи");
    assert_eq!(s.get(&v2.node_id).unwrap().endpoints[0].host, "10.0.0.9");
}

#[test]
fn store_limits_nodes_per_network_prefix() {
    let mut s = store();
    for i in 1..=3u8 {
        assert_eq!(s.insert(desc_with(i, &format!("10.0.0.{i}"), 1, Roles::RELAY, T0, 3600), T0), Insert::Added);
    }
    // четвёртый из той же /24 — отказ
    assert_eq!(
        s.insert(desc_with(4, "10.0.0.4", 1, Roles::RELAY, T0, 3600), T0),
        Insert::Rejected(Reject::PrefixLimit)
    );
    // из другой сети — можно
    assert_eq!(s.insert(desc_with(5, "10.0.1.4", 1, Roles::RELAY, T0, 3600), T0), Insert::Added);
    // обновление существующего узла из той же сети не упирается в лимит
    assert_eq!(s.insert(desc_with(1, "10.0.0.1", 2, Roles::RELAY, T0, 3600), T0), Insert::Updated);
    // имена: одна зона второго уровня тоже считается «сетью»
    for i in 10..13u8 {
        assert_eq!(s.insert(desc_with(i, &format!("n{i}.same.example"), 1, Roles::RELAY, T0, 3600), T0), Insert::Added);
    }
    assert_eq!(
        s.insert(desc_with(13, "n13.same.example", 1, Roles::RELAY, T0, 3600), T0),
        Insert::Rejected(Reject::PrefixLimit)
    );
}

#[test]
fn store_is_bounded_and_evicts_the_soonest_to_expire() {
    let mut s = DescriptorStore::new(
        StoreConfig { max_records: 4, max_per_prefix: 100, allow_private: true },
        None,
    );
    for i in 1..=4u8 {
        let valid = 1000 * i as u64; // 1000, 2000, 3000, 4000
        assert_eq!(s.insert(desc_with(i, &format!("10.0.{i}.1"), 1, Roles::RELAY, T0, valid), T0), Insert::Added);
    }
    // новая живёт дольше самой короткой — вытесняет её
    let fresh = desc_with(9, "10.0.9.1", 1, Roles::RELAY, T0, 5000);
    assert_eq!(s.insert(fresh.clone(), T0), Insert::Added);
    assert_eq!(s.len(), 4);
    assert!(s.get(&fresh.node_id).is_some());
    // новая, живущая меньше всех — отказ (нельзя вытеснять долгоживущих короткоживущими)
    assert_eq!(
        s.insert(desc_with(10, "10.0.10.1", 1, Roles::RELAY, T0, 10), T0),
        Insert::Rejected(Reject::Full)
    );
    assert_eq!(s.len(), 4);
}

#[test]
fn store_ignores_its_own_record_and_expires_old_ones() {
    let me = desc_with(1, "10.0.0.1", 1, Roles::RELAY, T0, 3600);
    let mut s = DescriptorStore::new(StoreConfig { allow_private: true, ..Default::default() }, Some(me.node_id));
    assert_eq!(s.insert(me, T0), Insert::Stale, "про себя мы знаем лучше всех");
    let other = desc_with(2, "10.0.1.1", 1, Roles::RELAY, T0, 100);
    s.insert(other.clone(), T0);
    assert_eq!(s.live(T0 + 50).count(), 1);
    assert_eq!(s.live(T0 + 101).count(), 0);
    assert_eq!(s.gc(T0 + 101), 1);
    assert!(s.is_empty());
}

#[test]
fn digest_window_rotates_over_a_large_store() {
    let mut s = DescriptorStore::new(
        StoreConfig { max_records: 5000, max_per_prefix: 100_000, allow_private: true },
        None,
    );
    let n = store::MAX_DIGEST_ENTRIES + 120;
    for i in 0..n {
        let id = SwarmIdentity::from_static_private({
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            k
        });
        let d = NodeDescriptor::sign(
            &id.signing, id.static_pub, Roles(Roles::RELAY), 1, (2, 6), 1, T0, 3600, String::new(),
            vec![Endpoint { kind: EndpointKind::Tcp, host: format!("10.{}.{}.1", i / 250, i % 250), port: 443 }],
        );
        assert_eq!(s.insert(d, T0), Insert::Added);
    }
    let mut seen = std::collections::HashSet::new();
    for round in 0..4 {
        let dg = s.digest(T0, round);
        assert!(dg.len() <= store::MAX_DIGEST_ENTRIES);
        seen.extend(dg.into_iter().map(|(id, _)| id));
    }
    assert_eq!(seen.len(), n, "за несколько раундов дайджест обходит весь каталог");
}

#[test]
fn export_import_round_trip_and_tampering() {
    let mut s = store();
    for i in 1..=3u8 {
        s.insert(desc_with(i, &format!("10.0.{i}.1"), 1, Roles::RELAY, T0, 3600), T0);
    }
    let snap = s.export(T0);
    let mut s2 = store();
    assert_eq!(s2.import(&snap, T0), 3);
    // испорченный снимок: всё, что не проходит подпись, отбрасывается
    let mut bad = snap.clone();
    let k = bad.len() - 10;
    bad[k] ^= 0xff;
    let mut s3 = store();
    assert!(s3.import(&bad, T0) < 3);
    assert_eq!(store().import(b"garbage", T0), 0);
    // и истёкшее в снимок не попадает
    assert_eq!(s.export(T0 + 10_000)[8..12], 0u32.to_be_bytes());
}

// ─────────────────────────────── gossip ────────────────────────────────────

#[test]
fn messages_round_trip_and_reject_oversize() {
    let a = sample(1, "10.0.0.1");
    let b = sample(2, "10.0.1.1");
    for m in [
        Message::Digest(vec![(a.node_id, 5), (b.node_id, 9)]),
        Message::Reply { records: vec![a.clone(), b.clone()], want: vec![b.node_id] },
        Message::Push(vec![a.clone()]),
        Message::Digest(vec![]),
    ] {
        assert_eq!(Message::decode(&m.encode()).unwrap(), m);
    }
    assert_eq!(Message::decode(&[]), Err(GossipError::Empty));
    assert_eq!(Message::decode(&[99]), Err(GossipError::UnknownTag(99)));
    assert!(Message::decode(&vec![1u8; gossip::MAX_MSG_BYTES + 1]).is_err());
    // дайджест с заявленной длиной больше предела
    let mut huge = vec![1u8];
    huge.extend_from_slice(&u16::MAX.to_be_bytes());
    assert!(Message::decode(&huge).is_err());
    // хвост
    let mut tail = Message::Digest(vec![]).encode();
    tail.push(0);
    assert!(Message::decode(&tail).is_err());
}

#[test]
fn two_nodes_learn_each_other_and_a_third_through_one_exchange() {
    let sw = swarm();
    let a = dir(1, "10.0.0.1", &sw);
    let b = dir(2, "10.0.1.1", &sw);
    let c = dir(3, "10.0.2.1", &sw);
    // A знает C; B знает только себя
    assert_eq!(a.insert(c.own(T0), T0), Insert::Added);
    let (sa, sb) = exchange(&a, &b, T0 + 1);
    assert_eq!(sa.learned(), 1, "A узнал о B");
    assert_eq!(sb.learned(), 2, "B узнал об A и о C (через пуш)");
    assert_eq!(b.len(), 2);
    assert_eq!(a.len(), 2);
    let ids: Vec<_> = b.peers(T0 + 1).into_iter().map(|p| p.node_id).collect();
    assert!(ids.contains(&a.node_id_hex()) && ids.contains(&c.node_id_hex()));
    // повторный обмен ничего нового не приносит
    let (sa2, sb2) = exchange(&a, &b, T0 + 2);
    assert_eq!((sa2.learned(), sb2.learned()), (0, 0));
}

#[test]
fn network_converges_by_random_pairwise_exchanges() {
    let sw = swarm();
    let n = 40usize;
    let nodes: Vec<Directory> = (0..n)
        .map(|i| dir(i as u8 + 1, &format!("10.{}.{}.1", i / 8, i % 8), &sw))
        .collect();
    // каждый знает только следующего по кольцу (минимальный seed)
    for i in 0..n {
        nodes[i].insert(nodes[(i + 1) % n].own(T0), T0);
    }
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let mut rounds = 0;
    let target = n - 1;
    while rounds < 40 && !nodes.iter().all(|d| d.len() == target) {
        rounds += 1;
        for i in 0..n {
            // выбираем случайного известного соседа
            let peers = nodes[i].gossip_peers(T0 + rounds);
            if peers.is_empty() {
                continue;
            }
            let p = &peers[rng.random_range(0..peers.len())];
            let j = nodes.iter().position(|d| d.node_id_hex() == p.node_id).unwrap();
            exchange(&nodes[i], &nodes[j], T0 + rounds);
        }
    }
    assert!(
        nodes.iter().all(|d| d.len() == target),
        "after {rounds} rounds: {:?}",
        nodes.iter().map(|d| d.len()).collect::<Vec<_>>()
    );
    // для 40 узлов хватает порядка log2(n) раундов с запасом
    assert!(rounds <= 12, "converged in {rounds} rounds");
}

#[test]
fn forged_stale_and_non_gossipable_records_do_not_spread() {
    let sw = swarm();
    let honest = dir(1, "10.0.0.1", &sw);
    let victim = dir(2, "10.0.1.1", &sw);
    let evil = dir(3, "10.0.2.1", &sw);

    // 1) подделка: чужой node_id с чужим адресом под нашей подписью
    let mut forged = victim.own(T0);
    forged.endpoints[0].host = "10.99.99.99".into();
    // 2) мост: не пересказывается
    let bridge = {
        let id = SwarmIdentity::from_static_private([7; 32]);
        NodeDescriptor::sign(&id.signing, id.static_pub, Roles(Roles::BRIDGE), 1, (2, 6), 1, T0, 3600, String::new(),
            vec![Endpoint { kind: EndpointKind::Tcp, host: "10.0.7.1".into(), port: 443 }])
    };
    // 3) честная запись жертвы
    let real = victim.own(T0);

    let push = Message::Push(vec![forged.clone(), bridge.clone(), real.clone()]).encode();
    let Ok(Handled::Absorbed(st)) = honest.handle_incoming(&push, T0 + 1) else { panic!() };
    assert_eq!(st.added, 1, "принята только настоящая запись жертвы: {st:?}");
    assert_eq!(st.rejected, 2);
    let peers = honest.peers(T0 + 1);
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].host, "10.0.1.1");

    // мост из локального импорта хранится, но в gossip не попадает
    let d = dir(4, "10.0.4.1", &sw);
    assert_eq!(d.insert(bridge.clone(), T0), Insert::Added);
    let (_, sb) = exchange(&d, &honest, T0 + 1);
    assert!(honest.peers(T0 + 1).iter().all(|p| p.node_id != node_id_hex(&bridge.node_id)));
    let _ = (sb, evil);
}

#[test]
fn sybil_flood_from_one_network_cannot_fill_the_directory() {
    let sw = swarm();
    let victim = dir(1, "10.0.0.1", &sw);
    let flood: Vec<NodeDescriptor> = (0..60u8)
        .map(|i| desc_with(100 + i, &format!("10.5.5.{}", i + 1), 1, Roles::RELAY, T0, 3600))
        .collect();
    // сообщения по 20 записей
    for chunk in flood.chunks(20) {
        let msg = Message::Push(chunk.to_vec()).encode();
        let _ = victim.handle_incoming(&msg, T0 + 1);
    }
    assert_eq!(victim.len(), 3, "с одной /24 принимается не больше max_per_prefix");
}

#[test]
fn incoming_requests_are_rate_limited() {
    let sw = swarm();
    let d = dir_with(1, "10.0.0.1", &sw, |c| {
        c.max_requests_per_window = 5;
        c.window_secs = 10;
    });
    let digest = Message::Digest(vec![]).encode();
    for _ in 0..5 {
        assert!(d.handle_incoming(&digest, T0 + 1).is_ok());
    }
    assert!(matches!(d.handle_incoming(&digest, T0 + 2), Err(DirectoryError::RateLimited)));
    // новое окно — снова можно
    assert!(d.handle_incoming(&digest, T0 + 20).is_ok());
    // ответ вместо запроса — ошибка протокола
    let reply = Message::Reply { records: vec![], want: vec![] }.encode();
    assert!(matches!(d.handle_incoming(&reply, T0 + 21), Err(DirectoryError::UnexpectedMessage)));
    assert!(d.handle_incoming(&[], T0 + 21).is_err());
}

#[test]
fn replies_respect_the_frame_budget() {
    let sw = swarm();
    let big = dir_with(1, "10.0.0.1", &sw, |c| c.store.max_per_prefix = 100_000);
    for i in 0..300u16 {
        let mut k = [0u8; 32];
        k[..2].copy_from_slice(&(i + 1).to_be_bytes());
        k[31] = 77;
        let id = SwarmIdentity::from_static_private(k);
        let d = NodeDescriptor::sign(
            &id.signing, id.static_pub, Roles(Roles::RELAY), 1, (2, 6), 1, T0, 3600, "www.example.org".into(),
            vec![Endpoint { kind: EndpointKind::Tcp, host: format!("10.{}.{}.1", i / 250, i % 250), port: 443 }],
        );
        big.insert(d, T0);
    }
    let fresh = dir(2, "10.200.0.1", &sw);
    let digest = fresh.begin_exchange(T0 + 1);
    let Ok(Handled::Reply(reply)) = big.handle_incoming(&digest, T0 + 1) else { panic!() };
    assert!(reply.len() <= gossip::MAX_MSG_BYTES, "reply is {} bytes", reply.len());
    assert!(reply.len() < 16_360, "must fit one NRXP frame");
    let (st, _) = fresh.complete_exchange(&reply, T0 + 1).unwrap();
    assert!(st.learned() > 20, "{st:?}");
}

// ───────────────────────── роль, рой, допуск ──────────────────────────────

#[test]
fn own_record_is_reissued_before_it_expires_with_a_higher_seq() {
    let sw = swarm();
    let d = dir_with(1, "10.0.0.1", &sw, |c| c.validity_secs = 3000);
    let first = d.own(T0);
    assert_eq!(d.own(T0 + 1000).seq, first.seq, "пока срока хватает, запись та же");
    let later = d.own(T0 + 2500);
    assert!(later.seq > first.seq && later.valid_until > first.valid_until);
    assert_eq!(later.verify(T0 + 2500, true), Ok(()));
}

#[test]
fn swarm_key_gates_mesh_admission_without_publishing_secrets() {
    let sw = swarm();
    let other = SwarmKey::from_bytes([1u8; 32]);
    let a = dir(1, "10.0.0.1", &sw);
    let b = dir(2, "10.0.1.1", &sw);
    a.insert(b.own(T0), T0);

    // секрет соседа считается из ключа роя и в записи нигде не лежит
    let peers = a.peers(T0);
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].nrxp_secret, sw.node_secret(&b.node_id()));
    assert!(!hex::encode(b.own(T0).encode()).contains(&peers[0].nrxp_secret));

    // допуск: знает секрет роя для своего id — пускаем; чужой рой/чужой id — нет
    let id = b.node_id_hex();
    assert!(a.validate_mesh_peer(&id, &sw.node_secret(&b.node_id())));
    assert!(!a.validate_mesh_peer(&id, &other.node_secret(&b.node_id())));
    assert!(!a.validate_mesh_peer(&id, &sw.node_secret(&a.node_id())));
    assert!(!a.validate_mesh_peer("not-hex", "x"));
    assert!(!a.validate_mesh_peer(&id, ""));
    // секрет детерминирован и различается по узлам и по ключу
    assert_eq!(sw.node_secret(&a.node_id()), sw.node_secret(&a.node_id()));
    assert_ne!(sw.node_secret(&a.node_id()), sw.node_secret(&b.node_id()));
    assert_ne!(sw.node_secret(&a.node_id()), other.node_secret(&a.node_id()));
    assert_eq!(sw.node_secret(&a.node_id()).len(), 64);
    assert!(format!("{sw:?}").contains("REDACTED"));
}

#[test]
fn old_nodes_without_gossip_support_are_not_sent_gossip() {
    let sw = swarm();
    let a = dir(1, "10.0.0.1", &sw);
    let id = SwarmIdentity::from_static_private([2; 32]);
    let legacy = NodeDescriptor::sign(
        &id.signing, id.static_pub, Roles(Roles::RELAY), 0 /* без GOSSIP */, (2, 5), 1, T0, 3600, String::new(),
        vec![Endpoint { kind: EndpointKind::Tcp, host: "10.0.1.1".into(), port: 443 }],
    );
    a.insert(legacy, T0);
    assert_eq!(a.peers(T0).len(), 1, "в маршрутах участвует");
    assert!(a.gossip_peers(T0).is_empty(), "но неизвестный кадр ему не шлём: он рвёт ногу");
}

#[tokio::test]
async fn directory_validator_serves_peers_and_admission_without_a_panel() {
    use crate::net::AuthValidator;
    let sw = swarm();
    let a = std::sync::Arc::new(dir(1, "10.0.0.1", &sw));
    let b = dir(2, "10.0.1.1", &sw);
    a.insert(b.own(unix_now()), unix_now());
    let v = DirectoryValidator::new(a.clone(), None);
    let peers = v.list_mesh_peers().await;
    // записи выпущены на T0 (в прошлом/будущем относительно unix_now) — допускаем оба исхода,
    // главное: ошибки панели нет и узлы без аккаунтов не падают
    assert!(peers.is_ok());
    assert!(v.validate("any-user-token").await.is_err(), "без панели пользовательских токенов нет");
    assert!(v.report_node_health(crate::net::NodeHealthReport {
        active_sessions: 0,
        active_legs: 0,
        active_streams: 0,
        bytes_up_total_mb: 0.0,
        bytes_down_total_mb: 0.0,
        error_totals: Default::default(),
        uptime_secs: 0,
    }).await.is_ok());
    assert!(v.validate_mesh_peer(&b.node_id_hex(), &sw.node_secret(&b.node_id())).await.is_ok());
    assert!(v.validate_mesh_peer(&b.node_id_hex(), "wrong").await.is_err());
}
