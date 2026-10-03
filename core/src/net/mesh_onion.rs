//! HPKE-sealed, one-hop-at-a-time mesh route instructions.
//!
//! The ingress builds the complete route backwards. Each relay receives only
//! its own instruction and the opaque capsule for the next relay. Capsules are
//! HPKE Base mode (X25519/HKDF-SHA256/ChaCha20-Poly1305) and are carried inside
//! the already authenticated NRXP peer session.

use bytes::{BufMut, BytesMut};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};

use crate::net::MAX_MESH_HOPS;
use crate::{crypto::LocalIdentity, net::MeshPeer};

const CAPSULE_VERSION: u8 = 1;
const HPKE_ENCAPSULATED_KEY_LEN: usize = 32;
pub(crate) const MAX_ONION_CAPSULE_SIZE: usize = 12 * 1024;
const MAX_TARGET_LEN: usize = 2048;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

#[derive(Debug)]
pub(crate) enum OnionInstruction {
    Forward {
        next_peer: MeshPeer,
        next_capsule: Vec<u8>,
    },
    Exit {
        target: String,
    },
}

#[derive(Debug)]
pub(crate) struct OpenedOnionCapsule {
    pub(crate) strong_privacy: bool,
    pub(crate) is_udp: bool,
    pub(crate) remaining_hops: u8,
    pub(crate) expires_at_unix: u64,
    pub(crate) replay_nonce: [u8; 16],
    pub(crate) instruction: OnionInstruction,
}

/// Seal one instruction for the node identified by `recipient`'s NRXP static
/// public key. The node ID is part of HPKE's info string to prevent a valid
/// capsule from being replayed to another identity using the same key bytes.
pub(crate) fn seal_capsule(
    recipient: &MeshPeer,
    strong_privacy: bool,
    is_udp: bool,
    remaining_hops: u8,
    expires_at_unix: u64,
    replay_nonce: [u8; 16],
    instruction: OnionInstruction,
) -> Result<Vec<u8>, String> {
    let public_bytes = hex::decode(recipient.nrxp_static_public.trim())
        .map_err(|_| "invalid mesh onion recipient public key")?;
    let public_key = <Kem as KemTrait>::PublicKey::from_bytes(&public_bytes)
        .map_err(|_| "invalid mesh onion recipient public key")?;
    let plaintext = encode_capsule(
        strong_privacy,
        is_udp,
        remaining_hops,
        expires_at_unix,
        replay_nonce,
        instruction,
    )?;
    let (encapped_key, mut sender) = setup_sender::<Aead, Kdf, Kem>(
        &OpModeS::Base,
        &public_key,
        hpke_info(&recipient.node_id).as_slice(),
    )
    .map_err(|_| "failed to initialize mesh onion encryption")?;
    let ciphertext = sender
        .seal(&plaintext, b"")
        .map_err(|_| "failed to encrypt mesh onion capsule")?;

    let mut wire = Vec::with_capacity(encapped_key.to_bytes().len() + ciphertext.len());
    wire.extend_from_slice(encapped_key.to_bytes().as_slice());
    wire.extend_from_slice(&ciphertext);
    if wire.len() > MAX_ONION_CAPSULE_SIZE {
        return Err("mesh onion capsule exceeds the size limit".into());
    }
    Ok(wire)
}

/// Open the layer addressed to the local node. The caller separately enforces
/// expiry and per-node replay protection before acting on the instruction.
pub(crate) fn open_capsule(
    local_node_id: &str,
    identity: &LocalIdentity,
    wire: &[u8],
) -> Result<OpenedOnionCapsule, String> {
    if wire.len() <= HPKE_ENCAPSULATED_KEY_LEN + 16 || wire.len() > MAX_ONION_CAPSULE_SIZE {
        return Err("mesh onion capsule has an invalid size".into());
    }
    let (encapped_bytes, ciphertext) = wire.split_at(HPKE_ENCAPSULATED_KEY_LEN);
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(encapped_bytes)
        .map_err(|_| "invalid mesh onion encapsulated key")?;
    let private_bytes = zeroize::Zeroizing::new(identity.onion_private_key_bytes());
    let private_key = <Kem as KemTrait>::PrivateKey::from_bytes(private_bytes.as_ref())
        .map_err(|_| "local mesh onion key is invalid")?;
    let mut receiver = setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &private_key,
        &encapped_key,
        hpke_info(local_node_id).as_slice(),
    )
    .map_err(|_| "failed to initialize mesh onion decryption")?;
    let plaintext = receiver
        .open(ciphertext, b"")
        .map_err(|_| "mesh onion capsule authentication failed")?;
    decode_capsule(&plaintext)
}

fn hpke_info(node_id: &str) -> Vec<u8> {
    let mut info = b"netrunner-mesh-onion-v1\0".to_vec();
    info.extend_from_slice(node_id.as_bytes());
    info
}

fn encode_capsule(
    strong_privacy: bool,
    is_udp: bool,
    remaining_hops: u8,
    expires_at_unix: u64,
    replay_nonce: [u8; 16],
    instruction: OnionInstruction,
) -> Result<Vec<u8>, String> {
    match (&instruction, remaining_hops) {
        (OnionInstruction::Exit { .. }, 1)
        | (OnionInstruction::Forward { .. }, 2..=MAX_MESH_HOPS) => {}
        _ => return Err("mesh onion instruction does not match its hop budget".into()),
    }
    let mut out = BytesMut::with_capacity(512);
    out.put_u8(CAPSULE_VERSION);
    out.put_u8(u8::from(strong_privacy));
    out.put_u8(u8::from(is_udp));
    out.put_u8(remaining_hops);
    out.put_u64(expires_at_unix);
    out.extend_from_slice(&replay_nonce);
    match instruction {
        OnionInstruction::Forward {
            next_peer,
            next_capsule,
        } => {
            out.put_u8(1);
            put_string_u8(&mut out, &next_peer.node_id, 64)?;
            put_string_u16(&mut out, &next_peer.host, 255)?;
            out.put_u16(next_peer.port);
            put_string_u16(&mut out, &next_peer.decoy_sni, 255)?;
            put_string_u8(&mut out, &next_peer.nrxp_secret, 128)?;
            put_string_u8(&mut out, &next_peer.nrxp_static_public, 64)?;
            put_bytes_u16(&mut out, &next_capsule, MAX_ONION_CAPSULE_SIZE)?;
        }
        OnionInstruction::Exit { target } => {
            if target.is_empty() || target.len() > MAX_TARGET_LEN || target.contains('\0') {
                return Err("mesh onion target is invalid".into());
            }
            out.put_u8(2);
            put_string_u16(&mut out, &target, MAX_TARGET_LEN)?;
        }
    }
    if out.len() > MAX_ONION_CAPSULE_SIZE - HPKE_ENCAPSULATED_KEY_LEN - 16 {
        return Err("mesh onion instruction exceeds the size limit".into());
    }
    Ok(out.to_vec())
}

fn decode_capsule(mut input: &[u8]) -> Result<OpenedOnionCapsule, String> {
    if take(&mut input, 1)?[0] != CAPSULE_VERSION {
        return Err("unsupported mesh onion capsule version".into());
    }
    let strong_privacy = match take(&mut input, 1)?[0] {
        0 => false,
        1 => true,
        _ => return Err("invalid mesh onion privacy mode".into()),
    };
    let is_udp = match take(&mut input, 1)?[0] {
        0 => false,
        1 => true,
        _ => return Err("invalid mesh onion transport protocol".into()),
    };
    let remaining_hops = take(&mut input, 1)?[0];
    if remaining_hops == 0 || remaining_hops > MAX_MESH_HOPS {
        return Err("mesh onion hop budget is outside the allowed range".into());
    }
    let expires_at_unix = u64::from_be_bytes(take(&mut input, 8)?.try_into().unwrap());
    let replay_nonce = take(&mut input, 16)?.try_into().unwrap();
    let instruction = match take(&mut input, 1)?[0] {
        1 => {
            let node_id = take_string_u8(&mut input, 64)?;
            let host = take_string_u16(&mut input, 255)?;
            let port = u16::from_be_bytes(take(&mut input, 2)?.try_into().unwrap());
            let decoy_sni = take_string_u16(&mut input, 255)?;
            let nrxp_secret = take_string_u8(&mut input, 128)?;
            let nrxp_static_public = take_string_u8(&mut input, 64)?;
            let next_capsule = take_bytes_u16(&mut input, MAX_ONION_CAPSULE_SIZE)?;
            if node_id.is_empty()
                || host.is_empty()
                || port == 0
                || nrxp_secret.is_empty()
                || nrxp_static_public.len() != 64
                || next_capsule.len() <= HPKE_ENCAPSULATED_KEY_LEN + 16
            {
                return Err("mesh onion forward instruction is incomplete".into());
            }
            OnionInstruction::Forward {
                next_peer: MeshPeer {
                    node_id,
                    host,
                    port,
                    decoy_sni,
                    nrxp_secret,
                    nrxp_static_public,
                },
                next_capsule,
            }
        }
        2 => {
            let target = take_string_u16(&mut input, MAX_TARGET_LEN)?;
            if target.is_empty() || target.contains('\0') {
                return Err("mesh onion exit target is invalid".into());
            }
            OnionInstruction::Exit { target }
        }
        _ => return Err("unknown mesh onion instruction".into()),
    };
    if !input.is_empty() {
        return Err("mesh onion capsule has trailing data".into());
    }
    match (&instruction, remaining_hops) {
        (OnionInstruction::Exit { .. }, 1)
        | (OnionInstruction::Forward { .. }, 2..=MAX_MESH_HOPS) => {}
        _ => return Err("mesh onion instruction does not match its hop budget".into()),
    }
    Ok(OpenedOnionCapsule {
        strong_privacy,
        is_udp,
        remaining_hops,
        expires_at_unix,
        replay_nonce,
        instruction,
    })
}

fn put_string_u8(out: &mut BytesMut, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max || value.len() > u8::MAX as usize {
        return Err("mesh onion string exceeds its size limit".into());
    }
    out.put_u8(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_string_u16(out: &mut BytesMut, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max || value.len() > u16::MAX as usize {
        return Err("mesh onion string exceeds its size limit".into());
    }
    out.put_u16(value.len() as u16);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_bytes_u16(out: &mut BytesMut, value: &[u8], max: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max || value.len() > u16::MAX as usize {
        return Err("mesh onion field exceeds its size limit".into());
    }
    out.put_u16(value.len() as u16);
    out.extend_from_slice(value);
    Ok(())
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], String> {
    if input.len() < len {
        return Err("truncated mesh onion instruction".into());
    }
    let (value, remainder) = input.split_at(len);
    *input = remainder;
    Ok(value)
}

fn take_string_u8(input: &mut &[u8], max: usize) -> Result<String, String> {
    let len = usize::from(take(input, 1)?[0]);
    take_string(input, len, max)
}

fn take_string_u16(input: &mut &[u8], max: usize) -> Result<String, String> {
    let len = usize::from(u16::from_be_bytes(take(input, 2)?.try_into().unwrap()));
    take_string(input, len, max)
}

fn take_string(input: &mut &[u8], len: usize, max: usize) -> Result<String, String> {
    if len == 0 || len > max {
        return Err("mesh onion string has an invalid length".into());
    }
    String::from_utf8(take(input, len)?.to_vec())
        .map_err(|_| "mesh onion string is not valid UTF-8".into())
}

fn take_bytes_u16(input: &mut &[u8], max: usize) -> Result<Vec<u8>, String> {
    let len = usize::from(u16::from_be_bytes(take(input, 2)?.try_into().unwrap()));
    if len == 0 || len > max {
        return Err("mesh onion field has an invalid length".into());
    }
    Ok(take(input, len)?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{kem::X25519HkdfSha256, Kem as KemTrait};

    fn test_peer(node_id: &str, public_key: &[u8]) -> MeshPeer {
        MeshPeer {
            node_id: node_id.into(),
            host: "192.0.2.10".into(),
            port: 443,
            decoy_sni: "www.example.org".into(),
            nrxp_secret: "secret".into(),
            nrxp_static_public: hex::encode(public_key),
        }
    }

    #[test]
    fn capsule_opens_only_for_recipient_and_preserves_next_hop() {
        let (private, public) = X25519HkdfSha256::gen_keypair();
        let peer = test_peer("node-a", public.to_bytes().as_slice());
        let capsule = seal_capsule(
            &peer,
            true,
            false,
            1,
            1234,
            [0x5a; 16],
            OnionInstruction::Exit {
                target: "203.0.113.5:443".into(),
            },
        )
        .unwrap();
        let local = LocalIdentity::from_hex(
            &hex::encode([7u8; 32]),
            &hex::encode(private.to_bytes()),
            true,
        )
        .unwrap();

        let opened = open_capsule("node-a", &local, &capsule).unwrap();
        assert!(opened.strong_privacy);
        assert!(!opened.is_udp);
        assert_eq!(opened.remaining_hops, 1);
        assert_eq!(opened.expires_at_unix, 1234);
        assert_eq!(opened.replay_nonce, [0x5a; 16]);
        assert!(matches!(
            opened.instruction,
            OnionInstruction::Exit { ref target } if target == "203.0.113.5:443"
        ));
        assert!(open_capsule("node-b", &local, &capsule).is_err());
    }

    #[test]
    fn nested_capsule_reveals_only_the_next_relay_until_exit() {
        let (private_a, public_a) = X25519HkdfSha256::gen_keypair();
        let (private_b, public_b) = X25519HkdfSha256::gen_keypair();
        let peer_a = test_peer("node-a", public_a.to_bytes().as_slice());
        let peer_b = test_peer("node-b", public_b.to_bytes().as_slice());
        let target = "203.0.113.5:443";
        let inner = seal_capsule(
            &peer_b,
            false,
            false,
            1,
            2000,
            [0x22; 16],
            OnionInstruction::Exit {
                target: target.into(),
            },
        )
        .unwrap();
        let outer = seal_capsule(
            &peer_a,
            false,
            false,
            2,
            2000,
            [0x11; 16],
            OnionInstruction::Forward {
                next_peer: peer_b,
                next_capsule: inner.clone(),
            },
        )
        .unwrap();

        let identity_a = LocalIdentity::from_hex(
            &hex::encode([1u8; 32]),
            &hex::encode(private_a.to_bytes()),
            true,
        )
        .unwrap();
        let identity_b = LocalIdentity::from_hex(
            &hex::encode([2u8; 32]),
            &hex::encode(private_b.to_bytes()),
            true,
        )
        .unwrap();
        let first_layer = open_capsule("node-a", &identity_a, &outer).unwrap();
        assert_eq!(first_layer.remaining_hops, 2);
        let OnionInstruction::Forward {
            next_peer,
            next_capsule,
        } = first_layer.instruction
        else {
            panic!("first relay must receive only a forward instruction")
        };
        assert_eq!(next_peer.node_id, "node-b");
        assert_eq!(next_capsule, inner);
        assert!(!outer
            .windows(target.len())
            .any(|window| window == target.as_bytes()));

        let exit_layer = open_capsule(&next_peer.node_id, &identity_b, &next_capsule).unwrap();
        assert_eq!(exit_layer.remaining_hops, 1);
        assert!(matches!(
            exit_layer.instruction,
            OnionInstruction::Exit { target: ref opened } if opened == target
        ));
    }

    #[test]
    fn altered_capsule_is_rejected() {
        let (private, public) = X25519HkdfSha256::gen_keypair();
        let peer = test_peer("node-a", public.to_bytes().as_slice());
        let mut capsule = seal_capsule(
            &peer,
            false,
            false,
            1,
            1234,
            [0x11; 16],
            OnionInstruction::Exit {
                target: "203.0.113.5:443".into(),
            },
        )
        .unwrap();
        *capsule.last_mut().unwrap() ^= 0x80;
        let local = LocalIdentity::from_hex(
            &hex::encode([9u8; 32]),
            &hex::encode(private.to_bytes()),
            true,
        )
        .unwrap();
        assert!(open_capsule("node-a", &local, &capsule).is_err());
    }
}
