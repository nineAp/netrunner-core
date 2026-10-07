# Why this is secure

🇷🇺 [Русская версия](../SECURITY.md)

This document answers one question: **what the security of the Netrunner channel rests on and why it
can be trusted**. It is an analysis of the essence, not a specification: concrete formats, offsets,
labels and constants are deliberately omitted here — they are not needed to understand the model (see
"Why there are no numbers here" at the end; the byte-level specification lives in
[PROTOCOL.md](PROTOCOL.md), and the threat model in [SECURITY_MODEL.md](SECURITY_MODEL.md)).

MTProto — the best-known "home-made" transport cryptographic protocol — is examined alongside for
contrast. It is useful as a mirror: you can see which decisions yield security and which are
historical debt.

---

## 1. The essence of MTProto in two paragraphs

MTProto solves the same basic task: turning an untrusted channel into a protected one without relying
on a TLS stack. The scheme is hybrid — asymmetric cryptography to establish the session
(Diffie-Hellman, RSA for the initial binding to the server) and symmetric for the data stream (AES).
The key idea: the parties never transmit the key itself, they compute it independently from an open
exchange — intercepting the handshake gives nothing by itself.

One technique is worth noting: the secret Diffie-Hellman exponent is assembled from **two** sources
of randomness — the client's and the server's — so a weak generator on one side does not collapse the
whole strength. This is sound engineering against a real, not a paper, threat: a bad RNG on a mobile
device occurs more often than cryptanalysis of AES.

**Where MTProto is criticized.** Academic analysis points out that the classic scheme provides
neither authenticated encryption in the modern sense nor resistance to chosen-ciphertext attacks:
authentication is built as a hash of the plaintext, the padding length is not checked, and the order
and replay of messages were historically controlled by the server. Hence the well-known set of
complaints — length extension, manipulations of the last block, reordering and replay of messages,
timing leaks at the verification stage. Some were closed by protocol versions, but the price is client
incompatibility and slow spread of fixes.

The conclusion drawn from this: **what is dangerous is not "home-made cryptography" as such, but a
home-made gluing of primitives and home-made integrity guarantees.**

---

## 2. What Netrunner does

The channel is built in two steps and at each uses only standard, proven primitives — there is no
custom arithmetic in the project at all.

**Step one — session negotiation.** The parties exchange ephemeral public keys on an elliptic curve
and independently compute a shared secret. Additionally, each side mixes in its own random salt, and
both halves enter the key derivation — the same logic of two-sided randomization as in MTProto, but
simpler and without manual assembly.

The shared secret is **never used directly as a key**. It goes through a standard key derivation
function, which expands it into several cryptographically independent values: separate encryption
keys per direction and a separate authentication key. Compromising one tells nothing about the others,
and the mirroring of roles guarantees that one side's "write key" is the other side's "read key".

**Step two — the data stream.** Each unit of transmission is encrypted with a modern AEAD cipher:
confidentiality and integrity are provided by one primitive, in one operation, with an authentication
tag that is verified before the plaintext reaches the parser. Any modification of the bytes in the
channel — even one bit — causes decryption to fail, rather than a "nearly correct" result.

---

## 3. Why it is secure: five properties

### Forward secrecy for real, not in words

The session's private key is ephemeral and **spent exactly once**: the language and type structure do
not allow it to be reused — after the shared secret is computed it is physically no longer in the
object's memory. The practical meaning: traffic recorded by an observer today cannot be decrypted
tomorrow even with full access to the server. Each session has its own key pair; there is no portable
secret between sessions.

### Integrity and confidentiality — one primitive, not a home-made glue

This is where the main line of difference from historical MTProto runs. There integrity was built by
hand on top of the cipher, and analysis showed the glue leaks. Here the AEAD is used in its standard
mode: encryption and authentication are inseparable by construction. There is no separate "did the
plaintext hash match" check, no unchecked padding, no path by which distorted data would reach
parsing. A verification failure is not a parsing error but a channel teardown.

### Nonce uniqueness is structural, and ordering is a free consequence

The cipher's one-time value is **not transmitted over the network**: both sides compute it in lockstep
from the session's base material and their own counter, separate for each direction. Two effects
follow.

First: nonce reuse under one key — the only way to fatally break such a cipher — is excluded by
construction, not by runtime checks.

Second, and more important: **a skipped, duplicated or reordered message breaks decryption
immediately.** The sender's and receiver's counters must stay in step; any attempt to hold back,
reorder or replay data inside a session desynchronizes them and kills the channel. Exactly the class
of attacks that in MTProto had to be closed with protocol versions does not exist here as a
possibility — it is excluded by the shape of the construction.

### Session replay is cut off at the entrance

The previous property has a boundary: it protects *inside* an established session. An observer who
recorded traffic can try something else — replay it later as a new connection, to distinguish a proxy
from an ordinary web server by the server's reaction. This is a standard active-probing technique on
the part of DPI.

So the very first message — the one that opens the connection — carries a short authenticator bound to
time and to the parameters of this specific connection. It has no session keys yet, so it is built on
the node's long-term secret. A connection with a wrong authenticator gets not a refusal but the answer
of a real decoy site: the observer sees no distinguishable reaction. A small tolerance for clock skew
is provided; outside it the tag is invalid.

An honest boundary: there is no store of used tags, so a verbatim replay of a recorded first message
passes this check inside a short window (the adversary gets no keys from it). Inside an established
session, replay and reordering are cut off by the AEAD itself with a one-time-value counter. Details —
in [SECURITY_MODEL.md](SECURITY_MODEL.md).

### Verification runs in constant time

Timing leaks at the verification stage are one of the recorded complaints against MTProto, and this is
not a theoretical quibble: a millisecond difference between "rejected at once" and "rejected after a
full check" is a leak channel. Here the authenticator check **always** runs the full set of candidates
and compares bytes by accumulating the difference, with no early exit and no branching on an
intermediate result. The duration of the operation does not depend on what arrived or whether it
matched at all. This is recorded in the code as an invariant, not as a happy coincidence.

---

## 4. The second layer: indistinguishability

Everything above is about resistance to reading. But a blocking-circumvention system has a second,
independent task: **the observer must not realize that a tunnel is in front of them**. A cipher does
not help here — encrypted garbage looks like encrypted garbage.

The answer has three layers, and each covers its own sign:

- **Shape.** From the outside the connection is indistinguishable from an ordinary HTTPS session: both
  establishment and the subsequent stream fit the structure that DPI classifies as ordinary web
  traffic.
- **Fingerprint.** Looking like TLS is not enough — you must look like *someone's specific* browser.
  The session's first packet reproduces the fingerprint of popular browsers in full, including the
  order and content of elements: it is by this that modern systems tell a "browser" from a "home-made
  client pretending to be a browser".
- **Statistics.** Message lengths are also a signature. Every unit of transmission is padded with
  random padding, and record lengths are quantized along irregular boundaries, separate for each
  connection, which removes the correlation between the observed length and the real content. The
  padding is not blind: for large transfers it is disabled, because there it hides nothing and only
  cuts speed.

An essential detail: the padding sits **under** the encryption and **inside** the authentication zone.
It is not cosmetics on top of the channel — the observer can neither distinguish it from data nor cut
it off.

---

## 5. The model's boundaries — what is honestly not protected

This section is mandatory. A protocol that does not state its boundaries misleads more surely than a
weak protocol that does.

**A node authenticates itself only to someone who knows it in advance.** The client receives the
node's long-term public key in advance, over a separate, already trusted channel, and weaves it into
the key negotiation. An adversary wedged into the connection does not have this key, so they will not
get a shared secret with the client: node substitution is detected by the data simply not decrypting.
Nothing additional is transmitted over the wire — the long-term key does not appear in messages and
does not become a stable hook for an observer.

The boundary here is where the client gets this key: trust in the channel that delivers it is part of
the model. A device that was not given the key connects under the old scheme, without node
authentication, and is not protected from an adversary in the gap; a node can be switched to a mode
where such connections are rejected outright.

**This is not end-to-end.** The channel is protected between the client and the exit node; beyond the
node the traffic lives by its own rules. Everything that already went over HTTPS stays under its own
encryption all the way — but the very fact "the client contacted such-and-such" is visible to the exit
node. Trust in the node's operator is part of the model.

**The authenticator is tied to time.** So it depends on the clock. A device with a badly wrong time —
beyond the allowed tolerance — will not connect at all; this is a conspicuous failure, not a quiet
degradation of security.

**Strength is inherited from the primitives.** No cryptographic operation here is written in the
project: standard, audited implementations of common algorithms are used. This is deliberate — and it
also means the guarantees are no stronger than the algorithms themselves. What is custom in the scheme
is only the composition, and the composition is deliberately arranged not to create new assumptions.

---

## 6. The summary in one paragraph

Security rests not on the secrecy of the scheme but on four things: each session's keys are ephemeral
and unrecoverable after the fact; confidentiality and integrity are provided by one standard AEAD
primitive, not a home-made glue; the uniqueness of one-time values and the impossibility of replay are
ensured by the shape of the construction, not by checks; and everything that could leak through timing
is brought to constant time by an explicit invariant. The analysis of MTProto is useful precisely as a
reference point: its problems almost all grow out of hand-assembling integrity guarantees on top of a
cipher — and that path is not repeated here.

---

## Why there are no numbers here

This document describes properties, not bytes. Concrete sizes, offsets, constant values, key-derivation
labels and padding parameters are exactly the material from which DPI signatures are built. Resistance
to reading would not have suffered from their publication: it rests on keys, not on the secrecy of the
scheme. But indistinguishability — the second layer described above — relies in part on there being
nothing to look for. So the byte-level specification has been moved into a separate file —
[PROTOCOL.md](PROTOCOL.md); whether to publish it is the owner's decision.
