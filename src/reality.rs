//! REALITY client: a minimal TLS 1.3 client (X25519MLKEM768 / X25519, AES-128/256-GCM,
//! ChaCha20-Poly1305) with a Chrome-like ClientHello whose session ID carries REALITY's
//! authentication. Instead of a CA chain, the server proves itself with an ed25519
//! certificate whose signature is HMAC-SHA512(auth key, public key).
//!
//! Flow (mirrors Xray's client): one ephemeral X25519 key is used both for REALITY's
//! auth key (with the server's REALITY public key) and for the TLS key exchange.

use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use log::debug;
use ml_kem::kem::Decapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::util::BoxStream;

const MAX_RECORD: usize = 16384;
/// Version bytes Xray puts in the session ID (servers may enforce min/max client versions).
const CLIENT_VERSION: [u8; 3] = [1, 8, 24];

/// Parsed REALITY parameters.
#[derive(Debug, Clone)]
pub struct RealityOpts {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub server_name: String,
}

impl RealityOpts {
    /// `pbk`: the server's X25519 public key, base64url without padding (as Xray prints it);
    /// `sid`: short ID, up to 16 hex digits.
    pub fn parse(pbk: &str, sid: &str, server_name: &str) -> Result<Self> {
        use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
        let trimmed = pbk.trim().trim_end_matches('=');
        let key = URL_SAFE_NO_PAD.decode(trimmed).or_else(|_| STANDARD_NO_PAD.decode(trimmed)).map_err(|_| anyhow!("bad REALITY public key"))?;
        let public_key: [u8; 32] = key.try_into().map_err(|_| anyhow!("REALITY public key must be 32 bytes"))?;
        if sid.len() > 16 || !sid.len().is_multiple_of(2) {
            bail!("REALITY short id must be 0-16 hex digits, even length");
        }
        let mut short_id = [0u8; 8];
        let bytes = hex::decode(sid).map_err(|_| anyhow!("bad REALITY short id"))?;
        short_id[..bytes.len()].copy_from_slice(&bytes);
        if server_name.is_empty() {
            bail!("REALITY needs sni (the server name it impersonates)");
        }
        Ok(RealityOpts { public_key, short_id, server_name: server_name.to_string() })
    }
}

// ---------------------------------------------------------------- key schedule

/// The two hashes TLS 1.3 suites use.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Hash {
    Sha256,
    Sha384,
}

impl Hash {
    fn len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
        }
    }
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
        }
    }
    fn extract(self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
            Hash::Sha384 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
        }
    }
    fn expand(self, prk: &[u8], info: &[u8], out: &mut [u8]) {
        match self {
            Hash::Sha256 => Hkdf::<Sha256>::from_prk(prk).expect("prk length").expand(info, out),
            Hash::Sha384 => Hkdf::<Sha384>::from_prk(prk).expect("prk length").expand(info, out),
        }
        .expect("expand length")
    }
    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            Hash::Sha384 => {
                let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac key");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

fn expand_label(hash: Hash, secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let mut out = vec![0u8; len];
    hash.expand(secret, &info, &mut out);
    out
}

fn derive_secret(hash: Hash, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    expand_label(hash, secret, label, transcript_hash, hash.len())
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Suite {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20,
}

impl Suite {
    fn from_id(id: u16) -> Result<Self> {
        match id {
            0x1301 => Ok(Suite::Aes128Gcm),
            0x1302 => Ok(Suite::Aes256Gcm),
            0x1303 => Ok(Suite::Chacha20),
            other => bail!("server chose unexpected cipher suite {other:#06x}"),
        }
    }
    fn key_len(self) -> usize {
        match self {
            Suite::Aes128Gcm => 16,
            Suite::Aes256Gcm | Suite::Chacha20 => 32,
        }
    }
    fn hash(self) -> Hash {
        match self {
            Suite::Aes256Gcm => Hash::Sha384,
            _ => Hash::Sha256,
        }
    }
}

// Built once per connection and never moved on a hot path; boxing would only add an indirection.
#[allow(clippy::large_enum_variant)]
enum Aead2 {
    Aes(Aes128Gcm),
    Aes256(Aes256Gcm),
    Chacha(ChaCha20Poly1305),
}

/// One direction of record protection: AEAD, static IV and sequence number.
struct RecordCipher {
    aead: Aead2,
    iv: [u8; 12],
    seq: u64,
}

impl RecordCipher {
    fn new(suite: Suite, traffic_secret: &[u8]) -> Self {
        let key = expand_label(suite.hash(), traffic_secret, "key", b"", suite.key_len());
        let iv: [u8; 12] = expand_label(suite.hash(), traffic_secret, "iv", b"", 12).try_into().unwrap();
        let aead = match suite {
            Suite::Aes128Gcm => Aead2::Aes(Aes128Gcm::new_from_slice(&key).unwrap()),
            Suite::Aes256Gcm => Aead2::Aes256(Aes256Gcm::new_from_slice(&key).unwrap()),
            Suite::Chacha20 => Aead2::Chacha(ChaCha20Poly1305::new_from_slice(&key).unwrap()),
        };
        RecordCipher { aead, iv, seq: 0 }
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut n = self.iv;
        for (i, b) in self.seq.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= b;
        }
        self.seq += 1;
        n
    }

    /// Encrypts `data` of `content_type` into a complete TLS record.
    fn seal(&mut self, content_type: u8, data: &[u8]) -> Vec<u8> {
        let mut inner = Vec::with_capacity(data.len() + 1);
        inner.extend_from_slice(data);
        inner.push(content_type);
        let len = (inner.len() + 16) as u16;
        let header = [0x17, 0x03, 0x03, (len >> 8) as u8, len as u8];
        let n = self.nonce();
        let n = GenericArray::from_slice(&n);
        let payload = Payload { msg: &inner, aad: &header };
        let ct = match &self.aead {
            Aead2::Aes(c) => c.encrypt(n, payload),
            Aead2::Aes256(c) => c.encrypt(n, payload),
            Aead2::Chacha(c) => c.encrypt(n, payload),
        }
        .expect("aead encrypt");
        [header.as_slice(), &ct].concat()
    }

    /// Decrypts one record body; returns (inner content type, plaintext).
    fn open(&mut self, header: &[u8; 5], body: &[u8]) -> Result<(u8, Vec<u8>)> {
        let n = self.nonce();
        let n = GenericArray::from_slice(&n);
        let payload = Payload { msg: body, aad: header };
        let mut pt = match &self.aead {
            Aead2::Aes(c) => c.decrypt(n, payload),
            Aead2::Aes256(c) => c.decrypt(n, payload),
            Aead2::Chacha(c) => c.decrypt(n, payload),
        }
        .map_err(|_| anyhow!("TLS record decryption failed"))?;
        while pt.last() == Some(&0) {
            pt.pop();
        }
        let ty = pt.pop().ok_or_else(|| anyhow!("empty TLS record"))?;
        Ok((ty, pt))
    }
}

// ---------------------------------------------------------------- ClientHello

fn grease(rng: &mut impl RngCore) -> u16 {
    0x0a0a + 0x1010 * (rng.next_u32() % 16) as u16
}

fn ext(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

fn u16_list(items: &[u16]) -> Vec<u8> {
    let mut v = ((items.len() * 2) as u16).to_be_bytes().to_vec();
    for i in items {
        v.extend_from_slice(&i.to_be_bytes());
    }
    v
}

/// Offset of the 32-byte session ID inside the ClientHello handshake message.
const SESSION_ID_AT: usize = 4 + 2 + 32 + 1;

const X25519: u16 = 0x001d;
/// Hybrid post-quantum group; REALITY servers insist on a share for it ahead of X25519.
const X25519_MLKEM768: u16 = 0x11ec;
const MLKEM_EK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;

/// A Chrome-shaped ClientHello handshake message (type + length + body) with an all-zero
/// session ID, offering TLS 1.3 with X25519MLKEM768 and X25519 key shares (`mlkem_ek` is
/// the ML-KEM-768 encapsulation key; the hybrid share reuses the X25519 key, like Chrome).
fn client_hello(random: &[u8; 32], key_share: &[u8; 32], mlkem_ek: &[u8], server_name: &str) -> Vec<u8> {
    debug_assert_eq!(mlkem_ek.len(), MLKEM_EK_LEN);
    let mut rng = rand::thread_rng();
    let (g1, g2, g3, g4) = (grease(&mut rng), grease(&mut rng), grease(&mut rng), grease(&mut rng));
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(random);
    body.push(32);
    body.extend_from_slice(&[0u8; 32]);
    body.extend(u16_list(&[
        g1, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
        0x002f, 0x0035,
    ]));
    body.extend_from_slice(&[1, 0]);

    let mut exts = Vec::new();
    ext(&mut exts, g2, &[]);
    let name = server_name.as_bytes();
    let mut sni = ((name.len() + 3) as u16).to_be_bytes().to_vec();
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    ext(&mut exts, 0x0000, &sni);
    ext(&mut exts, 0x0017, &[]);
    ext(&mut exts, 0xff01, &[0]);
    ext(&mut exts, 0x000a, &u16_list(&[g3, X25519_MLKEM768, X25519, 0x0017, 0x0018]));
    ext(&mut exts, 0x000b, &[1, 0]);
    ext(&mut exts, 0x0023, &[]);
    ext(&mut exts, 0x0010, &[0x00, 0x0c, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']);
    ext(&mut exts, 0x0005, &[1, 0, 0, 0, 0]);
    ext(&mut exts, 0x000d, &u16_list(&[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]));
    ext(&mut exts, 0x0012, &[]);
    // compress_certificate (brotli), as Chrome: keeps the target's certificate flight small
    // enough for the REALITY server to mirror (it gives up past 17 KB).
    ext(&mut exts, 0x001b, &[2, 0x00, 0x02]);
    let mut shares = Vec::new();
    shares.extend_from_slice(&g3.to_be_bytes());
    shares.extend_from_slice(&[0, 1, 0]);
    shares.extend_from_slice(&X25519_MLKEM768.to_be_bytes());
    shares.extend_from_slice(&((mlkem_ek.len() + 32) as u16).to_be_bytes());
    shares.extend_from_slice(mlkem_ek);
    shares.extend_from_slice(key_share);
    shares.extend_from_slice(&X25519.to_be_bytes());
    shares.extend_from_slice(&32u16.to_be_bytes());
    shares.extend_from_slice(key_share);
    let mut ks = (shares.len() as u16).to_be_bytes().to_vec();
    ks.extend(shares);
    ext(&mut exts, 0x0033, &ks);
    ext(&mut exts, 0x002d, &[1, 1]);
    let mut versions = vec![6];
    for v in [g4, 0x0304, 0x0303] {
        versions.extend_from_slice(&v.to_be_bytes());
    }
    ext(&mut exts, 0x002b, &versions);
    // Like BoringSSL, never repeat the first GREASE extension: Go's parser (REALITY servers)
    // rejects duplicate extensions and the server then relays us to the real site.
    let mut g5 = grease(&mut rng);
    if g5 == g2 {
        g5 ^= 0x1010;
    }
    ext(&mut exts, g5, &[0]);

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend(exts);
    let mut msg = vec![0x01];
    msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    msg.extend(body);
    msg
}

/// Seals REALITY's 16-byte session ID plaintext into the hello's session ID field.
fn seal_session_id(hello: &mut [u8], random: &[u8; 32], auth_key: &[u8; 32], short_id: &[u8; 8], unix: u32) {
    let mut plain = [0u8; 16];
    plain[..3].copy_from_slice(&CLIENT_VERSION);
    plain[4..8].copy_from_slice(&unix.to_be_bytes());
    plain[8..].copy_from_slice(short_id);
    let aead = Aes256Gcm::new_from_slice(auth_key).expect("key length");
    // The AAD is the whole hello with the session ID still zero.
    let sealed = aead
        .encrypt(GenericArray::from_slice(&random[20..]), Payload { msg: &plain, aad: hello })
        .expect("aead encrypt");
    hello[SESSION_ID_AT..SESSION_ID_AT + 32].copy_from_slice(&sealed);
}

fn reality_auth_key(shared: &[u8; 32], random: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&random[..20]), shared).expand(b"REALITY", &mut key).expect("hkdf length");
    key
}

// ---------------------------------------------------------------- parsing

fn be16(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_be_bytes([*b.get(at).ok_or_else(short)?, *b.get(at + 1).ok_or_else(short)?]))
}

fn short() -> anyhow::Error {
    anyhow!("truncated TLS message")
}

/// From a ServerHello body: (cipher suite, key share group, server share).
fn parse_server_hello(body: &[u8]) -> Result<(u16, u16, Vec<u8>)> {
    const HRR: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11,
        0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
    ];
    if body.get(2..34) == Some(&HRR[..]) {
        bail!("server sent HelloRetryRequest (it doesn't accept X25519?)");
    }
    let sid_len = *body.get(34).ok_or_else(short)? as usize;
    let mut p = 35 + sid_len;
    let suite = be16(body, p)?;
    p += 3;
    let ext_end = p + 2 + be16(body, p)? as usize;
    p += 2;
    let (mut version, mut share) = (0u16, None);
    while p + 4 <= ext_end {
        let (kind, len) = (be16(body, p)?, be16(body, p + 2)? as usize);
        let data = body.get(p + 4..p + 4 + len).ok_or_else(short)?;
        match kind {
            0x002b => version = be16(data, 0)?,
            0x0033 => {
                let (group, len) = (be16(data, 0)?, be16(data, 2)? as usize);
                let want = match group {
                    X25519 => 32,
                    X25519_MLKEM768 => MLKEM_CT_LEN + 32,
                    other => bail!("server chose key share group {other:#06x}"),
                };
                if len != want {
                    bail!("bad key share length {len} for group {group:#06x}");
                }
                share = Some((group, data.get(4..4 + len).ok_or_else(short)?.to_vec()));
            }
            _ => {}
        }
        p += 4 + len;
    }
    if version != 0x0304 {
        bail!("server didn't negotiate TLS 1.3");
    }
    let (group, share) = share.ok_or_else(|| anyhow!("server sent no key share"))?;
    Ok((suite, group, share))
}

/// Reads one DER TLV at `at`; returns (tag, content range).
fn der(b: &[u8], at: usize) -> Result<(u8, usize, usize)> {
    let tag = *b.get(at).ok_or_else(short)?;
    let first = *b.get(at + 1).ok_or_else(short)? as usize;
    let (len, start) = if first < 0x80 {
        (first, at + 2)
    } else {
        let n = first & 0x7f;
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(at + 2 + i).ok_or_else(short)? as usize;
        }
        (len, at + 2 + n)
    };
    if start + len > b.len() {
        return Err(short());
    }
    Ok((tag, start, start + len))
}

/// From an X.509 certificate: (ed25519 public key, signature value).
fn cert_key_and_signature(cert: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    let (_, outer, _) = der(cert, 0)?;
    let (_, tbs_start, tbs_end) = der(cert, outer)?;
    let (_, _, alg_end) = der(cert, tbs_end)?;
    let (tag, sig_start, sig_end) = der(cert, alg_end)?;
    if tag != 0x03 || sig_end <= sig_start {
        bail!("certificate has no signature");
    }
    let signature = cert[sig_start + 1..sig_end].to_vec();
    let tbs = &cert[tbs_start..tbs_end];
    const ED25519_OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
    let oid = tbs.windows(5).position(|w| w == ED25519_OID).ok_or_else(|| anyhow!("certificate key isn't ed25519"))?;
    let bit = tbs[oid..].windows(3).position(|w| w == [0x03, 0x21, 0x00]).ok_or_else(|| anyhow!("no ed25519 key"))?;
    let at = oid + bit + 3;
    let key = <[u8; 32]>::try_from(tbs.get(at..at + 32).ok_or_else(short)?).unwrap();
    Ok((key, signature))
}

fn verify_reality_cert(cert: &[u8], auth_key: &[u8; 32]) -> Result<()> {
    // Without valid auth the server relays the real site, whose certificate isn't ed25519.
    let (key, signature) = cert_key_and_signature(cert)
        .map_err(|e| anyhow!("REALITY verification failed: {e} (got the real site's certificate? check public key, short id and sni)"))?;
    let mut m = <Hmac<Sha512> as Mac>::new_from_slice(auth_key).expect("hmac key");
    m.update(&key);
    if m.finalize().into_bytes().as_slice() != signature.as_slice() {
        bail!("REALITY verification failed: the server isn't a REALITY server for this key (check public key, short id and sni)");
    }
    Ok(())
}

// ---------------------------------------------------------------- handshake

async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> Result<([u8; 5], Vec<u8>)> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header).await.context("reading TLS record")?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_RECORD + 256 {
        bail!("TLS record too large");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok((header, body))
}

/// Splits complete handshake messages off the front of `buf`.
fn take_handshake(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    (buf.len() >= 4 + len).then(|| buf.drain(..4 + len).collect())
}

fn alert_text(body: &[u8]) -> String {
    match body.get(1) {
        Some(40) => "handshake_failure".into(),
        Some(42) => "bad_certificate".into(),
        Some(70) => "protocol_version".into(),
        Some(d) => format!("alert {d}"),
        None => "alert".into(),
    }
}

/// Runs the REALITY handshake over `stream` and returns the protected byte stream.
pub async fn connect(mut stream: BoxStream, opts: &RealityOpts) -> Result<BoxStream> {
    let r = handshake(&mut stream, opts).await?;
    Ok(protected_stream(stream, r.rx, r.tx))
}

/// The application-data protection of an established REALITY session.
pub struct RealityRecords {
    rx: RecordCipher,
    tx: RecordCipher,
}

impl crate::vision::RecordLayer for RealityRecords {
    fn seal(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(data.len() + 32);
        for chunk in data.chunks(MAX_RECORD) {
            out.extend(self.tx.seal(0x17, chunk));
        }
        Ok(out)
    }

    fn open(&mut self, record: &[u8]) -> std::io::Result<Option<Vec<u8>>> {
        let header: [u8; 5] = record[..5].try_into().unwrap();
        if header[0] == 0x14 {
            return Ok(Some(Vec::new()));
        }
        match self.rx.open(&header, &record[5..]) {
            Ok((0x17, data)) => Ok(Some(data)),
            Ok((0x16, _)) => Ok(Some(Vec::new())),
            Ok(_) => Ok(None),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())),
        }
    }

    fn close(&mut self) -> Vec<u8> {
        self.tx.seal(0x15, &[1, 0])
    }
}

/// Runs the REALITY handshake over `stream`, leaving it right after the client Finished.
pub async fn handshake(stream: &mut BoxStream, opts: &RealityOpts) -> Result<RealityRecords> {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);

    let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut rand::thread_rng());
    let mut hello = client_hello(&random, public.as_bytes(), mlkem_ek.as_bytes().as_slice(), &opts.server_name);
    let auth_shared = secret.diffie_hellman(&PublicKey::from(opts.public_key));
    let auth_key = reality_auth_key(auth_shared.as_bytes(), &random);
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as u32);
    seal_session_id(&mut hello, &random, &auth_key, &opts.short_id, unix);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    stream.write_all(&record).await?;
    stream.flush().await?;

    // Raw transcript; hashed on demand once the suite (and so the hash) is known.
    let mut transcript = hello.clone();

    // ServerHello (plaintext; may be preceded by nothing else).
    let mut hs_buf = Vec::new();
    let server_hello = loop {
        let (header, body) = read_record(stream).await?;
        match header[0] {
            0x16 => {
                hs_buf.extend(body);
                if let Some(msg) = take_handshake(&mut hs_buf) {
                    break msg;
                }
            }
            0x15 => bail!("server rejected the handshake ({})", alert_text(&body)),
            other => bail!("unexpected TLS record type {other} before ServerHello"),
        }
    };
    if server_hello[0] != 0x02 {
        bail!("expected ServerHello");
    }
    let (suite_id, group, server_share) = parse_server_hello(&server_hello[4..])?;
    let suite = Suite::from_id(suite_id)?;
    let hash = suite.hash();
    transcript.extend_from_slice(&server_hello);

    // X25519MLKEM768: the share is ML-KEM ciphertext then X25519; the secret is the
    // ML-KEM secret then the X25519 one.
    let x_share = <[u8; 32]>::try_from(&server_share[server_share.len() - 32..]).unwrap();
    let mut shared = Vec::with_capacity(64);
    if group == X25519_MLKEM768 {
        let ct = ml_kem::Ciphertext::<MlKem768>::try_from(&server_share[..MLKEM_CT_LEN]).map_err(|_| anyhow!("bad ML-KEM ciphertext"))?;
        let ss = mlkem_dk.decapsulate(&ct).map_err(|_| anyhow!("ML-KEM decapsulation failed"))?;
        shared.extend_from_slice(ss.as_slice());
    }
    shared.extend_from_slice(secret.diffie_hellman(&PublicKey::from(x_share)).as_bytes());
    let zeros = vec![0u8; hash.len()];
    let early = hash.extract(&zeros, &zeros);
    let empty_hash = hash.digest(b"");
    let hs_secret = hash.extract(&derive_secret(hash, &early, "derived", &empty_hash), &shared);
    let th = hash.digest(&transcript);
    let c_hs = derive_secret(hash, &hs_secret, "c hs traffic", &th);
    let s_hs = derive_secret(hash, &hs_secret, "s hs traffic", &th);
    let mut server_cipher = RecordCipher::new(suite, &s_hs);
    let mut client_cipher = RecordCipher::new(suite, &c_hs);

    // EncryptedExtensions, Certificate, CertificateVerify, Finished.
    let mut verified_cert = false;
    loop {
        let (header, body) = read_record(stream).await?;
        match header[0] {
            0x14 => continue,
            0x15 => bail!("server alert during handshake ({})", alert_text(&body)),
            0x17 => {}
            other => bail!("unexpected TLS record type {other} during handshake"),
        }
        let (ty, plain) = server_cipher.open(&header, &body)?;
        if ty != 0x16 {
            bail!("unexpected content type {ty} during handshake");
        }
        hs_buf.extend(plain);
        let mut finished = false;
        while let Some(msg) = take_handshake(&mut hs_buf) {
            match msg[0] {
                11 => {
                    let b = &msg[4..];
                    let ctx = *b.first().ok_or_else(short)? as usize;
                    let p = 1 + ctx + 3;
                    let len = u32::from_be_bytes([0, *b.get(p).ok_or_else(short)?, b[p + 1], b[p + 2]]) as usize;
                    let cert = b.get(p + 3..p + 3 + len).ok_or_else(short)?;
                    verify_reality_cert(cert, &auth_key)?;
                    verified_cert = true;
                }
                20 => {
                    let key = expand_label(hash, &s_hs, "finished", b"", hash.len());
                    let expect = hash.hmac(&key, &hash.digest(&transcript));
                    if msg[4..] != expect[..] {
                        bail!("server Finished doesn't verify");
                    }
                    finished = true;
                }
                _ => {}
            }
            transcript.extend_from_slice(&msg);
            if finished {
                break;
            }
        }
        if finished {
            break;
        }
    }
    if !verified_cert {
        bail!("server sent no certificate");
    }

    let th_server_fin = hash.digest(&transcript);
    let master = hash.extract(&derive_secret(hash, &hs_secret, "derived", &empty_hash), &zeros);
    let c_ap = derive_secret(hash, &master, "c ap traffic", &th_server_fin);
    let s_ap = derive_secret(hash, &master, "s ap traffic", &th_server_fin);

    let verify = hash.hmac(&expand_label(hash, &c_hs, "finished", b"", hash.len()), &th_server_fin);
    let mut fin = vec![20, 0, 0, verify.len() as u8];
    fin.extend(verify);
    let mut out = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    out.extend(client_cipher.seal(0x16, &fin));
    stream.write_all(&out).await?;
    stream.flush().await?;
    debug!("REALITY handshake with {} done ({suite:?}, group {group:#06x})", opts.server_name);

    if !hs_buf.is_empty() {
        debug!("REALITY: {} stray handshake bytes after Finished", hs_buf.len());
    }
    Ok(RealityRecords { rx: RecordCipher::new(suite, &s_ap), tx: RecordCipher::new(suite, &c_ap) })
}

/// Bridges the TLS application-data records to a plain byte stream.
fn protected_stream(stream: BoxStream, mut rx: RecordCipher, mut tx: RecordCipher) -> BoxStream {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let (app, inner) = tokio::io::duplex(64 * 1024);
    let (mut ird, mut iwr) = tokio::io::split(inner);
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_RECORD];
        loop {
            let n = match ird.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if wr.write_all(&tx.seal(0x17, &buf[..n])).await.is_err() {
                return;
            }
        }
        let _ = wr.write_all(&tx.seal(0x15, &[1, 0])).await; // close_notify
        let _ = wr.shutdown().await;
    });
    tokio::spawn(async move {
        loop {
            let (header, body) = match read_record(&mut rd).await {
                Ok(r) => r,
                Err(_) => break,
            };
            if header[0] == 0x14 {
                continue;
            }
            match rx.open(&header, &body) {
                Ok((0x17, data)) => {
                    if iwr.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok((0x16, _)) => {} // NewSessionTicket etc.
                Ok((0x15, _)) | Ok(_) | Err(_) => break,
            }
        }
        let _ = iwr.shutdown().await;
    });
    Box::new(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8448 "Simple 1-RTT Handshake": handshake secrets from the shared X25519 secret.
    #[test]
    fn key_schedule_matches_rfc8448() {
        let shared = hex::decode("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d").unwrap();
        let h = Hash::Sha256;
        let early = h.extract(&[0u8; 32], &[0u8; 32]);
        assert_eq!(hex::encode(&early), "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        let empty = h.digest(b"");
        let derived = derive_secret(h, &early, "derived", &empty);
        assert_eq!(hex::encode(&derived), "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        let hs = h.extract(&derived, &shared);
        assert_eq!(hex::encode(hs), "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac");
    }

    #[test]
    fn hello_shape_and_session_id_sealing() {
        let random = [7u8; 32];
        let share = [9u8; 32];
        let mut hello = client_hello(&random, &share, &[4u8; MLKEM_EK_LEN], "www.example.com");
        assert_eq!(hello[0], 1);
        assert_eq!(u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize, hello.len() - 4);
        assert!(hello[SESSION_ID_AT..SESSION_ID_AT + 32].iter().all(|b| *b == 0));
        assert!(hello.windows(15).any(|w| w == b"www.example.com"));
        // The hybrid share (1216 bytes) comes before the plain X25519 one.
        let hybrid = hello.windows(4).position(|w| w == [0x11, 0xec, 0x04, 0xc0]).unwrap();
        let plain = hello.windows(4).position(|w| w == [0x00, 0x1d, 0x00, 0x20]).unwrap();
        assert!(hybrid < plain);
        // Go's TLS parser (REALITY servers) rejects duplicate extensions, so the two GREASE
        // extensions must never collide.
        for _ in 0..500 {
            let h = client_hello(&random, &share, &[4u8; MLKEM_EK_LEN], "www.example.com");
            let mut p = SESSION_ID_AT + 32;
            p += 2 + be16(&h, p).unwrap() as usize; // cipher suites
            p += 1 + h[p] as usize; // compression methods
            let end = p + 2 + be16(&h, p).unwrap() as usize;
            p += 2;
            let mut seen = std::collections::HashSet::new();
            while p < end {
                assert!(seen.insert(be16(&h, p).unwrap()), "duplicate extension in ClientHello");
                p += 4 + be16(&h, p + 2).unwrap() as usize;
            }
            assert_eq!(p, end);
        }
        assert_eq!(&hello[hybrid + 4 + MLKEM_EK_LEN..hybrid + 4 + MLKEM_EK_LEN + 32], &share);
        let zeroed = hello.clone();
        let key = [3u8; 32];
        seal_session_id(&mut hello, &random, &key, &[0xab; 8], 1_700_000_000);
        // The server reverses this with the same key, nonce and the zeroed hello as AAD.
        let sid = &hello[SESSION_ID_AT..SESSION_ID_AT + 32];
        let plain = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(GenericArray::from_slice(&random[20..]), Payload { msg: sid, aad: &zeroed })
            .unwrap();
        assert_eq!(&plain[..3], &CLIENT_VERSION);
        assert_eq!(&plain[4..8], &1_700_000_000u32.to_be_bytes());
        assert_eq!(&plain[8..], &[0xab; 8]);
    }

    #[test]
    fn record_roundtrip() {
        for suite in [Suite::Aes128Gcm, Suite::Aes256Gcm, Suite::Chacha20] {
            let secret = vec![5u8; suite.hash().len()];
            let (mut a, mut b) = (RecordCipher::new(suite, &secret), RecordCipher::new(suite, &secret));
            for msg in [&b"hello"[..], &[0u8; 0][..], &[1u8; 16000][..]] {
                let rec = a.seal(0x17, msg);
                let header: [u8; 5] = rec[..5].try_into().unwrap();
                assert_eq!(b.open(&header, &rec[5..]).unwrap(), (0x17, msg.to_vec()));
            }
        }
    }

    #[test]
    fn options() {
        let o = RealityOpts::parse("9I6Pn-IkB7bhN8WjQWdKJhwFS7VS9qGcApt5SmR43G4", "6ba85179e30d4fc2", "www.microsoft.com").unwrap();
        assert_eq!(o.short_id, [0x6b, 0xa8, 0x51, 0x79, 0xe3, 0x0d, 0x4f, 0xc2]);
        assert_eq!(RealityOpts::parse("9I6Pn-IkB7bhN8WjQWdKJhwFS7VS9qGcApt5SmR43G4", "ab", "x").unwrap().short_id[..2], [0xab, 0]);
        assert!(RealityOpts::parse("short", "", "x").is_err());
        assert!(RealityOpts::parse("9I6Pn-IkB7bhN8WjQWdKJhwFS7VS9qGcApt5SmR43G4", "abc", "x").is_err());
    }
}
