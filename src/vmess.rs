//! VMess client with AEAD headers (alterId 0) or legacy MD5/AES-CFB headers (alterId > 0),
//! chunk stream + length masking,
//! body security aes-128-gcm or chacha20-poly1305, over any stream transport (TCP, TLS, WebSocket).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::ChaCha20Poly1305;
use log::debug;
use md5::{Digest, Md5};
use rand::RngCore;
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::transport::Transport;
use crate::udp::{write_port_addr, UdpPipe};
use crate::util::{BoxStream, Target};
use crate::vless::parse_uuid;

const TAG: usize = 16;
const MAX_PAYLOAD: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Security {
    Aes128Gcm,
    Chacha20Poly1305,
}

impl Security {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "auto" | "aes-128-gcm" => Security::Aes128Gcm,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Security::Chacha20Poly1305,
            _ => bail!("unsupported vmess encrypt-method {s:?} (supported: auto, aes-128-gcm, chacha20-poly1305)"),
        })
    }

    fn id(self) -> u8 {
        match self {
            Security::Aes128Gcm => 0x03,
            Security::Chacha20Poly1305 => 0x04,
        }
    }
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

/// HMAC nested over HMAC: `keys[0]` wraps SHA-256, each later key wraps the previous HMAC.
fn nested_hmac(keys: &[&[u8]], parts: &[&[u8]]) -> [u8; 32] {
    let Some((key, inner)) = keys.split_last() else { return sha256(parts) };
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&nested_hmac(inner, &[key]));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut first: Vec<&[u8]> = vec![&ipad];
    first.extend_from_slice(parts);
    let inner_sum = nested_hmac(inner, &first);
    nested_hmac(inner, &[&opad, &inner_sum])
}

/// VMess AEAD KDF.
fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = vec![b"VMess AEAD KDF"];
    keys.extend_from_slice(path);
    nested_hmac(&keys, &[key])
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().unwrap()
}

fn gcm_seal(key: &[u8; 16], iv: &[u8], msg: &[u8], aad: &[u8]) -> Vec<u8> {
    Aes128Gcm::new(key.into()).encrypt(GenericArray::from_slice(&iv[..12]), Payload { msg, aad }).expect("aead encrypt")
}

fn gcm_open(key: &[u8; 16], iv: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    Aes128Gcm::new(key.into())
        .decrypt(GenericArray::from_slice(&iv[..12]), Payload { msg, aad: b"" })
        .map_err(|_| anyhow!("vmess: response header decryption failed (wrong uuid?)"))
}

fn auth_id(cmd_key: &[u8; 16], unix: u64) -> [u8; 16] {
    use aes::cipher::BlockEncrypt;
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&unix.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut buf[8..12]);
    let crc = crc32fast::hash(&buf[..12]);
    buf[12..].copy_from_slice(&crc.to_be_bytes());
    let cipher = Aes128::new(&kdf16(cmd_key, &[b"AES Auth ID Encryption"]).into());
    let mut block = GenericArray::clone_from_slice(&buf);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// `auth_id | sealed(len) | nonce | sealed(header)`.
fn seal_header(cmd_key: &[u8; 16], header: &[u8]) -> Vec<u8> {
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let id = auth_id(cmd_key, unix);
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let path = |label: &'static [u8]| -> [&[u8]; 3] { [label, &id, &nonce] };
    let len_key = kdf16(cmd_key, &path(b"VMess Header AEAD Key_Length"));
    let len_iv = kdf(cmd_key, &path(b"VMess Header AEAD Nonce_Length"));
    let key = kdf16(cmd_key, &path(b"VMess Header AEAD Key"));
    let iv = kdf(cmd_key, &path(b"VMess Header AEAD Nonce"));
    let mut out = id.to_vec();
    out.extend(gcm_seal(&len_key, &len_iv, &(header.len() as u16).to_be_bytes(), &id));
    out.extend_from_slice(&nonce);
    out.extend(gcm_seal(&key, &iv, header, &id));
    out
}

/// AES-128-CFB (full-block feedback), used by the legacy header.
struct Cfb {
    cipher: Aes128,
    reg: [u8; 16],
    ks: [u8; 16],
    pos: usize,
}

impl Cfb {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Cfb { cipher: Aes128::new(key.into()), reg: *iv, ks: [0; 16], pos: 0 }
    }

    fn apply(&mut self, data: &mut [u8], decrypt: bool) {
        use aes::cipher::BlockEncrypt;
        for b in data {
            if self.pos == 0 {
                let mut block = GenericArray::clone_from_slice(&self.reg);
                self.cipher.encrypt_block(&mut block);
                self.ks.copy_from_slice(&block);
            }
            let c = if decrypt { *b } else { *b ^ self.ks[self.pos] };
            *b ^= self.ks[self.pos];
            self.reg[self.pos] = c;
            self.pos = (self.pos + 1) % 16;
        }
    }
}

/// Legacy (alterId > 0): `HMAC-MD5(uuid, t) | AES-CFB(cmd_key, MD5(t x4), header)`.
fn seal_header_legacy(uuid: &[u8; 16], cmd_key: &[u8; 16], header: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let t = (now + (rand::thread_rng().next_u32() % 61) as u64).saturating_sub(30).to_be_bytes();
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(uuid).expect("any key length");
    Mac::update(&mut mac, &t);
    let mut out = mac.finalize().into_bytes().to_vec();
    let iv: [u8; 16] = Md5::digest([t, t, t, t].concat()).into();
    let mut enc = header.to_vec();
    Cfb::new(cmd_key, &iv).apply(&mut enc, false);
    out.extend(enc);
    out
}

fn fnv1a32(data: &[u8]) -> u32 {
    data.iter().fold(0x811c9dc5u32, |h, b| (h ^ *b as u32).wrapping_mul(0x01000193))
}

fn request_header(sec: Security, key: &[u8; 16], iv: &[u8; 16], resp_v: u8, cmd: u8, target: Option<&Target>) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let padding = (rng.next_u32() % 16) as usize;
    let mut h = Vec::with_capacity(64 + padding);
    h.push(1);
    h.extend_from_slice(iv);
    h.extend_from_slice(key);
    h.push(resp_v);
    h.push(0x01 | 0x04); // chunk stream + chunk length masking
    h.push(((padding as u8) << 4) | sec.id());
    h.push(0);
    h.push(cmd);
    // Mux (XUDP) requests carry no address.
    if let Some(t) = target {
        write_port_addr(t, &mut h)?;
    }
    let mut pad = vec![0u8; padding];
    rng.fill_bytes(&mut pad);
    h.extend_from_slice(&pad);
    let f = fnv1a32(&h);
    h.extend_from_slice(&f.to_be_bytes());
    Ok(h)
}

// Built once per connection and never moved on a hot path; boxing would only add an indirection.
#[allow(clippy::large_enum_variant)]
enum BodyCipher {
    Aes(Aes128Gcm),
    Chacha(ChaCha20Poly1305),
}

/// One direction of the body: AEAD with `count || iv[2..12]` nonces, SHAKE128 length masks.
struct BodyState {
    cipher: BodyCipher,
    iv: [u8; 16],
    count: u16,
    mask: sha3::Shake128Reader,
}

impl BodyState {
    fn new(sec: Security, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let cipher = match sec {
            Security::Aes128Gcm => BodyCipher::Aes(Aes128Gcm::new(key.into())),
            Security::Chacha20Poly1305 => {
                let k1: [u8; 16] = Md5::digest(key).into();
                let k2: [u8; 16] = Md5::digest(k1).into();
                let full: Vec<u8> = [k1, k2].concat();
                BodyCipher::Chacha(ChaCha20Poly1305::new_from_slice(&full).expect("key length"))
            }
        };
        let mut shake = Shake128::default();
        Update::update(&mut shake, iv);
        BodyState { cipher, iv: *iv, count: 0, mask: shake.finalize_xof() }
    }

    fn next_mask(&mut self) -> u16 {
        let mut m = [0u8; 2];
        self.mask.read(&mut m);
        u16::from_be_bytes(m)
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&self.count.to_be_bytes());
        n[2..].copy_from_slice(&self.iv[2..12]);
        self.count = self.count.wrapping_add(1);
        n
    }

    fn seal_chunk(&mut self, data: &[u8], out: &mut Vec<u8>) {
        let n = self.nonce();
        let n = GenericArray::from_slice(&n);
        let sealed = match &self.cipher {
            BodyCipher::Aes(c) => c.encrypt(n, data),
            BodyCipher::Chacha(c) => c.encrypt(n, data),
        }
        .expect("aead encrypt");
        let len = sealed.len() as u16 ^ self.next_mask();
        out.extend_from_slice(&len.to_be_bytes());
        out.extend(sealed);
    }

    fn open_chunk(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let n = self.nonce();
        let n = GenericArray::from_slice(&n);
        match &self.cipher {
            BodyCipher::Aes(c) => c.decrypt(n, data),
            BodyCipher::Chacha(c) => c.decrypt(n, data),
        }
        .map_err(|_| anyhow!("vmess: body decryption failed"))
    }
}

struct Session {
    sec: Security,
    key: [u8; 16],
    iv: [u8; 16],
    resp_key: [u8; 16],
    resp_iv: [u8; 16],
    resp_v: u8,
    legacy: bool,
}

impl Session {
    fn new(sec: Security, legacy: bool) -> Self {
        let mut rng = rand::thread_rng();
        let (mut key, mut iv) = ([0u8; 16], [0u8; 16]);
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);
        // Legacy derives the response key/IV with MD5, AEAD with SHA-256.
        let derive = |x: &[u8; 16]| -> [u8; 16] { if legacy { Md5::digest(x).into() } else { sha256(&[x])[..16].try_into().unwrap() } };
        Session { sec, key, iv, resp_key: derive(&key), resp_iv: derive(&iv), resp_v: (rng.next_u32() & 0xff) as u8, legacy }
    }
}

async fn encrypt_loop<R, W>(sess_sec: Security, key: [u8; 16], iv: [u8; 16], head: Vec<u8>, mut src: R, mut dst: W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut st = BodyState::new(sess_sec, &key, &iv);
    dst.write_all(&head).await?;
    let mut buf = vec![0u8; MAX_PAYLOAD];
    let mut out = Vec::with_capacity(MAX_PAYLOAD + 32);
    loop {
        let n = src.read(&mut buf).await?;
        out.clear();
        st.seal_chunk(&buf[..n], &mut out); // an empty chunk marks end of stream
        dst.write_all(&out).await?;
        // Flush a lone UDP request before waiting for the next request or EOF.
        dst.flush().await?;
        if n == 0 {
            break;
        }
    }
    dst.flush().await?;
    Ok(())
}

async fn read_response_header<R: AsyncRead + Unpin>(sess: &Session, src: &mut R) -> Result<()> {
    if sess.legacy {
        // `resp_v | opt | cmd | cmd_len | cmd...` under AES-CFB.
        let mut cfb = Cfb::new(&sess.resp_key, &sess.resp_iv);
        let mut head = [0u8; 4];
        src.read_exact(&mut head).await?;
        cfb.apply(&mut head, true);
        if head[0] != sess.resp_v {
            bail!("vmess: response auth mismatch (wrong uuid or alterId?)");
        }
        let mut cmd = vec![0u8; head[3] as usize];
        src.read_exact(&mut cmd).await?;
        return Ok(());
    }
    let len_key = kdf16(&sess.resp_key, &[b"AEAD Resp Header Len Key"]);
    let len_iv = kdf(&sess.resp_iv, &[b"AEAD Resp Header Len IV"]);
    let mut enc_len = [0u8; 2 + TAG];
    src.read_exact(&mut enc_len).await?;
    let len = gcm_open(&len_key, &len_iv, &enc_len)?;
    let len = u16::from_be_bytes([len[0], len[1]]) as usize;
    let key = kdf16(&sess.resp_key, &[b"AEAD Resp Header Key"]);
    let iv = kdf(&sess.resp_iv, &[b"AEAD Resp Header IV"]);
    let mut enc = vec![0u8; len + TAG];
    src.read_exact(&mut enc).await?;
    let head = gcm_open(&key, &iv, &enc)?;
    if head.first() != Some(&sess.resp_v) {
        bail!("vmess: response auth mismatch");
    }
    Ok(())
}

/// Next chunk's plaintext, or `None` at end of stream (EOF or the empty end chunk).
async fn read_chunk<R: AsyncRead + Unpin>(st: &mut BodyState, src: &mut R) -> Result<Option<Vec<u8>>> {
    let mut l = [0u8; 2];
    match src.read_exact(&mut l).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = (u16::from_be_bytes(l) ^ st.next_mask()) as usize;
    if len < TAG {
        bail!("vmess: bad chunk length");
    }
    let mut buf = vec![0u8; len];
    src.read_exact(&mut buf).await?;
    let data = st.open_chunk(&buf)?;
    Ok((!data.is_empty()).then_some(data))
}

async fn decrypt_loop<R, W>(sess: Session, mut src: R, mut dst: W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    read_response_header(&sess, &mut src).await?;
    let mut st = BodyState::new(sess.sec, &sess.resp_key, &sess.resp_iv);
    while let Some(data) = read_chunk(&mut st, &mut src).await? {
        dst.write_all(&data).await?;
    }
    dst.shutdown().await?;
    Ok(())
}

pub struct VmessServer {
    /// Set for legacy (alterId > 0) servers.
    legacy_uuid: Option<[u8; 16]>,
    cmd_key: [u8; 16],
    sec: Security,
    transport: Arc<Transport>,
}

impl VmessServer {
    /// With `alter_id > 0` the legacy header is used, authenticated with the primary id (which
    /// servers accept alongside the derived alter ids).
    pub fn new(transport: Transport, uuid: &str, method: &str, alter_id: u16) -> Result<Self> {
        let id = parse_uuid(uuid)?;
        let mut h = Md5::new();
        Digest::update(&mut h, id);
        Digest::update(&mut h, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        Ok(VmessServer {
            legacy_uuid: (alter_id > 0).then_some(id),
            cmd_key: h.finalize().into(),
            sec: Security::parse(method)?,
            transport: Arc::new(transport),
        })
    }

    /// UDP is XUDP over a Mux (cmd 3) request, so one connection reaches any number of remotes.
    pub fn open_udp(&self, target: &Target) -> UdpPipe {
        let (legacy, cmd_key, sec, transport) = (self.legacy_uuid, self.cmd_key, self.sec, self.transport.clone());
        crate::udp::xudp(target, move |first| async move {
            let mut s = connect_cmd(legacy, &cmd_key, sec, &transport, 3, None).await?;
            s.write_all(&first).await?;
            Ok(s)
        })
    }

    pub async fn connect(&self, target: &Target) -> Result<BoxStream> {
        connect_cmd(self.legacy_uuid, &self.cmd_key, self.sec, &self.transport, 1, Some(target)).await
    }
}

async fn connect_cmd(
    legacy: Option<[u8; 16]>,
    cmd_key: &[u8; 16],
    sec: Security,
    transport: &Transport,
    cmd: u8,
    target: Option<&Target>,
) -> Result<BoxStream> {
    let stream = transport.connect().await?;
    let sess = Session::new(sec, legacy.is_some());
    let header = request_header(sess.sec, &sess.key, &sess.iv, sess.resp_v, cmd, target)?;
    let head = match &legacy {
        Some(uuid) => seal_header_legacy(uuid, cmd_key, &header),
        None => seal_header(cmd_key, &header),
    };
    let (rd, wr) = tokio::io::split(stream);
    let (app, inner) = tokio::io::duplex(64 * 1024);
    let (ird, iwr) = tokio::io::split(inner);
    let (sec, key, iv) = (sess.sec, sess.key, sess.iv);
    tokio::spawn(async move {
        if let Err(e) = encrypt_loop(sec, key, iv, head, ird, wr).await {
            debug!("vmess upstream closed: {e:#}");
        }
    });
    tokio::spawn(async move {
        if let Err(e) = decrypt_loop(sess, rd, iwr).await {
            debug!("vmess downstream closed: {e:#}");
        }
    });
    Ok(Box::new(app))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_layer_matches_rfc4231() {
        // One layer over SHA-256 is plain HMAC-SHA256 (RFC 4231 test case 2).
        let mac = nested_hmac(&[b"Jefe"], &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(hex::encode(mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn cfb_matches_nist() {
        // NIST SP 800-38A F.3.13, CFB128-AES128.Encrypt, first two blocks.
        let key: [u8; 16] = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap().try_into().unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap().try_into().unwrap();
        let plain = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51").unwrap();
        let mut data = plain.clone();
        let mut enc = Cfb::new(&key, &iv);
        enc.apply(&mut data[..5], false);
        enc.apply(&mut data[5..], false);
        assert_eq!(hex::encode(&data), "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b");
        Cfb::new(&key, &iv).apply(&mut data, true);
        assert_eq!(data, plain);
    }

    #[test]
    fn fnv() {
        assert_eq!(fnv1a32(b""), 0x811c9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c292c);
    }

    /// Server-side AEAD request reader, including authentication and the addressless
    /// Mux command. Tests use the public open_udp path, not a pre-negotiated stream.
    async fn mock_mux_session(wire: &mut BoxStream, cmd_key: &[u8; 16], sec: Security) -> Session {
        let mut prefix = [0u8; 42]; // AuthID, sealed length, nonce
        wire.read_exact(&mut prefix).await.unwrap();
        let (id, nonce) = (&prefix[..16], &prefix[34..]);
        let open = |label_key: &'static [u8], label_iv: &'static [u8], data: &[u8]| {
            let key = kdf16(cmd_key, &[label_key, id, nonce]);
            let iv = kdf(cmd_key, &[label_iv, id, nonce]);
            Aes128Gcm::new((&key).into()).decrypt(GenericArray::from_slice(&iv[..12]), Payload { msg: data, aad: id }).unwrap()
        };
        let len = open(b"VMess Header AEAD Key_Length", b"VMess Header AEAD Nonce_Length", &prefix[16..34]);
        let mut enc = vec![0; u16::from_be_bytes(len.try_into().unwrap()) as usize + TAG];
        wire.read_exact(&mut enc).await.unwrap();
        let head = open(b"VMess Header AEAD Key", b"VMess Header AEAD Nonce", &enc);
        assert_eq!(head[0], 1);
        assert_eq!(&head[34..38], &[5, (head[35] & 0xf0) | sec.id(), 0, 3]);
        assert_eq!(head.len(), 38 + (head[35] >> 4) as usize + 4, "Mux request must have no target address");
        let end = head.len() - 4;
        assert_eq!(&head[end..], &fnv1a32(&head[..end]).to_be_bytes());
        let key: [u8; 16] = head[17..33].try_into().unwrap();
        let iv: [u8; 16] = head[1..17].try_into().unwrap();
        let sess = Session {
            sec, key, iv, resp_v: head[33], legacy: false,
            resp_key: sha256(&[&key])[..16].try_into().unwrap(),
            resp_iv: sha256(&[&iv])[..16].try_into().unwrap(),
        };
        let response = [sess.resp_v, 0, 0, 0];
        let mut sealed = gcm_seal(
            &kdf16(&sess.resp_key, &[b"AEAD Resp Header Len Key"]),
            &kdf(&sess.resp_iv, &[b"AEAD Resp Header Len IV"]),
            &(response.len() as u16).to_be_bytes(), b"",
        );
        sealed.extend(gcm_seal(
            &kdf16(&sess.resp_key, &[b"AEAD Resp Header Key"]),
            &kdf(&sess.resp_iv, &[b"AEAD Resp Header IV"]), &response, b"",
        ));
        wire.write_all(&sealed).await.unwrap();
        sess
    }

    async fn mock_xudp_packet(wire: &mut BoxStream, state: &mut BodyState, pending: &mut Vec<u8>, first: bool) -> crate::udp::Packet {
        // A datagram may span VMess chunks; chunk boundaries are not UDP boundaries.
        let mut needed = 2;
        while pending.len() < needed {
            pending.extend(read_chunk(state, wire).await.unwrap().expect("UDP stream closed before reply"));
        }
        let meta_len = u16::from_be_bytes(pending[..2].try_into().unwrap()) as usize;
        needed = 2 + meta_len + 2;
        while pending.len() < needed {
            pending.extend(read_chunk(state, wire).await.unwrap().unwrap());
        }
        assert_eq!(&pending[2..7], &[0, 0, if first { 1 } else { 2 }, 1, 2]);
        let (addr, used) = crate::udp::parse_port_addr(&pending[7..2 + meta_len]).unwrap();
        assert_eq!(meta_len, 5 + used + if first { 8 } else { 0 });
        if first { assert_eq!(&pending[7 + used..2 + meta_len], &[0; 8]); }
        let size = u16::from_be_bytes(pending[needed - 2..needed].try_into().unwrap()) as usize;
        let start = needed;
        needed += size;
        while pending.len() < needed {
            pending.extend(read_chunk(state, wire).await.unwrap().unwrap());
        }
        let data = pending[start..needed].to_vec();
        pending.drain(..needed);
        crate::udp::Packet { addr, data }
    }

    #[tokio::test]
    async fn udp_roundtrip_keeps_one_vmess_connection() {
        use crate::udp::Packet;
        use tokio::sync::mpsc;

        for method in ["aes-128-gcm", "chacha20-poly1305"] {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let (listener, mut incoming) = mpsc::unbounded_channel();
                let transport = Transport::new("mock".into(), 1, false, None, false, None).unwrap().with_test_wire(listener);
                let vmess = VmessServer::new(transport, "b831381d-6324-4d53-ad4f-8cda48b30811", method, 0).unwrap();
                let targets = [Target::new("stun.example", 19302), Target::new("1.2.3.4", 3478), Target::new("2001:db8::1", 53)];
                let payloads = [vec![1; 20], vec![2; MAX_PAYLOAD + 100], b"third request".to_vec()];
                let source = Target::new("2001:db8::2", 19302);
                let mut pipe = vmess.open_udp(&targets[0]);
                let (cmd_key, sec) = (vmess.cmd_key, vmess.sec);
                let server_targets = targets.clone();
                let server_payloads = payloads.clone();
                let server_source = source.clone();
                let server = tokio::spawn(async move {
                    let mut wire = incoming.recv().await.unwrap();
                    let sess = mock_mux_session(&mut wire, &cmd_key, sec).await;
                    let mut up = BodyState::new(sec, &sess.key, &sess.iv);
                    let mut down = BodyState::new(sec, &sess.resp_key, &sess.resp_iv);
                    let mut pending = Vec::new();
                    for i in 0..3 {
                        let packet = mock_xudp_packet(&mut wire, &mut up, &mut pending, i == 0).await;
                        assert_eq!(packet.addr.to_string(), server_targets[i].to_string());
                        assert_eq!(packet.data, server_payloads[i]);
                        // Xray sends Keep frames, optionally with a source address.
                        let mut meta = vec![0, 0, 2, 1];
                        if i != 2 {
                            meta.push(2);
                            write_port_addr(&server_source, &mut meta).unwrap();
                        }
                        let mut reply = (meta.len() as u16).to_be_bytes().to_vec();
                        reply.extend(meta);
                        reply.extend_from_slice(&(packet.data.len() as u16).to_be_bytes());
                        reply.extend_from_slice(&packet.data);
                        // KeepAlive before a reply, and metadata split over body chunks.
                        let mut frames = vec![0, 4, 0, 0, 4, 0];
                        frames.extend(reply);
                        for part in frames.chunks(7) {
                            let mut encrypted = Vec::new();
                            down.seal_chunk(part, &mut encrypted);
                            wire.write_all(&encrypted).await.unwrap();
                        }
                        assert!(incoming.try_recv().is_err(), "one connection per association");
                    }
                    // Remote End closes the association after all replies.
                    let mut end = Vec::new();
                    down.seal_chunk(&[0, 4, 0, 0, 3, 0], &mut end);
                    wire.write_all(&end).await.unwrap();
                });
                for i in 0..3 {
                    pipe.tx.send(Packet { addr: targets[i].clone(), data: payloads[i].clone() }).await.unwrap();
                    // Wait for each reply before sending again: a request must be flushed
                    // and the connection must stay open while the peer is silent.
                    let reply = pipe.rx.recv().await.expect("UDP association closed early");
                    assert_eq!(reply.data, payloads[i]);
                    assert_eq!(reply.addr.to_string(), if i == 2 { &targets[0] } else { &source }.to_string());
                }
                assert!(pipe.rx.recv().await.is_none());
                server.await.unwrap();
            }).await.expect("VMess UDP round trip timed out");
        }
    }

    #[tokio::test]
    async fn udp_chunk_is_flushed_before_next_request_or_eof() {
        let (mut app, input) = tokio::io::duplex(4096);
        let (wire, mut server) = tokio::io::duplex(4096);
        let key = [7; 16];
        let iv = [9; 16];
        let task = tokio::spawn(encrypt_loop(Security::Aes128Gcm, key, iv, Vec::new(), input, tokio::io::BufWriter::new(wire)));
        let frame = crate::udp::xudp_frame(true, &Target::new("stun.example", 19302), b"stun request").unwrap();
        app.write_all(&frame).await.unwrap();
        let mut state = BodyState::new(Security::Aes128Gcm, &key, &iv);
        let got = tokio::time::timeout(std::time::Duration::from_secs(1), read_chunk(&mut state, &mut server)).await.unwrap().unwrap().unwrap();
        assert_eq!(got, frame);
        task.abort();
    }

    #[tokio::test]
    async fn body_roundtrip() {
        for sec in [Security::Aes128Gcm, Security::Chacha20Poly1305] {
            let (key, iv) = ([7u8; 16], [9u8; 16]);
            let payload: Vec<u8> = (0..50_000u32).map(|i| (i * 7) as u8).collect();
            let (mut a, b) = tokio::io::duplex(1 << 20);
            let (c, mut d) = tokio::io::duplex(1 << 20);
            a.write_all(&payload).await.unwrap();
            drop(a);
            encrypt_loop(sec, key, iv, Vec::new(), b, c).await.unwrap();
            let mut wire = Vec::new();
            d.read_to_end(&mut wire).await.unwrap();
            let mut st = BodyState::new(sec, &key, &iv);
            let (mut pos, mut plain) = (0, Vec::new());
            loop {
                let len = (u16::from_be_bytes([wire[pos], wire[pos + 1]]) ^ st.next_mask()) as usize;
                let data = st.open_chunk(&wire[pos + 2..pos + 2 + len]).unwrap();
                pos += 2 + len;
                if data.is_empty() {
                    break;
                }
                plain.extend(data);
            }
            assert_eq!(plain, payload);
            assert_eq!(pos, wire.len());
        }
    }
}
