//! VMess client with AEAD headers (alterId 0), chunk stream + length masking,
//! body security aes-128-gcm or chacha20-poly1305, over TCP with optional TLS.

use std::net::IpAddr;
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
use rustls::pki_types::ServerName;
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::trojan::tls_client;
use crate::udp::{pipe_pair, UdpPipe};
use crate::util::{connect_tcp, BoxStream, Host, Target};
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

fn fnv1a32(data: &[u8]) -> u32 {
    data.iter().fold(0x811c9dc5u32, |h, b| (h ^ *b as u32).wrapping_mul(0x01000193))
}

fn request_header(sec: Security, key: &[u8; 16], iv: &[u8; 16], resp_v: u8, cmd: u8, target: &Target) -> Result<Vec<u8>> {
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
    h.extend_from_slice(&target.port.to_be_bytes());
    match &target.host {
        Host::Ip(IpAddr::V4(v4)) => {
            h.push(1);
            h.extend_from_slice(&v4.octets());
        }
        Host::Domain(d) => {
            if d.len() > 255 {
                bail!("domain too long");
            }
            h.push(2);
            h.push(d.len() as u8);
            h.extend_from_slice(d.as_bytes());
        }
        Host::Ip(IpAddr::V6(v6)) => {
            h.push(3);
            h.extend_from_slice(&v6.octets());
        }
    }
    let mut pad = vec![0u8; padding];
    rng.fill_bytes(&mut pad);
    h.extend_from_slice(&pad);
    let f = fnv1a32(&h);
    h.extend_from_slice(&f.to_be_bytes());
    Ok(h)
}

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
}

impl Session {
    fn new(sec: Security) -> Self {
        let mut rng = rand::thread_rng();
        let (mut key, mut iv) = ([0u8; 16], [0u8; 16]);
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);
        Session {
            sec,
            key,
            iv,
            resp_key: sha256(&[&key])[..16].try_into().unwrap(),
            resp_iv: sha256(&[&iv])[..16].try_into().unwrap(),
            resp_v: (rng.next_u32() & 0xff) as u8,
        }
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
        if n == 0 {
            break;
        }
    }
    dst.flush().await?;
    Ok(())
}

async fn read_response_header<R: AsyncRead + Unpin>(sess: &Session, src: &mut R) -> Result<()> {
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
    server: String,
    port: u16,
    cmd_key: [u8; 16],
    sec: Security,
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

impl VmessServer {
    pub fn new(
        server: String,
        port: u16,
        uuid: &str,
        method: &str,
        tls: bool,
        sni: Option<String>,
        skip_cert_verify: bool,
    ) -> Result<Self> {
        let mut h = Md5::new();
        Digest::update(&mut h, parse_uuid(uuid)?);
        Digest::update(&mut h, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let tls = if tls { Some(tls_client(&server, sni, skip_cert_verify)?) } else { None };
        Ok(VmessServer { server, port, cmd_key: h.finalize().into(), sec: Security::parse(method)?, tls })
    }

    async fn transport(&self) -> Result<BoxStream> {
        let tcp = connect_tcp(&self.server, self.port).await?;
        Ok(match &self.tls {
            Some((connector, sni)) => Box::new(connector.connect(sni.clone(), tcp).await?),
            None => Box::new(tcp),
        })
    }

    /// UDP (cmd 2): each body chunk carries exactly one packet.
    pub async fn open_udp(&self, target: &Target) -> Result<UdpPipe> {
        let stream = self.transport().await?;
        let sess = Session::new(self.sec);
        let head = seal_header(&self.cmd_key, &request_header(sess.sec, &sess.key, &sess.iv, sess.resp_v, 2, target)?);
        let (mut rd, mut wr) = tokio::io::split(stream);
        let (app, side) = pipe_pair();
        let UdpPipe { tx, mut rx } = side;
        let (sec, key, iv) = (sess.sec, sess.key, sess.iv);
        tokio::spawn(async move {
            let mut st = BodyState::new(sec, &key, &iv);
            if wr.write_all(&head).await.is_err() {
                return;
            }
            // An empty chunk means end of stream, so empty datagrams can't be sent.
            while let Some(p) = rx.recv().await {
                if p.is_empty() {
                    continue;
                }
                let mut out = Vec::with_capacity(p.len() + 32);
                st.seal_chunk(&p, &mut out);
                if wr.write_all(&out).await.is_err() {
                    return;
                }
            }
            let mut out = Vec::new();
            st.seal_chunk(&[], &mut out);
            let _ = wr.write_all(&out).await;
        });
        tokio::spawn(async move {
            if read_response_header(&sess, &mut rd).await.is_err() {
                return;
            }
            let mut st = BodyState::new(sess.sec, &sess.resp_key, &sess.resp_iv);
            loop {
                tokio::select! {
                    _ = tx.closed() => break,
                    r = read_chunk(&mut st, &mut rd) => match r {
                        Ok(Some(p)) => if tx.send(p).await.is_err() { break },
                        _ => break,
                    },
                }
            }
        });
        Ok(app)
    }

    pub async fn connect(&self, target: &Target) -> Result<BoxStream> {
        let stream = self.transport().await?;
        let sess = Session::new(self.sec);
        let head = seal_header(&self.cmd_key, &request_header(sess.sec, &sess.key, &sess.iv, sess.resp_v, 1, target)?);
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
    fn fnv() {
        assert_eq!(fnv1a32(b""), 0x811c9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c292c);
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
