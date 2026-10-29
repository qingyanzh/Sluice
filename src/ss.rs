//! Shadowsocks AEAD client (SIP004): aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305.

use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use log::debug;
use md5::{Digest, Md5};
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::udp::{parse_socks_addr, pipe_pair, UdpPipe, MAX_PACKET};
use crate::util::{connect_tcp, resolve, udp_socket, BoxStream, Target};

const TAG: usize = 16;
const MAX_CHUNK: usize = 0x3FFF;

#[derive(Clone, Copy, Debug)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Method {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Method::Aes128Gcm,
            "aes-256-gcm" => Method::Aes256Gcm,
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Method::Chacha20Poly1305,
            _ => bail!("unsupported encrypt-method {s:?} (supported: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305)"),
        })
    }

    fn key_len(self) -> usize {
        match self {
            Method::Aes128Gcm => 16,
            _ => 32,
        }
    }
}

/// OpenSSL EVP_BytesToKey with MD5, as used by Shadowsocks to derive the master key.
pub fn evp_bytes_to_key(password: &[u8], len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        prev = h.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(len);
    key
}

enum Cipher {
    A128(Aes128Gcm),
    A256(Aes256Gcm),
    Chacha(ChaCha20Poly1305),
}

/// One direction of an AEAD session: a per-salt subkey plus an incrementing nonce.
struct AeadState {
    cipher: Cipher,
    nonce: [u8; 12],
}

impl AeadState {
    fn new(method: Method, key: &[u8], salt: &[u8]) -> Self {
        let mut sub = vec![0u8; method.key_len()];
        Hkdf::<Sha1>::new(Some(salt), key).expand(b"ss-subkey", &mut sub).expect("valid hkdf length");
        let cipher = match method {
            Method::Aes128Gcm => Cipher::A128(Aes128Gcm::new_from_slice(&sub).expect("key length")),
            Method::Aes256Gcm => Cipher::A256(Aes256Gcm::new_from_slice(&sub).expect("key length")),
            Method::Chacha20Poly1305 => Cipher::Chacha(ChaCha20Poly1305::new_from_slice(&sub).expect("key length")),
        };
        AeadState { cipher, nonce: [0; 12] }
    }

    fn bump(&mut self) {
        for b in self.nonce.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    fn seal(&mut self, data: &[u8]) -> Vec<u8> {
        let n = GenericArray::from_slice(&self.nonce);
        let out = match &self.cipher {
            Cipher::A128(c) => c.encrypt(n, data),
            Cipher::A256(c) => c.encrypt(n, data),
            Cipher::Chacha(c) => c.encrypt(n, data),
        }
        .expect("aead encrypt");
        self.bump();
        out
    }

    fn open(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let n = GenericArray::from_slice(&self.nonce);
        let out = match &self.cipher {
            Cipher::A128(c) => c.decrypt(n, data),
            Cipher::A256(c) => c.decrypt(n, data),
            Cipher::Chacha(c) => c.decrypt(n, data),
        }
        .map_err(|_| anyhow!("shadowsocks decryption failed (wrong password or method?)"))?;
        self.bump();
        Ok(out)
    }

    fn seal_chunks(&mut self, data: &[u8], out: &mut Vec<u8>) {
        for chunk in data.chunks(MAX_CHUNK) {
            out.extend(self.seal(&(chunk.len() as u16).to_be_bytes()));
            out.extend(self.seal(chunk));
        }
    }
}

/// Encrypts `first` and then everything read from `src` into `dst`.
pub async fn encrypt_loop<R, W>(method: Method, key: &[u8], first: Vec<u8>, mut src: R, mut dst: W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut salt = vec![0u8; method.key_len()];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut st = AeadState::new(method, key, &salt);
    let mut out = salt;
    st.seal_chunks(&first, &mut out);
    dst.write_all(&out).await?;
    let mut buf = vec![0u8; MAX_CHUNK];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        out.clear();
        st.seal_chunks(&buf[..n], &mut out);
        dst.write_all(&out).await?;
    }
    dst.shutdown().await?;
    Ok(())
}

/// Decrypts the stream from `src` and writes plaintext to `dst`.
pub async fn decrypt_loop<R, W>(method: Method, key: &[u8], mut src: R, mut dst: W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let eof = |e: &std::io::Error| e.kind() == std::io::ErrorKind::UnexpectedEof;
    let mut salt = vec![0u8; method.key_len()];
    match src.read_exact(&mut salt).await {
        Ok(_) => {}
        Err(e) if eof(&e) => return Ok(dst.shutdown().await?),
        Err(e) => return Err(e.into()),
    }
    let mut st = AeadState::new(method, key, &salt);
    let mut len_buf = [0u8; 2 + TAG];
    let mut buf = vec![0u8; MAX_CHUNK + TAG];
    loop {
        match src.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if eof(&e) => break,
            Err(e) => return Err(e.into()),
        }
        let l = st.open(&len_buf)?;
        let len = u16::from_be_bytes([l[0], l[1]]) as usize & MAX_CHUNK;
        src.read_exact(&mut buf[..len + TAG]).await?;
        dst.write_all(&st.open(&buf[..len + TAG])?).await?;
    }
    dst.shutdown().await?;
    Ok(())
}

/// One UDP packet: `salt | AEAD(subkey(salt), nonce 0, plain)`.
fn udp_seal(method: Method, key: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut salt = vec![0u8; method.key_len()];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut st = AeadState::new(method, key, &salt);
    let mut out = salt;
    out.extend(st.seal(plain));
    out
}

fn udp_open(method: Method, key: &[u8], packet: &[u8]) -> Result<Vec<u8>> {
    let kl = method.key_len();
    if packet.len() < kl + TAG {
        bail!("shadowsocks UDP packet too short");
    }
    AeadState::new(method, key, &packet[..kl]).open(&packet[kl..])
}

pub struct SsServer {
    server: String,
    port: u16,
    method: Method,
    key: Vec<u8>,
}

impl SsServer {
    pub fn new(server: String, port: u16, method: &str, password: &str) -> Result<Self> {
        let method = Method::parse(method)?;
        let key = evp_bytes_to_key(password.as_bytes(), method.key_len());
        Ok(SsServer { server, port, method, key })
    }

    pub async fn open_udp(&self, target: &Target) -> Result<UdpPipe> {
        let addr = *resolve(&self.server, self.port).await?.first().ok_or_else(|| anyhow!("{}: no address", self.server))?;
        let sock = udp_socket(&addr)?;
        sock.connect(addr).await?;
        let mut header = Vec::new();
        target.write_socks_addr(&mut header)?;
        let (method, key) = (self.method, self.key.clone());
        let (app, mut side) = pipe_pair();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                tokio::select! {
                    p = side.rx.recv() => match p {
                        Some(p) => {
                            let plain = [header.as_slice(), &p].concat();
                            let _ = sock.send(&udp_seal(method, &key, &plain)).await;
                        }
                        None => break,
                    },
                    r = sock.recv(&mut buf) => match r {
                        Ok(n) => match udp_open(method, &key, &buf[..n]) {
                            Ok(plain) => {
                                let Some((_, off)) = parse_socks_addr(&plain) else { continue };
                                if side.tx.send(plain[off..].to_vec()).await.is_err() { break }
                            }
                            Err(e) => debug!("ss UDP: {e}"),
                        },
                        Err(e) => { debug!("ss UDP: {e}"); break }
                    },
                }
            }
        });
        Ok(app)
    }

    /// Returns a plaintext stream; two background tasks do the crypto.
    pub async fn connect(&self, target: &Target) -> Result<BoxStream> {
        let (rd, wr) = connect_tcp(&self.server, self.port).await?.into_split();
        let (app, inner) = tokio::io::duplex(64 * 1024);
        let (ird, iwr) = tokio::io::split(inner);
        let mut header = Vec::new();
        target.write_socks_addr(&mut header)?;

        let (method, key) = (self.method, self.key.clone());
        tokio::spawn(async move {
            if let Err(e) = encrypt_loop(method, &key, header, ird, wr).await {
                debug!("ss upstream closed: {e:#}");
            }
        });
        let key = self.key.clone();
        tokio::spawn(async move {
            if let Err(e) = decrypt_loop(method, &key, rd, iwr).await {
                debug!("ss downstream closed: {e:#}");
            }
        });
        Ok(Box::new(app))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_all_methods() {
        for m in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            let method = Method::parse(m).unwrap();
            let key = evp_bytes_to_key(b"secret", method.key_len());
            let payload: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
            let (mut a, b) = tokio::io::duplex(1 << 20);
            let (c, mut d) = tokio::io::duplex(1 << 20);
            a.write_all(&payload).await.unwrap();
            drop(a);
            encrypt_loop(method, &key, b"hdr".to_vec(), b, c).await.unwrap();
            let (mut e, f) = tokio::io::duplex(1 << 20);
            let mut wire = Vec::new();
            d.read_to_end(&mut wire).await.unwrap();
            decrypt_loop(method, &key, &wire[..], f).await.unwrap();
            let mut plain = Vec::new();
            e.read_to_end(&mut plain).await.unwrap();
            assert_eq!(&plain[..3], b"hdr");
            assert_eq!(&plain[3..], &payload[..]);
        }
    }

    #[test]
    fn udp_packet_roundtrip() {
        let key = evp_bytes_to_key(b"k", 32);
        let pkt = udp_seal(Method::Chacha20Poly1305, &key, b"hello");
        assert_eq!(udp_open(Method::Chacha20Poly1305, &key, &pkt).unwrap(), b"hello");
        assert!(udp_open(Method::Chacha20Poly1305, &evp_bytes_to_key(b"x", 32), &pkt).is_err());
    }

    #[tokio::test]
    async fn wrong_key_fails() {
        let m = Method::Aes256Gcm;
        let (c, mut d) = tokio::io::duplex(1 << 16);
        encrypt_loop(m, &evp_bytes_to_key(b"a", 32), b"x".to_vec(), &b""[..], c).await.unwrap();
        let mut wire = Vec::new();
        d.read_to_end(&mut wire).await.unwrap();
        let (_e, f) = tokio::io::duplex(1 << 16);
        assert!(decrypt_loop(m, &evp_bytes_to_key(b"b", 32), &wire[..], f).await.is_err());
    }
}
