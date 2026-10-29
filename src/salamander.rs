//! Hysteria2 "Salamander" obfuscation: every UDP packet becomes
//! `salt(8) | payload XOR BLAKE2b-256(password | salt)` (key repeated every 32 bytes).
//! Implemented as a socket wrapper under quinn, so QUIC itself is unaware of it.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use blake2::{Blake2b, Digest};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::RngCore;

type Blake2b256 = Blake2b<blake2::digest::consts::U32>;

const SALT: usize = 8;

fn keystream(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(password);
    h.update(salt);
    h.finalize().into()
}

fn xor(data: &mut [u8], key: &[u8; 32]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % 32];
    }
}

pub fn obfuscate(password: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; SALT + payload.len()];
    rand::thread_rng().fill_bytes(&mut out[..SALT]);
    out[SALT..].copy_from_slice(payload);
    let key = keystream(password, &out[..SALT]);
    xor(&mut out[SALT..], &key);
    out
}

/// Reverses [`obfuscate`] in place; returns the payload length (0 if too short).
pub fn deobfuscate_in_place(password: &[u8], packet: &mut [u8]) -> usize {
    if packet.len() <= SALT {
        return 0;
    }
    let key = keystream(password, &packet[..SALT]);
    xor(&mut packet[SALT..], &key);
    packet.copy_within(SALT.., 0);
    packet.len() - SALT
}

pub struct Salamander {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Vec<u8>,
}

impl Salamander {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, password: &str) -> Self {
        Salamander { inner, password: password.as_bytes().to_vec() }
    }
}

impl fmt::Debug for Salamander {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salamander")
    }
}

impl AsyncUdpSocket for Salamander {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // max_transmit_segments() is 1, so each transmit is exactly one datagram.
        let contents = obfuscate(&self.password, transmit.contents);
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &contents,
            segment_size: None,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let n = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        for (buf, m) in bufs.iter_mut().zip(meta.iter_mut()).take(n) {
            let len = deobfuscate_in_place(&self.password, &mut buf[..m.len]);
            m.len = len;
            m.stride = len;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_password() {
        let payload: Vec<u8> = (0..1300u32).map(|i| i as u8).collect();
        let mut wire = obfuscate(b"secret", &payload);
        assert_eq!(wire.len(), payload.len() + 8);
        assert_ne!(&wire[8..], &payload[..]);
        let mut other = wire.clone();
        let n = deobfuscate_in_place(b"secret", &mut wire);
        assert_eq!(&wire[..n], &payload[..]);
        let n = deobfuscate_in_place(b"wrong", &mut other);
        assert_ne!(&other[..n], &payload[..]);
        assert_eq!(deobfuscate_in_place(b"x", &mut [1, 2, 3]), 0);
    }
}
