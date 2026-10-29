//! Process-wide traffic counters. They survive config reloads; rates are left to the
//! reader (sample twice and divide).

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::util::BoxStream;

static UP: AtomicU64 = AtomicU64::new(0);
static DOWN: AtomicU64 = AtomicU64::new(0);
static ACTIVE: AtomicI64 = AtomicI64::new(0);

pub fn add_up(n: usize) {
    UP.fetch_add(n as u64, Ordering::Relaxed);
}

pub fn add_down(n: usize) {
    DOWN.fetch_add(n as u64, Ordering::Relaxed);
}

/// (bytes sent upstream, bytes received, connections open now).
pub fn snapshot() -> (u64, u64, i64) {
    (UP.load(Ordering::Relaxed), DOWN.load(Ordering::Relaxed), ACTIVE.load(Ordering::Relaxed).max(0))
}

/// Counts bytes as they flow, so long-lived connections show up in rates while open.
struct Counted {
    inner: BoxStream,
}

impl Drop for Counted {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

impl AsyncRead for Counted {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        add_down(buf.filled().len() - before);
        r
    }
}

impl AsyncWrite for Counted {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            add_up(n);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Wraps an upstream stream so its traffic and lifetime are counted.
pub fn counted(inner: BoxStream) -> BoxStream {
    ACTIVE.fetch_add(1, Ordering::Relaxed);
    Box::new(Counted { inner })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn counts_both_directions() {
        let (a, mut b) = tokio::io::duplex(1024);
        let (up0, down0, active0) = snapshot();
        let mut s = counted(Box::new(a));
        assert_eq!(snapshot().2, active0 + 1);
        s.write_all(b"hello").await.unwrap();
        b.write_all(b"worlds!").await.unwrap();
        let mut buf = [0u8; 7];
        s.read_exact(&mut buf).await.unwrap();
        let (up, down, _) = snapshot();
        assert!(up - up0 >= 5 && down - down0 >= 7);
        drop(s);
        assert_eq!(snapshot().2, active0);
    }
}
