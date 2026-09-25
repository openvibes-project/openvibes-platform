//! A write-stall deadline for accepted connections.

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};

/// Wraps a connection so a write that makes no progress for `limit` fails
/// with `TimedOut`, closing the connection. A slow reader that keeps
/// draining is served; one that stops reading cannot hold its connection
/// slot and response buffer (up to 1 MiB) indefinitely.
pub(crate) struct WriteDeadline<S> {
    inner: S,
    limit: Duration,
    /// Armed while a write or flush is waiting for the peer.
    stall: Option<Pin<Box<Sleep>>>,
}

impl<S> WriteDeadline<S> {
    pub(crate) fn new(inner: S, limit: Duration) -> Self {
        Self {
            inner,
            limit,
            stall: None,
        }
    }

    /// Clears the deadline after progress; arms it (once) and checks it
    /// while the peer is not accepting bytes.
    fn watch<T>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if poll.is_ready() {
            self.stall = None;
            return poll;
        }
        let limit = self.limit;
        let stall = self
            .stall
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(Instant::now() + limit)));
        match stall.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.stall = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "peer stopped reading",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteDeadline<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteDeadline<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.watch(cx, poll)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.inner).poll_flush(cx);
        self.watch(cx, poll)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::WriteDeadline;

    #[tokio::test]
    async fn a_peer_that_stops_reading_times_out() {
        let (ours, _theirs) = tokio::io::duplex(64);
        let mut stream = WriteDeadline::new(ours, Duration::from_millis(100));
        let result = tokio::time::timeout(Duration::from_secs(5), stream.write_all(&[0; 4096]))
            .await
            .expect("the write deadline fires, not the test's");
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_slow_but_steady_reader_is_served() {
        let (ours, mut theirs) = tokio::io::duplex(64);
        let mut stream = WriteDeadline::new(ours, Duration::from_millis(200));
        let reader = tokio::spawn(async move {
            let mut received = 0;
            let mut chunk = [0; 64];
            while received < 1024 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                received += theirs.read(&mut chunk).await.unwrap();
            }
            received
        });
        // Takes ~320 ms in total, longer than the limit, but never stalls.
        stream.write_all(&[0; 1024]).await.unwrap();
        assert_eq!(reader.await.unwrap(), 1024);
    }
}
