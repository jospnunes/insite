//! A CONNECT proxy for the tests.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct Proxy {
    pub addr: SocketAddr,
    tunnels: Arc<AtomicUsize>,
}

impl Proxy {
    /// Tunnels every CONNECT, or answers 403 to all of them when `refuse`.
    pub async fn start(refuse: bool) -> Proxy {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tunnels = Arc::new(AtomicUsize::new(0));
        let counter = tunnels.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    return;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if client.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let target = head.split_whitespace().nth(1).unwrap_or_default().to_owned();
                    if refuse || !head.starts_with("CONNECT ") {
                        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
                        return;
                    }
                    let Ok(mut upstream) = TcpStream::connect(&target).await else {
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        return;
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        Proxy { addr, tunnels }
    }

    pub fn tunnels(&self) -> usize {
        self.tunnels.load(Ordering::SeqCst)
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}
