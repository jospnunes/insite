//! TCP connection with Happy Eyeballs (RFC 8305).
//!
//! Addresses are tried alternating families, IPv6 first. A new attempt starts when
//! the previous one fails or after the connection attempt delay, whichever comes
//! first; the first attempt to connect wins and the others are dropped.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::task::JoinSet;

const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

pub struct Connected {
    pub stream: TcpStream,
    pub peer: SocketAddr,
    /// When the winning attempt called `connect()`, as an offset from t = 0.
    pub connect_at: Duration,
    pub tcp: Duration,
}

pub async fn happy_eyeballs(addresses: &[IpAddr], port: u16, t0: Instant) -> io::Result<Connected> {
    let order = interleave(addresses);
    let mut attempts = JoinSet::new();
    let mut next = 0;
    let mut last_error = None;
    let mut launch = true;

    loop {
        if launch && next < order.len() {
            let peer = SocketAddr::new(order[next], port);
            next += 1;
            attempts.spawn(async move {
                let start = Instant::now();
                let stream = TcpStream::connect(peer).await?;
                let tcp = start.elapsed();
                stream.set_nodelay(true)?;
                Ok::<_, io::Error>(Connected {
                    stream,
                    peer,
                    connect_at: start - t0,
                    tcp,
                })
            });
        }
        launch = false;

        let more = next < order.len();
        tokio::select! {
            Some(joined) = attempts.join_next() => match joined {
                Ok(Ok(connected)) => return Ok(connected),
                Ok(Err(e)) => {
                    last_error = Some(e);
                    if attempts.is_empty() && !more {
                        break;
                    }
                    launch = true;
                }
                Err(e) => last_error = Some(io::Error::other(e)),
            },
            _ = tokio::time::sleep(CONNECTION_ATTEMPT_DELAY), if more => launch = true,
            else => break,
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses to connect to")))
}

/// IPv6 first, then alternating families, keeping the resolver's order within each.
fn interleave(addresses: &[IpAddr]) -> Vec<IpAddr> {
    let (v6, v4): (Vec<IpAddr>, Vec<IpAddr>) = addresses.iter().partition(|a| a.is_ipv6());
    let mut order = Vec::with_capacity(addresses.len());
    let (mut a, mut b) = (v6.into_iter(), v4.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => break,
            (x, y) => order.extend(x.into_iter().chain(y)),
        }
    }
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaves_starting_with_ipv6() {
        let addrs: Vec<IpAddr> = ["192.0.2.1", "192.0.2.2", "2001:db8::1", "192.0.2.3"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let order: Vec<String> = interleave(&addrs).iter().map(ToString::to_string).collect();
        assert_eq!(order, ["2001:db8::1", "192.0.2.1", "192.0.2.2", "192.0.2.3"]);
    }
}
