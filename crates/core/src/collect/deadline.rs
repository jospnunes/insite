//! The collection deadline: an instant fixed at t = 0, which an interruption
//! (Ctrl-C) can bring forward so the snapshot closes with what has arrived.

use std::future::Future;

use tokio::sync::watch;
use tokio::time::Instant;

#[derive(Debug, Clone)]
pub struct Deadline {
    at: Instant,
    /// Turns true when the collection is interrupted.
    stop: Option<watch::Receiver<bool>>,
}

impl Deadline {
    pub fn new(at: Instant, stop: Option<watch::Receiver<bool>>) -> Self {
        Deadline { at, stop }
    }

    pub fn instant(&self) -> Instant {
        self.at
    }

    pub fn interrupted(&self) -> bool {
        self.stop.as_ref().is_some_and(|s| *s.borrow())
    }

    pub fn passed(&self) -> bool {
        self.interrupted() || Instant::now() >= self.at
    }

    /// Completes when the deadline passes or the collection is interrupted.
    pub async fn reached(&self) {
        let mut stop = self.stop.clone();
        let interrupted = async {
            let stopped = match stop.as_mut() {
                Some(s) => s.wait_for(|stopped| *stopped).await.is_ok(),
                None => false,
            };
            // A dropped sender can no longer interrupt anything.
            if !stopped {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            _ = tokio::time::sleep_until(self.at) => {}
            _ = interrupted => {}
        }
    }

    /// `fut`'s output, or `None` when the deadline comes first.
    pub async fn run<F: Future>(&self, fut: F) -> Option<F::Output> {
        tokio::select! {
            biased;
            out = fut => Some(out),
            _ = self.reached() => None,
        }
    }

    /// Like `run`, with an earlier limit of its own: `Err(Expired::Global)` when
    /// the deadline came first, `Err(Expired::Limit)` when the limit did.
    pub async fn run_until<F: Future>(&self, limit: Instant, fut: F) -> Result<F::Output, Expired> {
        tokio::select! {
            biased;
            out = fut => Ok(out),
            _ = self.reached() => Err(Expired::Global),
            _ = tokio::time::sleep_until(limit) => Err(Expired::Limit),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expired {
    /// The deadline passed or the collection was interrupted.
    Global,
    /// The caller's own, earlier limit passed.
    Limit,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn stops_at_the_instant_or_on_interruption() {
        let soon = Deadline::new(Instant::now() + Duration::from_millis(20), None);
        assert_eq!(soon.run(std::future::pending::<()>()).await, None);
        assert!(soon.passed());

        let (tx, rx) = watch::channel(false);
        let far = Deadline::new(Instant::now() + Duration::from_secs(60), Some(rx));
        assert_eq!(far.run(async { 7 }).await, Some(7));
        let limit = Instant::now() + Duration::from_millis(10);
        assert_eq!(
            far.run_until(limit, std::future::pending::<()>()).await,
            Err(Expired::Limit)
        );
        tx.send(true).unwrap();
        assert!(far.interrupted() && far.passed());
        assert_eq!(far.run(std::future::pending::<()>()).await, None);
    }

    #[tokio::test]
    async fn a_dropped_sender_does_not_interrupt() {
        let (tx, rx) = watch::channel(false);
        drop(tx);
        let d = Deadline::new(Instant::now() + Duration::from_millis(30), Some(rx));
        let started = Instant::now();
        assert_eq!(d.run(std::future::pending::<()>()).await, None);
        assert!(started.elapsed() >= Duration::from_millis(25));
        assert!(!d.interrupted());
    }
}
