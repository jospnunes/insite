//! Progress events: what the collector reports while it works, for a live view.
//! Without a sender nothing is built or sent, and the analysis never sees them.

use std::time::Duration;

use crate::snapshot::DomainRole;

/// One thing that happened during collection. Events are sent as they happen, in
/// the order the collector produced them; a send error (the view is gone) is ignored.
#[derive(Debug, Clone, PartialEq)]
pub enum Progress {
    /// A phase of the main chain's request finished. `hop` is the index in the final
    /// chain (0 = first request). A retried attempt may report a phase again: the
    /// last one per `(hop, phase)` wins. A reused connection has no Dns/Tcp/Tls.
    Phase { hop: usize, phase: Phase, took: Duration },
    /// Hop `hop` answered with a redirect to `to`; `took` is its time to the end of the body.
    Redirect {
        hop: usize,
        from: String,
        to: String,
        status: u16,
        took: Duration,
    },
    /// A part of the collection settled (also when it was skipped, so a view never waits for it).
    Done(Part),
    /// The headless browser moved on.
    Browser(BrowserStage),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Dns,
    Tcp,
    Tls,
    Ttfb,
    Download,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Page,
    HttpCheck,
    Records(DomainRole),
    Auxiliary,
    Asn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserStage {
    Navigating,
    Loaded,
    Quiet,
}

pub type ProgressSender = tokio::sync::mpsc::UnboundedSender<Progress>;

/// Sends `event` if someone listens. Build events that allocate only when `tx` is `Some`.
pub(crate) fn emit(tx: &Option<ProgressSender>, event: Progress) {
    if let Some(tx) = tx {
        let _ = tx.send(event);
    }
}
