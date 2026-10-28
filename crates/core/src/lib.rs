//! insite core: collection (the only part that touches the network), analysis
//! (pure functions from `Snapshot` to `Report`) and the report types.

pub mod analyze;
pub mod collect;
pub mod data;
pub mod detect;
pub mod extract;
pub mod findings;
pub mod report;
pub mod snapshot;
