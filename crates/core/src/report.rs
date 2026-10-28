//! What the analysis concluded. Every output format is a rendering of a `Report`.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::analyze::dns::Dns;
use crate::analyze::infra::Infra;
use crate::analyze::network::Network;
use crate::analyze::security::Security;
use crate::analyze::seo::Seo;
use crate::analyze::stack::Stack;
use crate::analyze::tls::Tls;
use crate::analyze::weight::Weight;

/// Semver: a new field bumps the minor version, a removal or type change the major.
pub const SCHEMA_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: &'static str,
    pub collector_version: String,
    pub analyzer_version: &'static str,
    pub target: TargetInfo,
    /// RFC 3339, from the snapshot's `collected_at`, never from the analysis clock.
    pub started_at: String,
    pub duration_ms: f64,
    pub outcome: Outcome,
    pub modules: Modules,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetInfo {
    /// The normalized input URL (punycode for international domains).
    pub input: String,
    /// The input host as people write it.
    pub display_host: String,
    pub final_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Complete,
    /// Something changes how the result should be read: a module timed out or
    /// failed, or the page does not represent the site.
    Partial {
        reasons: Vec<String>,
    },
    /// No HTTP response at all, neither over HTTPS nor over port 80.
    Unreachable {
        reason: String,
    },
}

impl Outcome {
    pub fn exit_code(&self) -> i32 {
        match self {
            Outcome::Complete => 0,
            Outcome::Unreachable { .. } => 1,
            Outcome::Partial { .. } => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Modules {
    pub network: Module<Network>,
    pub tls: Module<Tls>,
    pub dns: Module<Dns>,
    pub infra: Module<Infra>,
    pub security: Module<Security>,
    pub stack: Module<Stack>,
    pub seo: Module<Seo>,
    pub weight: Module<Weight>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Module<T> {
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub data: Option<T>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Partial,
    Timeout,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable across versions and languages; consumers should key on this and `params`.
    pub id: &'static str,
    pub severity: Severity,
    pub params: BTreeMap<String, String>,
    /// The observed data that produced the finding.
    pub evidence: String,
    pub title: String,
    pub detail: String,
    pub fix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }
}
