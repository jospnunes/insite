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
    /// Reference data the analysis used, with versions, so results can be traced.
    pub sources: Vec<DataSource>,
    pub modules: Modules,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DataSource {
    pub name: &'static str,
    pub version: String,
    pub license: &'static str,
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

/// The modules of a report, in report order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleName {
    Network,
    Tls,
    Dns,
    Infra,
    Security,
    Stack,
    Seo,
    Weight,
}

impl ModuleName {
    pub const ALL: [ModuleName; 8] = [
        ModuleName::Network,
        ModuleName::Tls,
        ModuleName::Dns,
        ModuleName::Infra,
        ModuleName::Security,
        ModuleName::Stack,
        ModuleName::Seo,
        ModuleName::Weight,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ModuleName::Network => "network",
            ModuleName::Tls => "tls",
            ModuleName::Dns => "dns",
            ModuleName::Infra => "infra",
            ModuleName::Security => "security",
            ModuleName::Stack => "stack",
            ModuleName::Seo => "seo",
            ModuleName::Weight => "weight",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|m| m.as_str().eq_ignore_ascii_case(name.trim()))
    }
}

/// A set of modules, as chosen with `-m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection(u8);

impl Selection {
    pub fn all() -> Self {
        Selection(u8::MAX)
    }

    pub fn contains(self, module: ModuleName) -> bool {
        self.0 & 1 << module as u8 != 0
    }

    /// A comma-separated list such as `tls,dns`.
    pub fn parse(list: &str) -> Result<Self, String> {
        let mut bits = 0u8;
        for name in list.split(',').filter(|n| !n.trim().is_empty()) {
            let module = ModuleName::parse(name).ok_or_else(|| {
                let known: Vec<&str> = ModuleName::ALL.iter().map(|m| m.as_str()).collect();
                format!("unknown module `{}` (known: {})", name.trim(), known.join(", "))
            })?;
            bits |= 1 << module as u8;
        }
        if bits == 0 {
            return Err("no module chosen".into());
        }
        Ok(Selection(bits))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Module<T> {
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub data: Option<T>,
    pub findings: Vec<Finding>,
}

impl<T> Module<T> {
    pub fn skipped(reason: impl Into<String>) -> Self {
        Module {
            status: Status::Skipped,
            reason: Some(reason.into()),
            data: None,
            findings: Vec::new(),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selections_parse_module_lists() {
        let s = Selection::parse("tls, DNS").unwrap();
        assert!(s.contains(ModuleName::Tls) && s.contains(ModuleName::Dns));
        assert!(!s.contains(ModuleName::Seo));
        assert!(Selection::parse("tls,css").unwrap_err().contains("css"));
        assert!(Selection::parse(",").is_err());
        assert!(ModuleName::ALL.iter().all(|m| Selection::all().contains(*m)));
    }
}
