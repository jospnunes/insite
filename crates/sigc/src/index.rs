//! The compiled detection index: what the runtime engine loads.

use serde::{Deserialize, Serialize};

/// Bumped whenever these types change; an index with another format version is
/// ignored by the runtime.
pub const FORMAT: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub format: u32,
    /// Where the signatures came from, e.g. the webappanalyzer commit.
    pub source: String,
    /// ISO date of the source, used to decide whether an update is newer.
    pub source_date: String,
    pub categories: Vec<Category>,
    pub techs: Vec<Tech>,
    pub patterns: Vec<Pattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub id: u32,
    pub name: String,
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tech {
    pub name: String,
    pub cats: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub implies: Vec<Implied>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires_category: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excludes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Implied {
    pub name: String,
    pub confidence: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Field {
    Headers,
    Cookies,
    Meta,
    ScriptSrc,
    Scripts,
    Html,
    Text,
    Url,
    Dom,
    Dns,
    CertIssuer,
    Js,
    Xhr,
    Css,
    Robots,
}

impl Field {
    pub fn as_str(self) -> &'static str {
        match self {
            Field::Headers => "headers",
            Field::Cookies => "cookies",
            Field::Meta => "meta",
            Field::ScriptSrc => "scriptSrc",
            Field::Scripts => "scripts",
            Field::Html => "html",
            Field::Text => "text",
            Field::Url => "url",
            Field::Dom => "dom",
            Field::Dns => "dns",
            Field::CertIssuer => "certIssuer",
            Field::Js => "js",
            Field::Xhr => "xhr",
            Field::Css => "css",
            Field::Robots => "robots",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Engine {
    /// The `regex` crate, bytes mode, ASCII classes: linear time.
    Regex,
    /// `fancy-regex`, for lookaround and backreferences, with a backtrack limit.
    Fancy,
}

/// What a `dom` pattern checks on the elements its selector matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "check", content = "name")]
pub enum DomCheck {
    Exists,
    Attribute(String),
    /// A JavaScript property of the element; needs a browser.
    Property(String),
    Text,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub tech: u32,
    pub field: Field,
    /// Header, cookie or meta name, DNS record type, JS property path or CSS selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dom: Option<DomCheck>,
    /// Translated regex, matched case-insensitively. `None` checks existence only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    pub engine: Engine,
    /// Compile with Unicode classes and case folding (only when ASCII mode rejects
    /// the pattern).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unicode: bool,
    /// Version template such as `\1` or `\1?4:3`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub confidence: u8,
    /// Lowercase literals of which every match contains at least one; the
    /// prefilter only runs the regex when one is present. Empty means always run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needles: Vec<String>,
}
