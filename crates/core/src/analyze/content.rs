//! Whether the page body can be analyzed at all, and how far its absence-based
//! conclusions can be trusted. Shared by every module that reads the content.

use url::Url;

use super::infra;
use crate::extract::{self, PageFacts};
use crate::snapshot::Snapshot;

pub struct Content {
    pub facts: PageFacts,
    pub url: Url,
    /// Set when the page was analyzed but does not represent the site (an error
    /// status) or is incomplete; modules then report partial results.
    pub limitation: Option<String>,
    /// Absence-based findings ("no title", "no H1") are only safe on a complete,
    /// representative page.
    pub findings_allowed: bool,
}

/// The extracted page, or why there is nothing to analyze.
pub fn content(snapshot: &Snapshot) -> Result<Content, String> {
    let hop = snapshot.chain.last().ok_or("there is no response to analyze")?;
    let page = snapshot.page.as_ref().ok_or("the final response has no body")?;
    if let Some(challenge) = infra::challenge(snapshot) {
        return Err(format!(
            "{} answered with a bot challenge instead of the page",
            challenge.name
        ));
    }
    let content_type = hop.header("content-type");
    let declared_html = content_type.is_some_and(|ct| {
        let ct = ct.to_ascii_lowercase();
        ct.starts_with("text/html") || ct.starts_with("application/xhtml+xml")
    });
    // MIME sniffing only for a missing or generic type, as browsers do.
    let generic = content_type.is_none_or(|ct| {
        let ct = ct.trim().to_ascii_lowercase();
        ct.is_empty() || ct.starts_with("text/plain") || ct.starts_with("application/octet-stream")
    });
    let sniffed = !declared_html && generic && extract::sniff_html(&page.body);
    if !declared_html && !sniffed {
        return Err(format!(
            "the page is {}, not HTML",
            content_type.unwrap_or("of unknown type")
        ));
    }
    let url = Url::parse(&hop.url).map_err(|e| format!("invalid final URL: {e}"))?;
    let facts = extract::extract(&page.body, content_type, &url);

    let mut limitation = None;
    let mut findings_allowed = true;
    if hop.status >= 400 {
        limitation = Some(format!(
            "the page answered {}, so this describes an error page",
            hop.status
        ));
        findings_allowed = false;
    } else if page.truncated {
        limitation = Some("the page body was cut, so later content was not seen".into());
    }
    Ok(Content {
        facts,
        url,
        limitation,
        findings_allowed,
    })
}
