//! Weight and third parties: what the HTML costs, what blocks rendering and which
//! other domains the page loads. Resource sizes need a browser (`--browser`).

use std::collections::BTreeMap;

use serde::Serialize;

use super::content::Content;
use crate::collect::records::registrable;
use crate::findings::finding;
use crate::report::{Finding, Module, Status, format_bytes};
use crate::snapshot::Snapshot;

/// Text bodies smaller than this gain little from compression.
const COMPRESSION_MIN: u64 = 1024;
const LARGE_HTML: u64 = 512 << 10;

#[derive(Debug, Clone, Serialize)]
pub struct Weight {
    pub html_transferred_bytes: u64,
    pub html_bytes: u64,
    pub compression: Option<String>,
    pub scripts_external: usize,
    pub scripts_inline: usize,
    pub inline_script_bytes: usize,
    pub render_blocking_scripts: Vec<String>,
    pub stylesheets: usize,
    pub inline_styles: usize,
    pub inline_style_bytes: usize,
    pub images: usize,
    pub image_formats: BTreeMap<String, usize>,
    pub images_lazy: usize,
    pub images_without_dimensions: usize,
    pub iframes: usize,
    pub preload: usize,
    pub preconnect: usize,
    pub third_parties: Vec<ThirdParty>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThirdParty {
    pub domain: String,
    pub resources: usize,
    /// `script`, `stylesheet`, `image`, `iframe`.
    pub kinds: Vec<&'static str>,
    /// Technologies whose detection evidence points at this domain.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub technologies: Vec<String>,
}

pub fn analyze(snapshot: &Snapshot, content: &Result<Content, String>) -> Module<Weight> {
    let content = match content {
        Ok(c) => c,
        Err(reason) => {
            return Module {
                status: Status::Skipped,
                reason: Some(reason.clone()),
                data: None,
                findings: vec![],
            };
        }
    };
    let facts = &content.facts;
    let page = snapshot.page.as_ref().expect("content implies a page");
    let compression = page
        .content_encoding
        .clone()
        .filter(|e| !e.eq_ignore_ascii_case("identity"));

    let render_blocking: Vec<String> = facts
        .scripts
        .iter()
        .filter(|s| s.blocks_rendering())
        .filter_map(|s| s.src.clone())
        .collect();
    let mut formats = BTreeMap::new();
    for image in &facts.images {
        if let Some(format) = image.src.as_deref().and_then(image_format) {
            *formats.entry(format.to_owned()).or_insert(0) += 1;
        }
    }

    // Resources on another registrable domain than the page's.
    let own = content.url.host_str().map(registrable).unwrap_or_default();
    let mut parties: BTreeMap<String, ThirdParty> = BTreeMap::new();
    let resources = facts
        .scripts
        .iter()
        .filter_map(|s| s.src.as_deref().map(|u| (u, "script")))
        .chain(
            facts
                .links_with_rel("stylesheet")
                .filter_map(|l| l.href.as_deref().map(|u| (u, "stylesheet"))),
        )
        .chain(
            facts
                .images
                .iter()
                .filter_map(|i| i.src.as_deref().map(|u| (u, "image"))),
        )
        .chain(facts.iframes.iter().map(|u| (u.as_str(), "iframe")));
    for (url, kind) in resources {
        let Some(host) = url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_owned)) else {
            continue;
        };
        let domain = registrable(&host);
        if domain == own {
            continue;
        }
        let party = parties.entry(domain.clone()).or_insert(ThirdParty {
            domain,
            resources: 0,
            kinds: Vec::new(),
            technologies: Vec::new(),
        });
        party.resources += 1;
        if !party.kinds.contains(&kind) {
            party.kinds.push(kind);
        }
    }
    let mut third_parties: Vec<ThirdParty> = parties.into_values().collect();
    third_parties.sort_by(|a, b| b.resources.cmp(&a.resources).then(a.domain.cmp(&b.domain)));

    let html_bytes = page.body.len() as u64;
    let mut findings: Vec<Finding> = Vec::new();
    if compression.is_none() && html_bytes >= COMPRESSION_MIN {
        findings.push(finding(
            "weight.uncompressed",
            &[("size", format_bytes(html_bytes))],
            format!("{html_bytes} bytes without Content-Encoding"),
        ));
    }
    if !render_blocking.is_empty() {
        findings.push(finding(
            "weight.render_blocking",
            &[("count", render_blocking.len().to_string())],
            render_blocking.join(", "),
        ));
    }
    if html_bytes > LARGE_HTML {
        findings.push(finding(
            "weight.html_large",
            &[("size", format_bytes(html_bytes))],
            format!("{html_bytes} bytes of HTML"),
        ));
    }
    if !content.findings_allowed {
        findings.clear();
    }

    let data = Weight {
        html_transferred_bytes: page.transferred,
        html_bytes,
        compression,
        scripts_external: facts.scripts.iter().filter(|s| s.src.is_some()).count(),
        scripts_inline: facts
            .scripts
            .iter()
            .filter(|s| s.src.is_none() && s.inline_bytes > 0)
            .count(),
        inline_script_bytes: facts
            .scripts
            .iter()
            .filter(|s| s.src.is_none())
            .map(|s| s.inline_bytes)
            .sum(),
        render_blocking_scripts: render_blocking,
        stylesheets: facts.links_with_rel("stylesheet").count(),
        inline_styles: facts.inline_styles,
        inline_style_bytes: facts.inline_style_bytes,
        images: facts.images.len(),
        image_formats: formats,
        images_lazy: facts.images.iter().filter(|i| i.lazy).count(),
        images_without_dimensions: facts.images.iter().filter(|i| !i.has_dimensions).count(),
        iframes: facts.iframes.len(),
        preload: facts.links_with_rel("preload").count(),
        preconnect: facts.links_with_rel("preconnect").count(),
        third_parties,
    };
    let (status, reason) = match &content.limitation {
        Some(l) => (Status::Partial, Some(l.clone())),
        None => (Status::Ok, None),
    };
    Module {
        status,
        reason,
        data: Some(data),
        findings,
    }
}

fn image_format(url: &str) -> Option<&'static str> {
    let path = url.split(['?', '#']).next()?.to_ascii_lowercase();
    let ext = path.rsplit_once('.')?.1;
    Some(match ext {
        "jpg" | "jpeg" => "jpeg",
        "png" => "png",
        "gif" => "gif",
        "webp" => "webp",
        "avif" => "avif",
        "svg" => "svg",
        "ico" => "ico",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_formats_from_extensions() {
        assert_eq!(image_format("https://x/a.JPG?w=100"), Some("jpeg"));
        assert_eq!(image_format("https://x/a.webp#x"), Some("webp"));
        assert_eq!(image_format("https://x/image"), None);
    }

    #[test]
    fn finding_sizes_use_the_shared_formatter() {
        // 934 000 bytes: the weight line prints "934 KB", and so must the finding.
        let body = format!(
            "<html><head><title>t</title></head><body>{}</body></html>",
            "x".repeat(600_000)
        );
        let mut snapshot = crate::analyze::infra::tests::snapshot_with(200, &[("content-type", "text/html")], &body);
        let len = snapshot.page.as_ref().unwrap().body.len() as u64;
        snapshot.page.as_mut().unwrap().transferred = len;
        let content = crate::analyze::content::content(&snapshot);
        let module = analyze(&snapshot, &content);
        let size = format_bytes(len);
        assert_eq!(size, "600 KB");
        for id in ["weight.uncompressed", "weight.html_large"] {
            let f = module
                .findings
                .iter()
                .find(|f| f.id == id)
                .unwrap_or_else(|| panic!("{id}"));
            assert_eq!(f.params["size"], size);
            assert!(f.title.contains(&size), "{}", f.title);
        }
    }
}
