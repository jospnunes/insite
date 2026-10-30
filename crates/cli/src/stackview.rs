//! What the summary shows as the site's stack and as the services it uses.
//!
//! The JSON keeps every technology. The `stack` line is what the site is built
//! with (origin `page`); the `services` line is what only the DNS records show
//! (a mail provider, a domain-verification record), which the company uses but
//! the site is not built with. The certificate authority belongs to the `tls`
//! line. `-v` shows all of it.

use insite_core::detect::{TechOrigin, Technology};

use crate::style::Style;

/// Names the `services` line lists before it folds the rest into `+N`.
pub const SERVICES_SHOWN: usize = 6;

/// Technologies that are protocol or feature markers, not part of a stack:
/// webappanalyzer detects them from a header or a tag. They cannot be hidden
/// by category, which is too wide: HSTS is "Security" and Priority Hints is
/// "Performance", each shared with real products, and "Miscellaneous" also
/// holds Webpack, Vite and Babel, which are stack.
const MARKERS: &[&str] = &[
    "HSTS",
    "HTTP/2",
    "HTTP/3",
    "SPDY",
    "Priority Hints",
    "Open Graph",
    "RSS",
    "PWA",
    "WebSocket",
    "Websocket",
    "WebRTC",
    "X-Clacks-Overhead",
];

/// The certificate authorities are a category of their own, and the `tls` line
/// already names the issuer.
const CERTIFICATE_AUTHORITIES: &str = "SSL/TLS certificate authorities";

/// Whether a technology is a marker or a certificate authority: not stack.
pub fn is_marker(t: &Technology) -> bool {
    MARKERS.contains(&t.name.as_str()) || t.categories.iter().any(|c| c == CERTIFICATE_AUTHORITIES)
}

pub struct View<'a> {
    /// What the site is built with.
    pub stack: Vec<&'a Technology>,
    /// What only DNS shows (and, with `all`, the certificate issuer).
    pub services: Vec<&'a Technology>,
}

/// Splits the technologies by origin, each side in order of importance: the
/// category priority (lower first, as in Wappalyzer), then the name. With `all`
/// the markers stay in the stack and the certificate authority joins the
/// services.
pub fn view(technologies: &[Technology], all: bool) -> View<'_> {
    let mut stack = Vec::new();
    let mut services = Vec::new();
    for t in technologies {
        match t.origin {
            TechOrigin::Page if all || !is_marker(t) => stack.push(t),
            TechOrigin::Dns if all || !is_marker(t) => services.push(t),
            TechOrigin::Certificate if all => services.push(t),
            _ => {}
        }
    }
    for list in [&mut stack, &mut services] {
        list.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.name.cmp(&b.name)));
    }
    View { stack, services }
}

/// Name and version; a probable detection is dimmed and marked with `?`.
pub fn label(t: &Technology, s: &Style) -> String {
    let mut name = t.name.clone();
    if let Some(v) = &t.version {
        name = format!("{name} {v}");
    }
    if t.confidence < 100 {
        s.dim(&format!("{name}?"))
    } else {
        name
    }
}

/// The names of the `services` line: at most `SERVICES_SHOWN`, then `+N`;
/// all of them with `all`.
pub fn services_names(services: &[&Technology], s: &Style, all: bool) -> Vec<String> {
    let shown = if all { services.len() } else { SERVICES_SHOWN };
    let mut names: Vec<String> = services.iter().take(shown).map(|t| label(t, s)).collect();
    if services.len() > shown {
        names.push(s.dim(&format!("+{}", services.len() - shown)));
    }
    names
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use insite_core::detect::Evidence;

    pub(crate) fn tech(name: &str, priority: u8, origin: TechOrigin) -> Technology {
        let field = match origin {
            TechOrigin::Page => "html",
            TechOrigin::Dns => "dns",
            TechOrigin::Certificate => "certIssuer",
        };
        Technology {
            name: name.into(),
            version: None,
            confidence: 100,
            categories: Vec::new(),
            website: None,
            evidence: vec![Evidence {
                field,
                key: None,
                value: name.to_lowercase(),
            }],
            implied_by: None,
            origin,
            priority,
        }
    }

    fn names<'a>(list: &[&'a Technology]) -> Vec<&'a str> {
        list.iter().map(|t| t.name.as_str()).collect()
    }

    fn sample() -> Vec<Technology> {
        let mut digicert = tech("DigiCert", 9, TechOrigin::Certificate);
        digicert.categories = vec![CERTIFICATE_AUTHORITIES.to_owned()];
        let mut lets_encrypt = tech("Let's Encrypt", 9, TechOrigin::Page);
        lets_encrypt.categories = vec![CERTIFICATE_AUTHORITIES.to_owned()];
        vec![
            tech("Zoom", 10, TechOrigin::Dns),
            tech("Open Graph", 10, TechOrigin::Page),
            tech("HSTS", 9, TechOrigin::Page),
            tech("React", 8, TechOrigin::Page),
            tech("WordPress", 1, TechOrigin::Page),
            tech("Microsoft 365", 2, TechOrigin::Dns),
            tech("Webpack", 10, TechOrigin::Page),
            tech("Astro", 1, TechOrigin::Page),
            digicert,
            lets_encrypt,
        ]
    }

    #[test]
    fn the_stack_is_page_only_without_markers_in_order_of_importance() {
        let all = sample();
        let v = view(&all, false);
        // Lower priority first, then by name; the dns ones, markers and
        // certificate authorities are out. Webpack is Miscellaneous, not a marker.
        assert_eq!(names(&v.stack), ["Astro", "WordPress", "React", "Webpack"]);
    }

    #[test]
    fn services_are_the_dns_only_ones_without_the_certificate_authority() {
        let all = sample();
        let v = view(&all, false);
        assert_eq!(names(&v.services), ["Microsoft 365", "Zoom"]);
    }

    #[test]
    fn verbose_shows_everything_with_its_origin_side() {
        let all = sample();
        let v = view(&all, true);
        assert_eq!(
            names(&v.stack),
            [
                "Astro",
                "WordPress",
                "React",
                "HSTS",
                "Let's Encrypt",
                "Open Graph",
                "Webpack"
            ]
        );
        assert_eq!(names(&v.services), ["Microsoft 365", "DigiCert", "Zoom"]);
    }

    #[test]
    fn services_fold_after_six_names() {
        let s = Style::new(false);
        let many: Vec<Technology> = (0..9).map(|i| tech(&format!("Svc{i}"), 9, TechOrigin::Dns)).collect();
        let v = view(&many, false);
        let folded = services_names(&v.services, &s, false);
        assert_eq!(folded, ["Svc0", "Svc1", "Svc2", "Svc3", "Svc4", "Svc5", "+3"]);
        assert_eq!(services_names(&v.services, &s, true).len(), 9);
        // Exactly six: nothing folded.
        let six = view(&many[..6], false);
        assert_eq!(services_names(&six.services, &s, false).len(), 6);
        assert!(
            !services_names(&six.services, &s, false)
                .iter()
                .any(|n| n.starts_with('+'))
        );
    }

    #[test]
    fn a_probable_name_is_marked() {
        let mut t = tech("Maybe", 9, TechOrigin::Page);
        t.confidence = 50;
        t.version = Some("2".into());
        assert_eq!(label(&t, &Style::new(false)), "Maybe 2?");
    }
}
