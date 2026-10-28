//! Turns what the user typed into the URL we fetch.

use url::{Host, Url};

#[derive(Debug, Clone)]
pub struct Target {
    pub url: Url,
    /// The input named a non-default port, which disables the port 80 check.
    pub explicit_port: bool,
}

impl Target {
    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err("empty URL".into());
        }
        let with_scheme = if trimmed.contains("://") {
            trimmed.to_owned()
        } else {
            format!("https://{trimmed}")
        };
        // The url crate applies UTS 46, so `açaí.com.br` becomes `xn--aa-...`.
        let mut url = Url::parse(&with_scheme).map_err(|e| format!("invalid URL `{trimmed}`: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(format!("unsupported scheme `{}`: only http and https", url.scheme()));
        }
        if url.host().is_none() {
            return Err(format!("URL `{trimmed}` has no host"));
        }
        url.set_fragment(None);
        // `Url::port` is None for the scheme's default port, so `:443` is not explicit.
        let explicit_port = url.port().is_some();
        Ok(Target { url, explicit_port })
    }

    pub fn is_ip_literal(&self) -> bool {
        !matches!(self.url.host(), Some(Host::Domain(_)))
    }
}

/// The host as people write it: `açaí.com.br`, not `xn--aa-...`.
pub fn display_host(url: &Url) -> String {
    match url.host() {
        Some(Host::Domain(domain)) => idna::domain_to_unicode(domain).0,
        Some(host) => host.to_string(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_domain_becomes_https() {
        let t = Target::parse("exemplo.com.br").unwrap();
        assert_eq!(t.url.as_str(), "https://exemplo.com.br/");
        assert!(!t.explicit_port);
    }

    #[test]
    fn default_port_is_not_explicit() {
        assert!(!Target::parse("https://exemplo.com:443/").unwrap().explicit_port);
        assert!(Target::parse("https://exemplo.com:8443/").unwrap().explicit_port);
    }

    #[test]
    fn idn_goes_to_punycode_and_back() {
        let t = Target::parse("açaí.com.br/cardápio").unwrap();
        assert_eq!(t.url.host_str(), Some("xn--aa-4iaz.com.br"));
        assert_eq!(display_host(&t.url), "açaí.com.br");
    }

    #[test]
    fn ip_literal_and_fragment() {
        let t = Target::parse("http://192.0.2.10/a#b").unwrap();
        assert!(t.is_ip_literal());
        assert_eq!(t.url.as_str(), "http://192.0.2.10/a");
    }

    #[test]
    fn rejects_other_schemes() {
        assert!(Target::parse("ftp://exemplo.com").is_err());
        assert!(Target::parse("  ").is_err());
    }
}
