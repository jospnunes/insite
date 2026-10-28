//! What the signatures look at, gathered from the snapshot and the page facts.

use std::collections::HashMap;

use insite_sigc::index::Field;

use super::dom::ElementIndex;

#[derive(Default)]
pub struct Inputs<'a> {
    /// Lowercase name and value; repeated headers stay separate.
    pub headers: Vec<(String, String)>,
    /// Lowercase cookie names from every `Set-Cookie` in the chain, with values.
    pub cookies: Vec<(String, String)>,
    /// `<meta>` name or property, lowercase, and content.
    pub meta: Vec<(String, String)>,
    /// DNS record type and record.
    pub dns: Vec<(String, String)>,
    /// JavaScript property path and its value, from the browser.
    pub js: Vec<(String, String)>,
    pub script_src: Vec<String>,
    /// Inline script contents.
    pub scripts: Vec<String>,
    pub html: Option<&'a str>,
    pub text: Option<String>,
    pub url: Vec<String>,
    pub robots: Option<String>,
    pub cert_issuer: Option<String>,
    pub xhr: Vec<String>,
    pub elements: Option<ElementIndex<'a>>,
    /// Element property values a browser read, by selector and property.
    pub dom_properties: HashMap<(String, String), Vec<String>>,
}

impl Inputs<'_> {
    /// Unkeyed fields and their contents.
    pub(super) fn lists(&self) -> Vec<(Field, Vec<&str>)> {
        fn strings(v: &[String]) -> Vec<&str> {
            v.iter().map(String::as_str).collect()
        }
        vec![
            (Field::ScriptSrc, strings(&self.script_src)),
            (Field::Scripts, strings(&self.scripts)),
            (Field::Html, self.html.into_iter().collect()),
            (Field::Text, self.text.as_deref().into_iter().collect()),
            (Field::Url, strings(&self.url)),
            (Field::Robots, self.robots.as_deref().into_iter().collect()),
            (Field::CertIssuer, self.cert_issuer.as_deref().into_iter().collect()),
            (Field::Xhr, strings(&self.xhr)),
        ]
    }

    /// Keyed fields: (field, key, values for that key).
    pub(super) fn keyed(&self) -> Vec<(Field, &str, Vec<&str>)> {
        let mut out = Vec::new();
        for (field, pairs) in [
            (Field::Headers, &self.headers),
            (Field::Cookies, &self.cookies),
            (Field::Meta, &self.meta),
            (Field::Dns, &self.dns),
            (Field::Js, &self.js),
        ] {
            let mut keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
            keys.sort_unstable();
            keys.dedup();
            for key in keys {
                let values = pairs
                    .iter()
                    .filter(|(k, _)| k == key)
                    .map(|(_, v)| v.as_str())
                    .collect();
                out.push((field, key, values));
            }
        }
        out
    }
}
