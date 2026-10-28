//! HTML extraction: one pass over the page body into `PageFacts`, the facts every
//! analyzer needs, plus an element index that signature selectors run against.
//!
//! It runs in the analysis, over the body stored in the snapshot, so `--from` can
//! re-extract with a newer extractor.

mod charset;
mod stack;

use std::cell::RefCell;
use std::rc::Rc;

use lol_html::{HtmlRewriter, Settings, doc_text, element};
use serde::Serialize;
use url::Url;

pub use charset::{decode, sniff_html};
use stack::{is_void, starts_body_content};

/// Text kept per element, for signature `text` conditions.
const ELEMENT_TEXT_LIMIT: usize = 256;
/// Inline script text kept for signature matching.
const INLINE_SCRIPT_LIMIT: usize = 64 << 10;
const JSON_LD_LIMIT: usize = 256 << 10;
const TITLE_LIMIT: usize = 1024;
const HEADING_LIMIT: usize = 300;

#[derive(Debug, Clone, Default)]
pub struct PageFacts {
    /// Encoding the body was decoded with, and where it came from.
    pub charset: String,
    pub charset_source: &'static str,
    pub lang: Option<String>,
    /// Every `<title>` in the document; normally one.
    pub titles: Vec<String>,
    pub metas: Vec<Meta>,
    pub links: Vec<Link>,
    pub scripts: Vec<Script>,
    pub images: Vec<Image>,
    /// `(level, text)` in document order.
    pub headings: Vec<(u8, String)>,
    pub iframes: Vec<String>,
    pub forms: Vec<Form>,
    pub json_ld: Vec<String>,
    pub inline_styles: usize,
    pub inline_style_bytes: usize,
    pub anchors: usize,
    /// Every element with its attributes and parent, without a DOM.
    pub elements: Vec<Element>,
    /// Characters of the decoded document.
    pub html_chars: usize,
    /// The decoded document, for signatures that match raw HTML.
    pub html: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Meta {
    pub name: Option<String>,
    pub property: Option<String>,
    pub http_equiv: Option<String>,
    pub content: Option<String>,
    pub charset: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Link {
    /// Lowercase tokens.
    pub rel: Vec<String>,
    pub href: Option<String>,
    pub hreflang: Option<String>,
    pub as_: Option<String>,
    pub media: Option<String>,
    pub in_head: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Script {
    /// Resolved against the page URL.
    pub src: Option<String>,
    /// The attribute as written, for checks that depend on its form
    /// (relative, protocol-relative or absolute).
    pub src_attr: Option<String>,
    pub kind: Option<String>,
    pub is_async: bool,
    pub defer: bool,
    pub module: bool,
    pub integrity: bool,
    pub in_head: bool,
    /// First 64 KB of an inline script.
    pub inline: Option<String>,
    pub inline_bytes: usize,
}

impl Script {
    /// Classic scripts in the head without async or defer stop rendering until
    /// they download and run. Modules are deferred by default; data blocks
    /// (JSON-LD, templates) never run.
    pub fn blocks_rendering(&self) -> bool {
        let executable = self
            .kind
            .as_deref()
            .is_none_or(|t| t.is_empty() || t.contains("javascript") || t.contains("ecmascript"));
        self.in_head && self.src.is_some() && executable && !self.module && !self.is_async && !self.defer
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Image {
    pub src: Option<String>,
    /// `None` when the attribute is absent; `Some("")` marks a decorative image.
    pub alt: Option<String>,
    pub lazy: bool,
    pub has_dimensions: bool,
    pub srcset: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Form {
    pub action: Option<String>,
    pub method: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Element {
    pub tag: String,
    pub attrs: Vec<(String, String)>,
    pub parent: Option<usize>,
    /// Direct text, first 256 characters.
    pub text: String,
}

impl Element {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

impl PageFacts {
    pub fn meta(&self, name: &str) -> Option<&str> {
        self.metas
            .iter()
            .find(|m| m.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(name)))
            .and_then(|m| m.content.as_deref())
    }

    pub fn meta_property(&self, property: &str) -> Option<&str> {
        self.metas
            .iter()
            .find(|m| m.property.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(property)))
            .and_then(|m| m.content.as_deref())
    }

    pub fn links_with_rel<'a>(&'a self, rel: &'a str) -> impl Iterator<Item = &'a Link> + 'a {
        self.links.iter().filter(move |l| l.rel.iter().any(|r| r == rel))
    }
}

/// Extracts the facts of an HTML body. `content_type` is the response header,
/// used for the charset; `page_url` resolves relative URLs.
pub fn extract(body: &[u8], content_type: Option<&str>, page_url: &Url) -> PageFacts {
    let (text, charset, charset_source) = decode(body, content_type);
    let state = Rc::new(RefCell::new(State::new(page_url.clone())));
    {
        let on_element = state.clone();
        let on_text = state.clone();
        let settings = Settings::new()
            .with_strict(false)
            .append_element_content_handler(element!("*", move |el| {
                let tag = el.tag_name();
                let attrs: Vec<(String, String)> = el.attributes().iter().map(|a| (a.name(), a.value())).collect();
                let pushed = on_element.borrow_mut().open(&tag, attrs, el.can_have_content());
                if pushed && let Some(handlers) = el.end_tag_handlers() {
                    let on_end = on_element.clone();
                    let handler: lol_html::EndTagHandler<'static> = Box::new(move |_end| {
                        on_end.borrow_mut().close(&tag);
                        Ok(())
                    });
                    handlers.push(handler);
                }
                Ok(())
            }))
            .append_document_content_handler(doc_text!(move |chunk| {
                on_text.borrow_mut().text(chunk.as_str());
                Ok(())
            }));
        let mut rewriter = HtmlRewriter::new(settings, |_: &[u8]| {});
        // Malformed input only ends extraction early; what was seen is kept.
        let _ = rewriter.write(text.as_bytes()).and_then(|()| rewriter.end());
    }
    let state = Rc::try_unwrap(state)
        .map(RefCell::into_inner)
        .unwrap_or_else(|rc| rc.borrow().clone());
    let mut facts = state.facts;
    facts.charset = charset.to_owned();
    facts.charset_source = charset_source;
    facts.elements = state.elements;
    facts.html_chars = text.chars().count();
    facts.html = text.into_owned();
    facts
}

#[derive(Clone)]
struct State {
    base: Url,
    base_set: bool,
    facts: PageFacts,
    elements: Vec<Element>,
    stack: Vec<usize>,
    in_body: bool,
    /// Index into `facts.scripts` of the script being read, with its JSON-LD slot.
    open_script: Option<(usize, Option<usize>)>,
    open_title: Option<usize>,
    open_heading: Option<usize>,
    in_style: bool,
}

impl State {
    fn new(base: Url) -> Self {
        State {
            base,
            base_set: false,
            facts: PageFacts::default(),
            elements: Vec::new(),
            stack: Vec::new(),
            in_body: false,
            open_script: None,
            open_title: None,
            open_heading: None,
            in_style: false,
        }
    }

    fn resolve(&self, href: &str) -> Option<String> {
        let href = href.trim();
        if href.is_empty() || href.starts_with("javascript:") || href.starts_with("data:") {
            return None;
        }
        self.base.join(href).ok().map(String::from)
    }

    /// Records an element; returns whether it was pushed on the stack of open
    /// elements (and so needs an end-tag handler).
    fn open(&mut self, tag: &str, attrs: Vec<(String, String)>, can_have_content: bool) -> bool {
        stack::close_implied(tag, &mut self.stack, &self.elements);
        if tag == "body" || starts_body_content(tag) {
            self.in_body = true;
        }
        let in_head = !self.in_body;
        let attr = |name: &str| attrs.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
        let has = |name: &str| attrs.iter().any(|(n, _)| n == name);

        match tag {
            "html" => self.facts.lang = attr("lang").filter(|l| !l.trim().is_empty()),
            "base" if !self.base_set => {
                if let Some(base) = attr("href").and_then(|h| self.base.join(&h).ok()) {
                    self.base = base;
                    self.base_set = true;
                }
            }
            "meta" => self.facts.metas.push(Meta {
                name: attr("name"),
                property: attr("property"),
                http_equiv: attr("http-equiv"),
                content: attr("content"),
                charset: attr("charset"),
            }),
            "link" => {
                let link = Link {
                    rel: attr("rel")
                        .unwrap_or_default()
                        .split_ascii_whitespace()
                        .map(str::to_ascii_lowercase)
                        .collect(),
                    href: attr("href").and_then(|h| self.resolve(&h)),
                    hreflang: attr("hreflang"),
                    as_: attr("as"),
                    media: attr("media"),
                    in_head,
                };
                self.facts.links.push(link);
            }
            "script" => {
                let kind = attr("type").map(|t| t.trim().to_ascii_lowercase());
                let json_ld = kind.as_deref() == Some("application/ld+json");
                self.facts.scripts.push(Script {
                    src: attr("src").and_then(|s| self.resolve(&s)),
                    src_attr: attr("src"),
                    module: kind.as_deref() == Some("module"),
                    kind,
                    is_async: has("async"),
                    defer: has("defer"),
                    integrity: attr("integrity").is_some_and(|v| !v.is_empty()),
                    in_head,
                    inline: None,
                    inline_bytes: 0,
                });
                let json_slot = json_ld.then(|| {
                    self.facts.json_ld.push(String::new());
                    self.facts.json_ld.len() - 1
                });
                self.open_script = Some((self.facts.scripts.len() - 1, json_slot));
            }
            "style" => {
                self.facts.inline_styles += 1;
                self.in_style = true;
            }
            "title" => {
                self.facts.titles.push(String::new());
                self.open_title = Some(self.facts.titles.len() - 1);
            }
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                let level = tag.as_bytes()[1] - b'0';
                self.facts.headings.push((level, String::new()));
                self.open_heading = Some(self.facts.headings.len() - 1);
            }
            "img" => self.facts.images.push(Image {
                src: attr("src").and_then(|s| self.resolve(&s)),
                alt: attr("alt"),
                lazy: attr("loading").is_some_and(|l| l.eq_ignore_ascii_case("lazy")),
                has_dimensions: has("width") && has("height"),
                srcset: has("srcset"),
            }),
            "iframe" => {
                if let Some(src) = attr("src").and_then(|s| self.resolve(&s)) {
                    self.facts.iframes.push(src);
                }
            }
            "form" => self.facts.forms.push(Form {
                action: attr("action").and_then(|a| self.resolve(&a)),
                method: attr("method").map(|m| m.to_ascii_lowercase()),
            }),
            "a" => self.facts.anchors += 1,
            _ => {}
        }

        let parent = self.stack.last().copied();
        self.elements.push(Element {
            tag: tag.to_owned(),
            attrs,
            parent,
            text: String::new(),
        });
        let pushed = can_have_content && !is_void(tag);
        if pushed {
            self.stack.push(self.elements.len() - 1);
        } else {
            self.end_of(tag);
        }
        pushed
    }

    /// An end tag: pops up to and including the nearest open element of that name.
    fn close(&mut self, tag: &str) {
        if let Some(pos) = self.stack.iter().rposition(|&i| self.elements[i].tag == tag) {
            self.stack.truncate(pos);
        }
        self.end_of(tag);
    }

    fn end_of(&mut self, tag: &str) {
        match tag {
            "script" => self.open_script = None,
            "style" => self.in_style = false,
            "title" => self.open_title = None,
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => self.open_heading = None,
            _ => {}
        }
    }

    fn text(&mut self, chunk: &str) {
        if chunk.is_empty() {
            return;
        }
        if let Some((script, json)) = self.open_script {
            let s = &mut self.facts.scripts[script];
            s.inline_bytes += chunk.len();
            if s.src.is_none() {
                push_capped(s.inline.get_or_insert_with(String::new), chunk, INLINE_SCRIPT_LIMIT);
            }
            if let Some(slot) = json {
                push_capped(&mut self.facts.json_ld[slot], chunk, JSON_LD_LIMIT);
            }
            return;
        }
        if self.in_style {
            self.facts.inline_style_bytes += chunk.len();
            return;
        }
        if let Some(title) = self.open_title {
            push_capped(&mut self.facts.titles[title], chunk, TITLE_LIMIT);
        }
        if let Some(heading) = self.open_heading {
            push_capped(&mut self.facts.headings[heading].1, chunk, HEADING_LIMIT);
        }
        if let Some(&top) = self.stack.last() {
            push_capped(&mut self.elements[top].text, chunk, ELEMENT_TEXT_LIMIT);
        }
    }
}

fn push_capped(target: &mut String, chunk: &str, limit: usize) {
    if target.len() >= limit {
        return;
    }
    let room = limit - target.len();
    if chunk.len() <= room {
        target.push_str(chunk);
    } else {
        let mut end = room;
        while !chunk.is_char_boundary(end) {
            end -= 1;
        }
        target.push_str(&chunk[..end]);
    }
}

/// Collapses whitespace the way it renders, for titles and headings.
pub fn normalize_space(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests;
