//! The stack of open elements, with the implied end tags of the HTML parsing
//! algorithm that matter for descendant selectors. Not the full tree-construction
//! algorithm: enough that `<p>` and `<li>` left open do not swallow the rest of
//! the page.

use super::Element;

const VOID: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr",
];

/// Elements whose start tag closes an open `<p>`.
const CLOSES_P: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "details",
    "dialog",
    "div",
    "dl",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hgroup",
    "hr",
    "main",
    "menu",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "ul",
];

/// Elements that only appear in the body; seeing one means the head is over even
/// when the page omits `<body>`.
const BODY_CONTENT: &[&str] = &[
    "a", "article", "aside", "div", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "img", "main",
    "nav", "p", "section", "span", "table", "ul", "ol", "button", "input", "iframe", "video",
];

pub fn is_void(tag: &str) -> bool {
    VOID.contains(&tag)
}

pub fn starts_body_content(tag: &str) -> bool {
    BODY_CONTENT.contains(&tag)
}

/// Pops the elements that `tag`'s start tag implicitly closes.
pub fn close_implied(tag: &str, stack: &mut Vec<usize>, elements: &[Element]) {
    let top = |stack: &Vec<usize>| stack.last().map(|&i| elements[i].tag.as_str());
    if CLOSES_P.contains(&tag) && top(stack) == Some("p") {
        stack.pop();
    }
    match tag {
        "li" => pop_through(stack, elements, &["li"], &["ul", "ol", "menu"]),
        "dt" | "dd" => pop_through(stack, elements, &["dt", "dd"], &["dl"]),
        "option" if top(stack) == Some("option") => {
            stack.pop();
        }
        "optgroup" => pop_through(stack, elements, &["option", "optgroup"], &["select"]),
        "tr" => pop_through(stack, elements, &["tr"], &["table", "thead", "tbody", "tfoot"]),
        "td" | "th" => pop_through(stack, elements, &["td", "th"], &["tr", "table"]),
        "thead" | "tbody" | "tfoot" => pop_through(stack, elements, &["thead", "tbody", "tfoot"], &["table"]),
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" if top(stack).is_some_and(is_heading) => {
            stack.pop();
        }
        "body" if top(stack) == Some("head") => {
            stack.pop();
        }
        _ => {}
    }
}

fn is_heading(tag: &str) -> bool {
    matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6")
}

/// Pops up to and including the nearest element named in `targets`, unless a
/// `boundary` element comes first (then nothing is popped).
fn pop_through(stack: &mut Vec<usize>, elements: &[Element], targets: &[&str], boundary: &[&str]) {
    for pos in (0..stack.len()).rev() {
        let tag = elements[stack[pos]].tag.as_str();
        if boundary.contains(&tag) {
            return;
        }
        if targets.contains(&tag) {
            stack.truncate(pos);
            return;
        }
    }
}
