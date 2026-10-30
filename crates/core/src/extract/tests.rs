use super::*;

fn page(html: &str) -> PageFacts {
    extract(
        html.as_bytes(),
        Some("text/html; charset=utf-8"),
        &Url::parse("https://exemplo.com.br/loja/").unwrap(),
    )
}

fn parent_tag(facts: &PageFacts, tag: &str, nth: usize) -> Option<String> {
    let el = facts.elements.iter().filter(|e| e.tag == tag).nth(nth)?;
    el.parent.map(|p| facts.elements[p].tag.clone())
}

#[test]
fn head_facts() {
    let facts = page(
        r#"<!doctype html><html lang="pt-BR"><head>
        <title>  Loja   Exemplo </title>
        <meta name="description" content="Tudo para sua casa">
        <meta property="og:title" content="Loja">
        <link rel="canonical" href="/loja/">
        <link rel="stylesheet preload" href="app.css">
        <script src="/js/app.js"></script>
        <script src="/js/late.js" defer></script>
        <script type="module" src="/js/mod.js"></script>
        <script type="application/ld+json">{"@type":"Organization"}</script>
        </head><body><h1>Olá <span>mundo</span></h1><img src="a.png"><img src="b.webp" alt="">
        <script>window.x = 1;</script></body></html>"#,
    );
    assert_eq!(facts.lang.as_deref(), Some("pt-BR"));
    assert_eq!(normalize_space(&facts.titles[0]), "Loja Exemplo");
    assert_eq!(facts.meta("description"), Some("Tudo para sua casa"));
    assert_eq!(facts.meta_property("og:title"), Some("Loja"));
    let canonical: Vec<_> = facts.links_with_rel("canonical").collect();
    assert_eq!(canonical[0].href.as_deref(), Some("https://exemplo.com.br/loja/"));
    assert_eq!(facts.links_with_rel("stylesheet").count(), 1);

    let blocking: Vec<_> = facts.scripts.iter().filter(|s| s.blocks_rendering()).collect();
    assert_eq!(blocking.len(), 1);
    assert_eq!(blocking[0].src.as_deref(), Some("https://exemplo.com.br/js/app.js"));
    assert_eq!(facts.json_ld, [r#"{"@type":"Organization"}"#]);
    let inline = facts.scripts.iter().find(|s| s.src.is_none() && !s.in_head).unwrap();
    assert_eq!(inline.inline.as_deref(), Some("window.x = 1;"));

    assert_eq!(facts.headings, [(1, "Olá mundo".to_owned())]);
    assert_eq!(facts.images.len(), 2);
    assert_eq!(facts.images[0].alt, None);
    assert_eq!(facts.images[1].alt.as_deref(), Some(""));
    assert_eq!(
        facts.images[0].src.as_deref(),
        Some("https://exemplo.com.br/loja/a.png")
    );
}

#[test]
fn implied_end_tags_keep_ancestors_right() {
    let facts = page("<body><ul><li>a<li>b</ul><p>text<div class=x>block</div><table><tr><td>1<td>2<tr><td>3</table>");
    // The second <li> is a sibling, not a child, of the first.
    assert_eq!(parent_tag(&facts, "li", 1).as_deref(), Some("ul"));
    // A <div> closes the open <p>.
    assert_eq!(parent_tag(&facts, "div", 0).as_deref(), Some("body"));
    assert_eq!(parent_tag(&facts, "td", 1).as_deref(), Some("tr"));
    assert_eq!(parent_tag(&facts, "tr", 1).as_deref(), Some("table"));
}

#[test]
fn end_tags_close_what_was_left_open() {
    let facts = page("<div id=a><span>x<b>y</div><footer>z</footer>");
    assert_eq!(parent_tag(&facts, "footer", 0), None);
}

#[test]
fn base_href_changes_resolution() {
    let facts = page(r#"<head><base href="https://cdn.example/assets/"></head><body><img src="x.png">"#);
    assert_eq!(facts.images[0].src.as_deref(), Some("https://cdn.example/assets/x.png"));
}

#[test]
fn head_ends_at_body_content_even_without_tags() {
    let facts = page("<title>t</title><script src=a.js></script><div>x</div><script src=b.js></script>");
    let in_head: Vec<bool> = facts.scripts.iter().map(|s| s.in_head).collect();
    assert_eq!(in_head, [true, false]);
}

#[test]
fn latin1_pages_decode() {
    let facts = extract(
        b"<html><head><meta charset=iso-8859-1><title>Promo\xe7\xe3o</title>",
        Some("text/html"),
        &Url::parse("https://exemplo.com.br/").unwrap(),
    );
    assert_eq!(facts.titles, ["Promoção"]);
    assert_eq!(facts.charset_source, "meta tag");
}

#[test]
fn element_index_keeps_attributes_and_text() {
    let facts = page(r#"<div id="app" data-reactroot=""><p class="note">hello</p></div>"#);
    let div = facts.elements.iter().find(|e| e.tag == "div").unwrap();
    assert_eq!(div.attr("id"), Some("app"));
    assert_eq!(div.attr("data-reactroot"), Some(""));
    let p = facts.elements.iter().find(|e| e.tag == "p").unwrap();
    assert_eq!(p.text, "hello");
}

#[test]
fn malformed_input_does_not_panic() {
    for html in [
        "<",
        "<<<>>>",
        "<script>",
        "</div></div>",
        "<svg><path/></svg><p>x",
        "\u{0}\u{feff}<a href=\"x",
    ] {
        let _ = page(html);
    }
}

fn depth_of(facts: &PageFacts, mut i: usize) -> usize {
    let mut depth = 0;
    while let Some(p) = facts.elements[i].parent {
        depth += 1;
        i = p;
    }
    depth
}

#[test]
fn hostile_nesting_is_linear() {
    // Open elements that never close, then table cells whose target is not open:
    // every `<td>` used to walk the whole stack.
    let mut html = String::from("<body>");
    html.push_str(&"<b>".repeat(200_000));
    html.push_str(&"<td></td>".repeat(50_000));
    let started = std::time::Instant::now();
    let facts = page(&html);
    let elapsed = started.elapsed();
    assert!(elapsed.as_secs() < 10, "extraction took {elapsed:?}");
    assert_eq!(facts.elements.iter().filter(|e| e.tag == "td").count(), 50_000);
    let deepest = (0..facts.elements.len()).map(|i| depth_of(&facts, i)).max().unwrap();
    assert!(deepest <= 512, "nesting depth {deepest}");
}

#[test]
fn hostile_end_tags_are_linear() {
    let mut html = String::from("<body>");
    html.push_str(&"<b>".repeat(100_000));
    html.push_str(&"<i></i>".repeat(100_000));
    html.push_str(&"</b>".repeat(100_000));
    let started = std::time::Instant::now();
    let facts = page(&html);
    let elapsed = started.elapsed();
    assert!(elapsed.as_secs() < 10, "extraction took {elapsed:?}");
    assert_eq!(facts.elements.len(), 1 + 100_000 + 100_000);
}

#[test]
fn deep_nesting_still_closes_correctly() {
    let mut html = String::from("<div id=top>");
    html.push_str(&"<section>".repeat(600));
    html.push_str("<span>x</span>");
    html.push_str(&"</section>".repeat(600));
    html.push_str("</div><footer>z</footer>");
    let facts = page(&html);
    // Past the cap elements hang off the deepest open one, and their end tags do
    // not close anything else.
    assert_eq!(parent_tag(&facts, "footer", 0), None);
    assert!(parent_tag(&facts, "span", 0).is_some());
    assert_eq!(facts.elements.iter().filter(|e| e.tag == "section").count(), 600);
}

#[test]
fn script_past_the_depth_cap_is_still_read() {
    let mut html = String::from("<body>");
    html.push_str(&"<div>".repeat(600));
    html.push_str(r#"<script type="application/ld+json">{"a":1}</script><p>after</p>"#);
    let facts = page(&html);
    assert_eq!(facts.json_ld, [r#"{"a":1}"#]);
    assert_eq!(facts.scripts.len(), 1);
}

#[test]
fn svg_titles_are_not_document_titles() {
    let facts = page(
        "<head><title>Real</title></head><body><svg><g><title>Logo</title></g></svg>\
         <math><title>m</title></math><p>x</p></body>",
    );
    assert_eq!(facts.titles, ["Real"]);
    // The svg element itself is still indexed.
    assert!(facts.elements.iter().any(|e| e.tag == "svg"));
    // After the svg closes, a title in HTML counts again.
    let facts = page("<body><svg><title>a</title></svg><title>Late</title>");
    assert_eq!(facts.titles, ["Late"]);
}
