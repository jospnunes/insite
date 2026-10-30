use super::*;
use crate::extract::extract;
use url::Url;

fn engine_for(technologies: &str) -> Engine {
    let sources = insite_sigc::Sources {
        technologies: vec![technologies],
        categories: r#"{"1": {"name": "CMS", "priority": 1}, "2": {"name": "Programming languages", "priority": 5}, "3": {"name": "Ecommerce", "priority": 1}}"#,
        source: "test".into(),
        source_date: "2026-01-01".into(),
    };
    Engine::new(insite_sigc::compile(&sources).unwrap().0)
}

fn names(found: &[Technology]) -> Vec<String> {
    found.iter().map(|t| t.name.clone()).collect()
}

const SIGNATURES: &str = r##"{
    "WordPress": {
        "cats": [1],
        "meta": {"generator": "^WordPress ?([\\d.]+)?\\;version:\\1"},
        "html": ["<link rel=[\"']stylesheet[\"'] [^>]+/wp-(?:content|includes)/"],
        "scriptSrc": ["/wp-(?:content|includes)/"],
        "implies": ["PHP"]
    },
    "PHP": {"cats": [2], "headers": {"X-Powered-By": "^php/?([\\d.]+)?\\;version:\\1"}},
    "WooCommerce": {"cats": [3], "requires": ["WordPress"], "dom": {"body.woocommerce": {"exists": ""}}},
    "Shopify": {"cats": [3], "cookies": {"_shopify_y": ""}, "excludes": ["WordPress"]},
    "Probable": {"cats": [1], "html": ["probably-here\\;confidence:50"]},
    "Unicode": {"cats": [1], "text": ["Colis Priv[eé]"]}
}"##;

#[test]
fn detects_with_versions_evidence_and_implies() {
    let engine = engine_for(SIGNATURES);
    let html = r#"<html><head><meta name="generator" content="WordPress 6.6.2">
        <script src="/wp-includes/js/jquery.js"></script></head><body class="home woocommerce"></body></html>"#;
    let url = Url::parse("https://exemplo.com.br/").unwrap();
    let facts = extract(html.as_bytes(), Some("text/html"), &url);
    let inputs = Inputs {
        headers: vec![("x-powered-by".into(), "PHP/8.2.1".into())],
        meta: facts
            .metas
            .iter()
            .filter_map(|m| Some((m.name.clone()?.to_ascii_lowercase(), m.content.clone()?)))
            .collect(),
        script_src: facts.scripts.iter().filter_map(|s| s.src.clone()).collect(),
        html: Some(html),
        elements: Some(ElementIndex::new(&facts.elements)),
        ..Default::default()
    };
    let found = engine.detect(&inputs);
    assert_eq!(names(&found), ["WooCommerce", "WordPress", "PHP"]);
    let wp = &found[1];
    assert_eq!((wp.version.as_deref(), wp.confidence), (Some("6.6.2"), 100));
    assert!(
        wp.evidence
            .iter()
            .any(|e| e.field == "meta" && e.key.as_deref() == Some("generator"))
    );
    assert!(wp.evidence.iter().any(|e| e.field == "scriptSrc"));
    // Seen directly through its header, so not just implied.
    let php = &found[2];
    assert_eq!(
        (php.version.as_deref(), php.implied_by.as_deref()),
        (Some("8.2.1"), None)
    );
}

#[test]
fn requires_excludes_and_confidence() {
    let engine = engine_for(SIGNATURES);
    let html = "<body class=woocommerce>probably-here</body>";
    let facts = extract(
        html.as_bytes(),
        Some("text/html"),
        &Url::parse("https://x.example/").unwrap(),
    );
    let inputs = Inputs {
        cookies: vec![("_shopify_y".into(), "abc".into())],
        html: Some(html),
        elements: Some(ElementIndex::new(&facts.elements)),
        ..Default::default()
    };
    let found = engine.detect(&inputs);
    // WooCommerce needs WordPress, which was not detected.
    assert_eq!(names(&found), ["Probable", "Shopify"]);
    assert_eq!(found[0].confidence, 50);
}

#[test]
fn implied_only_technologies_say_so() {
    let engine = engine_for(SIGNATURES);
    let inputs = Inputs {
        script_src: vec!["https://x/wp-content/plugins/a.js".into()],
        ..Default::default()
    };
    let found = engine.detect(&inputs);
    let php = found.iter().find(|t| t.name == "PHP").unwrap();
    assert_eq!(php.implied_by.as_deref(), Some("WordPress"));
    assert!(php.evidence.is_empty());
}

#[test]
fn one_of_several_required_technologies_is_enough() {
    // A plugin for two platforms, as webappanalyzer writes ElasticSuite.
    let engine = engine_for(
        r#"{
        "Magento": {"cats": [3], "cookies": {"mage-cache-storage": ""}},
        "OroCommerce": {"cats": [3], "html": ["oro-commerce-marker"]},
        "Plugin": {"cats": [3], "scriptSrc": ["/plugin-tracker/"], "requires": ["OroCommerce", "Magento"]}
    }"#,
    );
    let inputs = Inputs {
        cookies: vec![("mage-cache-storage".into(), "{}".into())],
        script_src: vec!["https://x/static/plugin-tracker/a.js".into()],
        ..Default::default()
    };
    assert_eq!(names(&engine.detect(&inputs)), ["Magento", "Plugin"]);
}

#[test]
fn an_implied_technology_takes_the_version_its_implier_gives() {
    let engine = engine_for(
        r#"{
        "Magento": {"cats": [3], "cookies": {"mage-cache-storage": ""}},
        "Theme": {"cats": [1], "html": ["theme-marker"], "implies": ["Magento\\;version:2"]}
    }"#,
    );
    let inputs = Inputs {
        html: Some("theme-marker"),
        ..Default::default()
    };
    let found = engine.detect(&inputs);
    let magento = found.iter().find(|t| t.name == "Magento").unwrap();
    assert_eq!(magento.version.as_deref(), Some("2"));
}

#[test]
fn unicode_patterns_match() {
    let engine = engine_for(SIGNATURES);
    let inputs = Inputs {
        text: Some("Entrega por Colis Privé".into()),
        ..Default::default()
    };
    assert_eq!(names(&engine.detect(&inputs)), ["Unicode"]);
}

#[test]
fn embedded_index_loads_and_detects_common_stacks() {
    let engine = engine();
    assert!(engine.technology_count() > 7000);
    let html = r#"<html><head><meta name="generator" content="WordPress 6.6">
        <script src="https://exemplo.com.br/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
        <script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script></head><body></body></html>"#;
    let url = Url::parse("https://exemplo.com.br/").unwrap();
    let facts = extract(html.as_bytes(), Some("text/html"), &url);
    let inputs = Inputs {
        headers: vec![("server".into(), "nginx/1.24.0".into())],
        meta: vec![("generator".into(), "WordPress 6.6".into())],
        script_src: facts.scripts.iter().filter_map(|s| s.src.clone()).collect(),
        html: Some(html),
        elements: Some(ElementIndex::new(&facts.elements)),
        ..Default::default()
    };
    let found = names(&engine.detect(&inputs));
    for expected in ["WordPress", "PHP", "MySQL", "Nginx", "jQuery", "Google Analytics"] {
        assert!(found.contains(&expected.to_owned()), "{expected} not in {found:?}");
    }
    // gtag.js with a G- id is Google Analytics 4; without the corrections the
    // loose upstream pattern called it Google Tag Manager.
    assert!(!found.contains(&"Google Tag Manager".to_owned()), "{found:?}");
}
