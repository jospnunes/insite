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

const ORIGIN_SIGNATURES: &str = r##"{
    "Mailer": {"cats": [1], "dns": {"TXT": "^mailer-verification="}, "implies": ["Mail API"]},
    "Mail API": {"cats": [2]},
    "Issuer": {"cats": [1], "certIssuer": "Some Issuer"},
    "Builder": {"cats": [1], "headers": {"x-built-with": "builder"}, "implies": ["Runtime", "Mail API"]},
    "Runtime": {"cats": [2]},
    "Both": {"cats": [1], "dns": {"TXT": "both-record"}, "headers": {"x-both": ""}},
    "Chain": {"cats": [1], "dns": {"TXT": "chain-record"}, "implies": ["Middle"]},
    "Middle": {"cats": [2], "implies": ["End"]},
    "End": {"cats": [2]}
}"##;

fn origins(found: &[Technology]) -> Vec<(String, TechOrigin)> {
    found.iter().map(|t| (t.name.clone(), t.origin)).collect()
}

fn origin_of(found: &[Technology], name: &str) -> TechOrigin {
    found.iter().find(|t| t.name == name).unwrap().origin
}

#[test]
fn origin_follows_the_evidence_field() {
    let engine = engine_for(ORIGIN_SIGNATURES);
    let inputs = Inputs {
        dns: vec![("TXT".into(), "mailer-verification=abc".into())],
        cert_issuer: Some("Some Issuer Inc".into()),
        headers: vec![("x-both".into(), "1".into())],
        ..Default::default()
    };
    let found = engine.detect(&inputs);
    assert_eq!(origin_of(&found, "Mailer"), TechOrigin::Dns);
    assert_eq!(origin_of(&found, "Issuer"), TechOrigin::Certificate);
    // Seen through a header and no DNS record here: the page.
    assert_eq!(origin_of(&found, "Both"), TechOrigin::Page);
}

#[test]
fn page_wins_over_dns_when_a_technology_has_both() {
    let engine = engine_for(ORIGIN_SIGNATURES);
    let inputs = Inputs {
        dns: vec![("TXT".into(), "both-record".into())],
        headers: vec![("x-both".into(), "1".into())],
        ..Default::default()
    };
    let found = engine.detect(&inputs);
    assert_eq!(origin_of(&found, "Both"), TechOrigin::Page);
    let dns_only = engine.detect(&Inputs {
        dns: vec![("TXT".into(), "both-record".into())],
        ..Default::default()
    });
    assert_eq!(origin_of(&dns_only, "Both"), TechOrigin::Dns);
}

#[test]
fn an_implied_technology_inherits_the_origin_of_its_implier() {
    let engine = engine_for(ORIGIN_SIGNATURES);
    let dns_only = engine.detect(&Inputs {
        dns: vec![("TXT".into(), "mailer-verification=abc".into())],
        ..Default::default()
    });
    assert_eq!(
        origins(&dns_only),
        [
            ("Mailer".to_owned(), TechOrigin::Dns),
            ("Mail API".to_owned(), TechOrigin::Dns)
        ]
    );
    // Implied through a chain: dns all the way down.
    let chain = engine.detect(&Inputs {
        dns: vec![("TXT".into(), "chain-record".into())],
        ..Default::default()
    });
    assert!(
        chain.iter().all(|t| t.origin == TechOrigin::Dns),
        "{:?}",
        origins(&chain)
    );
    assert_eq!(chain.len(), 3);
}

#[test]
fn an_implied_technology_is_page_if_any_implier_is_page() {
    let engine = engine_for(ORIGIN_SIGNATURES);
    // Mail API is implied by Mailer (dns) and by Builder (page).
    let found = engine.detect(&Inputs {
        dns: vec![("TXT".into(), "mailer-verification=abc".into())],
        headers: vec![("x-built-with".into(), "builder".into())],
        ..Default::default()
    });
    assert_eq!(origin_of(&found, "Mailer"), TechOrigin::Dns);
    assert_eq!(origin_of(&found, "Mail API"), TechOrigin::Page);
    assert_eq!(origin_of(&found, "Runtime"), TechOrigin::Page);
}

#[test]
fn a_larger_origin_reaching_a_found_technology_passes_down() {
    let engine = engine_for(
        r#"{
        "Seed": {"cats": [1], "dns": {"TXT": "seed"}, "implies": ["Mid"]},
        "Page": {"cats": [1], "headers": {"x-page": ""}, "implies": ["Mid"]},
        "Mid": {"cats": [2], "implies": ["Tail"]},
        "Tail": {"cats": [2]}
    }"#,
    );
    let found = engine.detect(&Inputs {
        dns: vec![("TXT".into(), "seed".into())],
        headers: vec![("x-page".into(), "1".into())],
        ..Default::default()
    });
    assert_eq!(origin_of(&found, "Seed"), TechOrigin::Dns);
    assert_eq!(origin_of(&found, "Mid"), TechOrigin::Page);
    assert_eq!(origin_of(&found, "Tail"), TechOrigin::Page);
}

#[test]
fn the_origin_is_in_the_json() {
    let engine = engine_for(ORIGIN_SIGNATURES);
    let found = engine.detect(&Inputs {
        cert_issuer: Some("Some Issuer Inc".into()),
        ..Default::default()
    });
    let json = serde_json::to_value(&found[0]).unwrap();
    assert_eq!(json["origin"], "certificate");
    assert!(json.get("priority").is_none());
}

#[test]
fn warnings_are_held_back_until_taken() {
    // One test for the shared state: nothing is held unless asked to.
    warn("not held".into());
    assert!(take_warnings().is_empty());
    defer_warnings();
    warn("first".into());
    warn("second".into());
    assert_eq!(take_warnings(), ["first", "second"]);
    // Taking ends the deferral: the next warning goes to stderr, not into the list.
    warn("printed".into());
    assert!(take_warnings().is_empty());
}
