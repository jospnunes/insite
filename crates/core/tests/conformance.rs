//! Agreement with the webappanalyzer JavaScript core: both engines read the
//! same static inputs of the recorded sites, with the same signatures, and our
//! detections must reach the F1 of the v0.1 criterion against the core's. A
//! divergence is a difference between the engines, not between signatures.
//!
//! The recorded sites hold third-party HTML, so they live in the private
//! fixtures repository (`snapshots/`, the hand-labeled ones, and
//! `conformance/`, the rest of the reference list). The test runs when
//! `INSITE_FIXTURES` points to a checkout of it and Node is installed, and
//! passes trivially otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use insite_core::analyze::stack::reference_case;
use insite_core::snapshot::Snapshot;

/// The v0.1 exit criterion (docs/arquitetura.md, "Roadmap").
const MIN_F1: f64 = 0.90;

fn snapshot(path: &Path) -> Snapshot {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut text = String::new();
    flate2::read::MultiGzDecoder::new(file)
        .read_to_string(&mut text)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Snapshot::from_json(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Site name to snapshot path, from both directories of the fixtures.
fn recorded(dir: &Path) -> BTreeMap<String, PathBuf> {
    ["snapshots", "conformance"]
        .iter()
        .filter_map(|sub| std::fs::read_dir(dir.join(sub)).ok())
        .flatten()
        .filter_map(|e| {
            let path = e.ok()?.path();
            let site = path.file_name()?.to_str()?.strip_suffix(".json.gz")?.to_owned();
            Some((site, path))
        })
        .collect()
}

/// Technology names and versions per site, from the JavaScript core.
fn reference(lines: Vec<String>) -> BTreeMap<String, BTreeMap<String, String>> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/conformance/reference.js");
    let mut node = Command::new("node")
        .arg(&script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("node starts");
    let mut stdin = node.stdin.take().expect("piped stdin");
    // Written from another thread so that a full stdout pipe cannot stall both.
    let writer = std::thread::spawn(move || {
        for line in lines {
            // Node died early: stop quietly, the exit status below reports it.
            if writeln!(stdin, "{line}").is_err() {
                break;
            }
        }
    });
    let mut out = BTreeMap::new();
    for line in BufReader::new(node.stdout.take().expect("piped stdout")).lines() {
        let line: serde_json::Value = serde_json::from_str(&line.expect("node output")).expect("JSON from node");
        let technologies = line["technologies"]
            .as_array()
            .expect("a list of technologies")
            .iter()
            .map(|t| {
                (
                    t["name"].as_str().unwrap_or_default().to_owned(),
                    t["version"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        out.insert(line["site"].as_str().expect("the site").to_owned(), technologies);
    }
    writer.join().expect("the writer thread");
    assert!(node.wait().expect("node ends").success(), "the reference script failed");
    out
}

#[test]
fn agrees_with_the_javascript_core() {
    let Some(dir) = std::env::var_os("INSITE_FIXTURES").map(PathBuf::from) else {
        eprintln!("skipped: set INSITE_FIXTURES to a checkout of the fixtures repository");
        return;
    };
    if Command::new("node").arg("--version").output().is_err() {
        eprintln!("skipped: node is not installed");
        return;
    }

    let mut ours: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut lines = Vec::new();
    for (site, path) in recorded(&dir) {
        // A bot challenge: neither engine is asked.
        let Some((items, detected)) = reference_case(&snapshot(&path)) else {
            continue;
        };
        lines.push(serde_json::json!({ "site": site, "items": items }).to_string());
        let found = detected
            .into_iter()
            .map(|t| (t.name, t.version.unwrap_or_default()))
            .collect();
        ours.insert(site, found);
    }
    assert!(
        !ours.is_empty(),
        "no recorded sites found in {}; check INSITE_FIXTURES",
        dir.display()
    );
    let theirs = reference(lines);

    let (mut both, mut only_ours, mut only_theirs) = (0, 0, 0);
    let mut divergences = Vec::new();
    let mut versions = Vec::new();
    for (site, found) in &ours {
        let expected = theirs
            .get(site)
            .unwrap_or_else(|| panic!("the reference script gave no result for {site}"));
        let a: BTreeSet<&String> = found.keys().collect();
        let b: BTreeSet<&String> = expected.keys().collect();
        both += a.intersection(&b).count();
        let extra: Vec<&str> = a.difference(&b).map(|s| s.as_str()).collect();
        let missing: Vec<&str> = b.difference(&a).map(|s| s.as_str()).collect();
        only_ours += extra.len();
        only_theirs += missing.len();
        if !extra.is_empty() || !missing.is_empty() {
            divergences.push(format!(
                "{site}\n    only insite: {}\n    only the core: {}",
                extra.join(", "),
                missing.join(", ")
            ));
        }
        for name in a.intersection(&b) {
            let (v, w) = (&found[*name], &expected[*name]);
            if v != w {
                versions.push(format!("{site} {name}: insite {v:?}, core {w:?}"));
            }
        }
    }
    let precision = both as f64 / (both + only_ours) as f64;
    let recall = both as f64 / (both + only_theirs) as f64;
    let f1 = 2.0 * precision * recall / (precision + recall);
    eprintln!(
        "{} sites: {both} in both, {only_ours} only insite, {only_theirs} only the core; \
         precision {precision:.3}, recall {recall:.3}, F1 {f1:.3}",
        ours.len()
    );
    eprintln!("divergences:\n  {}", divergences.join("\n  "));
    eprintln!(
        "versions that differ ({}):\n  {}",
        versions.len(),
        versions.join("\n  ")
    );
    assert!(f1 >= MIN_F1, "F1 {f1:.3} below {MIN_F1}");
}
