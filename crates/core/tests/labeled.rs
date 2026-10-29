//! Detection precision on the hand-labeled sites of `bench/labels.tsv`, analyzed
//! from their recorded snapshots. The snapshots hold third-party HTML, so they
//! live in the private fixtures repository: the test runs when `INSITE_FIXTURES`
//! points to a checkout of it and passes trivially otherwise.
//!
//! Every detection must have a label, so a change in what is detected shows up
//! here and gets labeled; precision is the correct share of the labeled ones
//! that are not uncertain.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use insite_core::analyze::analyze;
use insite_core::snapshot::Snapshot;

/// The v0.1 exit criterion (docs/arquitetura.md, "Roadmap").
const MIN_PRECISION: f64 = 0.95;

fn fixtures() -> Option<PathBuf> {
    std::env::var_os("INSITE_FIXTURES").map(PathBuf::from)
}

/// (site, technology, version) to verdict.
fn labels() -> BTreeMap<(String, String, String), String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/labels.tsv");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with("site\t") && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            ((f[0].to_owned(), f[1].to_owned(), f[2].to_owned()), f[3].to_owned())
        })
        .collect()
}

fn snapshot(path: &Path) -> Snapshot {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut text = String::new();
    flate2::read::MultiGzDecoder::new(file)
        .read_to_string(&mut text)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Snapshot::from_json(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn detection_precision_on_the_labeled_sites() {
    let Some(dir) = fixtures() else {
        eprintln!("skipped: set INSITE_FIXTURES to a checkout of the fixtures repository");
        return;
    };
    let labels = labels();
    // Every recorded site, also those with nothing detected (a bot challenge).
    let sites: BTreeSet<String> = std::fs::read_dir(dir.join("snapshots"))
        .expect("the fixtures have a snapshots directory")
        .filter_map(|e| {
            e.ok()?
                .file_name()
                .to_str()?
                .strip_suffix(".json.gz")
                .map(str::to_owned)
        })
        .collect();

    let (mut correct, mut wrong, mut uncertain) = (0, 0, 0);
    let mut unlabeled = Vec::new();
    let mut wrong_ones = Vec::new();
    for site in &sites {
        let report = analyze(&snapshot(&dir.join("snapshots").join(format!("{site}.json.gz"))));
        let technologies = report.modules.stack.data.map(|s| s.technologies).unwrap_or_default();
        for t in technologies {
            let key = (site.clone(), t.name.clone(), t.version.clone().unwrap_or_default());
            match labels.get(&key).map(String::as_str) {
                Some("correct") => correct += 1,
                Some("wrong") => {
                    wrong += 1;
                    wrong_ones.push(format!("{site} {}", t.name));
                }
                Some("uncertain") => uncertain += 1,
                _ => unlabeled.push(format!("{site}\t{}\t{}", t.name, key.2)),
            }
        }
    }
    let precision = correct as f64 / (correct + wrong) as f64;
    eprintln!(
        "{} sites: {correct} correct, {wrong} wrong, {uncertain} uncertain; precision {precision:.3}",
        sites.len()
    );
    eprintln!("wrong: {}", wrong_ones.join(", "));

    assert!(
        unlabeled.is_empty(),
        "detections without a label in bench/labels.tsv:\n{}",
        unlabeled.join("\n")
    );
    assert!(
        precision >= MIN_PRECISION,
        "precision {precision:.3} below {MIN_PRECISION}"
    );
}
