//! Compiles the embedded webappanalyzer signatures into the detection index.

use std::path::{Path, PathBuf};

fn main() {
    let dir = Path::new("data/webappanalyzer");
    println!("cargo:rerun-if-changed=data/webappanalyzer");
    let (index, report) = insite_sigc::compile_dir(dir).unwrap_or_else(|e| panic!("signatures: {e}"));
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));
    std::fs::write(
        out.join("index.json"),
        serde_json::to_vec(&index).expect("index serializes"),
    )
    .expect("write index");

    let mut log = format!(
        "{} technologies, {} patterns ({} fancy-regex, {} without prefilter), {} dropped\n",
        report.techs,
        report.patterns,
        report.fancy,
        report.always_run,
        report.dropped.len()
    );
    for d in &report.dropped {
        log.push_str(&format!("{} [{}] {}: {}\n", d.tech, d.field, d.pattern, d.reason));
    }
    std::fs::write(out.join("sigc-report.txt"), log).expect("write report");
}
