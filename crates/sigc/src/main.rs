//! `insite-sigc <webappanalyzer dir>`: compiles the signatures and prints what
//! was kept and dropped. For maintainers updating the embedded base.

use std::path::Path;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "crates/core/data/webappanalyzer".into());
    let dir = Path::new(&dir);
    let (index, report) = match insite_sigc::compile_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("insite-sigc: {e}");
            std::process::exit(1);
        }
    };
    println!("source: {} ({})", index.source, index.source_date);
    println!("technologies: {}", report.techs);
    println!(
        "patterns: {} ({} fancy-regex, {} without prefilter)",
        report.patterns, report.fancy, report.always_run
    );
    for (field, count) in &report.by_field {
        println!("  {field}: {count}");
    }
    println!("dropped: {}", report.dropped.len());
    for d in &report.dropped {
        println!("  {} [{}] {:?}: {}", d.tech, d.field, d.pattern, d.reason);
    }
}
