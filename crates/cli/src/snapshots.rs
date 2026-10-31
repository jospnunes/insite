//! `--save` and `--from`: snapshots on disk, one JSON document per line,
//! gzip-compressed when the file name ends in `.gz`.

use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use flate2::Compression;
use flate2::read::MultiGzDecoder;
use flate2::write::GzEncoder;
use insite_core::analyze::analyze_selected;
use insite_core::report::Selection;
use insite_core::snapshot::Snapshot;

use crate::live::theme::Theme;
use crate::live::{self, Saved};
use crate::run::{Printer, write_out};
use crate::{Format, style};

pub enum Writer {
    Plain(BufWriter<File>),
    Gzip(GzEncoder<BufWriter<File>>),
}

impl Writer {
    pub fn create(path: &Path) -> Result<Self, String> {
        let file = File::create(path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        let file = BufWriter::new(file);
        Ok(if gzipped(path) {
            Writer::Gzip(GzEncoder::new(file, Compression::default()))
        } else {
            Writer::Plain(file)
        })
    }

    pub fn write(&mut self, snapshot: &Snapshot) -> std::io::Result<()> {
        let line = snapshot.to_json() + "\n";
        match self {
            Writer::Plain(w) => w.write_all(line.as_bytes()),
            Writer::Gzip(w) => w.write_all(line.as_bytes()),
        }
    }

    pub fn finish(self) -> std::io::Result<()> {
        match self {
            Writer::Plain(mut w) => w.flush(),
            Writer::Gzip(w) => w.finish()?.flush(),
        }
    }
}

fn gzipped(path: &Path) -> bool {
    path.extension().is_some_and(|e| e.eq_ignore_ascii_case("gz"))
}

/// Reads every snapshot in a file: one per line, or a single document.
pub fn read(path: &Path) -> Result<Vec<Snapshot>, String> {
    let file = File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut text = String::new();
    let read = if gzipped(path) {
        MultiGzDecoder::new(file).read_to_string(&mut text)
    } else {
        std::io::BufReader::new(file).read_to_string(&mut text)
    };
    read.map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if let Ok(one) = Snapshot::from_json(&text) {
        return Ok(vec![one]);
    }
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(n, line)| Snapshot::from_json(line).map_err(|e| format!("{} line {}: {e}", path.display(), n + 1)))
        .collect()
}

pub fn analyze_saved(path: &Path, selection: Selection, format: Format) -> ExitCode {
    let snapshots = match read(path) {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return crate::usage_error(&format!("{} has no snapshots", path.display())),
        Err(e) => return crate::usage_error(&e),
    };
    if selection.contains(insite_core::report::ModuleName::Stack) {
        insite_core::detect::warm_up();
    }
    let mut printer = Printer::new(format, snapshots.len());
    if let Format::Live { verbose } = format {
        // The live view's final frames, printed once: nothing moves.
        let saved: Vec<Saved> = snapshots
            .iter()
            .enumerate()
            .map(|(i, snapshot)| {
                let full = analyze_selected(snapshot, selection);
                printer.print(i, &full);
                Saved {
                    browser: snapshot.browser.is_some(),
                    full,
                }
            })
            .collect();
        let lines = live::saved_lines(&saved, verbose, style::terminal_width(), &Theme::detect());
        write_out(&(lines.join("\n") + "\n"));
        return printer.finish();
    }
    for (i, snapshot) in snapshots.iter().enumerate() {
        printer.print(i, &analyze_selected(snapshot, selection));
    }
    printer.finish()
}
