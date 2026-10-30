//! `insite explain`: the findings catalog from the terminal.

use std::fmt::Write as _;
use std::io::{IsTerminal, Write as _};
use std::process::ExitCode;

use insite_core::findings::{CATALOG, entry};

use crate::style::Style;

pub fn run(id: Option<&str>) -> ExitCode {
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let query = id.unwrap_or_default().trim();
    match text(query, color) {
        Some(text) => {
            write_out(&text);
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("insite: no finding `{query}`; `insite explain` lists them all");
            ExitCode::from(2)
        }
    }
}

/// Writes to stdout, ignoring a closed pipe (`insite explain | head`).
fn write_out(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes()).and_then(|_| out.flush());
}

/// One finding in full for an exact id, otherwise the ids that start with
/// `query`; `None` when nothing matches.
fn text(query: &str, color: bool) -> Option<String> {
    let s = Style::new(color);
    let mut out = String::new();
    if let Some((id, e)) = CATALOG
        .iter()
        .find(|(i, _)| *i == query)
        .and_then(|(i, _)| entry(i).map(|e| (*i, e)))
    {
        let _ = writeln!(
            out,
            "{}  {}",
            s.bold(&placeholders(e.title)),
            s.dim(&format!("{id} · {}", crate::render::severity(e.severity)))
        );
        let _ = writeln!(out, "\n{}\n", placeholders(e.detail));
        let _ = writeln!(out, "{}\n{}", s.bold("Fix"), placeholders(e.fix));
        return Some(out);
    }
    let matches: Vec<&str> = CATALOG
        .iter()
        .map(|(i, _)| *i)
        .filter(|i| i.starts_with(query))
        .collect();
    if matches.is_empty() {
        return None;
    }
    let width = matches.iter().map(|i| i.len()).max().unwrap_or(0);
    for id in matches {
        if let Some(e) = entry(id) {
            let severity = format!("{:<8}", crate::render::severity(e.severity));
            let _ = writeln!(out, "{id:<width$}  {}{}", s.dim(&severity), placeholders(e.title));
        }
    }
    Some(out)
}

/// `{days}` reads better as `<days>` outside a report.
fn placeholders(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        match rest[start..].find('}') {
            Some(end)
                if rest[start + 1..start + end]
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_') =>
            {
                out.push('<');
                out.push_str(&rest[start + 1..start + end]);
                out.push('>');
                rest = &rest[start + end + 1..];
            }
            _ => {
                out.push('{');
                rest = &rest[start + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_builds_its_text_instead_of_printing_it() {
        let (id, _) = CATALOG[0];
        let one = text(id, false).expect("a known id");
        assert!(one.contains(id) && one.contains("Fix"), "{one}");
        let all = text("", false).expect("the whole catalog");
        assert_eq!(all.lines().count(), CATALOG.len());
        assert_eq!(text("no.such.finding", false), None);
    }

    #[test]
    fn placeholders_become_angle_brackets() {
        assert_eq!(placeholders("expires in {days} days"), "expires in <days> days");
        assert_eq!(placeholders("a {b c} {"), "a {b c} {");
    }
}
