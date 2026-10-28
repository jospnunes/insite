//! `insite explain`: the findings catalog from the terminal.

use std::io::IsTerminal;
use std::process::ExitCode;

use insite_core::findings::{CATALOG, entry};

use crate::style::Style;

pub fn run(id: Option<&str>) -> ExitCode {
    let s = Style::new(std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()));
    let query = id.unwrap_or_default().trim();
    if let Some(e) = CATALOG
        .iter()
        .find(|(i, _)| *i == query)
        .and_then(|(i, _)| entry(i).map(|e| (*i, e)))
    {
        let (id, e) = e;
        println!(
            "{}  {}",
            s.bold(&placeholders(e.title)),
            s.dim(&format!("{id} · {}", crate::render::severity(e.severity)))
        );
        println!("\n{}\n", placeholders(e.detail));
        println!("{}\n{}", s.bold("Fix"), placeholders(e.fix));
        return ExitCode::SUCCESS;
    }
    let matches: Vec<&str> = CATALOG
        .iter()
        .map(|(i, _)| *i)
        .filter(|i| i.starts_with(query))
        .collect();
    if matches.is_empty() {
        eprintln!("insite: no finding `{query}`; `insite explain` lists them all");
        return ExitCode::from(2);
    }
    let width = matches.iter().map(|i| i.len()).max().unwrap_or(0);
    for id in matches {
        if let Some(e) = entry(id) {
            let severity = format!("{:<8}", crate::render::severity(e.severity));
            println!("{id:<width$}  {}{}", s.dim(&severity), placeholders(e.title));
        }
    }
    ExitCode::SUCCESS
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
    fn placeholders_become_angle_brackets() {
        assert_eq!(placeholders("expires in {days} days"), "expires in <days> days");
        assert_eq!(placeholders("a {b c} {"), "a {b c} {");
    }
}
