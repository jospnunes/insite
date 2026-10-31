//! ANSI styling written by hand, and the terminal width.

use std::io::IsTerminal;

pub struct Style {
    color: bool,
}

impl Style {
    pub fn new(color: bool) -> Self {
        Style { color }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color && !text.is_empty() {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    pub fn bold(&self, t: &str) -> String {
        self.paint("1", t)
    }

    pub fn dim(&self, t: &str) -> String {
        self.paint("2", t)
    }

    pub fn red(&self, t: &str) -> String {
        self.paint("31", t)
    }

    pub fn green(&self, t: &str) -> String {
        self.paint("32", t)
    }

    pub fn yellow(&self, t: &str) -> String {
        self.paint("33", t)
    }
}

/// The SGR codes `Style` writes; no other escape survives `neutralize`.
const OWN_SGR: [&str; 6] = ["0", "1", "2", "31", "32", "33"];

/// Makes text from a page, a DNS record or a certificate safe to print: control
/// characters (C0, DEL and C1) cannot clear the screen, retitle the window or
/// move the cursor. `\n` stays; `\t` and `\r` become a space; anything else
/// becomes U+FFFD. With `keep_sgr`, the colour sequences `Style` writes itself
/// pass through, and nothing else starting with ESC does.
pub fn neutralize(text: &str, keep_sgr: bool) -> String {
    if !text.chars().any(|c| c.is_control() && c != '\n') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        if c == '\x1b'
            && keep_sgr
            && let Some(len) = own_sgr(rest)
        {
            out.push_str(&rest[..len]);
            rest = &rest[len..];
            continue;
        }
        out.push(match c {
            '\n' => '\n',
            '\t' | '\r' => ' ',
            c if c.is_control() => '\u{fffd}',
            c => c,
        });
        rest = &rest[c.len_utf8()..];
    }
    out
}

/// Length of the colour sequence `Style` writes at the start of `text`, if any.
fn own_sgr(text: &str) -> Option<usize> {
    let body = text.strip_prefix("\x1b[")?;
    let end = body.find('m')?;
    OWN_SGR.contains(&&body[..end]).then_some(2 + end + 1)
}

/// Columns of the terminal on stdout, or `COLUMNS`, or 100.
pub fn terminal_width() -> usize {
    // Only a terminal on stdout is measured: crossterm would otherwise fall back to the
    // controlling tty or `tput`, and redirected output must keep using COLUMNS, then 100.
    let size = std::io::stdout()
        .is_terminal()
        .then(|| crossterm::terminal::size().ok().map(|(columns, _)| columns))
        .flatten();
    width_from(size, std::env::var("COLUMNS").ok().as_deref())
}

fn width_from(size: Option<u16>, columns: Option<&str>) -> usize {
    size.filter(|&c| c > 0)
        .map(usize::from)
        .or_else(|| columns.and_then(|c| c.parse().ok()).filter(|&c: &usize| c > 0))
        .unwrap_or(100)
}

/// Makes the terminal understand ANSI escapes. Only Windows needs work (virtual-terminal
/// processing); it returns whether escapes will be interpreted.
pub fn enable_ansi() -> bool {
    #[cfg(windows)]
    {
        crossterm::ansi_support::supports_ansi()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// Visible width: characters, not counting ANSI escapes.
pub fn visible_len(text: &str) -> usize {
    let mut len = 0;
    let mut escape = false;
    for c in text.chars() {
        match (escape, c) {
            (false, '\x1b') => escape = true,
            (true, 'm') => escape = false,
            (true, _) => {}
            (false, _) => len += 1,
        }
    }
    len
}

/// Terminal columns one character takes: 2 for East Asian wide and emoji, 0 for combining
/// marks and zero-width characters, 1 for the rest. A small table, not the full Unicode one.
pub fn char_width(c: char) -> usize {
    match c as u32 {
        0x0300..=0x036F | 0x200B..=0x200F | 0xFE00..=0xFE0F => 0,
        0x1100..=0x115F
        | 0x2E80..=0x303E
        | 0x3041..=0x33FF
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1F64F
        | 0x1F680..=0x1F6FF
        | 0x1F900..=0x1F9FF
        | 0x20000..=0x2FFFD
        | 0x30000..=0x3FFFD => 2,
        _ => 1,
    }
}

/// Columns on screen, not counting ANSI escapes: like `visible_len`, but wide characters
/// take two columns and combining marks none.
pub fn display_width(text: &str) -> usize {
    let mut width = 0;
    let mut escape = false;
    for c in text.chars() {
        match (escape, c) {
            (false, '\x1b') => escape = true,
            (true, 'm') => escape = false,
            (true, _) => {}
            (false, _) => width += char_width(c),
        }
    }
    width
}

/// Joins `items` with `separator`, wrapping to `width` with `indent` spaces
/// before continuation lines.
pub fn wrap_items(items: &[String], separator: &str, width: usize, indent: usize) -> String {
    let mut out = String::new();
    let mut line = 0;
    for (i, item) in items.iter().enumerate() {
        let len = visible_len(item);
        if i > 0 {
            if line + visible_len(separator) + len > width.saturating_sub(indent) {
                out.push('\n');
                out.push_str(&" ".repeat(indent));
                line = 0;
            } else {
                out.push_str(separator);
                line += visible_len(separator);
            }
        }
        out.push_str(item);
        line += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_do_not_count() {
        assert_eq!(visible_len("\x1b[1mbold\x1b[0m"), 4);
        assert_eq!(visible_len("ação"), 4);
    }

    #[test]
    fn display_width_counts_columns() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("ação"), 4);
        assert_eq!(display_width("日本語"), 6);
        assert_eq!(display_width("\x1b[31m日本\x1b[0m!"), 5);
        assert_eq!(display_width("🚀"), 2);
        assert_eq!(display_width("한글"), 4);
        assert_eq!(display_width("Ａ"), 2);
        assert_eq!(display_width("e\u{301}"), 1);
        assert_eq!(display_width("a\u{200b}b"), 2);
        assert_eq!(display_width(""), 0);
        // Unchanged: the plain renderer still counts characters.
        assert_eq!(visible_len("日本語"), 3);
    }

    #[test]
    fn control_characters_are_neutralized() {
        let hostile = "a\x1b[2J\x1b]0;pwned\x07b\u{9b}31m\u{85}\x7f\tc\rd\ne";
        let clean = neutralize(hostile, false);
        assert_eq!(
            clean,
            "a\u{fffd}[2J\u{fffd}]0;pwned\u{fffd}b\u{fffd}31m\u{fffd}\u{fffd} c d\ne"
        );
        assert!(!clean.chars().any(|c| c.is_control() && c != '\n'));
        assert_eq!(neutralize("ação ✓", false), "ação ✓");
    }

    #[test]
    fn only_own_colours_survive_when_kept() {
        let painted = Style::new(true).red("bad");
        assert_eq!(neutralize(&painted, true), painted);
        assert_eq!(
            neutralize("\x1b[8mhidden\x1b[2J\x1b[31", true),
            "\u{fffd}[8mhidden\u{fffd}[2J\u{fffd}[31"
        );
        assert_eq!(neutralize(&painted, false), "\u{fffd}[31mbad\u{fffd}[0m");
    }

    #[test]
    fn terminal_width_falls_back_to_columns_then_100() {
        assert_eq!(width_from(None, Some("72")), 72);
        assert_eq!(width_from(None, None), 100);
        assert_eq!(width_from(Some(120), Some("72")), 120);
        assert_eq!(width_from(None, Some("wide")), 100);
        assert_eq!(width_from(None, Some("0")), 100);
        assert_eq!(width_from(Some(0), Some("72")), 72);
    }

    #[test]
    fn wraps_with_indent() {
        let items: Vec<String> = ["alpha", "beta", "gamma", "delta"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(wrap_items(&items, " · ", 30, 4), "alpha · beta · gamma\n    delta");
        assert_eq!(wrap_items(&items, " · ", 100, 4), "alpha · beta · gamma · delta");
    }
}
