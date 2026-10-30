//! ANSI styling written by hand, and the terminal width.

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
    #[cfg(unix)]
    {
        // SAFETY: TIOCGWINSZ only writes a winsize into the struct we pass.
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0 && size.ws_col > 0 {
            return usize::from(size.ws_col);
        }
    }
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.parse().ok())
        .filter(|&c: &usize| c > 0)
        .unwrap_or(100)
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
    fn wraps_with_indent() {
        let items: Vec<String> = ["alpha", "beta", "gamma", "delta"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(wrap_items(&items, " · ", 30, 4), "alpha · beta · gamma\n    delta");
        assert_eq!(wrap_items(&items, " · ", 100, 4), "alpha · beta · gamma · delta");
    }
}
