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
    fn wraps_with_indent() {
        let items: Vec<String> = ["alpha", "beta", "gamma", "delta"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(wrap_items(&items, " · ", 30, 4), "alpha · beta · gamma\n    delta");
        assert_eq!(wrap_items(&items, " · ", 100, 4), "alpha · beta · gamma · delta");
    }
}
