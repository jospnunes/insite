//! JavaScript regex syntax to Rust's.
//!
//! Wappalyzer compiles every pattern as `new RegExp(pattern, 'i')`. Most of that
//! syntax is shared with the `regex` crate; the differences handled here are
//! escapes JavaScript tolerates (`\/`, identity escapes, `\uXXXX`), braces that are
//! literal when they do not form a quantifier, `[` inside classes, `[^]`, and the
//! constructs only a backtracking engine supports (lookaround, backreferences),
//! which select `fancy-regex`.

use crate::index::Engine;

pub fn translate(js: &str) -> Result<(String, Engine), String> {
    let chars: Vec<char> = js.chars().collect();
    let mut out = String::with_capacity(js.len() + 8);
    let mut engine = Engine::Regex;
    let mut in_class = false;
    let mut class_start = false;
    let mut class = ClassState::default();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        let first_in_class = class_start;
        class_start = false;
        match c {
            '\\' => {
                let Some(&next) = chars.get(i + 1) else {
                    return Err("pattern ends with a lone backslash".into());
                };
                i += 2;
                if in_class {
                    // Class shorthands cannot start or end a range.
                    class.item(!matches!(next, 'd' | 'D' | 'w' | 'W' | 's' | 'S'));
                }
                match next {
                    '1'..='9' if !in_class => {
                        engine = Engine::Fancy;
                        out.push('\\');
                        out.push(next);
                    }
                    '0' => out.push_str("\\x00"),
                    'u' => {
                        let hex: String = chars[i..].iter().take(4).collect();
                        if hex.len() == 4 && hex.chars().all(|h| h.is_ascii_hexdigit()) {
                            out.push_str(&format!("\\x{{{hex}}}"));
                            i += 4;
                        } else {
                            out.push('u');
                        }
                    }
                    'x' => {
                        let hex: String = chars[i..].iter().take(2).collect();
                        if hex.len() == 2 && hex.chars().all(|h| h.is_ascii_hexdigit()) {
                            // Above ASCII, JavaScript means the character; `\xE9` alone
                            // is the byte 0xE9 to a Unicode-off regex, never the UTF-8 text.
                            if hex.as_bytes()[0] >= b'8' {
                                out.push_str(&format!("\\x{{{hex}}}"));
                            } else {
                                out.push_str(&format!("\\x{hex}"));
                            }
                            i += 2;
                        } else {
                            out.push('x');
                        }
                    }
                    'c' => match chars.get(i) {
                        Some(letter) if letter.is_ascii_alphabetic() => {
                            out.push_str(&format!("\\x{:02X}", (*letter as u8) % 32));
                            i += 1;
                        }
                        _ => out.push_str("\\\\c"),
                    },
                    'd' | 'D' | 'w' | 'W' | 's' | 'S' | 'n' | 'r' | 't' | 'f' | 'v' => {
                        out.push('\\');
                        out.push(next);
                    }
                    // Word boundaries outside classes; a backspace inside them.
                    'b' | 'B' if !in_class => {
                        out.push('\\');
                        out.push(next);
                    }
                    'b' => out.push_str("\\x08"),
                    // `\<` and `\>` are word boundaries to the regex crate, literals in JS.
                    '<' | '>' => out.push(next),
                    // Identity escapes of punctuation keep their literal meaning.
                    p if p.is_ascii_punctuation() => {
                        out.push('\\');
                        out.push(p);
                    }
                    // Other identity escapes (`\a`, `\q`...) are the letter itself in JS.
                    other => out.push_str(&regex_syntax::escape(&other.to_string())),
                }
                continue;
            }
            '[' if in_class => {
                class.item(true);
                out.push_str("\\[");
            }
            '[' => {
                // `[^]` matches any character in JavaScript.
                if chars.get(i + 1) == Some(&'^') && chars.get(i + 2) == Some(&']') {
                    out.push_str("[\\s\\S]");
                    i += 3;
                    continue;
                }
                if chars.get(i + 1) == Some(&']') {
                    return Err("empty character class".into());
                }
                in_class = true;
                class_start = true;
                class = ClassState::default();
                out.push('[');
                if chars.get(i + 1) == Some(&'^') {
                    out.push('^');
                    i += 1;
                    class_start = true;
                }
            }
            ']' if in_class && !first_in_class => {
                in_class = false;
                out.push(']');
            }
            // Characters that are set operators in Rust classes but plain in JS.
            '&' | '~' if in_class => {
                class.item(true);
                out.push('\\');
                out.push(c);
            }
            // `--` is the difference operator in Rust classes. Ranges keep their
            // dash; a dash that is a range's end, or a literal next to another
            // dash, is escaped (`[+--]` is the range from `+` to `-`).
            '-' if in_class => {
                let range_start = class.prev_atom && chars.get(i + 1).is_some_and(|&n| n != ']');
                if class.range_open {
                    out.push_str("\\-");
                    class.item(false);
                } else if range_start {
                    out.push('-');
                    class.prev_atom = false;
                    class.range_open = true;
                } else if chars.get(i + 1) == Some(&'-') {
                    out.push_str("\\-");
                    class.item(true);
                } else {
                    out.push('-');
                    class.item(true);
                }
            }
            '{' if !in_class => match quantifier_len(&chars[i..]) {
                Some(len) => {
                    out.extend(&chars[i..i + len]);
                    i += len;
                    continue;
                }
                None => out.push_str("\\{"),
            },
            '}' if !in_class => out.push_str("\\}"),
            '(' if !in_class && chars.get(i + 1) == Some(&'?') => {
                let rest: String = chars[i + 2..].iter().take(2).collect();
                if rest.starts_with('=') || rest.starts_with('!') || rest == "<=" || rest == "<!" {
                    engine = Engine::Fancy;
                }
                out.push('(');
            }
            _ => {
                if in_class && !(c == ']' && !first_in_class) {
                    class.item(true);
                }
                out.push(c);
            }
        }
        i += 1;
    }
    if in_class {
        return Err("unterminated character class".into());
    }
    Ok((out, engine))
}

/// Where a character class is: whether the last item can start a range, and
/// whether a range operator is waiting for its end.
#[derive(Default)]
struct ClassState {
    prev_atom: bool,
    range_open: bool,
}

impl ClassState {
    /// One class item was written; `atom` if it is a single character.
    fn item(&mut self, atom: bool) {
        self.prev_atom = atom && !self.range_open;
        self.range_open = false;
    }
}

/// Length of a `{n}`, `{n,}` or `{n,m}` quantifier at the start of `chars`.
fn quantifier_len(chars: &[char]) -> Option<usize> {
    let mut i = 1;
    let digits = |from: usize| chars[from..].iter().take_while(|c| c.is_ascii_digit()).count();
    let n = digits(i);
    if n == 0 {
        return None;
    }
    i += n;
    if chars.get(i) == Some(&',') {
        i += 1;
        i += digits(i);
    }
    (chars.get(i) == Some(&'}')).then_some(i + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rust(js: &str) -> String {
        translate(js).unwrap().0
    }

    #[test]
    fn javascript_escapes() {
        assert_eq!(rust(r"wp-content\/themes\/([^\/]+)"), r"wp-content\/themes\/([^\/]+)");
        assert_eq!(rust(r"\u00e9t\x41"), r"\x{00e9}t\x41");
        assert_eq!(rust(r"a\0b"), r"a\x00b");
        assert_eq!(rust(r"\a"), "a");
    }

    /// Builds the way the compiler and the runtime do: ASCII first, Unicode if
    /// the pattern needs it.
    fn matches(js: &str, haystack: &str) -> bool {
        let (rust, _) = translate(js).unwrap();
        let build = |unicode| {
            regex::bytes::RegexBuilder::new(&rust)
                .case_insensitive(true)
                .unicode(unicode)
                .build()
        };
        let re = build(false)
            .or_else(|_| build(true))
            .unwrap_or_else(|e| panic!("{js} -> {rust}: {e}"));
        re.is_match(haystack.as_bytes())
    }

    #[test]
    fn angle_escapes_are_literal_characters() {
        // regex-syntax 0.8 reads `\<` and `\>` as word-boundary assertions.
        assert_eq!(rust(r"a\<b\>"), "a<b>");
        assert_eq!(rust(r"[\<\>]"), "[<>]");
        assert!(matches(r"a\<b\>", "xa<b>"));
        assert!(!matches(r"a\<b", "a b"));
        assert!(matches(r"[\<]x", "<x"));
    }

    #[test]
    fn unicode_escapes_match_the_utf8_character() {
        // `\u` already worked: `\x{e9}` compiles to the UTF-8 bytes even with
        // Unicode off. `\xe9` did not: it is the single byte 0xE9 there.
        assert!(matches(r"café", "café"));
        assert!(matches(r"caf\xe9", "café"));
        assert!(matches(r"[\xe8\xe9]x", "éx"));
        assert!(!matches(r"caf\xe9", "caf\u{fffd}"));
        assert_eq!(rust(r"\xe9"), r"\x{e9}");
        assert_eq!(rust(r"\x41"), r"\x41");
    }

    #[test]
    fn class_set_operators_are_literal() {
        assert!(matches("[a&&b]", "&"));
        assert!(matches("[a~~b]", "~"));
        assert!(matches("[a||b]", "|"));
        assert!(!matches("^[a||b]$", "x"));
        // `[+--]` is the range from `+` to `-` in JavaScript: `,` is in it.
        assert!(matches("^[+--]$", ","));
        assert!(matches("^[+--]$", "-"));
        assert!(!matches("^[+--]$", "."));
        // Ordinary dashes keep their form.
        assert_eq!(rust("jquery[.-]x[a-z-9]"), "jquery[.-]x[a-z-9]");
    }

    #[test]
    fn literal_braces_and_brackets() {
        assert_eq!(rust("a{2,3}b{x}"), r"a{2,3}b\{x\}");
        assert_eq!(rust("[[]x]"), r"[\[]x]");
        assert_eq!(rust("[^]"), r"[\s\S]");
        // An empty class never matches in JavaScript; such patterns are dropped.
        assert!(translate("[]a]").is_err());
        assert_eq!(rust("[a&&b]"), r"[a\&\&b]");
    }

    #[test]
    fn lookaround_and_backreferences_need_fancy() {
        assert_eq!(translate("foo(?=bar)").unwrap().1, Engine::Fancy);
        assert_eq!(translate("(?<!x)y").unwrap().1, Engine::Fancy);
        assert_eq!(translate(r"(a)\1").unwrap().1, Engine::Fancy);
        assert_eq!(translate(r"(?:a)(?<name>b)").unwrap().1, Engine::Regex);
    }

    #[test]
    fn translated_patterns_parse() {
        for js in [
            r"wp-content\/themes\/([^\/]+)",
            r"jquery[.-]([\d.]*\d)[^/]*\.js",
            "a{2,3}b{x}",
            "[[]x]",
            r"\-\:",
        ] {
            let (rust, _) = translate(js).unwrap();
            regex::bytes::RegexBuilder::new(&rust)
                .case_insensitive(true)
                .unicode(false)
                .build()
                .unwrap_or_else(|e| panic!("{js} -> {rust}: {e}"));
        }
    }
}
