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
                            out.push_str(&format!("\\x{hex}"));
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
            '[' if in_class => out.push_str("\\["),
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
                out.push('\\');
                out.push(c);
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
            _ => out.push(c),
        }
        i += 1;
    }
    if in_class {
        return Err("unterminated character class".into());
    }
    Ok((out, engine))
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
