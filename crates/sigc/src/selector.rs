//! The CSS subset signature selectors use: type, `#id`, `.class`, attribute
//! selectors (`[a]`, `=`, `~=`, `|=`, `^=`, `$=`, `*=`, with an optional `i` flag),
//! descendant and child combinators, and comma lists. Anything else (pseudo-
//! classes, sibling combinators) is rejected at build time and counted.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorList(pub Vec<Complex>);

/// Compounds from left to right; each one after the first is joined to the
/// previous by its combinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Complex(pub Vec<(Combinator, Compound)>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Combinator {
    Descendant,
    Child,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Compound {
    pub tag: Option<String>,
    pub id: Option<String>,
    pub classes: Vec<String>,
    pub attrs: Vec<AttrSelector>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrSelector {
    pub name: String,
    pub op: Option<(AttrOp, String)>,
    pub case_insensitive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrOp {
    Equals,
    Includes,
    DashMatch,
    Prefix,
    Suffix,
    Substring,
}

pub fn parse(text: &str) -> Result<SelectorList, String> {
    let mut list = Vec::new();
    for part in split_top_level(text, ',') {
        let part = part.trim();
        if part.is_empty() {
            return Err("empty selector in list".into());
        }
        list.push(parse_complex(part)?);
    }
    Ok(SelectorList(list))
}

/// Splits on `sep` outside brackets and quotes.
fn split_top_level(text: &str, sep: char) -> Vec<&str> {
    let (mut parts, mut start, mut depth, mut quote) = (Vec::new(), 0, 0i32, None::<char>);
    for (i, c) in text.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, '[') => depth += 1,
            (None, ']') => depth -= 1,
            (None, c) if c == sep && depth == 0 => {
                parts.push(&text[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&text[start..]);
    parts
}

fn parse_complex(text: &str) -> Result<Complex, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut parts = Vec::new();
    let mut combinator = Combinator::Descendant;
    while i < chars.len() {
        let mut saw_space = false;
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
            saw_space = true;
        }
        if i >= chars.len() {
            break;
        }
        match chars[i] {
            '>' => {
                combinator = Combinator::Child;
                i += 1;
                continue;
            }
            '+' | '~' => return Err(format!("sibling combinator `{}` is not supported", chars[i])),
            _ => {}
        }
        if parts.is_empty() || saw_space || combinator == Combinator::Child {
            let (compound, next) = parse_compound(&chars, i)?;
            parts.push((combinator, compound));
            combinator = Combinator::Descendant;
            i = next;
        } else {
            return Err("unexpected character between compounds".into());
        }
    }
    if parts.is_empty() {
        return Err("empty selector".into());
    }
    Ok(Complex(parts))
}

fn ident(chars: &[char], mut i: usize) -> (String, usize) {
    let mut out = String::new();
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            out.push(chars[i + 1]);
            i += 2;
        } else if c.is_alphanumeric() || c == '-' || c == '_' || !c.is_ascii() {
            out.push(c);
            i += 1;
        } else {
            break;
        }
    }
    (out, i)
}

fn parse_compound(chars: &[char], mut i: usize) -> Result<(Compound, usize), String> {
    let mut compound = Compound::default();
    let mut any = false;
    if chars[i] == '*' {
        i += 1;
        any = true;
    } else if chars[i].is_alphabetic() {
        let (tag, next) = ident(chars, i);
        compound.tag = Some(tag.to_ascii_lowercase());
        i = next;
        any = true;
    }
    while i < chars.len() && !chars[i].is_whitespace() && chars[i] != '>' {
        match chars[i] {
            '#' => {
                let (id, next) = ident(chars, i + 1);
                if id.is_empty() {
                    return Err("empty id".into());
                }
                compound.id = Some(id);
                i = next;
            }
            '.' => {
                let (class, next) = ident(chars, i + 1);
                if class.is_empty() {
                    return Err("empty class".into());
                }
                compound.classes.push(class);
                i = next;
            }
            '[' => {
                let end = closing_bracket(chars, i).ok_or("unterminated attribute selector")?;
                compound
                    .attrs
                    .push(parse_attr(&chars[i + 1..end].iter().collect::<String>())?);
                i = end + 1;
            }
            ':' => return Err("pseudo-classes are not supported".into()),
            c => return Err(format!("unexpected `{c}`")),
        }
        any = true;
    }
    if !any {
        return Err("empty compound".into());
    }
    Ok((compound, i))
}

/// The `]` closing the attribute selector opened at `start`, skipping quoted values.
fn closing_bracket(chars: &[char], start: usize) -> Option<usize> {
    let mut quote = None;
    for (i, &c) in chars.iter().enumerate().skip(start + 1) {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, ']') => return Some(i),
            _ => {}
        }
    }
    None
}

fn parse_attr(body: &str) -> Result<AttrSelector, String> {
    let body = body.trim();
    let ops = [
        ("~=", AttrOp::Includes),
        ("|=", AttrOp::DashMatch),
        ("^=", AttrOp::Prefix),
        ("$=", AttrOp::Suffix),
        ("*=", AttrOp::Substring),
        ("=", AttrOp::Equals),
    ];
    for (token, op) in ops {
        if let Some(pos) = body.find(token) {
            let name = body[..pos].trim().to_ascii_lowercase();
            let mut value = body[pos + token.len()..].trim();
            let mut case_insensitive = false;
            if let Some(stripped) = value.strip_suffix(" i").or_else(|| value.strip_suffix(" I")) {
                value = stripped.trim();
                case_insensitive = true;
            }
            let value = value.trim_matches(|c| c == '"' || c == '\'').to_owned();
            if name.is_empty() {
                return Err("attribute selector without a name".into());
            }
            return Ok(AttrSelector {
                name,
                op: Some((op, value)),
                case_insensitive,
            });
        }
    }
    if body.is_empty() || body.contains(|c: char| c.is_whitespace()) {
        return Err(format!("invalid attribute selector `[{body}]`"));
    }
    Ok(AttrSelector {
        name: body.to_ascii_lowercase(),
        op: None,
        case_insensitive: false,
    })
}

impl AttrSelector {
    pub fn matches(&self, value: &str) -> bool {
        let Some((op, expected)) = &self.op else { return true };
        let (value, expected) = if self.case_insensitive {
            (value.to_lowercase(), expected.to_lowercase())
        } else {
            (value.to_owned(), expected.clone())
        };
        match op {
            AttrOp::Equals => value == expected,
            AttrOp::Includes => value.split_whitespace().any(|w| w == expected),
            AttrOp::DashMatch => value == expected || value.starts_with(&format!("{expected}-")),
            AttrOp::Prefix => !expected.is_empty() && value.starts_with(&expected),
            AttrOp::Suffix => !expected.is_empty() && value.ends_with(&expected),
            AttrOp::Substring => !expected.is_empty() && value.contains(&expected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_supported_subset() {
        let list = parse(r#"div#app.main > script[src*="wp-content" i], meta[name=generator]"#).unwrap();
        assert_eq!(list.0.len(), 2);
        let first = &list.0[0].0;
        assert_eq!(first[0].1.tag.as_deref(), Some("div"));
        assert_eq!(first[0].1.id.as_deref(), Some("app"));
        assert_eq!(first[0].1.classes, ["main"]);
        assert_eq!(first[1].0, Combinator::Child);
        let attr = &first[1].1.attrs[0];
        assert_eq!((attr.name.as_str(), attr.case_insensitive), ("src", true));
        assert!(attr.matches("/WP-CONTENT/x.js"));
    }

    #[test]
    fn rejects_what_the_matcher_cannot_do() {
        assert!(parse("a:not(.x)").is_err());
        assert!(parse("h1 + p").is_err());
        assert!(parse("").is_err());
        assert!(parse("[ ]").is_err());
    }

    #[test]
    fn brackets_inside_quoted_values() {
        let list = parse("button[name='age_gate[confirm]']").unwrap();
        let attr = &list.0[0].0[0].1.attrs[0];
        assert!(attr.matches("age_gate[confirm]"));
    }

    #[test]
    fn descendants_and_escapes() {
        let list = parse(r"body .shopify-section  div[data-x]").unwrap();
        assert_eq!(list.0[0].0.len(), 3);
        assert!(parse(r"#__next").is_ok());
        assert_eq!(parse(r".a\:b").unwrap().0[0].0[0].1.classes, ["a:b"]);
    }
}
