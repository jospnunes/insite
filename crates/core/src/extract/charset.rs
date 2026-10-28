//! Character encoding and content sniffing, following the HTML and MIME Sniffing
//! standards closely enough for real pages.

use std::borrow::Cow;

use encoding_rs::{Encoding, UTF_8, WINDOWS_1252};

/// Decodes the body: `Content-Type` charset first, then the BOM, then a
/// `<meta>` in the first 1024 bytes, then windows-1252 as browsers do. Returns the
/// text, the encoding name and where the decision came from.
pub fn decode<'a>(body: &'a [u8], content_type: Option<&str>) -> (Cow<'a, str>, &'static str, &'static str) {
    let (encoding, source) = if let Some((enc, _)) = Encoding::for_bom(body) {
        (enc, "byte order mark")
    } else if let Some(enc) = content_type.and_then(header_charset) {
        (enc, "Content-Type header")
    } else if let Some(enc) = prescan(body) {
        (enc, "meta tag")
    } else if std::str::from_utf8(body).is_ok() {
        // Not what the standard says, but a page that is valid UTF-8 and declares
        // nothing is UTF-8 in practice; windows-1252 would garble it.
        (UTF_8, "valid UTF-8")
    } else {
        (WINDOWS_1252, "default")
    };
    let (text, _, _) = encoding.decode(body);
    (text, encoding.name(), source)
}

fn header_charset(content_type: &str) -> Option<&'static Encoding> {
    content_type.split(';').skip(1).find_map(|param| {
        let (key, value) = param.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("charset") {
            Encoding::for_label(value.trim().trim_matches(['"', '\'']).as_bytes())
        } else {
            None
        }
    })
}

/// `<meta charset>` or `<meta http-equiv="content-type" content="...charset=...">`
/// in the first 1024 bytes. A declared UTF-16 means UTF-8, since an ASCII-readable
/// meta tag cannot be UTF-16.
fn prescan(body: &[u8]) -> Option<&'static Encoding> {
    let head = &body[..body.len().min(1024)];
    let lower: Vec<u8> = head.iter().map(u8::to_ascii_lowercase).collect();
    let mut from = 0;
    while let Some(pos) = find(&lower[from..], b"<meta") {
        let start = from + pos;
        let end = find(&lower[start..], b">").map_or(lower.len(), |e| start + e);
        let tag = &lower[start..end];
        if let Some(i) = find(tag, b"charset") {
            let rest = &tag[i + 7..];
            let rest = rest
                .iter()
                .skip_while(|b| b.is_ascii_whitespace())
                .copied()
                .collect::<Vec<_>>();
            if let Some(value) = rest.strip_prefix(b"=") {
                let value: Vec<u8> = value
                    .iter()
                    .skip_while(|b| b.is_ascii_whitespace() || **b == b'"' || **b == b'\'')
                    .take_while(|b| !b.is_ascii_whitespace() && !matches!(b, b'"' | b'\'' | b';' | b'/' | b'>'))
                    .copied()
                    .collect();
                if let Some(enc) = Encoding::for_label(&value) {
                    return Some(if enc.name().starts_with("UTF-16") { UTF_8 } else { enc });
                }
            }
        }
        from = end.max(start + 1);
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Whether a body without a usable `Content-Type` is HTML, as the MIME Sniffing
/// standard's HTML signatures decide: the first non-whitespace bytes open one of
/// the tags that only HTML starts with.
pub fn sniff_html(body: &[u8]) -> bool {
    let start = body.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(body.len());
    let head: Vec<u8> = body[start..body.len().min(start + 16)]
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect();
    const SIGNATURES: &[&[u8]] = &[
        b"<!doctype html",
        b"<html",
        b"<head",
        b"<script",
        b"<iframe",
        b"<h1",
        b"<div",
        b"<font",
        b"<table",
        b"<a",
        b"<style",
        b"<title",
        b"<b",
        b"<body",
        b"<br",
        b"<p",
        b"<!--",
    ];
    SIGNATURES.iter().any(|sig| {
        head.starts_with(sig)
            && (sig.starts_with(b"<!--") || matches!(head.get(sig.len()), Some(b' ' | b'>' | b'\t' | b'\n' | b'\r')))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_wins_over_meta_and_bom_wins_over_header() {
        let body = "<meta charset=utf-8><p>ação</p>".as_bytes();
        assert_eq!(decode(body, Some("text/html; charset=UTF-8")).1, "UTF-8");
        let latin = b"<meta charset=\"iso-8859-1\"><p>a\xe7\xe3o</p>";
        let (text, name, source) = decode(latin, Some("text/html"));
        assert_eq!((name, source), ("windows-1252", "meta tag"));
        assert!(text.contains("ação"));
        let bom = b"\xef\xbb\xbf<p>x</p>";
        assert_eq!(decode(bom, Some("text/html; charset=iso-8859-1")).2, "byte order mark");
    }

    #[test]
    fn http_equiv_content_type() {
        let body = br#"<head><meta http-equiv="Content-Type" content="text/html; charset=windows-1251">"#;
        assert_eq!(decode(body, None).1, "windows-1251");
    }

    #[test]
    fn undeclared_valid_utf8_stays_utf8() {
        assert_eq!(decode("<p>São Paulo</p>".as_bytes(), None).1, "UTF-8");
        assert_eq!(decode(b"<p>S\xe3o</p>", None).1, "windows-1252");
    }

    #[test]
    fn sniffs_html_signatures() {
        assert!(sniff_html(b"  \n<!DOCTYPE html><html>"));
        assert!(sniff_html(b"<HTML lang=pt>"));
        assert!(!sniff_html(b"{\"json\": true}"));
        assert!(!sniff_html(b"<abbr>"));
        assert!(!sniff_html(b"%PDF-1.7"));
    }
}
