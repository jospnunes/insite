//! Colors, glyphs and drawing primitives for the live terminal output.

use crate::style::neutralize;

/// What the terminal can show: 24-bit color or the 16 basic ones, UTF-8 glyphs or ASCII.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Theme {
    pub(crate) truecolor: bool,
    pub(crate) unicode: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Corner {
    Top,
    Bottom,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Glyph {
    Ok,
    Warn,
    Bad,
    Neutral,
    Skipped,
    Brand,
    Arrow,
    Corner(Corner),
    Pipe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MeterColor {
    Good,
    Warn,
    Poor,
}

/// The palette (GitHub dark): each tone has an RGB value and a basic ANSI fallback.
#[derive(Clone, Copy)]
enum Tone {
    Dim,
    White,
    Green,
    Yellow,
    Orange,
    Red,
    Cyan,
    Magenta,
    Track,
}

/// SGR code of a basic color: `base` is 30 (foreground) or 40 (background), and the
/// bright variants sit 60 higher.
fn basic_code(base: u8, bright: bool, n: u8) -> String {
    let base = if bright { base + 60 } else { base };
    (base + n).to_string()
}

impl Tone {
    fn rgb(self) -> (u8, u8, u8) {
        match self {
            Tone::Dim => (0x8b, 0x94, 0x9e),
            Tone::White => (0xf0, 0xf6, 0xfc),
            Tone::Green => (0x3f, 0xb9, 0x50),
            Tone::Yellow => (0xd2, 0x99, 0x22),
            Tone::Orange => (0xdb, 0x6d, 0x28),
            Tone::Red => (0xf8, 0x51, 0x49),
            Tone::Cyan => (0x39, 0xc5, 0xcf),
            Tone::Magenta => (0xbc, 0x8c, 0xff),
            Tone::Track => (0x21, 0x26, 0x2d),
        }
    }

    /// Index 0-7 of the basic ANSI color, with whether it is the bright variant.
    fn basic(self) -> (u8, bool) {
        match self {
            Tone::Dim | Tone::Track => (0, true),
            Tone::White => (7, false),
            Tone::Green => (2, false),
            Tone::Yellow | Tone::Orange => (3, false),
            Tone::Red => (1, false),
            Tone::Cyan => (6, false),
            Tone::Magenta => (5, false),
        }
    }
}

const BRAND_FROM: (u8, u8, u8) = (0x39, 0xc5, 0xcf);
const BRAND_TO: (u8, u8, u8) = (0xbc, 0x8c, 0xff);
const BADGE_TEXT: (u8, u8, u8) = (0x0d, 0x11, 0x17);
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_ASCII: [&str; 4] = ["|", "/", "-", "\\"];
/// Partial cells for 1/8 to 7/8, left to right.
const EIGHTHS: [&str; 7] = ["▏", "▎", "▍", "▌", "▋", "▊", "▉"];

impl Theme {
    /// Reads `COLORTERM`, `LC_ALL`, `LC_CTYPE` and `LANG` from the environment.
    pub(crate) fn detect() -> Theme {
        let var = |name: &str| std::env::var(name).ok();
        Theme::from_vars(
            var("COLORTERM").as_deref(),
            var("LC_ALL").as_deref(),
            var("LC_CTYPE").as_deref(),
            var("LANG").as_deref(),
        )
    }

    /// 24-bit color only for `truecolor`/`24bit`; UTF-8 glyphs when the first of `LC_ALL`,
    /// `LC_CTYPE` and `LANG` that is set and non-empty names UTF-8 (POSIX precedence).
    pub(crate) fn from_vars(
        colorterm: Option<&str>,
        lc_all: Option<&str>,
        lc_ctype: Option<&str>,
        lang: Option<&str>,
    ) -> Theme {
        let truecolor = matches!(colorterm, Some("truecolor" | "24bit"));
        let unicode = [lc_all, lc_ctype, lang]
            .into_iter()
            .flatten()
            .find(|v| !v.is_empty())
            .is_some_and(|v| {
                let v = v.to_ascii_lowercase();
                v.contains("utf-8") || v.contains("utf8")
            });
        Theme { truecolor, unicode }
    }

    /// No color depth, no UTF-8: what tests use to get predictable output.
    #[cfg(test)]
    pub(crate) fn plain_ascii() -> Theme {
        Theme {
            truecolor: false,
            unicode: false,
        }
    }

    /// SGR parameters for a foreground color.
    fn fg(&self, tone: Tone) -> String {
        if self.truecolor {
            let (r, g, b) = tone.rgb();
            return format!("38;2;{r};{g};{b}");
        }
        let (n, bright) = tone.basic();
        basic_code(30, bright, n)
    }

    /// SGR parameters for a background color.
    fn bg(&self, tone: Tone) -> String {
        if self.truecolor {
            let (r, g, b) = tone.rgb();
            return format!("48;2;{r};{g};{b}");
        }
        let (n, bright) = tone.basic();
        basic_code(40, bright, n)
    }

    fn paint(&self, params: &str, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        format!("\x1b[{params}m{text}\x1b[0m")
    }

    fn tone(&self, tone: Tone, text: &str) -> String {
        self.paint(&self.fg(tone), text)
    }

    pub(crate) fn dim(&self, text: &str) -> String {
        self.tone(Tone::Dim, text)
    }

    /// Bold; white with 24-bit color, the terminal's own bold color otherwise.
    pub(crate) fn bold(&self, text: &str) -> String {
        let params = if self.truecolor {
            format!("1;{}", self.fg(Tone::White))
        } else {
            "1".to_owned()
        };
        self.paint(&params, text)
    }

    pub(crate) fn green(&self, text: &str) -> String {
        self.tone(Tone::Green, text)
    }

    pub(crate) fn yellow(&self, text: &str) -> String {
        self.tone(Tone::Yellow, text)
    }

    pub(crate) fn red(&self, text: &str) -> String {
        self.tone(Tone::Red, text)
    }

    pub(crate) fn cyan(&self, text: &str) -> String {
        self.tone(Tone::Cyan, text)
    }

    pub(crate) fn magenta(&self, text: &str) -> String {
        self.tone(Tone::Magenta, text)
    }

    /// Bold, shading from cyan to magenta across the characters with 24-bit color;
    /// plain bold cyan otherwise.
    pub(crate) fn brand(&self, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        if !self.truecolor {
            return self.paint(&format!("1;{}", self.fg(Tone::Cyan)), text);
        }
        let last = text.chars().count().saturating_sub(1).max(1) as f64;
        let mix = |a: u8, b: u8, t: f64| (f64::from(a) + (f64::from(b) - f64::from(a)) * t).round() as u8;
        let mut out = String::new();
        for (i, c) in text.chars().enumerate() {
            let t = i as f64 / last;
            let (r, g, b) = (
                mix(BRAND_FROM.0, BRAND_TO.0, t),
                mix(BRAND_FROM.1, BRAND_TO.1, t),
                mix(BRAND_FROM.2, BRAND_TO.2, t),
            );
            out.push_str(&format!("\x1b[1;38;2;{r};{g};{b}m{c}"));
        }
        out.push_str("\x1b[0m");
        out
    }

    pub(crate) fn glyph(&self, g: Glyph) -> &'static str {
        let (unicode, ascii) = match g {
            Glyph::Ok => ("✓", "+"),
            Glyph::Warn => ("▲", "!"),
            Glyph::Bad => ("✗", "x"),
            Glyph::Neutral => ("·", "."),
            Glyph::Skipped => ("–", "-"),
            Glyph::Brand => ("◆", "*"),
            Glyph::Arrow => ("──▶", "-->"),
            Glyph::Corner(Corner::Top) => ("┌", "+"),
            Glyph::Corner(Corner::Bottom) => ("└", "+"),
            Glyph::Pipe => ("│", "|"),
        };
        if self.unicode { unicode } else { ascii }
    }

    /// One frame of the spinner; `frame` wraps around.
    pub(crate) fn spinner(&self, frame: usize) -> &'static str {
        if self.unicode {
            SPINNER[frame % SPINNER.len()]
        } else {
            SPINNER_ASCII[frame % SPINNER_ASCII.len()]
        }
    }

    /// A bar `cells` wide (fractions allowed), uncolored: eighth-block partial cells
    /// with unicode, whole `#` cells (rounded) with ASCII.
    pub(crate) fn bar(&self, cells: f64) -> String {
        if !cells.is_finite() || cells <= 0.0 {
            return String::new();
        }
        if !self.unicode {
            return "#".repeat(cells.round() as usize);
        }
        // Round to the nearest eighth first so 0.97 becomes a whole cell, not "▉".
        let eighths = (cells * 8.0).round() as usize;
        let mut out = "█".repeat(eighths / 8);
        if let Some(partial) = (eighths % 8).checked_sub(1) {
            out.push_str(EIGHTHS[partial]);
        }
        out
    }

    /// `width` cells: the filled share of `fraction` (clamped to 0..=1) in the meter's
    /// color, then the track.
    pub(crate) fn meter(&self, fraction: f64, width: usize, color: MeterColor) -> String {
        let fraction = if fraction.is_nan() {
            0.0
        } else {
            fraction.clamp(0.0, 1.0)
        };
        let filled = ((fraction * width as f64).round() as usize).min(width);
        let (full, track) = if self.unicode { ("█", "█") } else { ("#", "-") };
        let tone = match color {
            MeterColor::Good => Tone::Green,
            MeterColor::Warn => Tone::Yellow,
            MeterColor::Poor => Tone::Red,
        };
        self.tone(tone, &full.repeat(filled)) + &self.tone(Tone::Track, &track.repeat(width - filled))
    }

    /// The grade in a colored box: bold dark text on green (A+, A, B), yellow (C),
    /// orange (D), red (F) or grey (anything else).
    pub(crate) fn badge(&self, grade: &str) -> String {
        if grade.is_empty() {
            return String::new();
        }
        // By letter: the security grade also comes as A-, B+, C-, D+ and so on.
        let tone = match grade.chars().next() {
            Some('A' | 'B') => Tone::Green,
            Some('C') => Tone::Yellow,
            Some('D') => Tone::Orange,
            Some('F') => Tone::Red,
            _ => Tone::Dim,
        };
        let text = if self.truecolor {
            let (r, g, b) = BADGE_TEXT;
            format!("38;2;{r};{g};{b}")
        } else {
            "30".to_owned()
        };
        self.paint(&format!("1;{text};{}", self.bg(tone)), &format!(" {grade} "))
    }
}

/// Page-controlled text with every control character neutralized, safe to color.
pub(crate) fn clean(text: &str) -> String {
    neutralize(text, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::style::visible_len;

    const ALL_GLYPHS: [Glyph; 9] = [
        Glyph::Ok,
        Glyph::Warn,
        Glyph::Bad,
        Glyph::Neutral,
        Glyph::Skipped,
        Glyph::Brand,
        Glyph::Arrow,
        Glyph::Corner(Corner::Top),
        Glyph::Corner(Corner::Bottom),
    ];

    fn themes() -> [Theme; 3] {
        [
            Theme::plain_ascii(),
            Theme {
                truecolor: false,
                unicode: true,
            },
            Theme {
                truecolor: true,
                unicode: true,
            },
        ]
    }

    #[test]
    fn ascii_theme_has_no_non_ascii() {
        let t = Theme::plain_ascii();
        for g in ALL_GLYPHS.into_iter().chain([Glyph::Pipe]) {
            assert!(t.glyph(g).is_ascii(), "{g:?}");
        }
        for frame in 0..20 {
            assert!(t.spinner(frame).is_ascii());
        }
        assert!(t.bar(3.5).is_ascii());
        assert!(t.meter(0.5, 10, MeterColor::Good).is_ascii());
        assert!(t.badge("A+").is_ascii());
    }

    #[test]
    fn unicode_glyphs_and_spinner() {
        let t = Theme {
            truecolor: false,
            unicode: true,
        };
        assert_eq!(t.glyph(Glyph::Ok), "✓");
        assert_eq!(t.glyph(Glyph::Arrow), "──▶");
        assert_eq!(t.glyph(Glyph::Corner(Corner::Top)), "┌");
        assert_eq!(t.spinner(0), "⠋");
        assert_eq!(t.spinner(10), "⠋");
        assert_eq!(Theme::plain_ascii().spinner(5), "/");
    }

    #[test]
    fn bar_uses_eighths() {
        let t = Theme {
            truecolor: false,
            unicode: true,
        };
        assert_eq!(t.bar(1.5), "█▌");
        assert_eq!(t.bar(2.0), "██");
        assert_eq!(t.bar(0.0), "");
        assert_eq!(t.bar(0.125), "▏");
        assert_eq!(t.bar(0.97), "█");
        assert_eq!(t.bar(-1.0), "");
        assert_eq!(Theme::plain_ascii().bar(3.0), "###");
    }

    #[test]
    fn meter_has_the_requested_width() {
        for t in themes() {
            for fraction in [-1.0, 0.0, 0.3, 0.5, 1.0, 7.0, f64::NAN] {
                for width in [0, 1, 12] {
                    let m = t.meter(fraction, width, MeterColor::Good);
                    assert_eq!(visible_len(&m), width, "{fraction} {width}");
                }
            }
        }
        let t = Theme::plain_ascii();
        assert_eq!(
            t.meter(0.3, 10, MeterColor::Warn),
            "\x1b[33m###\x1b[0m\x1b[90m-------\x1b[0m"
        );
    }

    #[test]
    fn detect_reads_colorterm_and_locale() {
        let utf8 = Some("pt_BR.UTF-8");
        assert!(Theme::from_vars(Some("truecolor"), None, None, utf8).truecolor);
        assert!(Theme::from_vars(Some("24bit"), None, None, utf8).truecolor);
        assert!(!Theme::from_vars(Some("yes"), None, None, utf8).truecolor);
        assert!(!Theme::from_vars(None, None, None, utf8).truecolor);
        assert!(Theme::from_vars(None, None, None, utf8).unicode);
        assert!(Theme::from_vars(None, None, None, Some("en_US.utf8")).unicode);
        assert!(!Theme::from_vars(None, None, None, Some("C")).unicode);
        assert!(!Theme::from_vars(None, None, None, None).unicode);
        // POSIX precedence: the first of LC_ALL, LC_CTYPE, LANG that is set and non-empty.
        assert!(!Theme::from_vars(None, Some("C"), None, utf8).unicode);
        assert!(Theme::from_vars(None, Some(""), Some("C.UTF-8"), Some("C")).unicode);
        assert!(!Theme::from_vars(None, None, Some("POSIX"), utf8).unicode);
        assert!(Theme::from_vars(None, Some(""), Some(""), utf8).unicode);
    }

    #[test]
    fn clean_removes_escapes() {
        assert!(!clean("a\x1b[2Jb").contains('\x1b'));
        assert_eq!(clean("plain"), "plain");
    }

    #[test]
    fn empty_input_stays_empty_and_painters_reset() {
        for t in themes() {
            let painters: [fn(&Theme, &str) -> String; 8] = [
                Theme::dim,
                Theme::bold,
                Theme::green,
                Theme::yellow,
                Theme::red,
                Theme::cyan,
                Theme::magenta,
                Theme::brand,
            ];
            for paint in painters {
                assert_eq!(paint(&t, ""), "");
                let s = paint(&t, "abc");
                assert!(s.starts_with("\x1b["), "{s:?}");
                assert!(s.ends_with("\x1b[0m"), "{s:?}");
                assert_eq!(visible_len(&s), 3);
            }
        }
    }

    #[test]
    fn colors_differ_by_depth() {
        let rgb = Theme {
            truecolor: true,
            unicode: true,
        };
        let basic = Theme {
            truecolor: false,
            unicode: true,
        };
        assert_eq!(rgb.green("x"), "\x1b[38;2;63;185;80mx\x1b[0m");
        assert_eq!(basic.green("x"), "\x1b[32mx\x1b[0m");
        assert_eq!(basic.dim("x"), "\x1b[90mx\x1b[0m");
    }

    #[test]
    fn brand_is_a_gradient_with_truecolor() {
        let rgb = Theme {
            truecolor: true,
            unicode: true,
        };
        let s = rgb.brand("ab");
        assert!(s.contains("38;2;57;197;207"), "{s:?}");
        assert!(s.contains("38;2;188;140;255"), "{s:?}");
        assert_eq!(visible_len(&s), 2);
        assert_eq!(rgb.brand("a").matches("\x1b[0m").count(), 1);
        let basic = Theme {
            truecolor: false,
            unicode: true,
        };
        assert_eq!(basic.brand("ab"), "\x1b[1;36mab\x1b[0m");
    }

    #[test]
    fn badge_colors_by_the_letter_of_the_grade() {
        let rgb = Theme {
            truecolor: true,
            unicode: true,
        };
        for g in ["A-", "B+", "B-"] {
            assert!(rgb.badge(g).contains("48;2;63;185;80"), "{g}");
        }
        for g in ["C+", "C-"] {
            assert!(rgb.badge(g).contains("48;2;210;153;34"), "{g}");
        }
        for g in ["D+", "D-"] {
            assert!(rgb.badge(g).contains("48;2;219;109;40"), "{g}");
        }
        let basic = Theme::plain_ascii();
        assert_eq!(basic.badge("A-"), "\x1b[1;30;42m A- \x1b[0m");
        assert_eq!(basic.badge("D+"), "\x1b[1;30;43m D+ \x1b[0m");
    }

    #[test]
    fn badge_pads_and_colors_by_grade() {
        for t in themes() {
            for g in ["A+", "A", "B", "C", "D", "F", "?"] {
                let b = t.badge(g);
                assert_eq!(visible_len(&b), g.len() + 2, "{g}");
                assert!(b.ends_with("\x1b[0m"));
            }
            assert_eq!(t.badge(""), "");
        }
        let rgb = Theme {
            truecolor: true,
            unicode: true,
        };
        assert!(rgb.badge("A").contains("48;2;63;185;80"));
        assert!(rgb.badge("C").contains("48;2;210;153;34"));
        assert!(rgb.badge("D").contains("48;2;219;109;40"));
        assert!(rgb.badge("F").contains("48;2;248;81;73"));
        assert!(rgb.badge("Z").contains("48;2;139;148;158"));
        let basic = Theme {
            truecolor: false,
            unicode: false,
        };
        assert_eq!(basic.badge("F"), "\x1b[1;30;41m F \x1b[0m");
        assert_eq!(basic.badge("D"), "\x1b[1;30;43m D \x1b[0m");
    }
}
