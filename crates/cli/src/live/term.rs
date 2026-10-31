//! Redraws a "live region" at the bottom of the terminal and commits finished text above it.

use std::io::{self, Write};

use crossterm::{cursor, queue, style, terminal};

use crate::style::visible_len;

/// Clips `line` to `width` visible columns without cutting inside an escape sequence;
/// a reset is appended only when something was cut, so colors do not leak past the line.
pub(crate) fn clip(line: &str, width: usize) -> String {
    let mut visible = 0;
    let mut escape = false;
    for (i, c) in line.char_indices() {
        match (escape, c) {
            (false, '\x1b') => escape = true,
            (true, 'm') => escape = false,
            (true, _) => {}
            (false, _) => {
                if visible == width {
                    return format!("{}\x1b[0m", &line[..i]);
                }
                visible += 1;
            }
        }
    }
    line.to_owned()
}

/// Rows the terminal uses for a line of `len` visible columns at `width` columns.
fn rows(len: usize, width: usize) -> usize {
    len.div_ceil(width.max(1)).max(1)
}

/// The lines last drawn at the bottom of the terminal, redrawn in place on every frame.
pub(crate) struct Region<W: Write> {
    out: W,
    /// Visible length of each line written by the last `draw`.
    drawn: Vec<usize>,
    /// Terminal width at the last `draw`.
    drawn_width: usize,
    hidden: bool,
}

impl<W: Write> Region<W> {
    pub(crate) fn new(out: W) -> Self {
        Region {
            out,
            drawn: Vec::new(),
            drawn_width: 0,
            hidden: false,
        }
    }

    /// Replaces the live area with `lines`.
    pub(crate) fn draw(&mut self, lines: &[String], width: usize) -> io::Result<()> {
        let mut buf = self.begin_frame(width, !self.hidden)?;
        let drawn = write_lines(&mut buf, lines, width)?;
        self.send(buf)?;
        self.hidden = true;
        self.drawn = drawn;
        self.drawn_width = width;
        Ok(())
    }

    /// Clears the live area and writes `lines` as permanent text; nothing is left to redraw.
    pub(crate) fn commit(&mut self, lines: &[String], width: usize) -> io::Result<()> {
        let mut buf = self.begin_frame(width, false)?;
        write_lines(&mut buf, lines, width)?;
        self.send(buf)?;
        self.drawn.clear();
        Ok(())
    }

    /// Clears the live area, shows the cursor and resets attributes.
    pub(crate) fn finish(mut self) -> io::Result<W> {
        let mut buf = self.begin_frame(self.drawn_width, false)?;
        queue!(
            buf,
            cursor::Show,
            style::SetAttribute(style::Attribute::Reset),
            terminal::EndSynchronizedUpdate
        )?;
        self.out.write_all(&buf)?;
        self.out.flush()?;
        Ok(self.out)
    }

    /// Starts a frame (hiding the cursor if asked): moves back to the top of the live area and clears from there down.
    /// The terminal reflows lines it already drew when it gets narrower, so those take
    /// more rows than lines.
    fn begin_frame(&self, width: usize, hide: bool) -> io::Result<Vec<u8>> {
        let up = if width < self.drawn_width {
            self.drawn.iter().map(|&len| rows(len, width)).sum()
        } else {
            self.drawn.len()
        };
        let mut buf = Vec::new();
        queue!(buf, terminal::BeginSynchronizedUpdate)?;
        if hide {
            queue!(buf, cursor::Hide)?;
        }
        // MoveUp(0) still moves one row on some terminals.
        if up > 0 {
            queue!(buf, cursor::MoveUp(up.min(usize::from(u16::MAX)) as u16))?;
        }
        queue!(
            buf,
            cursor::MoveToColumn(0),
            terminal::Clear(terminal::ClearType::FromCursorDown)
        )?;
        Ok(buf)
    }

    /// Ends the frame and sends it in one write, so the terminal never shows half of it.
    fn send(&mut self, mut buf: Vec<u8>) -> io::Result<()> {
        queue!(buf, terminal::EndSynchronizedUpdate)?;
        self.out.write_all(&buf)?;
        self.out.flush()
    }

    #[cfg(test)]
    fn written(&self) -> &W {
        &self.out
    }
}

/// Writes each line clipped to leave the last column free (so the terminal never wraps),
/// and returns the visible length of what was written.
fn write_lines(buf: &mut Vec<u8>, lines: &[String], width: usize) -> io::Result<Vec<usize>> {
    let mut lens = Vec::with_capacity(lines.len());
    for line in lines {
        let line = clip(line, width.saturating_sub(1));
        lens.push(visible_len(&line));
        queue!(buf, style::Print(line), style::Print("\r\n"))?;
    }
    Ok(lens)
}

/// Shows the cursor and resets colors on stdout, ignoring errors: for the second Ctrl-C
/// and for panics, when the region can no longer be finished properly.
pub(crate) fn restore_terminal() {
    let mut out = io::stdout().lock();
    let _ = write_restore(&mut out);
}

fn write_restore(out: &mut impl Write) -> io::Result<()> {
    queue!(out, cursor::Show, style::SetAttribute(style::Attribute::Reset))?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEGIN: &str = "\x1b[?2026h";
    const END: &str = "\x1b[?2026l";
    const HIDE: &str = "\x1b[?25l";
    const SHOW: &str = "\x1b[?25h";
    const CLEAR: &str = "\x1b[J";
    const COLUMN0: &str = "\x1b[1G";
    const RESET: &str = "\x1b[0m";

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn text(region: &Region<Vec<u8>>) -> String {
        String::from_utf8(region.written().clone()).unwrap()
    }

    #[test]
    fn first_draw_hides_the_cursor_and_moves_nowhere() {
        let mut r = Region::new(Vec::new());
        r.draw(&lines(&["a", "b"]), 100).unwrap();
        assert_eq!(text(&r), format!("{BEGIN}{HIDE}{COLUMN0}{CLEAR}a\r\nb\r\n{END}"));
    }

    #[test]
    fn draw_then_draw_rewrites_in_place() {
        let mut r = Region::new(Vec::new());
        r.draw(&lines(&["a", "b", "c"]), 100).unwrap();
        let first = text(&r).len();
        r.draw(&lines(&["x"]), 100).unwrap();
        assert_eq!(text(&r)[first..], format!("{BEGIN}\x1b[3A{COLUMN0}{CLEAR}x\r\n{END}"));
        // The next draw only goes up over the one line the second draw left.
        let second = text(&r).len();
        r.draw(&lines(&["y"]), 100).unwrap();
        assert!(text(&r)[second..].starts_with(&format!("{BEGIN}\x1b[1A")));
    }

    #[test]
    fn commit_leaves_text_above() {
        let mut r = Region::new(Vec::new());
        r.draw(&lines(&["live 1", "live 2"]), 100).unwrap();
        let before_commit = text(&r).len();
        r.commit(&lines(&["done"]), 100).unwrap();
        assert_eq!(
            text(&r)[before_commit..],
            format!("{BEGIN}\x1b[2A{COLUMN0}{CLEAR}done\r\n{END}")
        );
        // The committed text is not part of the live area: the next draw starts below it.
        let before_draw = text(&r).len();
        r.draw(&lines(&["live 3"]), 100).unwrap();
        let drawn = &text(&r)[before_draw..];
        assert_eq!(drawn, format!("{BEGIN}{COLUMN0}{CLEAR}live 3\r\n{END}"));
        assert_eq!(text(&r).matches("done").count(), 1);
    }

    #[test]
    fn long_lines_are_clipped() {
        let long = "x".repeat(200);
        let clipped = clip(&long, 40);
        assert_eq!(visible_len(&clipped), 40);
        // The region never writes into the last column, so the terminal cannot auto-wrap.
        let mut r = Region::new(Vec::new());
        r.draw(&[long], 40).unwrap();
        let drawn = text(&r);
        let row = drawn
            .split("\r\n")
            .next()
            .unwrap()
            .rsplit(CLEAR)
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(visible_len(&row), 39);
        assert!(row.ends_with(RESET));
    }

    #[test]
    fn clip_keeps_escapes_whole() {
        let colored = "\x1b[1;38;2;1;2;3mhello\x1b[0m \x1b[32mworld\x1b[0m";
        for width in 0..=visible_len(colored) + 2 {
            let clipped = clip(colored, width);
            assert_eq!(visible_len(&clipped), width.min(visible_len(colored)), "{width}");
            // Every escape that starts is complete.
            let mut open = false;
            for c in clipped.chars() {
                match (open, c) {
                    (false, '\x1b') => open = true,
                    (true, 'm') => open = false,
                    _ => {}
                }
            }
            assert!(!open, "partial escape at width {width}: {clipped:?}");
            if width < visible_len(colored) {
                assert!(clipped.ends_with(RESET), "{width}: {clipped:?}");
            } else {
                assert_eq!(clipped, colored);
            }
        }
        // Escapes after the last visible character are not a reason to cut.
        assert_eq!(clip("\x1b[31mab\x1b[0m", 2), "\x1b[31mab\x1b[0m");
        assert_eq!(clip("plain", 10), "plain");
        assert_eq!(clip("plain", 0), "\x1b[0m");
    }

    #[test]
    fn finish_shows_the_cursor() {
        let mut r = Region::new(Vec::new());
        r.draw(&lines(&["a", "b"]), 100).unwrap();
        let before = text(&r).len();
        let out = r.finish().unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap()[before..],
            format!("{BEGIN}\x1b[2A{COLUMN0}{CLEAR}{SHOW}{RESET}{END}")
        );
    }

    #[test]
    fn restore_bytes() {
        let mut out = Vec::new();
        write_restore(&mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), format!("{SHOW}{RESET}"));
    }

    #[test]
    fn narrower_redraw_moves_up_over_wrapped_rows() {
        let eighty = "y".repeat(80);
        let mut r = Region::new(Vec::new());
        r.draw(&[eighty.clone(), eighty.clone(), eighty.clone()], 100).unwrap();
        let first = text(&r).len();
        r.draw(&lines(&["a"]), 40).unwrap();
        // The terminal reflowed each 80-column line over two rows.
        assert!(text(&r)[first..].starts_with(&format!("{BEGIN}\x1b[6A{COLUMN0}{CLEAR}")));
        // Short lines and a wider terminal never move up more than the line count.
        let mut r = Region::new(Vec::new());
        r.draw(&lines(&["a", "", "b"]), 100).unwrap();
        let first = text(&r).len();
        r.draw(&lines(&["a"]), 20).unwrap();
        assert!(text(&r)[first..].starts_with(&format!("{BEGIN}\x1b[3A")));
        let mut r = Region::new(Vec::new());
        r.draw(&[eighty.clone(), eighty], 40).unwrap();
        let first = text(&r).len();
        r.draw(&lines(&["a"]), 200).unwrap();
        assert!(text(&r)[first..].starts_with(&format!("{BEGIN}\x1b[2A")));
    }

    #[test]
    fn empty_region_never_moves_up_by_zero() {
        let mut r = Region::new(Vec::new());
        r.draw(&[], 100).unwrap();
        r.commit(&lines(&["a"]), 100).unwrap();
        r.draw(&[], 100).unwrap();
        let out = String::from_utf8(r.finish().unwrap()).unwrap();
        // No cursor-up sequence at all (the only uppercase `A` would end one).
        assert!(!out.contains('A'), "{out:?}");
    }

    #[test]
    fn each_frame_is_one_write_and_one_flush() {
        #[derive(Default)]
        struct Counting {
            writes: usize,
            flushes: usize,
        }
        impl Write for Counting {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                Ok(())
            }
        }
        let mut r = Region::new(Counting::default());
        r.draw(&lines(&["a", "b"]), 80).unwrap();
        r.commit(&lines(&["c"]), 80).unwrap();
        let out = r.finish().unwrap();
        assert_eq!((out.writes, out.flushes), (3, 3));
    }
}
