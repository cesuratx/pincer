//! Minimal aligned-table renderer (no table crate). Columns size to their
//! widest cell; numeric columns right-align.

use std::fmt::Write as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    Left,
    Right,
}

#[derive(Debug)]
pub struct Table {
    headers: Vec<String>,
    aligns: Vec<Align>,
    rows: Vec<Vec<String>>,
}

impl Table {
    #[must_use]
    pub fn new(columns: &[(&str, Align)]) -> Self {
        Self {
            headers: columns
                .iter()
                .map(|(name, _)| (*name).to_string())
                .collect(),
            aligns: columns.iter().map(|(_, align)| *align).collect(),
            rows: Vec::new(),
        }
    }

    /// Append a row. Contract: the caller supplies exactly one cell per header
    /// column — a mismatched arity renders misaligned rather than panicking
    /// (no panics in library code).
    pub fn push(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Number of data rows (headers and rule excluded).
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Render to a string with two-space column gutters.
    #[must_use]
    pub fn render(&self) -> String {
        let cols = self.headers.len();
        let mut widths: Vec<usize> = self.headers.iter().map(|h| display_width(h)).collect();
        for row in &self.rows {
            for (idx, cell) in row.iter().enumerate() {
                if let Some(width) = widths.get_mut(idx) {
                    *width = (*width).max(display_width(cell));
                }
            }
        }

        let mut out = String::new();
        self.write_row(&mut out, &self.headers, &widths, cols);
        // underline
        let mut rule = Vec::with_capacity(cols);
        for width in &widths {
            rule.push("-".repeat(*width));
        }
        self.write_row(&mut out, &rule, &widths, cols);
        for row in &self.rows {
            self.write_row(&mut out, row, &widths, cols);
        }
        out
    }

    fn write_row(&self, out: &mut String, cells: &[String], widths: &[usize], cols: usize) {
        for idx in 0..cols {
            let cell = cells.get(idx).map_or("", String::as_str);
            let width = widths.get(idx).copied().unwrap_or(0);
            let align = self.aligns.get(idx).copied().unwrap_or(Align::Left);
            let pad = width.saturating_sub(display_width(cell));
            match align {
                Align::Left => {
                    let _ = write!(out, "{cell}");
                    if idx + 1 < cols {
                        let _ = write!(out, "{}", " ".repeat(pad));
                    }
                }
                Align::Right => {
                    let _ = write!(out, "{}{cell}", " ".repeat(pad));
                }
            }
            if idx + 1 < cols {
                out.push_str("  ");
            }
        }
        out.push('\n');
    }
}

fn display_width(text: &str) -> usize {
    text.chars().count()
}

/// Human-readable byte count: `1.5K`, `2.0M`, …
#[must_use]
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut value = bytes as f64;
    let mut unit = 0;
    // `>= 1023.95` not `>= 1024.0`: a value like 1048575 B is 1023.999 K, which
    // rounds to "1024.0K" at one decimal — roll it over to "1.0M" instead.
    while value >= 1023.95 && unit < UNITS.len().saturating_sub(1) {
        value /= 1024.0;
        unit = unit.saturating_add(1);
    }
    let suffix = UNITS.get(unit).copied().unwrap_or("B");
    if unit == 0 {
        format!("{bytes}{suffix}")
    } else {
        format!("{value:.1}{suffix}")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn aligns_columns() {
        let mut table = Table::new(&[("name", Align::Left), ("count", Align::Right)]);
        table.push(vec!["aa".into(), "5".into()]);
        table.push(vec!["bbbb".into(), "100".into()]);
        let rendered = table.render();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[0], "name  count");
        assert_eq!(lines[1], "----  -----");
        assert_eq!(lines[2], "aa        5");
        assert_eq!(lines[3], "bbbb    100");
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512B");
        assert_eq!(human_bytes(1536), "1.5K");
        assert_eq!(human_bytes(2 * 1024 * 1024), "2.0M");
    }

    #[test]
    fn human_bytes_rolls_over_instead_of_1024_unit() {
        // 1048575 B is 1023.999 K — must render "1.0M", never "1024.0K".
        assert_eq!(human_bytes(1024 * 1024 - 1), "1.0M");
        assert_eq!(human_bytes(1024 * 1024 * 1024 - 1), "1.0G");
        assert_eq!(human_bytes(1023), "1023B");
    }
}
