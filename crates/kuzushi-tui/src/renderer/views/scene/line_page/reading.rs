use super::LinePageRows;
use crate::app::GalleryTextAnchor;
use ratatui::prelude::Line;
use std::hash::{DefaultHasher, Hasher};

impl LinePageRows {
    pub(in crate::renderer::views::scene) fn reading_anchor(
        &self,
        visible: u16,
        scroll: usize,
    ) -> Option<GalleryTextAnchor> {
        if self.rows.is_empty() {
            return None;
        }
        let start = self.normalized_scroll(visible, scroll);
        let row = self.row_at(start);
        let skipped = start - self.starts[row];
        Some(GalleryTextAnchor {
            row,
            characters: self.rows[row][..skipped].iter().map(character_count).sum(),
            identity: row_identity(&self.rows[row]),
            tail: scroll == u16::MAX as usize,
        })
    }

    pub(in crate::renderer::views::scene) fn restore_reading(
        &self,
        visible: u16,
        anchor: GalleryTextAnchor,
    ) -> Option<usize> {
        let row = self.rows.get(anchor.row)?;
        if row_identity(row) != anchor.identity {
            return None;
        }
        if anchor.tail {
            return Some(u16::MAX as usize);
        }
        let line = line_containing(row, anchor.characters);
        Some(self.normalized_scroll(visible, self.starts[anchor.row] + line))
    }
}

fn line_containing(row: &[Line<'static>], characters: usize) -> usize {
    let mut end = 0;
    for (index, line) in row.iter().enumerate() {
        end += character_count(line);
        if end > characters {
            return index;
        }
    }
    row.len().saturating_sub(1)
}

fn character_count(line: &Line<'static>) -> usize {
    line.spans
        .iter()
        .flat_map(|span| span.content.chars())
        .filter(|ch| reading_character(*ch))
        .count()
}

fn row_identity(row: &[Line<'static>]) -> u64 {
    let mut hash = DefaultHasher::new();
    for ch in row
        .iter()
        .flat_map(|line| line.spans.iter())
        .flat_map(|span| span.content.chars())
    {
        if reading_character(ch) {
            hash.write_u32(ch as u32);
        }
    }
    hash.finish()
}

fn reading_character(ch: char) -> bool {
    !ch.is_whitespace() && !matches!(ch, '\u{2500}'..='\u{257f}')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(width: usize) -> LinePageRows {
        LinePageRows::from_document_lines(
            vec![
                Line::from("heading"),
                Line::from("prefix0123456789/owned/very/long/路径/component.rs evidence tail"),
                Line::from("tail"),
            ],
            width,
        )
    }

    #[test]
    fn a_continuation_can_return_to_the_same_position_after_widening() {
        let narrow = document(10);
        let anchor = narrow.reading_anchor(3, 3).unwrap();
        let wide = document(30);
        let wide_offset = wide.restore_reading(3, anchor).unwrap();
        assert!(wide_offset < 3);
        assert_eq!(narrow.restore_reading(3, anchor), Some(3));
    }

    #[test]
    fn changed_content_does_not_reuse_an_old_position() {
        let anchor = document(10).reading_anchor(3, 3).unwrap();
        let changed = LinePageRows::from_document_lines(
            vec![Line::from("heading"), Line::from("different content")],
            10,
        );
        assert_eq!(changed.restore_reading(3, anchor), None);
        assert!(LinePageRows::default().reading_anchor(3, 0).is_none());
    }

    #[test]
    fn end_remains_at_the_tail_after_resize() {
        let anchor = document(10).reading_anchor(3, u16::MAX as usize).unwrap();
        assert_eq!(
            document(30).restore_reading(3, anchor),
            Some(u16::MAX as usize)
        );
    }

    #[test]
    fn tree_continuations_do_not_change_row_identity() {
        let narrow = vec![Line::from("├─ owned/"), Line::from("│  component")];
        let wide = vec![Line::from("├─ owned/component")];
        assert_eq!(row_identity(&narrow), row_identity(&wide));
    }
}
