use super::*;

#[test]
fn reading_range_tracks_visible_wrapped_lines_after_resize_and_at_end() {
    assert_eq!(line_range(0, 200, 6), "1-6/200");
    assert_eq!(line_range(6, 200, 6), "7-12/200");
    assert_eq!(line_range(194, 200, 30), "171-200/200");
    assert_eq!(line_range(usize::MAX, 12, 30), "1-12/12");
    assert_eq!(line_range(0, 0, 6), "0/0");
    assert_eq!(line_range(9, 20, 0), "0/20");
}

#[test]
fn narrow_header_keeps_the_reading_position_without_splitting_wide_characters() {
    let title = "接続サービス 👩‍💻 with a long component name";
    for width in [0, 1, 6, 12, 36, 76, 116] {
        let heading = reading_heading(title, "195-200/200", width);
        assert!(heading.width() <= width, "{width}: {heading}");
        if width > 13 {
            assert!(heading.ends_with("195-200/200"));
        }
    }
}

#[test]
fn ordinary_tree_does_not_get_a_reader_heading() {
    let state = ScopeReviewState::new(std::path::PathBuf::from("/target"));
    assert!(scope_reader_heading(&state, 40, Rect::new(0, 0, 36, 6)).is_none());
}
