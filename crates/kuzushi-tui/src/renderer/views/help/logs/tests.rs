use super::*;

#[test]
fn long_paths_keep_their_exact_printable_text_across_prefix_widths() {
    let body = format!("/owned/{}/café  report.rs", "a".repeat(100));
    let rows = wrapped_log_body(&body, 14, 38);
    assert_eq!(rows.concat(), body);
    assert!(display_width(&rows[0]) <= 14);
    assert!(rows.iter().skip(1).all(|row| display_width(row) <= 38));
}

#[test]
fn log_wrap_preserves_spaces_and_complete_graphemes() {
    let body = "  /資料/👩‍💻/cafe\u{301}  notes.rs  ";
    let rows = wrapped_log_body(body, 12, 18);
    assert_eq!(rows.concat(), body);
    assert!(display_width(&rows[0]) <= 12);
    assert!(rows.iter().skip(1).all(|row| display_width(row) <= 18));
    assert!(rows.iter().any(|row| row.contains("👩‍💻")));
    assert!(rows.iter().any(|row| row.contains("e\u{301}")));
}

#[test]
fn wide_log_prefixes_use_terminal_cell_width() {
    let rows = wrapped_log_lines("資料", &"owned path ".repeat(10), false, 0, 40);
    assert!(rows.iter().all(|row| display_width(&line_text(row)) <= 40));
}
