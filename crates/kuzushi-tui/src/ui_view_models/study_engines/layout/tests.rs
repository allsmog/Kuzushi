use super::*;

#[test]
fn tall_stacked_terminal_shows_every_engine_without_borrowing_controls_or_reading_space() {
    let layout = engine_layout(96, 89, 14);
    assert_eq!(layout.list.height, 14);
    assert!(layout.detail.height >= 60);
    assert!(layout.list.bottom() < layout.detail.y);
    assert!(layout.detail.bottom() <= layout.controls.y);
}

#[test]
fn compact_layouts_preserve_their_existing_detail_and_controls() {
    for (width, height) in [(80, 24), (60, 20), (40, 12)] {
        let original = study_config_layout(study_config_area(width, height));
        let layout = engine_layout(width, height, 14);
        assert_eq!(layout.list, original.list);
        assert_eq!(layout.detail, original.detail);
        assert_eq!(layout.controls, original.controls);
        assert!(layout.detail.height >= 2);
    }
}

#[test]
fn engine_windows_include_both_ends_and_never_invent_rows() {
    for count in [0, 1, 14, 500] {
        for height in [0, 1, 3, 8, 14, 83] {
            for cursor in 0..=count {
                let window = engine_window(count, cursor, height);
                assert!(window.start <= window.end && window.end <= count);
                assert!(window.len() <= height);
                if count > 0 && height > 0 {
                    assert!(window.contains(&cursor.min(count - 1)));
                }
            }
        }
    }
    assert_eq!(engine_window(14, 0, 3), 0..3);
    assert_eq!(engine_window(14, 13, 3), 11..14);
}
