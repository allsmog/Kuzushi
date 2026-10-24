use crossterm::event::KeyCode;

pub(super) fn cursor_after_key(code: KeyCode, current: usize, count: usize, page: usize) -> usize {
    let last = count.saturating_sub(1);
    let previous = current.saturating_sub(1);
    let next = current.saturating_add(1).min(last);
    let page_up = current.saturating_sub(page);
    let page_down = current.saturating_add(page).min(last);
    [
        (KeyCode::Up, previous),
        (KeyCode::Char('k'), previous),
        (KeyCode::BackTab, previous),
        (KeyCode::Down, next),
        (KeyCode::Char('j'), next),
        (KeyCode::Tab, next),
        (KeyCode::PageUp, page_up),
        (KeyCode::PageDown, page_down),
        (KeyCode::Home, 0),
        (KeyCode::End, last),
    ]
    .into_iter()
    .find_map(|(key, value)| (key == code).then_some(value))
    .unwrap_or(current)
}
