use super::*;
use crate::ui_view_models::{cost_cap_halt_model, throttle_banner_model, transcript_chrome_height};

pub(crate) fn section_slot(kind: RenderSection, height: u16) -> Option<RenderSectionSlot> {
    (height > 0).then_some(RenderSectionSlot { kind, height })
}

pub(crate) fn fixed_chrome_height(sections: &[RenderSectionSlot]) -> u16 {
    PROMPT_HEIGHT + sections.iter().map(|section| section.height).sum::<u16>()
}

pub(crate) fn render_constraints(
    view_height: u16,
    sections: &[RenderSectionSlot],
) -> Vec<Constraint> {
    let mut constraints = vec![Constraint::Length(view_height), Constraint::Min(0)];
    constraints.extend(
        sections
            .iter()
            .map(|section| Constraint::Length(section.height)),
    );
    constraints.push(Constraint::Length(PROMPT_HEIGHT));
    constraints
}

pub(crate) fn transcript_height(app: &ShellApp, area: Rect) -> u16 {
    transcript_chrome_height(app, area.height)
}

pub(crate) fn keybind_footer_height(area: Rect) -> u16 {
    if area.height < 8 {
        return 0;
    }
    // M4 §4.2: narrow terminals (tmux side panes, sshd-on-mobile) wrap
    // the keybindings to a second line so they stay legible. 70 cols is
    // the threshold where the single-line layout starts truncating the
    // first row's hints; below that the two-line layout is more
    // readable.
    if area.width < 70 {
        3
    } else {
        2
    }
}

pub(crate) fn status_footer_height(area: Rect) -> u16 {
    if area.height >= 6 {
        1
    } else {
        0
    }
}

pub(crate) fn throttle_banner_height(app: &ShellApp, area: Rect) -> u16 {
    if throttle_banner_model(app).is_some() && area.height >= 5 {
        1
    } else {
        0
    }
}

pub(crate) fn cost_cap_halt_height(app: &ShellApp, area: Rect) -> u16 {
    if cost_cap_halt_model(app).is_some() && area.height >= 5 {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(width: u16, height: u16) -> Rect {
        Rect::new(0, 0, width, height)
    }

    #[test]
    fn keybind_footer_wraps_below_seventy_columns() {
        // M4 §4.2 contract: tall enough terminals get the full footer.
        // The threshold for wrap is width < 70 — narrow terminals get
        // an extra row so the binding hints stay legible.
        assert_eq!(keybind_footer_height(rect(120, 24)), 2);
        assert_eq!(keybind_footer_height(rect(80, 24)), 2);
        assert_eq!(keybind_footer_height(rect(70, 24)), 2);
        assert_eq!(keybind_footer_height(rect(69, 24)), 3);
        assert_eq!(keybind_footer_height(rect(60, 24)), 3);
        assert_eq!(keybind_footer_height(rect(40, 24)), 3);
    }

    #[test]
    fn keybind_footer_hides_in_tiny_terminals() {
        // Below 8 rows there is no room for chrome at all.
        assert_eq!(keybind_footer_height(rect(80, 7)), 0);
        assert_eq!(keybind_footer_height(rect(60, 7)), 0);
    }
}
