use super::*;
use crate::renderer::shared::text::display_width;

fn unbuilt_map_model() -> ProjectModel {
    ProjectModel {
        scope_label: "~/code/monorepo".to_string(),
        revision_label: "rev:checking…".to_string(),
        rows: vec![
            ProjectModelRow {
                section: "scope tree",
                origin: ProjectModelOrigin::Missing,
                state: "root only",
                summary: "no persisted nested scopes yet; run `next` to map project boundaries"
                    .to_string(),
                action: "next",
            },
            ProjectModelRow {
                section: "context feed",
                origin: ProjectModelOrigin::Stale,
                state: "unverifiable",
                summary: "no snapshot · not built".to_string(),
                action: "context build",
            },
            ProjectModelRow {
                section: "review surface",
                origin: ProjectModelOrigin::Missing,
                state: "missing",
                summary: "0 items · 0 triaged · 0 pending".to_string(),
                action: "threats summary",
            },
        ],
        next_hint: "Next: context build",
    }
}

fn row_text(row: &ProjectContextRow) -> String {
    row.segments()
        .into_iter()
        .map(|segment| segment.text)
        .collect()
}

#[test]
fn wide_terminals_render_state_and_action_columns() {
    let table = project_context_columns(&unbuilt_map_model(), 110);

    assert!(table.action_w > 0, "wide table columns");
    assert_eq!(table.section_w, display_width("review surface"));
    assert_eq!(table.state_w, display_width("unverifiable"));
    assert_eq!(table.action_w, display_width("threats summary"));
    let cells = table.rows[0]
        .segments()
        .into_iter()
        .map(|segment| segment.cell)
        .collect::<Vec<_>>();
    assert_eq!(
        cells,
        vec![
            ProjectContextCell::Origin,
            ProjectContextCell::Section,
            ProjectContextCell::Rule,
            ProjectContextCell::State,
            ProjectContextCell::Rule,
            ProjectContextCell::Summary,
            ProjectContextCell::Rule,
            ProjectContextCell::Action,
        ]
    );
}

#[test]
fn wide_rows_consume_the_whole_usable_width() {
    let table = project_context_columns(&unbuilt_map_model(), 110);

    for row in &table.rows {
        assert_eq!(
            display_width(&row_text(row)),
            110,
            "row leaves dead columns: {row:?}"
        );
    }
}

#[test]
fn narrow_terminals_collapse_to_the_two_column_row() {
    let table = project_context_columns(&unbuilt_map_model(), 60);

    assert_eq!(table.state_w, 0, "collapsed table columns");
    assert_eq!(table.action_w, 0);
    assert_eq!(table.section_w, COLLAPSED_SECTION_COLUMNS);
    assert_eq!(table.summary_w, 60 - COLLAPSED_SECTION_COLUMNS - 3);
    for row in &table.rows {
        assert_eq!(row.action, None, "collapsed rows carry no action column");
    }
}

#[test]
fn the_state_column_is_never_truncated_into_an_ellipsis() {
    for width in [60usize, 88, 98, 110, 124, 200] {
        let table = project_context_columns(&unbuilt_map_model(), width);
        for row in &table.rows {
            assert!(
                !row.state.contains('…'),
                "state truncated at width {width}: {:?}",
                row.state
            );
        }
    }
    let table = project_context_columns(&unbuilt_map_model(), 110);
    assert_eq!(table.rows[1].state.trim_end(), "unverifiable");
}

/// The line-based projection carries every cell and drops only the trailing
/// padding, so a surface that appends to the row does not inherit dead space.
#[test]
fn row_text_carries_every_cell_and_drops_trailing_padding() {
    let table = project_context_columns(&unbuilt_map_model(), 110);
    let text = table.rows[0].text();

    assert!(text.contains(CONTEXT_COLUMN_RULE), "column rule: {text}");
    assert!(text.contains("root only"), "state text: {text}");
    assert!(text.ends_with("▸ next"), "action text: {text}");
}
