use super::line_page::LinePageRows;
use crate::theme;
use crate::ui_view_models::{
    ComponentItem, ComponentScope, ComponentSource, ComponentSourceKind, ComponentStack,
};
use ratatui::prelude::{Line, Span, Style};

/// The component stack as the rows it projects. Each tree value is one row
/// however many display lines it wraps onto, so the page's row total is the
/// same at every canvas width.
pub(super) fn component_tree_rows(width: usize, model: &ComponentStack) -> LinePageRows {
    if let Some(hint) = &model.empty_hint {
        return LinePageRows::from_document_lines(
            crate::renderer::empty_state_panel(
                "no component stack",
                &[hint],
                &[("run sbom-scan:scan", "inventory manifests and lockfiles")],
            ),
            width,
        );
    }
    let mut rows = LinePageRows::default();
    append_summary(&mut rows, width, model);
    rows.push(Line::from(String::new()));
    rows.push(Line::styled(
        crate::renderer::shared::text::fit(&format!("◆ {}", model.target), width),
        theme::heading(),
    ));
    append_metadata(&mut rows, width, model);
    append_sources(&mut rows, width, &model.sources);
    rows
}

fn append_summary(rows: &mut LinePageRows, width: usize, model: &ComponentStack) {
    rows.push_wrapped(styled_wrapped_lines(
        &format!(
            "COMPONENT STACK · {} manifests · {} lockfiles",
            model.manifest_count, model.lockfile_count
        ),
        width,
        theme::accent(),
    ));
    rows.push_wrapped(styled_wrapped_lines(
        &format!(
            "{} declared · {} resolved · {}",
            model.declared_count,
            model.resolved_count,
            joined_or(&model.ecosystems, "no package ecosystem")
        ),
        width,
        theme::muted(),
    ));
    if model.from_tool {
        rows.push_wrapped(styled_wrapped_lines(
            "From the latest completed SBOM result. Source freshness is unverified.",
            width,
            theme::muted(),
        ));
    }
}

fn append_metadata(rows: &mut LinePageRows, width: usize, model: &ComponentStack) {
    append_tree_value(
        rows,
        width,
        "├─ ",
        "│  ",
        &format!(
            "languages · {}",
            joined_or(&model.languages, "none detected")
        ),
        theme::primary(),
    );
    append_tree_value(
        rows,
        width,
        "├─ ",
        "│  ",
        &format!(
            "build systems · {}",
            joined_or(&model.build_systems, "none detected")
        ),
        theme::primary(),
    );
}

fn append_sources(rows: &mut LinePageRows, width: usize, sources: &[ComponentSource]) {
    for (source_index, source) in sources.iter().enumerate() {
        let source_last = source_index + 1 == sources.len();
        let branch = if source_last { "└─ " } else { "├─ " };
        let continuation = if source_last { "   " } else { "│  " };
        append_tree_value(
            rows,
            width,
            branch,
            continuation,
            &format!(
                "{} · {} · {}",
                source.ecosystem,
                source.path,
                source_kind_label(source.kind)
            ),
            theme::heading(),
        );
        append_scopes(rows, width, continuation, &source.scopes);
    }
}

fn append_scopes(
    rows: &mut LinePageRows,
    width: usize,
    source_prefix: &str,
    scopes: &[ComponentScope],
) {
    for (scope_index, scope) in scopes.iter().enumerate() {
        let scope_last = scope_index + 1 == scopes.len();
        let branch = if scope_last { "└─ " } else { "├─ " };
        let scope_prefix = format!("{source_prefix}{branch}");
        let child_prefix = format!("{source_prefix}{}", if scope_last { "   " } else { "│  " });
        append_tree_value(
            rows,
            width,
            &scope_prefix,
            &child_prefix,
            &scope.name,
            theme::label(),
        );
        append_components(rows, width, &child_prefix, &scope.components);
    }
}

fn append_components(
    rows: &mut LinePageRows,
    width: usize,
    scope_prefix: &str,
    components: &[ComponentItem],
) {
    for (index, component) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        let branch = if last { "└─ " } else { "├─ " };
        let prefix = format!("{scope_prefix}{branch}");
        let continuation = format!("{scope_prefix}{}", if last { "   " } else { "│  " });
        append_tree_value(
            rows,
            width,
            &prefix,
            &continuation,
            &component_label(component),
            theme::primary(),
        );
    }
}

fn component_label(component: &ComponentItem) -> String {
    match (
        &component.declared,
        component.repository_versions.as_slice(),
    ) {
        (Some(declared), []) => format!("{} · declared {declared}", component.name),
        (Some(declared), repository_versions) => format!(
            "{} · declared {declared} · repo versions {}",
            component.name,
            repository_versions.join(", ")
        ),
        (None, []) => format!("{} · version unknown", component.name),
        (None, repository_versions) => format!(
            "{} · resolved {}",
            component.name,
            repository_versions.join(", ")
        ),
    }
}

/// One tree value as one row. A value too long for the canvas wraps under
/// its own continuation glyphs, which adds display lines to the row without
/// adding a row to the page.
fn append_tree_value(
    rows: &mut LinePageRows,
    width: usize,
    prefix: &str,
    continuation: &str,
    value: &str,
    style: Style,
) {
    let prefix_width = prefix.chars().count();
    if width <= prefix_width {
        rows.push_wrapped(styled_wrapped_lines(value, width, style));
        return;
    }
    let chunks = crate::renderer::shared::text::wrap_text(value, width - prefix_width);
    rows.push_wrapped(
        chunks
            .into_iter()
            .enumerate()
            .map(|(index, chunk)| {
                let tree = if index == 0 { prefix } else { continuation };
                Line::from(vec![
                    Span::styled(tree.to_string(), theme::subtle()),
                    Span::styled(chunk, style),
                ])
            })
            .collect(),
    );
}

fn styled_wrapped_lines(value: &str, width: usize, style: Style) -> Vec<Line<'static>> {
    crate::renderer::shared::text::wrap_text(value, width)
        .into_iter()
        .map(|chunk| Line::styled(chunk, style))
        .collect()
}

fn source_kind_label(kind: ComponentSourceKind) -> &'static str {
    match kind {
        ComponentSourceKind::Manifest => "declared",
        ComponentSourceKind::Lockfile => "lockfile",
    }
}

fn joined_or(values: &[String], fallback: &str) -> String {
    if values.is_empty() {
        fallback.to_string()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrow_failure_retains_the_full_cause_and_rerun_action() {
        let cause =
            "Component inventory failed: /owned/long/path/package.json exceeds its read limit.";
        let model = ComponentStack {
            empty_hint: Some(cause.into()),
            ..Default::default()
        };
        let rows = component_tree_rows(40, &model);
        let wrapped_total = component_tree_rows(120, &model).len();
        assert_eq!(
            rows.len(),
            wrapped_total,
            "a wrapped cause is still one row"
        );
        let lines = rows.into_lines();
        assert!(lines.iter().all(|line| line.width() <= 40));
        let text = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<String>();
        let compact = text.split_whitespace().collect::<String>();
        assert!(compact.contains(&cause.split_whitespace().collect::<String>()));
        assert!(compact.contains("runsbom-scan:scan"));
    }

    #[test]
    fn tree_preserves_version_semantics_at_narrow_width() {
        let model = ComponentStack {
            target: "demo".into(),
            languages: vec!["TypeScript".into()],
            build_systems: vec!["Node".into()],
            sources: vec![ComponentSource {
                path: "package.json".into(),
                ecosystem: "npm".into(),
                kind: ComponentSourceKind::Manifest,
                scopes: vec![ComponentScope {
                    name: "dependencies".into(),
                    components: vec![ComponentItem {
                        name: "framework-with-long-name".into(),
                        declared: Some("^1".into()),
                        repository_versions: vec!["1.4.2".into()],
                    }],
                }],
            }],
            manifest_count: 1,
            lockfile_count: 1,
            declared_count: 1,
            resolved_count: 1,
            ecosystems: vec!["npm".into()],
            empty_hint: None,
            from_tool: false,
        };

        let lines = component_tree_rows(28, &model).into_lines();
        let text = lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(text.contains("package.json"), "{text}");
        assert!(text.contains("declared ^1"), "{text}");
        assert!(normalized.contains("repo versions 1.4.2"), "{text}");
        assert!(lines.iter().all(|line| line.width() <= 28));
    }

    /// The defect this guards: one real 2731-component tree reported three
    /// different totals — `2731` on Map's embedded canvas, `2732` in the
    /// full-frame zoom, `2737` at 80 columns — because the total counted the
    /// display lines the canvas wrapped the tree into. The rows belong to the
    /// model, so every width must agree on how many there are.
    #[test]
    fn the_row_count_is_the_same_at_every_width() {
        let model = wide_component_model();

        let totals = [40, 80, 120, 200]
            .map(|width| component_tree_rows(width, &model).len())
            .to_vec();
        let display_lines = [40, 200]
            .map(|width| component_tree_rows(width, &model).into_lines().len())
            .to_vec();

        assert!(
            totals.windows(2).all(|pair| pair[0] == pair[1]),
            "{totals:?}"
        );
        assert!(
            display_lines[0] > display_lines[1],
            "fixture must wrap at 40 columns: {display_lines:?}"
        );
    }

    fn wide_component_model() -> ComponentStack {
        ComponentStack {
            target: "monorepo".into(),
            languages: vec!["Rust".into(), "TypeScript".into()],
            build_systems: vec!["Cargo".into(), "Node".into()],
            sources: vec![ComponentSource {
                path: "packages/app/package.json".into(),
                ecosystem: "npm".into(),
                kind: ComponentSourceKind::Manifest,
                scopes: vec![ComponentScope {
                    name: "dependencies".into(),
                    components: (0..24)
                        .map(|index| ComponentItem {
                            name: format!("@scope/package-with-a-long-name-{index:02}"),
                            declared: Some("^1.2.3".into()),
                            repository_versions: vec!["1.2.9".into(), "1.3.0".into()],
                        })
                        .collect(),
                }],
            }],
            manifest_count: 1,
            lockfile_count: 1,
            declared_count: 24,
            resolved_count: 24,
            ecosystems: vec!["npm".into()],
            empty_hint: None,
            // The freshness disclaimer wraps at 40 columns and is one row too.
            from_tool: true,
        }
    }

    #[test]
    fn tiny_width_keeps_values_instead_of_spending_the_row_on_tree_glyphs() {
        let mut rows = LinePageRows::default();

        append_tree_value(&mut rows, 3, "│  └─ ", "      ", "react", theme::primary());

        let lines = rows.into_lines();
        let text = lines
            .iter()
            .flat_map(|line| &line.spans)
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert_eq!(text, "react");
        assert!(lines.iter().all(|line| line.width() <= 3));
    }
}
