use crate::theme;
use crate::ui_view_models::{
    ComponentItem, ComponentScope, ComponentSource, ComponentSourceKind, ComponentStack,
};
use ratatui::prelude::{Line, Span, Style};

pub(super) fn component_tree_lines(width: usize, model: &ComponentStack) -> Vec<Line<'static>> {
    if let Some(hint) = &model.empty_hint {
        let lines = crate::renderer::empty_state_panel(
            "no component stack",
            &[hint],
            &[("run sbom-scan:scan", "inventory manifests and lockfiles")],
        );
        return crate::renderer::shared::text::wrap_document_lines(lines, width as u16);
    }
    let mut lines = component_summary_lines(width, model);
    if model.from_tool {
        lines.extend(styled_wrapped_lines(
            "From the latest completed SBOM result. Source freshness is unverified.",
            width,
            theme::muted(),
        ));
    }
    lines.push(Line::from(String::new()));
    lines.push(Line::styled(
        crate::renderer::shared::text::fit(&format!("◆ {}", model.target), width),
        theme::heading(),
    ));
    append_metadata(&mut lines, width, model);
    append_sources(&mut lines, width, &model.sources);
    lines
}

fn component_summary_lines(width: usize, model: &ComponentStack) -> Vec<Line<'static>> {
    let mut lines = styled_wrapped_lines(
        &format!(
            "COMPONENT STACK · {} manifests · {} lockfiles",
            model.manifest_count, model.lockfile_count
        ),
        width,
        theme::accent(),
    );
    lines.extend(styled_wrapped_lines(
        &format!(
            "{} declared · {} resolved · {}",
            model.declared_count,
            model.resolved_count,
            joined_or(&model.ecosystems, "no package ecosystem")
        ),
        width,
        theme::muted(),
    ));
    lines
}

fn append_metadata(lines: &mut Vec<Line<'static>>, width: usize, model: &ComponentStack) {
    append_tree_value(
        lines,
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
        lines,
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

fn append_sources(lines: &mut Vec<Line<'static>>, width: usize, sources: &[ComponentSource]) {
    for (source_index, source) in sources.iter().enumerate() {
        let source_last = source_index + 1 == sources.len();
        let branch = if source_last { "└─ " } else { "├─ " };
        let continuation = if source_last { "   " } else { "│  " };
        append_tree_value(
            lines,
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
        append_scopes(lines, width, continuation, &source.scopes);
    }
}

fn append_scopes(
    lines: &mut Vec<Line<'static>>,
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
            lines,
            width,
            &scope_prefix,
            &child_prefix,
            &scope.name,
            theme::label(),
        );
        append_components(lines, width, &child_prefix, &scope.components);
    }
}

fn append_components(
    lines: &mut Vec<Line<'static>>,
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
            lines,
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

fn append_tree_value(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    prefix: &str,
    continuation: &str,
    value: &str,
    style: Style,
) {
    let prefix_width = prefix.chars().count();
    if width <= prefix_width {
        lines.extend(styled_wrapped_lines(value, width, style));
        return;
    }
    let chunks = crate::renderer::shared::text::wrap_text(value, width - prefix_width);
    for (index, chunk) in chunks.into_iter().enumerate() {
        let tree = if index == 0 { prefix } else { continuation };
        lines.push(Line::from(vec![
            Span::styled(tree.to_string(), theme::subtle()),
            Span::styled(chunk, style),
        ]));
    }
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
        let lines = component_tree_lines(40, &model);
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

        let lines = component_tree_lines(28, &model);
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

    #[test]
    fn tiny_width_keeps_values_instead_of_spending_the_row_on_tree_glyphs() {
        let mut lines = Vec::new();

        append_tree_value(&mut lines, 3, "│  └─ ", "      ", "react", theme::primary());

        let text = lines
            .iter()
            .flat_map(|line| &line.spans)
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert_eq!(text, "react");
        assert!(lines.iter().all(|line| line.width() <= 3));
    }
}
