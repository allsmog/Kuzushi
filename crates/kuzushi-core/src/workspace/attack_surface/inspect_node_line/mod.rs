use super::*;

mod async_jobs;
mod auth_boundaries;
mod data_boundaries;
mod process_boundaries;
mod rpc_handlers;
mod uploads;

pub(crate) fn inspect_node_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let Some(inspection) = NodeLineInspection::new(source_file, framework, line_number, line)
    else {
        return;
    };

    auth_boundaries::inspect(&inspection, builder);
    rpc_handlers::inspect(&inspection, builder);
    async_jobs::inspect(&inspection, builder);
    data_boundaries::inspect_deserialization(&inspection, builder);
    uploads::inspect(&inspection, builder);
    data_boundaries::inspect_database(&inspection, builder);
    process_boundaries::inspect_command_execution(&inspection, builder);
    process_boundaries::inspect_cli_entrypoint(&inspection, builder);
}

pub(super) struct NodeLineInspection<'a> {
    pub(super) source_file: &'a InventorySourceFile,
    pub(super) framework: Option<&'a str>,
    pub(super) line_number: u32,
    pub(super) line: &'a str,
    pub(super) detail: String,
    pub(super) lower: String,
}

impl<'a> NodeLineInspection<'a> {
    fn new(
        source_file: &'a InventorySourceFile,
        framework: Option<&'a str>,
        line_number: u32,
        line: &'a str,
    ) -> Option<Self> {
        let detail = trim_detail(line);
        if detail.is_empty() {
            return None;
        }
        Some(Self {
            source_file,
            framework,
            line_number,
            line,
            lower: detail.to_ascii_lowercase(),
            detail,
        })
    }

    pub(super) fn has_any(&self, needles: &[&str]) -> bool {
        line_contains_any(&self.lower, needles)
    }

    pub(super) fn route(&self) -> RouteLine {
        node_route_from_line(self.line)
    }

    pub(super) fn add_surface(
        &self,
        builder: &mut AttackSurfaceBuilder,
        kind: AttackSurfaceKind,
        title: &str,
        method: Option<&str>,
        route: Option<&str>,
        boundary: Option<&str>,
        detector: &str,
    ) {
        builder.add(surface(
            kind,
            self.source_file,
            self.framework,
            self.line_number,
            title,
            &self.detail,
            method,
            route,
            boundary,
            json!({ "source": "source_line", "detector": detector }),
        ));
    }
}
