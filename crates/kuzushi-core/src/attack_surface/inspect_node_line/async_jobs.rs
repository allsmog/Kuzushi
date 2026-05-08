use super::*;

pub(super) fn inspect(inspection: &NodeLineInspection<'_>, builder: &mut AttackSurfaceBuilder) {
    if !inspection.has_any(&[
        "cron.schedule(",
        "new queue(",
        "queue(",
        "agenda.define(",
        ".process(",
        "setinterval(",
    ]) {
        return;
    }
    inspection.add_surface(
        builder,
        AttackSurfaceKind::BackgroundJob,
        "Background job or scheduler",
        None,
        None,
        Some("async_job"),
        "node.background-job",
    );
}
