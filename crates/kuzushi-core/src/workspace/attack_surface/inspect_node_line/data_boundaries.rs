use super::*;

pub(super) fn inspect_deserialization(
    inspection: &NodeLineInspection<'_>,
    builder: &mut AttackSurfaceBuilder,
) {
    if !inspection.has_any(&[
        "json.parse(",
        "yaml.load(",
        "yaml.parse(",
        "deserialize(",
        ".deserialize(",
        "jwt.decode(",
        "protobuf.decode(",
    ]) {
        return;
    }
    let route = inspection.route();
    inspection.add_surface(
        builder,
        AttackSurfaceKind::DeserializationPoint,
        "Deserialization or parser boundary",
        route.method.as_deref(),
        route.path.as_deref(),
        Some("parser_boundary"),
        "node.deserialization",
    );
}

pub(super) fn inspect_database(
    inspection: &NodeLineInspection<'_>,
    builder: &mut AttackSurfaceBuilder,
) {
    if !inspection.has_any(&[
        ".query(",
        "prisma.",
        "sequelize.query(",
        "mongoose.",
        "knex(",
        ".collection(",
    ]) {
        return;
    }
    let route = inspection.route();
    inspection.add_surface(
        builder,
        AttackSurfaceKind::DbQueryBoundary,
        "Database query boundary",
        route.method.as_deref(),
        route.path.as_deref(),
        Some("data_store"),
        "node.db-query",
    );
}

pub(super) fn inspect_external_client(
    inspection: &NodeLineInspection<'_>,
    builder: &mut AttackSurfaceBuilder,
) {
    if !inspection.has_any(&[
        "fetch(",
        "axios.",
        "axios(",
        "got(",
        "superagent.",
        "http.request(",
        "https.request(",
    ]) {
        return;
    }

    let route = inspection.route();
    inspection.add_surface(
        builder,
        AttackSurfaceKind::ExternalServiceClient,
        "External service client",
        route.method.as_deref(),
        route.path.as_deref(),
        Some("external_service"),
        "node.external-client",
    );
}
