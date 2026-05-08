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
    inspection.add_surface(
        builder,
        AttackSurfaceKind::DeserializationPoint,
        "Deserialization or parser boundary",
        None,
        None,
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
    inspection.add_surface(
        builder,
        AttackSurfaceKind::DbQueryBoundary,
        "Database query boundary",
        None,
        None,
        Some("data_store"),
        "node.db-query",
    );
}
