use super::*;

const DEPENDENCY_FIELDS: &[&str] = &["dependencies", "optionalDependencies"];

pub(super) fn edges(value: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    mapping_child(value, "snapshots")
        .into_iter()
        .flat_map(|snapshots| snapshots.iter())
        .flat_map(|(key, snapshot)| {
            package_dependency_edges(key, snapshot, source, DEPENDENCY_FIELDS)
        })
        .collect()
}

pub(super) fn validate(value: &Value) -> Result<()> {
    let Some(snapshots) = value.get("snapshots") else {
        return Ok(());
    };
    let snapshots = snapshots
        .as_object()
        .context("snapshots must be an object")?;
    for snapshot in snapshots.values() {
        validate_snapshot(snapshot)?;
    }
    Ok(())
}

fn validate_snapshot(value: &Value) -> Result<()> {
    let snapshot = value
        .as_object()
        .context("snapshot entries must be objects")?;
    for field in DEPENDENCY_FIELDS {
        if let Some(dependencies) = snapshot.get(*field) {
            validate_dependencies(dependencies)?;
        }
    }
    Ok(())
}

fn validate_dependencies(value: &Value) -> Result<()> {
    let dependencies = value
        .as_object()
        .context("snapshot dependency sections must be objects")?;
    for (name, version) in dependencies {
        anyhow::ensure!(
            !name.trim().is_empty(),
            "snapshot dependency names must not be empty"
        );
        let version = version
            .as_str()
            .context("snapshot dependency versions must be strings")?;
        anyhow::ensure!(
            !version.trim().is_empty(),
            "snapshot dependency versions must not be empty"
        );
    }
    Ok(())
}
