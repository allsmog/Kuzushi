use super::super::application::{apply_envelope, ProjectionHealth, RunProjection};
use super::super::{RunId, RunItemEnvelopeV1, RUN_ITEM_SCHEMA_VERSION};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunProjectionSource {
    TypedV1,
    Legacy,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunItemRead {
    pub items: Vec<RunItemEnvelopeV1>,
    pub health: ProjectionHealth,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunProjectionRead {
    pub projection: RunProjection,
    pub source: RunProjectionSource,
    #[serde(skip)]
    pub presentation_hydration: super::super::application::RunPresentationHydrationV1,
}

pub fn read_run_items(target: impl AsRef<Path>, run_id: &str) -> Result<Option<RunItemRead>> {
    let path = crate::run_artifacts::run_dir(target, run_id).join("items.jsonl");
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    Ok(Some(read_lines(BufReader::new(file))))
}

pub fn load_run_projection(target: impl AsRef<Path>, run_id: &str) -> Result<RunProjectionRead> {
    let target = target.as_ref();
    let path = crate::run_artifacts::run_dir(target, run_id).join("items.jsonl");
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return legacy_projection(run_id)
        }
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let mut projection = RunProjection {
        run_id: Some(RunId::parse(run_id)?),
        ..RunProjection::default()
    };
    reduce_lines(BufReader::new(file), &mut projection);
    let presentation_hydration =
        super::presentation_hydration::load_presentation_hydration(target, run_id, &projection);
    Ok(RunProjectionRead {
        projection,
        source: RunProjectionSource::TypedV1,
        presentation_hydration,
    })
}

fn reduce_lines(reader: impl BufRead, projection: &mut RunProjection) {
    for (index, line) in reader.lines().enumerate() {
        let item = match parse_line(line, index + 1) {
            Ok(item) => item,
            Err(reason) => {
                super::super::record_degraded_replay();
                projection.degrade(reason);
                break;
            }
        };
        if let Err(error) = apply_envelope(projection, item) {
            super::super::record_degraded_replay();
            projection.degrade(error.to_string());
            break;
        }
    }
}

fn read_lines(reader: impl BufRead) -> RunItemRead {
    let mut items = Vec::new();
    let mut projection = RunProjection::default();
    for (index, line) in reader.lines().enumerate() {
        let item = match parse_line(line, index + 1) {
            Ok(item) => item,
            Err(reason) => {
                projection.degrade(reason);
                break;
            }
        };
        if let Err(error) = apply_envelope(&mut projection, item.clone()) {
            projection.degrade(error.to_string());
            break;
        }
        items.push(item);
    }
    if matches!(projection.health, ProjectionHealth::Degraded { .. }) {
        super::super::record_degraded_replay();
    }
    RunItemRead {
        items,
        health: projection.health,
    }
}

fn parse_line(
    line: std::io::Result<String>,
    line_number: usize,
) -> Result<RunItemEnvelopeV1, String> {
    let line = line.map_err(|error| format!("line {line_number}: {error}"))?;
    let value = serde_json::from_str::<serde_json::Value>(&line)
        .map_err(|error| format!("line {line_number}: {error}"))?;
    let version = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64);
    if version != Some(u64::from(RUN_ITEM_SCHEMA_VERSION)) {
        return Err(format!(
            "line {line_number}: unknown schema version {version:?}"
        ));
    }
    serde_json::from_value(value).map_err(|error| format!("line {line_number}: {error}"))
}

fn legacy_projection(run_id: &str) -> Result<RunProjectionRead> {
    super::super::record_legacy_fallback();
    let mut projection = RunProjection {
        run_id: Some(RunId::parse(run_id)?),
        health: ProjectionHealth::LegacyLossy,
        ..RunProjection::default()
    };
    projection.degrade("typed run items are unavailable for this legacy run");
    projection.health = ProjectionHealth::LegacyLossy;
    Ok(RunProjectionRead {
        projection,
        source: RunProjectionSource::Legacy,
        presentation_hydration: super::super::application::RunPresentationHydrationV1::default(),
    })
}
