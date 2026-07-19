use super::super::application::{apply_envelope, ProjectionHealth, RunProjection};
use super::super::{RunId, RunItemEnvelopeV1};
use super::stream_reader::{parse_record, RunItemStreamReader};
use anyhow::{Context, Result};
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
    let target = target.as_ref();
    let run_id = RunId::parse(run_id)?;
    let path = crate::run_artifacts::checked_run_artifact_path(
        target,
        run_id.as_str(),
        "items.jsonl",
    )?;
    let Some(reader) = open_stream(target, &path)? else {
        return Ok(None);
    };
    Ok(Some(read_lines(reader)))
}

pub fn load_run_projection(target: impl AsRef<Path>, run_id: &str) -> Result<RunProjectionRead> {
    let target = target.as_ref();
    let run_id = RunId::parse(run_id)?;
    let path =
        crate::run_artifacts::checked_run_artifact_path(target, run_id.as_str(), "items.jsonl")?;
    let Some(reader) = open_stream(target, &path)? else {
        return legacy_projection(run_id.as_str());
    };
    let mut projection = RunProjection {
        run_id: Some(run_id.clone()),
        ..RunProjection::default()
    };
    reduce_lines(reader, &mut projection);
    let presentation_hydration = super::presentation_hydration::load_presentation_hydration(
        target,
        run_id.as_str(),
        &projection,
    );
    Ok(RunProjectionRead {
        projection,
        source: RunProjectionSource::TypedV1,
        presentation_hydration,
    })
}

fn open_stream(root: &Path, path: &Path) -> Result<Option<RunItemStreamReader>> {
    RunItemStreamReader::open_within(root, path)
        .with_context(|| format!("open {}", path.display()))
}

fn reduce_lines(mut reader: RunItemStreamReader, projection: &mut RunProjection) {
    loop {
        let item = match next_item(&mut reader) {
            Ok(Some(item)) => item,
            Ok(None) => break,
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

fn read_lines(mut reader: RunItemStreamReader) -> RunItemRead {
    let mut items = Vec::new();
    let mut projection = RunProjection::default();
    loop {
        let item = match next_item(&mut reader) {
            Ok(Some(item)) => item,
            Ok(None) => break,
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

fn next_item(reader: &mut RunItemStreamReader) -> Result<Option<RunItemEnvelopeV1>, String> {
    let record = reader.next_record().map_err(|error| error.to_string())?;
    record.map(parse_record).transpose()
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
