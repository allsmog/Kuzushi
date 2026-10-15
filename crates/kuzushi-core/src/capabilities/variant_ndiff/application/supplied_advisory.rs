use super::*;
use std::io::{self, Write};

const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;

pub(crate) fn record_from_input(id: &str, input: &Value) -> Result<Option<CveRecord>> {
    validate_metadata_input(input)?;
    let Some((value, _)) = supplied_record_value(id, input) else {
        return Ok(None);
    };
    let record: CveRecord = serde_json::from_value(value.clone())
        .context("Could not parse supplied advisory metadata")?;
    anyhow::ensure!(
        record.id.trim().eq_ignore_ascii_case(id.trim()),
        "Supplied record id {:?} does not match requested id {:?}",
        record.id,
        id
    );
    Ok(Some(record))
}

pub(crate) fn advisory_retrieval_mode(id: &str, input: &Value) -> &'static str {
    supplied_record_value(id, input)
        .map(|(_, mode)| mode)
        .unwrap_or("network")
}

fn supplied_record_value<'a>(id: &str, input: &'a Value) -> Option<(&'a Value, &'static str)> {
    if let Some(record) = input.get("record") {
        return Some((record, "supplied-record"));
    }
    let fixtures = input.get("fixtures")?.as_object()?;
    [
        id.to_string(),
        id.to_ascii_uppercase(),
        id.to_ascii_lowercase(),
    ]
    .iter()
    .find_map(|key| fixtures.get(key).map(|value| (value, "supplied-fixture")))
}

pub(crate) fn validate_metadata_input(input: &Value) -> Result<()> {
    let mut budget = MetadataByteBudget {
        used: 0,
        limit: metadata_limit(input)?,
    };
    for key in ["record", "fixtures", "patchFixtures", "osvFixtures"] {
        let Some(value) = input.get(key) else {
            continue;
        };
        anyhow::ensure!(
            value.is_object(),
            "Supplied {key} metadata must be a JSON object"
        );
        serde_json::to_writer(&mut budget, value)
            .context("Supplied metadata byte limit exceeded")?;
    }
    Ok(())
}

fn metadata_limit(input: &Value) -> Result<usize> {
    let Some(raw) = input.get("maxMetadataBytes") else {
        return Ok(MAX_METADATA_BYTES);
    };
    let limit = raw
        .as_u64()
        .context("maxMetadataBytes must be a positive integer")?;
    anyhow::ensure!(
        (1..=MAX_METADATA_BYTES as u64).contains(&limit),
        "maxMetadataBytes must be from 1 to {MAX_METADATA_BYTES}"
    );
    Ok(limit as usize)
}

struct MetadataByteBudget {
    used: usize,
    limit: usize,
}

impl Write for MetadataByteBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .filter(|used| *used <= self.limit)
            .ok_or_else(|| io::Error::other("metadata byte limit exceeded"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
