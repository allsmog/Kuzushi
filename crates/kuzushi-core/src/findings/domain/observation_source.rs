use super::*;

/// Recorded source for one exact finding generation. Missing fields stay
/// unknown; a later checkout or another observation must never fill them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedObservationSource {
    #[serde(deserialize_with = "source_schema_version")]
    pub schema_version: u32,
    pub generation_id: i64,
    pub run_id: String,
    pub snapshot_hash: String,
    pub tree_hash: Option<String>,
    pub blob_hash: Option<String>,
    pub git_commit: Option<String>,
    pub git_branch: Option<String>,
    pub dirty_hash: Option<String>,
}

fn source_schema_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u32, D::Error> {
    match u32::deserialize(deserializer)? {
        1 => Ok(1),
        _ => Err(serde::de::Error::custom(
            "Unsupported recorded source schema version",
        )),
    }
}
