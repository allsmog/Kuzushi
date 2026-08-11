use std::path::Path;

use serde_json::Value;

use super::model_artifact_checks::build_model;
use super::model_artifact_raw::RawModel;
use crate::identity::hash_parts;
use crate::review_yield::domain::{
    canonical_json_bytes_without_key, ReviewYieldEligibility, ValidatedReviewYieldModel,
    MAX_MODEL_FILE_BYTES, MODEL_DIGEST_DOMAIN,
};

const MODEL_ID_KEY: &str = "modelId";
const DIGEST_PREFIX: &str = "blake3:";
pub const SUPPORTED_MODEL_SCHEMA_VERSION: u64 = 1;

/// Every way loading a model artifact can fail. There is no variant for
/// "loaded with warnings": a model either passes every check or is not used.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ModelArtifactError {
    #[error("model artifact unreadable: {0}")]
    Unreadable(String),
    #[error("model artifact is {bytes} bytes; the limit is {limit}")]
    TooLarge { bytes: u64, limit: u64 },
    #[error("model artifact is not readable JSON: {0}")]
    Malformed(String),
    #[error("unsupported model schema version {found}; this build reads version 1")]
    UnsupportedSchemaVersion { found: String },
    #[error("model digest mismatch: declared {declared}, computed {computed}")]
    HashMismatch { declared: String, computed: String },
    #[error("model shape invalid: {0}")]
    Shape(String),
    #[error("model field out of bounds: {0}")]
    Bounds(String),
    #[error("model tree invalid: {0}")]
    Tree(String),
    #[error("model feature schema {found} does not match {expected}")]
    FeatureSchemaMismatch { found: String, expected: String },
}

/// Reads and checks a model artifact. Fails closed on size, syntax, schema
/// version, digest, shape, bounds, tree structure, and feature schema — in that
/// order, so a later check never runs on input an earlier one rejected.
pub fn load_model_artifact(path: &Path) -> Result<ValidatedReviewYieldModel, ModelArtifactError> {
    let bytes = read_bounded_bytes(path)?;
    parse_model_artifact(&bytes)
}

/// The pure half of loading, for tests and for callers that already hold bytes.
pub fn parse_model_artifact(bytes: &[u8]) -> Result<ValidatedReviewYieldModel, ModelArtifactError> {
    let document: Value = serde_json::from_slice(bytes)
        .map_err(|error| ModelArtifactError::Malformed(error.to_string()))?;
    require_schema_version_one(&document)?;
    verify_model_digest(&document)?;
    let raw: RawModel = serde_json::from_value(document)
        .map_err(|error| ModelArtifactError::Shape(error.to_string()))?;
    build_model(raw)
}

/// Maps a load failure onto the eligibility a scored finding reports. The match
/// is exhaustive on purpose: a new failure mode must choose its own kind rather
/// than fall into a wildcard.
pub fn eligibility_for_load_error(error: &ModelArtifactError) -> ReviewYieldEligibility {
    match error {
        ModelArtifactError::HashMismatch { .. } => ReviewYieldEligibility::InvalidModelHash,
        ModelArtifactError::FeatureSchemaMismatch { .. } => {
            ReviewYieldEligibility::FeatureSchemaMismatch
        }
        ModelArtifactError::Unreadable(_)
        | ModelArtifactError::TooLarge { .. }
        | ModelArtifactError::Malformed(_)
        | ModelArtifactError::UnsupportedSchemaVersion { .. }
        | ModelArtifactError::Shape(_)
        | ModelArtifactError::Bounds(_)
        | ModelArtifactError::Tree(_) => ReviewYieldEligibility::UnsupportedModelSchema,
    }
}

/// Refuses to read a file larger than the artifact bound before allocating it.
fn read_bounded_bytes(path: &Path) -> Result<Vec<u8>, ModelArtifactError> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| ModelArtifactError::Unreadable(format!("{}: {error}", path.display())))?;
    if metadata.len() > MAX_MODEL_FILE_BYTES {
        return Err(ModelArtifactError::TooLarge {
            bytes: metadata.len(),
            limit: MAX_MODEL_FILE_BYTES,
        });
    }
    std::fs::read(path)
        .map_err(|error| ModelArtifactError::Unreadable(format!("{}: {error}", path.display())))
}

/// Checked before hashing: a future schema version may canonicalize
/// differently, so recomputing this version's digest over it would be a lie.
fn require_schema_version_one(document: &Value) -> Result<(), ModelArtifactError> {
    let found = document.get("schemaVersion");
    if found.and_then(Value::as_u64) == Some(SUPPORTED_MODEL_SCHEMA_VERSION) {
        return Ok(());
    }
    Err(ModelArtifactError::UnsupportedSchemaVersion {
        found: found.map_or_else(|| "absent".to_string(), Value::to_string),
    })
}

/// Recomputes the digest over the canonical form with `modelId` removed and
/// compares it to the declared one.
fn verify_model_digest(document: &Value) -> Result<(), ModelArtifactError> {
    let declared = declared_digest(document)?;
    let canonical = canonical_json_bytes_without_key(document, MODEL_ID_KEY)
        .map_err(|error| ModelArtifactError::Malformed(error.to_string()))?;
    let computed = hash_parts(MODEL_DIGEST_DOMAIN, &[&canonical]).as_str().to_string();
    if declared == computed {
        return Ok(());
    }
    Err(ModelArtifactError::HashMismatch {
        declared: format!("{DIGEST_PREFIX}{declared}"),
        computed: format!("{DIGEST_PREFIX}{computed}"),
    })
}

/// The declared digest, as 64 lowercase hex characters without the prefix.
fn declared_digest(document: &Value) -> Result<String, ModelArtifactError> {
    let raw = document
        .get(MODEL_ID_KEY)
        .and_then(Value::as_str)
        .ok_or_else(|| ModelArtifactError::Shape("modelId is missing or not a string".into()))?;
    let hex = raw
        .strip_prefix(DIGEST_PREFIX)
        .ok_or_else(|| ModelArtifactError::Shape(format!("modelId {raw} is not blake3-prefixed")))?;
    if hex.len() != 64 || !hex.bytes().all(is_lowercase_hex) {
        return Err(ModelArtifactError::Shape(format!(
            "modelId {raw} is not 64 lowercase hex characters"
        )));
    }
    Ok(hex.to_string())
}

fn is_lowercase_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// The canonical bytes a digest covers, exposed so tests can pin their length
/// against the Python exporter's.
pub fn canonical_model_bytes(document: &Value) -> Result<Vec<u8>, ModelArtifactError> {
    canonical_json_bytes_without_key(document, MODEL_ID_KEY)
        .map_err(|error| ModelArtifactError::Malformed(error.to_string()))
}

/// The digest of an artifact document, in the `blake3:<hex>` form the artifact
/// stores. Used by tests and by the model-checking CLI report.
pub fn model_digest(document: &Value) -> Result<String, ModelArtifactError> {
    let canonical = canonical_model_bytes(document)?;
    Ok(format!(
        "{DIGEST_PREFIX}{}",
        hash_parts(MODEL_DIGEST_DOMAIN, &[&canonical])
    ))
}
