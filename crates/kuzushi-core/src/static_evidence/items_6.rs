use super::prelude::*;
use super::*;

pub(crate) fn evidence_edge_id(edge: &StaticEvidenceEdge) -> String {
    let metadata_json = serde_json::to_string(&edge.metadata).unwrap_or_else(|_| "{}".to_string());
    let hash = stable_hash_segments(&[
        "edge",
        edge.kind.as_str(),
        &edge.from_node_id,
        &edge.to_node_id,
        edge.finding_fingerprint.as_deref().unwrap_or(""),
        &metadata_json,
    ]);
    format!("SEV-E-{}", &hash[..16])
}

pub fn static_content_hash(body: &str) -> String {
    fnv1a_hex(body.as_bytes())
}

pub(crate) fn stable_hash_segments(segments: &[&str]) -> String {
    let mut bytes = Vec::new();
    for segment in segments {
        bytes.extend_from_slice(segment.as_bytes());
        bytes.push(0);
    }
    fnv1a_hex(&bytes)
}

pub(crate) fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn to_sql_error(error: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

pub(crate) fn to_sql_anyhow_error(error: anyhow::Error) -> rusqlite::Error {
    let error = io::Error::new(io::ErrorKind::InvalidData, error.to_string());
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}
