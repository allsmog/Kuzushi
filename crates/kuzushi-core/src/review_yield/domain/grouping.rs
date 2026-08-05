use crate::identity::hash_parts;

const EXAMPLE_DOMAIN: &str = "review-yield-example";
const IDENTITY_GROUP_DOMAIN: &str = "review-yield-identity-group";
const REPOSITORY_GROUP_DOMAIN: &str = "review-yield-repository-group";
const DATASET_DOMAIN: &str = "review-yield-dataset";

/// Stable row id: one durable identity plus the decision event that labeled it.
pub fn example_id(identity_id: &str, label_event_hash: &str) -> String {
    prefixed(EXAMPLE_DOMAIN, &[identity_id.as_bytes(), label_event_hash.as_bytes()])
}

/// Grouping key for leakage-safe splits. Domain-separated from `example_id` so
/// the identity id cannot be recovered by re-deriving one from the other.
pub fn identity_group(identity_id: &str) -> String {
    prefixed(IDENTITY_GROUP_DOMAIN, &[identity_id.as_bytes()])
}

/// Grouping key for the repository. Re-hashes the workspace root fingerprint,
/// which itself hashes a local absolute path and must never be exported.
pub fn repository_group(workspace_root_fingerprint: &str) -> String {
    prefixed(
        REPOSITORY_GROUP_DOMAIN,
        &[workspace_root_fingerprint.as_bytes()],
    )
}

/// Digest over the manifest (without its digest field) followed by every row
/// in exported order.
pub fn dataset_digest(parts: &[&[u8]]) -> String {
    prefixed(DATASET_DOMAIN, parts)
}

fn prefixed(domain: &str, parts: &[&[u8]]) -> String {
    format!("blake3:{}", hash_parts(domain, parts).as_str())
}
