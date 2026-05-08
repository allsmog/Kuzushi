use super::*;

pub(crate) fn attachment_id_error(id: &str, records: &[AttachmentRecord]) -> String {
    if records.is_empty() {
        format!(
            "unknown attachment id {id:?}; no attachments stored. Next: `attach <path-or-url>` first, then `kb` to see IDs"
        )
    } else {
        format!(
            "unknown attachment id {id:?}. Valid attachment IDs: {}. Next: kb",
            valid_attachment_ids(records)
        )
    }
}

pub(crate) fn attachment_id(module_id: &str, kind: &str, source: &str) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(module_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(kind.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(source.as_bytes());
    let hash = fnv1a_hex(&bytes);
    format!("A-{}", &hash[..12])
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
