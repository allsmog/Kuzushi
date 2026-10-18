use anyhow::Result;

pub(super) fn ids(values: Vec<String>) -> Result<Vec<String>> {
    values
        .into_iter()
        .map(|value| {
            let id = value.trim();
            anyhow::ensure!(
                !id.is_empty() && id.len() <= 64,
                "Scope filter ids need 1 to 64 bytes"
            );
            Ok(id.to_owned())
        })
        .collect()
}

pub(super) fn records(values: Vec<String>) -> Result<Vec<String>> {
    values
        .into_iter()
        .map(|value| {
            let hash = value.trim();
            anyhow::ensure!(
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "scopeRecord requires an exact 64-character record hash"
            );
            Ok(hash.to_ascii_lowercase())
        })
        .collect()
}
