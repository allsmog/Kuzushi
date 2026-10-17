use anyhow::Result;

pub(super) fn bind_batch_filter(
    existing: Option<String>,
    values: Vec<String>,
) -> Result<Option<String>> {
    if values.is_empty() {
        return Ok(existing);
    }
    anyhow::ensure!(
        values.len() == 1,
        "Choose one study for findings:list batchId"
    );
    let id = values[0].trim().to_owned();
    crate::capabilities::campaign::validate_scan_batch_id(&id)?;
    anyhow::ensure!(
        existing.as_ref().is_none_or(|previous| previous == &id),
        "Conflicting findings:list study filters; choose one batchId"
    );
    Ok(Some(id))
}
