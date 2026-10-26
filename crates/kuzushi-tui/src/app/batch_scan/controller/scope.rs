use super::BatchScanConfig;

pub(super) fn restore_scope_allowance(
    config: &mut BatchScanConfig,
    input: &serde_json::Value,
) -> anyhow::Result<()> {
    let reference: kuzushi_core::workspace::ScanScopeRef =
        serde_json::from_value(input["scanScopeRef"].clone())?;
    if let Some(allowance) = kuzushi_core::capabilities::campaign::load_scope_proposal_allowance(
        &config.target,
        &reference.proposal,
    )? {
        config.study.accounting_error = None;
        config.study.restore_allowance(allowance);
    }
    Ok(())
}
