use super::*;
use serde_json::Value;

pub(in crate::capabilities::campaign) fn from_input(
    root: &Path,
    input: &Value,
) -> Result<Option<BriefRevision>> {
    let Some(value) = input.get("briefRef") else {
        return Ok(None);
    };
    let reference: BriefReference =
        serde_json::from_value(value.clone()).context("Study briefRef is malformed")?;
    load_brief(root, &reference).map(Some)
}

pub(in crate::capabilities::campaign) fn attach(
    root: &Path,
    plan: &mut Value,
    input: &Value,
) -> Result<()> {
    if let Some(brief) = from_input(root, input)? {
        plan["investigationBrief"] = serde_json::to_value(brief)?;
    }
    Ok(())
}

pub(in crate::capabilities::campaign) fn validate_plan(root: &Path, plan: &Value) -> Result<()> {
    super::guidance_receipt(plan)?;
    let Some(value) = plan.get("investigationBrief") else {
        return Ok(());
    };
    let frozen: BriefRevision =
        serde_json::from_value(value.clone()).context("Plan investigation brief is malformed")?;
    let saved = load_brief(root, &frozen.reference)?;
    anyhow::ensure!(
        saved == frozen,
        "Plan brief text differs from its immutable revision"
    );
    Ok(())
}

pub fn load_plan_brief(root: &Path, id: &str) -> Result<Option<BriefRevision>> {
    let plan = super::super::approved_work::read_bounded_plan(root, id)?;
    plan.get("investigationBrief")
        .map(|value| serde_json::from_value(value.clone()).context("Plan brief is malformed"))
        .transpose()
}
