use anyhow::Result;

pub(super) fn ensure_active(canceled: &dyn Fn() -> bool) -> Result<()> {
    anyhow::ensure!(!canceled(), "entry-point extraction was cancelled");
    Ok(())
}
