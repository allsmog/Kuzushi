//! Join previously retained input and phase evidence into terminal receipts.
use super::*;

pub(super) fn attach(record: ToolRunRecord<'_>, output: Value) -> Result<Value> {
    let output = super::prepared_model_input::attach(record.target, record.run_id, output);
    super::scan_failure_context::attach(record, output)
}
