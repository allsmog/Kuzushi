use crate::command::ProofCommand;
use crate::support::require_cli_target;
use anyhow::Result;
use kuzushi_core::workflow_attempts::{
    record_proof_deferral, ProofDeferralRequest, RecordedProofDeferral,
};
use kuzushi_core::WorkspaceTarget;
use std::path::PathBuf;

pub(crate) fn proof_command(command: ProofCommand, default_target: Option<PathBuf>) -> Result<()> {
    let ProofCommand::Defer {
        reference,
        reason,
        json,
    } = command;
    let target = require_cli_target("proof defer", None, default_target)?;
    let workspace = WorkspaceTarget::new(target)?;
    let recorded = record_proof_deferral(&workspace, &ProofDeferralRequest { reference, reason })?;
    print_recorded_deferral(&recorded, json)
}

fn print_recorded_deferral(recorded: &RecordedProofDeferral, json: bool) -> Result<()> {
    let view = kuzushi_core::workflow_attempts::ProofDeferralView::from_record(&recorded.deferral);
    if json {
        println!("{}", serde_json::to_string_pretty(&view)?);
    } else {
        println!("{} · {}", recorded.subject, view.disclosure_line());
        println!("Next: kuzushi --target <path> finding {}", recorded.subject);
    }
    Ok(())
}
