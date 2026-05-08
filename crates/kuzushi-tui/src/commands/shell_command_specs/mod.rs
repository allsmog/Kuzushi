use super::prelude::*;
use super::*;

mod auth_config_model;
mod context_kb;
mod findings_evidence;
mod navigation;
mod options_tasks;
mod run_scan;
mod session;

pub(crate) const SHELL_COMMAND_SPEC_GROUPS: &[&[ShellCommandSpec]] = &[
    navigation::NAVIGATION_COMMANDS,
    run_scan::RUN_SCAN_COMMANDS,
    options_tasks::OPTIONS_TASK_COMMANDS,
    context_kb::CONTEXT_KB_COMMANDS,
    findings_evidence::FINDINGS_EVIDENCE_COMMANDS,
    auth_config_model::AUTH_CONFIG_MODEL_COMMANDS,
    session::SESSION_COMMANDS,
];
