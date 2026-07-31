mod bridge;
mod checks;
mod output;
mod report;
mod types;

pub(crate) use checks::{
    check_auth_env, check_container_runtime, check_cpg_engine, check_findings_db,
    check_model_config, check_offense_sandbox, check_revng_image, check_scanner_binary,
    check_treesitter_grammars, deterministic_capability_checks,
};
pub(crate) use output::{print_doctor_json, print_doctor_plain};
pub(crate) use report::build_doctor_report;
pub(crate) use types::{doctor_command, DoctorCheck, DoctorReport, DoctorStatus};
