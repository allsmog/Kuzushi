pub(in crate::app) use super::{
    planner_worker, validate_shell_model_id, OptionsFilter, PlanChange, PlanEvent, PlanProposal,
    ShellApp,
};
pub(in crate::app) use crate::commands::ShellCommand;
pub(in crate::app) use std::path::PathBuf;
pub(in crate::app) use std::sync::mpsc;
pub(in crate::app) use std::thread;
