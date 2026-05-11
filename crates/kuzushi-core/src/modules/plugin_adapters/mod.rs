use super::*;

use self::{builtin_module, dag, model_option, target_option, tool, tool_with_options};
use crate::capabilities::plugin_adapters::{
    list_shinsa_frameworks, list_tob_skills, run_plugin_finding_adapter, run_shinsa_assessment,
    validate_requested_tob_skills, PluginAdapterSpec,
};
use anyhow::Result;
use serde_json::Value;
pub(in crate::modules) use shinsa_module::*;
mod register_modules;
mod shinsa_module;
pub(in crate::modules) use register_modules::{execute_tool, plugin_root_option, register_modules};
