use super::*;

pub(in crate::modules) use max_findings_option::*;
pub(in crate::modules) use metadata::*;
mod descriptor_model;
mod max_findings_option;
mod metadata;
use serde::{Deserialize, Serialize};
#[cfg(test)]
mod tests;
pub use descriptor_model::{
    DagNodeDescriptor, ModuleKind, ModuleMetadata, OptionSpec, OptionType, ToolDescriptor,
};
pub use metadata::BuiltinModule;
