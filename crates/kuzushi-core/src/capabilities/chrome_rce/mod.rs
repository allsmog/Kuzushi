use crate::findings::{Finding, Severity};
use anyhow::{Context, Result};
pub(crate) use changed_files::*;
pub(crate) use collect_findings::*;
use std::fs;
use std::path::Path;
use std::process::Command;
mod changed_files;
mod collect_findings;
#[cfg(test)]
mod tests;
