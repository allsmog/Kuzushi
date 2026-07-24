use anyhow::Result;
use std::path::Path;

mod budget;
mod copy;
mod revision;
mod walker;

#[derive(Clone, Copy)]
pub struct BundleIdentityConfig {
    domain: &'static [u8],
    label: &'static str,
    max_entries: u64,
    max_bytes: u64,
    max_depth: usize,
}

impl BundleIdentityConfig {
    pub const fn new(
        domain: &'static [u8],
        label: &'static str,
        max_entries: u64,
        max_bytes: u64,
        max_depth: usize,
    ) -> Self {
        Self {
            domain,
            label,
            max_entries,
            max_bytes,
            max_depth,
        }
    }
}

pub fn bounded_bundle_identity(root: &Path, config: BundleIdentityConfig) -> Result<String> {
    walker::walk_bundle(root, None, config)
}

pub fn copy_bounded_bundle(
    root: &Path,
    destination: &Path,
    config: BundleIdentityConfig,
) -> Result<String> {
    copy_bounded_bundle_with_durability(root, destination, config, CopyDurability::Durable)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyDurability {
    /// Flush every copied file before returning. Use for durable artifacts.
    Durable,
    /// Rely on ordinary filesystem writeback. Use for disposable execution snapshots.
    Ephemeral,
}

pub fn copy_bounded_bundle_with_durability(
    root: &Path,
    destination: &Path,
    config: BundleIdentityConfig,
    durability: CopyDurability,
) -> Result<String> {
    copy::prepare_empty_destination(root, destination, config.label)?;
    let target = copy::CopyTarget::new(destination, durability);
    walker::walk_bundle(root, Some(target), config)
}

#[cfg(test)]
mod tests;
