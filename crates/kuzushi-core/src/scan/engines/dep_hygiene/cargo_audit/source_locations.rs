//! Match advisory locators to package-name declarations in captured input only.
use super::Finding;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct PackageLocations {
    by_locator: BTreeMap<String, Option<u32>>,
}

#[derive(Deserialize)]
struct Lockfile {
    #[serde(default)]
    package: Vec<LockedPackage>,
}

#[derive(Deserialize)]
struct LockedPackage {
    name: toml::Spanned<String>,
    version: toml::Spanned<String>,
}

impl PackageLocations {
    pub(super) fn from_bytes(source: &[u8]) -> Self {
        match toml::from_slice::<Lockfile>(source) {
            Ok(lockfile) => Self::from_packages(lockfile.package, source),
            Err(_) => Self::default(),
        }
    }

    fn from_packages(mut packages: Vec<LockedPackage>, source: &[u8]) -> Self {
        packages.sort_unstable_by_key(|package| package.name.span().start);
        let mut by_locator = BTreeMap::new();
        let (mut cursor, mut line) = (0, 1usize);
        for package in packages {
            let start = package.name.span().start;
            let Some(prefix) = source.get(cursor..start) else {
                continue;
            };
            line += prefix.iter().filter(|byte| **byte == b'\n').count();
            cursor = start;
            let locator = format!(
                "Cargo.lock#{}@{}",
                package.name.get_ref(),
                package.version.get_ref()
            );
            by_locator
                .entry(locator)
                .and_modify(|known| *known = None)
                .or_insert_with(|| u32::try_from(line).ok());
        }
        Self { by_locator }
    }

    pub(super) fn bind(&self, findings: &mut [Finding]) {
        for finding in findings {
            let line = finding
                .symbol_locator
                .as_ref()
                .and_then(|locator| self.by_locator.get(locator))
                .copied()
                .flatten();
            set_package_line(finding, line);
        }
    }
}

fn set_package_line(finding: &mut Finding, line: Option<u32>) {
    match line {
        Some(line) => finding.start_line = line,
        None => {
            finding.start_line = 0;
            finding.end_line = None;
            finding.message.push_str(
                " · Package declaration location is unavailable in the captured Cargo.lock.",
            );
        }
    }
}

#[cfg(test)]
mod tests;
