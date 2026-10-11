use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_READ_SCOPE_FILES: usize = 100_000;
pub const MAX_READ_SCOPE_BYTES: usize = 8 * 1024 * 1024;
pub const READ_ONLY_SCOPE_POLICY_ID: &str = "source.membership-read-only.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentReadScope {
    pub schema_version: u32,
    pub files: Vec<String>,
    pub sha256: String,
}

impl AgentReadScope {
    pub fn new(files: impl IntoIterator<Item = String>) -> Result<Self> {
        let files = bounded_members(files)?;
        validate_files(&files)?;
        let sha256 = digest_files(&files)?;
        Ok(Self {
            schema_version: 1,
            files,
            sha256,
        })
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == 1,
            "unsupported read membership version"
        );
        validate_files(&self.files)?;
        anyhow::ensure!(
            digest_files(&self.files)? == self.sha256,
            "read membership digest differs from its files"
        );
        Ok(())
    }
}

fn bounded_members(files: impl IntoIterator<Item = String>) -> Result<Vec<String>> {
    let mut members = BTreeSet::new();
    let mut path_bytes = 0;
    for file in files {
        validate_file(&file)?;
        let length = file.len();
        if !members.insert(file) {
            continue;
        }
        path_bytes += length;
        anyhow::ensure!(
            members.len() <= MAX_READ_SCOPE_FILES,
            "read membership exceeds 100,000 files"
        );
        anyhow::ensure!(
            path_bytes <= MAX_READ_SCOPE_BYTES,
            "read membership exceeds 8 MiB; approve a smaller scope"
        );
    }
    Ok(members.into_iter().collect())
}

fn validate_files(files: &[String]) -> Result<()> {
    anyhow::ensure!(
        !files.is_empty() && files.len() <= MAX_READ_SCOPE_FILES,
        "read membership requires 1 to 100,000 files"
    );
    anyhow::ensure!(
        files.windows(2).all(|pair| pair[0] < pair[1]),
        "read membership must be sorted and unique"
    );
    for file in files {
        validate_file(file)?;
    }
    Ok(())
}

fn validate_file(file: &str) -> Result<()> {
    anyhow::ensure!(
        !file.is_empty() && file.len() <= 4096,
        "read membership path exceeds its limit"
    );
    anyhow::ensure!(
        !file.contains('\\') && !file.chars().any(char::is_control),
        "read membership path contains unsupported characters"
    );
    anyhow::ensure!(
        file.split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".."),
        "read membership paths must be canonical repository-relative files"
    );
    Ok(())
}

fn digest_files(files: &[String]) -> Result<String> {
    let bytes = serde_json::to_vec(files).context("could not encode read membership")?;
    anyhow::ensure!(
        bytes.len() <= MAX_READ_SCOPE_BYTES,
        "read membership exceeds 8 MiB; split and approve a smaller scope"
    );
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_membership_is_literal_unique_and_authenticated() {
        let scope = AgentReadScope::new(
            [
                "app/[route]/file.rs",
                "shared/dependency.rs",
                "app/[route]/file.rs",
            ]
            .map(String::from),
        )
        .unwrap();
        assert_eq!(scope.files.len(), 2);
        scope.validate().unwrap();
        let mut changed = scope.clone();
        changed.files.push("unapproved.rs".into());
        assert!(changed.validate().is_err());
        assert!(AgentReadScope::new(Vec::new()).is_err());
        for path in [
            "../outside.rs",
            "/outside.rs",
            "a//b.rs",
            "./a.rs",
            "a\\b.rs",
            "a\u{0}b.rs",
        ] {
            assert!(AgentReadScope::new([path.into()]).is_err(), "{path:?}");
        }
    }
}
