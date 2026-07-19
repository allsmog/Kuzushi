use super::*;
use crate::remediation::patch_process_adapter::ProgramReadScope;
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod identity;
#[cfg(test)]
mod tests;

use identity::*;

const CODEQL_LAUNCHER_INPUT_KEY: &str = "__kuzushiCodeqlLauncher";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub(crate) enum PreparedCodeqlLauncher {
    Unavailable,
    Ready {
        path: PathBuf,
        #[serde(rename = "bundleRoot", skip_serializing_if = "Option::is_none")]
        bundle_root: Option<PathBuf>,
        #[serde(rename = "repositoryRelative", skip_serializing_if = "Option::is_none")]
        repository_relative: Option<PathBuf>,
        #[serde(rename = "contentDigest")]
        content_digest: String,
        #[serde(rename = "bundleIdentity", skip_serializing_if = "Option::is_none")]
        bundle_identity: Option<String>,
    },
}

pub(crate) struct ResolvedCodeqlLauncher {
    path: PathBuf,
    read_scope: ProgramReadScope,
}

impl ResolvedCodeqlLauncher {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn read_scope(&self) -> &ProgramReadScope {
        &self.read_scope
    }
}

pub(crate) fn bind_codeql_launcher(
    tool_name: &str,
    source_root: &Path,
    input: &mut Value,
) -> Result<()> {
    let prepared = prepare_codeql_launcher(tool_name, source_root, input)?;
    input
        .as_object_mut()
        .context("repository execution input must be an object")?
        .insert(
            CODEQL_LAUNCHER_INPUT_KEY.to_string(),
            serde_json::to_value(prepared)?,
        );
    Ok(())
}

pub(crate) fn verify_codeql_launcher(
    tool_name: &str,
    source_root: &Path,
    input: &Value,
) -> Result<()> {
    let expected = prepared_codeql_launcher(input)?;
    let actual = prepare_codeql_launcher(tool_name, source_root, input)?;
    anyhow::ensure!(
        actual == expected,
        "CodeQL launcher or bundle changed after preparation; prepare and authorize the operation again"
    );
    Ok(())
}

pub(crate) fn prepared_codeql_launcher(input: &Value) -> Result<PreparedCodeqlLauncher> {
    let value = input.get(CODEQL_LAUNCHER_INPUT_KEY).context(
        "CodeQL repository execution is missing its prepared launcher binding; prepare the operation through the module registry",
    )?;
    serde_json::from_value(value.clone()).context("CodeQL launcher binding is invalid")
}

impl PreparedCodeqlLauncher {
    pub(crate) fn resolve_for_checkout(
        &self,
        source_root: &Path,
        source_binding: &RepositorySourceBinding,
        checkout_target: &Path,
    ) -> Result<Option<ResolvedCodeqlLauncher>> {
        match self {
            Self::Unavailable => Ok(None),
            Self::Ready {
                path,
                bundle_root,
                repository_relative,
                content_digest,
                bundle_identity,
            } => resolve_ready_launcher(
                source_root,
                source_binding,
                checkout_target,
                path,
                bundle_root.as_deref(),
                repository_relative.as_deref(),
                content_digest,
                bundle_identity.as_deref(),
            )
            .map(Some),
        }
    }

    pub(crate) fn display_path(&self) -> Option<&Path> {
        match self {
            Self::Unavailable => None,
            Self::Ready { path, .. } => Some(path),
        }
    }
}

fn prepare_codeql_launcher(
    tool_name: &str,
    source_root: &Path,
    input: &Value,
) -> Result<PreparedCodeqlLauncher> {
    let Some(requested) = requested_codeql_launcher(tool_name, input)? else {
        return Ok(PreparedCodeqlLauncher::Unavailable);
    };
    let path = canonical_launcher(&requested)?;
    let source_binding = crate::remediation::patch::repository_source_binding(input)?;
    let repository_root = repository_root(source_root, &source_binding)?;
    let content_digest = launcher_digest(&path)?;
    if let Ok(relative) = path.strip_prefix(&repository_root) {
        let repository_relative = relative.to_path_buf();
        return Ok(PreparedCodeqlLauncher::Ready {
            path,
            bundle_root: None,
            repository_relative: Some(repository_relative),
            content_digest,
            bundle_identity: None,
        });
    }
    let bundle_root = path
        .parent()
        .context("CodeQL launcher has no bundle root")?
        .to_path_buf();
    validate_external_bundle_root(&bundle_root, &repository_root)?;
    let bundle_identity = external_bundle_identity(&bundle_root)?;
    Ok(PreparedCodeqlLauncher::Ready {
        path,
        bundle_root: Some(bundle_root),
        repository_relative: None,
        content_digest,
        bundle_identity: Some(bundle_identity),
    })
}

fn requested_codeql_launcher(tool_name: &str, input: &Value) -> Result<Option<PathBuf>> {
    if let Some(path) = configured_launcher(tool_name, input)? {
        return Ok(Some(path));
    }
    Ok(default_codeql_launcher())
}

fn configured_launcher(tool_name: &str, input: &Value) -> Result<Option<PathBuf>> {
    match tool_name {
        "codeql:create-db" => input
            .get("codeqlBin")
            .and_then(Value::as_str)
            .map(resolve_explicit_launcher)
            .transpose(),
        "taint-iris-next:codeql-db" => std::env::var_os("KUZUSHI_CODEQL_BIN")
            .map(|path| resolve_explicit_launcher(&path.to_string_lossy()))
            .transpose(),
        _ => Ok(None),
    }
}

fn resolve_explicit_launcher(path: &str) -> Result<PathBuf> {
    let requested = PathBuf::from(path);
    if requested.components().count() == 1 {
        return kuzushi_sandbox::which(path)
            .with_context(|| format!("CodeQL launcher {path:?} was not found on PATH"));
    }
    anyhow::ensure!(
        requested.is_file(),
        "CodeQL launcher path is missing: {}",
        requested.display()
    );
    Ok(requested)
}

fn default_codeql_launcher() -> Option<PathBuf> {
    kuzushi_sandbox::which("codeql").or_else(|| {
        let home = dirs::home_dir()?;
        [home.join(".local/bin/codeql"), home.join("bin/codeql")]
            .into_iter()
            .chain([
                PathBuf::from("/usr/local/bin/codeql"),
                PathBuf::from("/opt/homebrew/bin/codeql"),
            ])
            .find(|path| path.is_file())
    })
}

fn resolve_ready_launcher(
    source_root: &Path,
    source_binding: &RepositorySourceBinding,
    checkout_target: &Path,
    path: &Path,
    bundle_root: Option<&Path>,
    repository_relative: Option<&Path>,
    expected_digest: &str,
    expected_bundle_identity: Option<&str>,
) -> Result<ResolvedCodeqlLauncher> {
    if let Some(relative) = repository_relative {
        return resolve_repository_launcher(
            source_binding,
            checkout_target,
            relative,
            expected_digest,
        );
    }
    let repository_root = repository_root(source_root, source_binding)?;
    let bundle_root = bundle_root.context("external CodeQL launcher has no bundle root")?;
    let expected_bundle_identity = expected_bundle_identity.context(
        "external CodeQL launcher has no prepared bundle identity; prepare the operation again",
    )?;
    validate_external_bundle_root(bundle_root, &repository_root)?;
    let canonical = canonical_launcher(path)?;
    anyhow::ensure!(
        canonical == path,
        "CodeQL launcher changed after preparation"
    );
    verify_launcher_identity(path, expected_digest)?;
    verify_external_bundle_identity(bundle_root, expected_bundle_identity)?;
    anyhow::ensure!(
        path.starts_with(bundle_root),
        "CodeQL launcher escaped its bundle"
    );
    Ok(ResolvedCodeqlLauncher {
        path: path.to_path_buf(),
        read_scope: ProgramReadScope::ExternalBundle(bundle_root.to_path_buf()),
    })
}

fn resolve_repository_launcher(
    source_binding: &RepositorySourceBinding,
    checkout_target: &Path,
    relative: &Path,
    expected_digest: &str,
) -> Result<ResolvedCodeqlLauncher> {
    let checkout_root = repository_root(checkout_target, source_binding)?;
    let path = fs::canonicalize(checkout_root.join(relative)).with_context(|| {
        "the repository-local CodeQL launcher is absent from the bound commit; track it or use an external CodeQL bundle"
    })?;
    anyhow::ensure!(
        path.starts_with(&checkout_root),
        "CodeQL launcher escaped checkout"
    );
    verify_launcher_identity(&path, expected_digest)?;
    let read_scope = if path.starts_with(checkout_target) {
        ProgramReadScope::Checkout
    } else {
        ProgramReadScope::IsolatedFile
    };
    Ok(ResolvedCodeqlLauncher { path, read_scope })
}
