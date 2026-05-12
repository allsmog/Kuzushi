use anyhow::{Context, Result};
use kuzushi_core::AnthropicOauthConfig;
use std::fs;
use std::path::{Path, PathBuf};

use super::environment::current_unix_ms;

pub const DEFAULT_CREDENTIALS_REL_PATH: &str = ".kuzushi/oauth-credentials.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OauthReadiness {
    Ready { expires_at_ms: u64 },
    Expired { expires_at_ms: u64 },
    Missing { searched: PathBuf },
    Invalid { searched: PathBuf, reason: String },
}

pub fn probe(cfg: &AnthropicOauthConfig) -> Result<OauthReadiness> {
    let path = resolve_credentials_path(cfg)?;
    if !path.exists() {
        return Ok(OauthReadiness::Missing { searched: path });
    }
    probe_path(&path)
}

pub fn probe_path(path: &Path) -> Result<OauthReadiness> {
    let raw = match read_credentials(path) {
        Ok(value) => value,
        Err(readiness) => return Ok(readiness),
    };
    let entry = match anthropic_credentials_entry(path, &raw) {
        Ok(entry) => entry,
        Err(readiness) => return Ok(readiness),
    };
    readiness_from_entry(path, &entry)
}

fn read_credentials(path: &Path) -> std::result::Result<String, OauthReadiness> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(value),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(OauthReadiness::Missing {
                searched: path.to_path_buf(),
            })
        }
        Err(error) => Err(OauthReadiness::Invalid {
            searched: path.to_path_buf(),
            reason: format!("could not read credentials file: {}", error.kind()),
        }),
    }
}

fn anthropic_credentials_entry(
    path: &Path,
    raw: &str,
) -> std::result::Result<serde_json::Value, OauthReadiness> {
    let bag: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| OauthReadiness::Invalid {
            searched: path.to_path_buf(),
            reason: "credentials file is not valid JSON".to_string(),
        })?;
    match bag.get("anthropic") {
        Some(value) if value.is_object() => Ok(value.clone()),
        _ => Err(OauthReadiness::Invalid {
            searched: path.to_path_buf(),
            reason: "credentials file is missing an `anthropic` provider entry".to_string(),
        }),
    }
}

fn readiness_from_entry(path: &Path, entry: &serde_json::Value) -> Result<OauthReadiness> {
    let has_refresh = non_empty_string_field(entry, "refresh");
    let has_access = non_empty_string_field(entry, "access");
    let expires_at_ms = entry
        .get("expires")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    if !has_access {
        return Ok(OauthReadiness::Invalid {
            searched: path.to_path_buf(),
            reason: "anthropic entry is missing the `access` field".to_string(),
        });
    }

    let now = current_unix_ms();
    if expires_at_ms <= now {
        if !has_refresh {
            return Ok(OauthReadiness::Invalid {
                searched: path.to_path_buf(),
                reason: "anthropic access token is expired and no `refresh` token is present"
                    .to_string(),
            });
        }
        return Ok(OauthReadiness::Expired { expires_at_ms });
    }
    // Access token is non-empty and not yet expired. An empty `refresh` is
    // allowed for non-refreshable long-lived tokens — the bridge uses
    // `access` directly until expiry and only refreshes when needed.
    Ok(OauthReadiness::Ready { expires_at_ms })
}

fn non_empty_string_field(entry: &serde_json::Value, name: &str) -> bool {
    entry
        .get(name)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.is_empty())
}

pub fn resolve_credentials_path(cfg: &AnthropicOauthConfig) -> Result<PathBuf> {
    if let Some(path) = &cfg.credentials_path {
        if path.is_absolute() {
            return Ok(path.clone());
        }
        return Ok(home_dir()?.join(path));
    }
    Ok(home_dir()?.join(DEFAULT_CREDENTIALS_REL_PATH))
}

fn home_dir() -> Result<PathBuf> {
    dirs::home_dir().context("could not resolve home directory")
}
