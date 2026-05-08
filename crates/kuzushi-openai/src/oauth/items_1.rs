use super::prelude::*;
use super::*;

pub const DEFAULT_CREDENTIALS_REL_PATH: &str = ".kuzushi/oauth-credentials.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OauthReadiness {
    /// Credentials file exists, has an `anthropic` entry, looks structurally valid.
    /// `expires_at_ms` is the value reported in the file (Unix ms); the bridge
    /// is the authority on whether refresh is needed.
    Ready { expires_at_ms: u64 },
    /// Credentials file exists but expired with an apparently-valid refresh token —
    /// the bridge will refresh on the next call.
    Expired { expires_at_ms: u64 },
    /// File missing; an env-var token may still be acceptable.
    Missing { searched: PathBuf },
    /// File present but unreadable, malformed, or missing the `anthropic` entry.
    /// `reason` is a generic string — never includes file content or token bytes.
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
    let raw = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(OauthReadiness::Missing {
                searched: path.to_path_buf(),
            });
        }
        Err(error) => {
            return Ok(OauthReadiness::Invalid {
                searched: path.to_path_buf(),
                reason: format!("could not read credentials file: {}", error.kind()),
            });
        }
    };

    // Parse only the structural fields we need. Use serde_json::Value with a
    // narrow accessor pattern — we never bind `access` or `refresh` to a Rust
    // string variable, so no token bytes can be accidentally formatted into an
    // error message later.
    let bag: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(_) => {
            return Ok(OauthReadiness::Invalid {
                searched: path.to_path_buf(),
                reason: "credentials file is not valid JSON".to_string(),
            });
        }
    };

    let entry = bag.get("anthropic");
    let entry = match entry {
        Some(value) if value.is_object() => value,
        _ => {
            return Ok(OauthReadiness::Invalid {
                searched: path.to_path_buf(),
                reason: "credentials file is missing an `anthropic` provider entry".to_string(),
            });
        }
    };

    let has_refresh = entry
        .get("refresh")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.is_empty());
    let has_access = entry
        .get("access")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.is_empty());
    let expires_at_ms = entry
        .get("expires")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    if !has_refresh || !has_access {
        return Ok(OauthReadiness::Invalid {
            searched: path.to_path_buf(),
            reason: "anthropic entry is missing access/refresh fields".to_string(),
        });
    }

    let now_ms = current_unix_ms();
    if expires_at_ms <= now_ms {
        return Ok(OauthReadiness::Expired { expires_at_ms });
    }

    Ok(OauthReadiness::Ready { expires_at_ms })
}

pub fn resolve_credentials_path(cfg: &AnthropicOauthConfig) -> Result<PathBuf> {
    if let Some(p) = &cfg.credentials_path {
        if p.is_absolute() {
            return Ok(p.clone());
        }
        let home = dirs::home_dir().context("could not resolve home directory")?;
        return Ok(home.join(p));
    }
    let home = dirs::home_dir().context("could not resolve home directory")?;
    Ok(home.join(DEFAULT_CREDENTIALS_REL_PATH))
}
