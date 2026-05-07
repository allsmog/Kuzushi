use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use kuzushi_core::AnthropicOauthConfig;

/// Default credentials path under the user's home directory.
pub const DEFAULT_CREDENTIALS_REL_PATH: &str = ".kuzushi/oauth-credentials.json";

/// What we found when probing the OAuth state. No token bytes leak into here.
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

/// Probe an Anthropic OAuth credentials file. Returns a structured readiness
/// status; the caller decides whether to warn, error, or proceed based on it.
///
/// This function does NOT refresh, does NOT call out to the bridge, and does
/// NOT log token bytes.
pub fn probe(cfg: &AnthropicOauthConfig) -> Result<OauthReadiness> {
    let path = resolve_credentials_path(cfg)?;
    if !path.exists() {
        return Ok(OauthReadiness::Missing { searched: path });
    }
    probe_path(&path)
}

/// Same as [`probe`] but takes an explicit path. Useful for tests.
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

/// Resolve the credentials path, defaulting to `$HOME/.kuzushi/oauth-credentials.json`.
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

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Whether an env-var fallback token is set. The bridge's auth chain prefers
/// OAuth, so if both are present the OAuth file wins.
pub fn has_env_token() -> bool {
    ["ANTHROPIC_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"]
        .iter()
        .any(|name| {
            std::env::var(name)
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_file(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn probe_reports_missing_when_file_absent() {
        let tmp = tempdir().unwrap();
        let cfg = AnthropicOauthConfig {
            credentials_path: Some(tmp.path().join("does-not-exist.json")),
            allow_env_token: false,
        };
        match probe(&cfg).unwrap() {
            OauthReadiness::Missing { .. } => {}
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn probe_reports_invalid_for_malformed_json() {
        let tmp = tempdir().unwrap();
        let path = write_file(tmp.path(), "creds.json", "{ not json");
        match probe_path(&path).unwrap() {
            OauthReadiness::Invalid { reason, .. } => {
                assert!(reason.contains("not valid JSON"));
                // Critical: the error reason must not leak the file body.
                assert!(!reason.contains("not json"));
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn probe_reports_invalid_when_anthropic_entry_missing() {
        let tmp = tempdir().unwrap();
        let path = write_file(
            tmp.path(),
            "creds.json",
            r#"{"openai-codex":{"refresh":"r","access":"a","expires":99999999999999}}"#,
        );
        match probe_path(&path).unwrap() {
            OauthReadiness::Invalid { reason, .. } => {
                assert!(reason.contains("anthropic"));
                // Reason must not contain the openai-codex token bytes.
                assert!(!reason.contains("\"r\""));
                assert!(!reason.contains("\"a\""));
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn probe_reports_invalid_when_required_fields_missing() {
        let tmp = tempdir().unwrap();
        let path = write_file(
            tmp.path(),
            "creds.json",
            r#"{"anthropic":{"expires":99999999999999}}"#,
        );
        match probe_path(&path).unwrap() {
            OauthReadiness::Invalid { reason, .. } => {
                assert!(reason.contains("access"));
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn probe_reports_expired_when_past() {
        let tmp = tempdir().unwrap();
        let path = write_file(
            tmp.path(),
            "creds.json",
            r#"{"anthropic":{"refresh":"r","access":"a","expires":1}}"#,
        );
        match probe_path(&path).unwrap() {
            OauthReadiness::Expired { expires_at_ms } => assert_eq!(expires_at_ms, 1),
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn probe_reports_ready_when_future() {
        let tmp = tempdir().unwrap();
        // 100 years in the future — covers test farms with skewed clocks.
        let far_future_ms = current_unix_ms() + 100u64 * 365 * 24 * 3600 * 1000;
        let path = write_file(
            tmp.path(),
            "creds.json",
            &format!(r#"{{"anthropic":{{"refresh":"r","access":"a","expires":{far_future_ms}}}}}"#),
        );
        match probe_path(&path).unwrap() {
            OauthReadiness::Ready { expires_at_ms } => {
                assert_eq!(expires_at_ms, far_future_ms);
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    #[test]
    fn errors_never_contain_token_bytes() {
        // Defence-in-depth: even if a future change accidentally formats the
        // token into a reason, this catch-all test should fail.
        let tmp = tempdir().unwrap();
        let secret_token = "SECRET-TOKEN-DO-NOT-LEAK-XYZ";
        let body = format!(
            r#"{{"anthropic":{{"refresh":"{secret_token}","access":"{secret_token}","expires":1}}}}"#
        );
        let path = write_file(tmp.path(), "creds.json", &body);
        let outcome = probe_path(&path).unwrap();
        let debug = format!("{outcome:?}");
        assert!(
            !debug.contains(secret_token),
            "OauthReadiness Debug must not contain token bytes"
        );
    }
}
