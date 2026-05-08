#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::AnthropicOauthConfig;
    use std::fs;
    use std::path::{Path, PathBuf};
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
