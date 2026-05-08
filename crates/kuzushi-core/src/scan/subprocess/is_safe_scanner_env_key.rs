use super::*;

pub(crate) fn is_safe_scanner_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    if is_credential_env_key(&upper) {
        return false;
    }

    SCANNER_ENV_ALLOWLIST
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(key))
        || upper.starts_with("LC_")
}

pub(in crate::scan) fn is_credential_env_key(upper_key: &str) -> bool {
    const SENSITIVE_EXACT: &[&str] = &[
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "DATABASE_URL",
        "DB_URL",
    ];
    const SENSITIVE_FRAGMENTS: &[&str] = &[
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "CONNECTION_STRING",
        "COOKIE",
        "SESSION",
    ];

    SENSITIVE_EXACT.contains(&upper_key)
        || SENSITIVE_FRAGMENTS
            .iter()
            .any(|fragment| upper_key.contains(fragment))
}

#[derive(Debug)]
pub(in crate::scan) struct ProcessOutput {
    pub(in crate::scan) stdout: Vec<u8>,
}

pub(in crate::scan) fn read_pipe(mut pipe: impl Read) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    pipe.read_to_end(&mut output)?;
    Ok(output)
}
