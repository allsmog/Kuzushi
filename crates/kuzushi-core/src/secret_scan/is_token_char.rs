use super::prelude::*;
use super::*;

pub(super) fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'/' | b'+' | b'.')
}

pub(super) fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

pub(super) fn is_alnum(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

pub(super) fn is_alnum_hyphen(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

pub(super) fn is_alnum_underscore_hyphen(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

pub(super) fn is_base64_secret_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'=')
}

pub(super) fn is_generic_secret_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!@#$%^&*_+/=-".contains(&byte)
}

pub(super) fn skip_ascii_whitespace(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    cursor
}

pub(super) fn is_binary_extension(path: &Path, binary_exts: &BTreeSet<String>) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext.to_ascii_lowercase()))
        .is_some_and(|ext| binary_exts.contains(ext.as_str()))
}

pub(super) fn is_likely_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(4096).any(|byte| *byte == 0)
}

pub(super) fn locate_match(text: &str, index: usize) -> MatchLocation {
    let mut line = 1u32;
    let mut line_start = 0usize;
    for (cursor, byte) in text.as_bytes().iter().copied().enumerate().take(index) {
        if byte == b'\n' {
            line += 1;
            line_start = cursor + 1;
        }
    }
    let line_end = text[line_start..]
        .find('\n')
        .map(|offset| line_start + offset)
        .unwrap_or(text.len());
    MatchLocation {
        line,
        line_text: text[line_start..line_end].to_string(),
    }
}

#[derive(Debug, Clone)]
pub(super) struct MatchLocation {
    pub(super) line: u32,
    pub(super) line_text: String,
}

pub(super) fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut counts = BTreeMap::<char, usize>::new();
    for ch in input.chars() {
        *counts.entry(ch).or_default() += 1;
    }

    let len = input.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub(super) fn redact_secret(secret: &str) -> String {
    let chars = secret.chars().collect::<Vec<_>>();
    if chars.len() <= 4 {
        return "***".to_string();
    }
    let prefix = chars.iter().take(4).collect::<String>();
    format!("{}{}", prefix, "*".repeat((chars.len() - 4).min(8)))
}

pub(super) fn fingerprint_for(
    repo_root: &Path,
    detector_id: &str,
    file_path: &str,
    line: u32,
    matched: &str,
) -> String {
    let repo_name = repo_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let input = format!("{repo_name}|secret-scan|{detector_id}|{file_path}|{line}|{matched}");
    format!(
        "secret-scan:{detector_id}:{:016x}",
        fnv1a64(input.as_bytes())
    )
}

pub(super) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub(super) fn aws_access_key_detector() -> Detector {
    Detector {
        id: "aws-access-key",
        name: "AWS Access Key ID",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "AWS access key ID committed to source.",
    }
}

pub(super) fn aws_secret_key_detector() -> Detector {
    Detector {
        id: "aws-secret-key",
        name: "AWS Secret Access Key",
        severity: SecretSeverity::Error,
        entropy_threshold: Some(4.0),
        cwe: "CWE-798",
        description: "AWS secret access key candidate (40-char base64).",
    }
}

pub(super) fn github_pat_detector() -> Detector {
    Detector {
        id: "github-pat",
        name: "GitHub Personal Access Token",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "GitHub fine-grained or classic personal access token.",
    }
}

pub(super) fn slack_token_detector() -> Detector {
    Detector {
        id: "slack-token",
        name: "Slack Token",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Slack bot/user/app token.",
    }
}

pub(super) fn stripe_live_key_detector() -> Detector {
    Detector {
        id: "stripe-live-key",
        name: "Stripe Live Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Stripe live API key (production credentials).",
    }
}

pub(super) fn stripe_test_key_detector() -> Detector {
    Detector {
        id: "stripe-test-key",
        name: "Stripe Test Key",
        severity: SecretSeverity::Warning,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Stripe test API key - still a leak even if low-impact.",
    }
}

pub(super) fn google_api_key_detector() -> Detector {
    Detector {
        id: "google-api-key",
        name: "Google API Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Google Cloud / Maps / Firebase API key.",
    }
}

pub(super) fn anthropic_api_key_detector() -> Detector {
    Detector {
        id: "anthropic-api-key",
        name: "Anthropic API Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Anthropic API key.",
    }
}

pub(super) fn openai_api_key_detector() -> Detector {
    Detector {
        id: "openai-api-key",
        name: "OpenAI API Key",
        severity: SecretSeverity::Error,
        entropy_threshold: Some(3.5),
        cwe: "CWE-798",
        description: "OpenAI-style API key (sk-... or sk-proj-...).",
    }
}

pub(super) fn jwt_token_detector() -> Detector {
    Detector {
        id: "jwt-token",
        name: "JSON Web Token",
        severity: SecretSeverity::Warning,
        entropy_threshold: None,
        cwe: "CWE-522",
        description: "JWT-shaped token; verify it isn't a long-lived credential.",
    }
}

pub(super) fn pem_private_key_detector() -> Detector {
    Detector {
        id: "pem-private-key",
        name: "PEM Private Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "PEM-encoded private key block.",
    }
}

pub(super) fn generic_secret_assignment_detector() -> Detector {
    Detector {
        id: "generic-secret-assignment",
        name: "Generic Secret Assignment",
        severity: SecretSeverity::Warning,
        entropy_threshold: Some(3.5),
        cwe: "CWE-798",
        description: "Likely-credential assignment with a high-entropy value.",
    }
}
