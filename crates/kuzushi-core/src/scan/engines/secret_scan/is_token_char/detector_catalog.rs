use super::*;

pub(in crate::scan::engines::secret_scan) fn aws_access_key_detector() -> Detector {
    Detector {
        id: "aws-access-key",
        name: "AWS Access Key ID",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "AWS access key ID committed to source.",
    }
}

pub(in crate::scan::engines::secret_scan) fn aws_secret_key_detector() -> Detector {
    Detector {
        id: "aws-secret-key",
        name: "AWS Secret Access Key",
        severity: SecretSeverity::Error,
        entropy_threshold: Some(4.0),
        cwe: "CWE-798",
        description: "AWS secret access key candidate (40-char base64).",
    }
}

pub(in crate::scan::engines::secret_scan) fn github_pat_detector() -> Detector {
    Detector {
        id: "github-pat",
        name: "GitHub Personal Access Token",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "GitHub fine-grained or classic personal access token.",
    }
}

pub(in crate::scan::engines::secret_scan) fn slack_token_detector() -> Detector {
    Detector {
        id: "slack-token",
        name: "Slack Token",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Slack bot/user/app token.",
    }
}

pub(in crate::scan::engines::secret_scan) fn stripe_live_key_detector() -> Detector {
    Detector {
        id: "stripe-live-key",
        name: "Stripe Live Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Stripe live API key (production credentials).",
    }
}

pub(in crate::scan::engines::secret_scan) fn stripe_test_key_detector() -> Detector {
    Detector {
        id: "stripe-test-key",
        name: "Stripe Test Key",
        severity: SecretSeverity::Warning,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Stripe test API key - still a leak even if low-impact.",
    }
}

pub(in crate::scan::engines::secret_scan) fn google_api_key_detector() -> Detector {
    Detector {
        id: "google-api-key",
        name: "Google API Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Google Cloud / Maps / Firebase API key.",
    }
}

pub(in crate::scan::engines::secret_scan) fn anthropic_api_key_detector() -> Detector {
    Detector {
        id: "anthropic-api-key",
        name: "Anthropic API Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Anthropic API key.",
    }
}

pub(in crate::scan::engines::secret_scan) fn openai_api_key_detector() -> Detector {
    Detector {
        id: "openai-api-key",
        name: "OpenAI API Key",
        severity: SecretSeverity::Error,
        entropy_threshold: Some(3.5),
        cwe: "CWE-798",
        description: "OpenAI-style API key (sk-... or sk-proj-...).",
    }
}

pub(in crate::scan::engines::secret_scan) fn jwt_token_detector() -> Detector {
    Detector {
        id: "jwt-token",
        name: "JSON Web Token",
        severity: SecretSeverity::Warning,
        entropy_threshold: None,
        cwe: "CWE-522",
        description: "JWT-shaped token; verify it isn't a long-lived credential.",
    }
}

pub(in crate::scan::engines::secret_scan) fn pem_private_key_detector() -> Detector {
    Detector {
        id: "pem-private-key",
        name: "PEM Private Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "PEM-encoded private key block.",
    }
}

pub(in crate::scan::engines::secret_scan) fn generic_secret_assignment_detector() -> Detector {
    Detector {
        id: "generic-secret-assignment",
        name: "Generic Secret Assignment",
        severity: SecretSeverity::Warning,
        entropy_threshold: Some(3.5),
        cwe: "CWE-798",
        description: "Likely-credential assignment with a high-entropy value.",
    }
}
