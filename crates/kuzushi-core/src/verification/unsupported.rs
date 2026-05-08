use super::*;

impl VerificationOutcome {
    pub fn unsupported(backend: SandboxBackend, language: &str) -> Self {
        Self {
            proof_level: 1,
            proof_verdict: ProofVerdict::LanguageUnsupportedYet,
            backend,
            language: Some(language.to_string()),
            harness_path: None,
            crash_evidence: None,
            duration_ms: 0,
            cost_usd: 0.0,
            notes: vec![format!(
                "verify: language `{language}` not yet wired into the verify pipeline"
            )],
        }
    }

    pub fn insufficient(backend: SandboxBackend, reason: &str) -> Self {
        Self {
            proof_level: 1,
            proof_verdict: ProofVerdict::InsufficientFindingDetail,
            backend,
            language: None,
            harness_path: None,
            crash_evidence: None,
            duration_ms: 0,
            cost_usd: 0.0,
            notes: vec![format!("verify: {reason}")],
        }
    }

    /// Convert to the persistence-side type (for FindingStore).
    pub fn to_persisted(&self) -> PersistedVerification {
        PersistedVerification {
            proof_level: self.proof_level,
            proof_verdict: match self.proof_verdict {
                ProofVerdict::Exploited => PersistedProofVerdict::Exploited,
                ProofVerdict::NotReproduced => PersistedProofVerdict::NotReproduced,
                ProofVerdict::HarnessFailedToBuild => PersistedProofVerdict::HarnessFailedToBuild,
                ProofVerdict::InfrastructureError => PersistedProofVerdict::InfrastructureError,
                ProofVerdict::LanguageUnsupportedYet => {
                    PersistedProofVerdict::LanguageUnsupportedYet
                }
                ProofVerdict::InsufficientFindingDetail => {
                    PersistedProofVerdict::InsufficientFindingDetail
                }
            },
            backend: match self.backend {
                SandboxBackend::Bwrap => PersistedSandboxBackend::Bwrap,
                SandboxBackend::Podman => PersistedSandboxBackend::Podman,
                SandboxBackend::Plain => PersistedSandboxBackend::Plain,
            },
            language: self.language.clone(),
            harness_path: self.harness_path.as_ref().map(|p| p.display().to_string()),
            crash_evidence: self.crash_evidence.clone(),
            duration_ms: self.duration_ms,
            cost_usd: self.cost_usd,
            notes: self.notes.clone(),
            created_at: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub backend: Option<SandboxBackend>,
    pub timeout_ms: u64,
    /// When `false`, runs that select the `Plain` backend are clamped to
    /// `proof_level <= 3` even if a crash is observed. Set to `true`
    /// only in throw-away local testing.
    pub trust_plain_backend: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            backend: None,
            timeout_ms: 60_000,
            trust_plain_backend: false,
        }
    }
}

pub async fn verify_finding(finding: &Finding, opts: VerifyOptions) -> Result<VerificationOutcome> {
    let backend = detect_backend(opts.backend);
    let language = infer_language(&finding.file_path);
    let mut outcome = verify_with_language(finding, backend, &opts, &language).await?;
    // Record which language adapter produced the outcome so persistence
    // round-trips it.
    outcome.language = Some(language_label(language));
    Ok(outcome)
}

async fn verify_with_language(
    finding: &Finding,
    backend: SandboxBackend,
    opts: &VerifyOptions,
    language: &Lang,
) -> Result<VerificationOutcome> {
    match language {
        Lang::Rust => verify_rust(finding, backend, opts).await,
        Lang::C => verify_c_like(finding, backend, opts, CCompiler::Gcc).await,
        Lang::Cpp => verify_c_like(finding, backend, opts, CCompiler::Gpp).await,
        Lang::Python => verify_python(finding, backend, opts).await,
        Lang::JavaScript => verify_node(finding, backend, opts, "js").await,
        Lang::TypeScript => verify_node(finding, backend, opts, "ts").await,
        Lang::Other(name) => Ok(VerificationOutcome::unsupported(backend, name)),
    }
}

fn language_label(language: Lang) -> String {
    match language {
        Lang::Rust => "rust".to_string(),
        Lang::C => "c".to_string(),
        Lang::Cpp => "cpp".to_string(),
        Lang::Python => "python".to_string(),
        Lang::JavaScript => "javascript".to_string(),
        Lang::TypeScript => "typescript".to_string(),
        Lang::Other(name) => name,
    }
}
