use super::*;

impl VerificationOutcome {
    pub fn not_attempted(backend: SandboxBackend, reason: impl Into<String>) -> Self {
        Self {
            proof_level: 1,
            proof_verdict: ProofVerdict::NotAttempted,
            backend,
            language: None,
            harness_path: None,
            crash_evidence: None,
            duration_ms: 0,
            cost_usd: 0.0,
            notes: vec![format!("verify: not attempted: {}", reason.into())],
            provenance: None,
        }
    }

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
            provenance: None,
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
            provenance: None,
        }
    }

    /// Convert to the persistence-side type (for FindingStore).
    pub fn to_persisted(&self) -> PersistedVerification {
        PersistedVerification {
            proof_level: self.proof_level,
            proof_verdict: match self.proof_verdict {
                ProofVerdict::NotAttempted => PersistedProofVerdict::NotAttempted,
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
            // Temp harness directories are intentionally ephemeral. New rows
            // cite the durable CAS reproducer instead; old paths remain readable.
            harness_path: None,
            crash_evidence: self
                .crash_evidence
                .as_deref()
                .and_then(bounded_runtime_evidence),
            duration_ms: self.duration_ms,
            cost_usd: self.cost_usd,
            notes: self.notes.clone(),
            verification_run_id: None,
            verified_scan_id: None,
            provenance: self.provenance.clone(),
            created_at: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub backend: Option<SandboxBackend>,
    pub timeout_ms: u64,
    /// Retained for input compatibility. Plain execution is always refused.
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

pub async fn verify_finding(
    finding: &Finding,
    opts: VerifyOptions,
    workspace_root: &Path,
) -> Result<VerificationOutcome> {
    verify_finding_with_payload(finding, opts, workspace_root, None).await
}

pub(crate) async fn verify_finding_with_payload(
    finding: &Finding,
    opts: VerifyOptions,
    workspace_root: &Path,
    payload: Option<&[u8]>,
) -> Result<VerificationOutcome> {
    let backend = detect_backend(opts.backend);
    let language = infer_language(&finding.file_path);
    if backend != SandboxBackend::Bwrap {
        return Ok(unsupported_backend_outcome(backend, &language));
    }
    let source_identity = match capture_verification_source_identity(workspace_root) {
        Ok(identity) => identity,
        Err(error) => return Ok(source_capture_error(backend, &language, error)),
    };
    let outcome = verify_with_language(
        finding,
        backend,
        &opts,
        &language,
        workspace_root,
        &source_identity,
        payload,
    )
    .await?;
    Ok(finalize_verification(
        outcome,
        &language,
        &source_identity,
        workspace_root,
    ))
}

fn unsupported_backend_outcome(backend: SandboxBackend, language: &Lang) -> VerificationOutcome {
    language_outcome(
        VerificationOutcome::not_attempted(backend, unsupported_backend_reason(backend)),
        language,
    )
}

fn unsupported_backend_reason(backend: SandboxBackend) -> &'static str {
    if backend == SandboxBackend::Podman {
        "the Podman verifier has no pinned image contract; target and harness code were not executed"
    } else {
        "no supported isolating sandbox backend is available; target and harness code were not executed"
    }
}

fn source_capture_error(
    backend: SandboxBackend,
    language: &Lang,
    error: impl std::fmt::Display,
) -> VerificationOutcome {
    language_outcome(
        infrastructure_error(
            backend,
            None,
            format!("verification source snapshot capture failed: {error}"),
        ),
        language,
    )
}

fn finalize_verification(
    mut outcome: VerificationOutcome,
    language: &Lang,
    source_identity: &crate::workflow_attempts::TargetContentIdentity,
    workspace_root: &Path,
) -> VerificationOutcome {
    outcome
        .provenance
        .get_or_insert_with(|| crate::findings::VerificationProvenance {
            source_identity: source_identity.clone(),
            reproducer: None,
        });
    confirm_source_binding(&mut outcome, source_identity, workspace_root);
    enforce_empirical_provenance(&mut outcome);
    language_outcome(outcome, language)
}

fn confirm_source_binding(
    outcome: &mut VerificationOutcome,
    source_identity: &crate::workflow_attempts::TargetContentIdentity,
    workspace_root: &Path,
) {
    match crate::incremental_index::current_workspace_tree_hash(workspace_root) {
        Ok(current) if indexed_tree_hash(source_identity) == Some(current.as_str()) => {}
        Ok(_) => downgrade_source_binding(
            outcome,
            "verification target changed while the empirical harness was running",
        ),
        Err(error) => downgrade_source_binding(
            outcome,
            &format!("could not confirm the post-verification target identity: {error}"),
        ),
    }
}

fn language_outcome(mut outcome: VerificationOutcome, language: &Lang) -> VerificationOutcome {
    outcome.language = Some(language_label(language));
    outcome
}

fn downgrade_source_binding(outcome: &mut VerificationOutcome, reason: &str) {
    outcome.proof_level = 1;
    outcome.proof_verdict = ProofVerdict::InfrastructureError;
    outcome.harness_path = None;
    outcome.crash_evidence = bounded_runtime_evidence(reason);
    outcome.notes.push(format!("verify: {reason}"));
}

pub(super) fn enforce_empirical_provenance(outcome: &mut VerificationOutcome) {
    if !matches!(
        outcome.proof_verdict,
        ProofVerdict::Exploited | ProofVerdict::NotReproduced
    ) {
        return;
    }
    let reusable = outcome.backend == SandboxBackend::Bwrap
        && outcome.provenance.as_ref().is_some_and(|provenance| {
            provenance.source_identity.permits_cross_attempt_reuse()
                && provenance.reproducer.is_some()
        });
    if !reusable {
        downgrade_source_binding(
            outcome,
            "empirical verdict lacked an isolating backend, reusable source identity, or durable reproducer",
        );
    }
}

async fn verify_with_language(
    finding: &Finding,
    backend: SandboxBackend,
    opts: &VerifyOptions,
    language: &Lang,
    workspace_root: &Path,
    source_identity: &crate::workflow_attempts::TargetContentIdentity,
    payload: Option<&[u8]>,
) -> Result<VerificationOutcome> {
    let verification = LanguageVerification {
        finding,
        backend,
        opts,
        workspace_root,
        source_identity,
        payload,
    };
    match language {
        Lang::Rust => verification.run_rust().await,
        Lang::C => verification.run_c(CCompiler::Gcc).await,
        Lang::Cpp => verification.run_c(CCompiler::Gpp).await,
        Lang::Python => verify_python(finding, backend, opts).await,
        Lang::JavaScript => verify_node(finding, backend, opts, "js").await,
        Lang::TypeScript => verify_node(finding, backend, opts, "ts").await,
        Lang::Other(name) => Ok(VerificationOutcome::unsupported(backend, name)),
    }
}

struct LanguageVerification<'a> {
    finding: &'a Finding,
    backend: SandboxBackend,
    opts: &'a VerifyOptions,
    workspace_root: &'a Path,
    source_identity: &'a crate::workflow_attempts::TargetContentIdentity,
    payload: Option<&'a [u8]>,
}

impl LanguageVerification<'_> {
    async fn run_rust(&self) -> Result<VerificationOutcome> {
        verify_rust(
            self.finding,
            self.backend,
            self.opts,
            self.workspace_root,
            self.source_identity,
            self.payload,
        )
        .await
    }

    async fn run_c(&self, compiler: CCompiler) -> Result<VerificationOutcome> {
        verify_c_like(
            self.finding,
            self.backend,
            self.opts,
            compiler,
            self.workspace_root,
            self.source_identity,
            self.payload,
        )
        .await
    }
}

fn language_label(language: &Lang) -> String {
    match language {
        Lang::Rust => "rust".to_string(),
        Lang::C => "c".to_string(),
        Lang::Cpp => "cpp".to_string(),
        Lang::Python => "python".to_string(),
        Lang::JavaScript => "javascript".to_string(),
        Lang::TypeScript => "typescript".to_string(),
        Lang::Other(name) => name.clone(),
    }
}
