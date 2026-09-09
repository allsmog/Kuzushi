use kuzushi_sandbox::{detect_backend, SandboxBackend};

/// A backend discovery result, not a guarantee that sandbox startup or the
/// generated harness will succeed. Execution checks still run at dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalVerificationReadiness {
    BubblewrapDetected,
    PodmanUnsupported,
    NoSupportedBackend,
}

impl LocalVerificationReadiness {
    pub fn for_backend(backend: SandboxBackend) -> Self {
        match backend {
            SandboxBackend::Bwrap => Self::BubblewrapDetected,
            SandboxBackend::Podman => Self::PodmanUnsupported,
            SandboxBackend::Plain => Self::NoSupportedBackend,
        }
    }

    pub fn can_attempt(self) -> bool {
        self == Self::BubblewrapDetected
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::BubblewrapDetected => "bubblewrap detected; sandbox startup and the harness are checked when execution starts",
            Self::PodmanUnsupported => "Podman is detected but is not supported for local reproduction; use bubblewrap on Linux",
            Self::NoSupportedBackend => "Requires bubblewrap on Linux; none detected.",
        }
    }
}

/// Called at application/execution edges, never by a renderer.
pub fn local_verification_readiness() -> LocalVerificationReadiness {
    LocalVerificationReadiness::for_backend(detect_backend(None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_supported_isolating_backend_allows_an_attempt() {
        assert!(LocalVerificationReadiness::for_backend(SandboxBackend::Bwrap).can_attempt());
        for backend in [SandboxBackend::Plain, SandboxBackend::Podman] {
            let readiness = LocalVerificationReadiness::for_backend(backend);
            assert!(!readiness.can_attempt());
            assert!(readiness.message().contains("bubblewrap on Linux"));
        }
    }

    #[test]
    fn discovery_does_not_claim_execution_will_succeed() {
        assert!(LocalVerificationReadiness::BubblewrapDetected
            .message()
            .contains("checked when execution starts"));
    }
}
