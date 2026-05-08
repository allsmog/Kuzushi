use super::prelude::*;
use super::*;

impl ReconHttpFingerprinter {
    pub(crate) fn from_input(input: &HttpFingerprintInput) -> Self {
        Self {
            target: input.target.clone(),
            binary: input.binary.clone(),
            timeout_seconds: input.timeout_seconds,
        }
    }

    pub(crate) fn fingerprint(&self, cancel: &ScanCancellation) -> Result<HttpFingerprint> {
        let target = ensure_http_scheme(&self.target);
        let args = vec![
            "-i".to_string(),
            "-L".to_string(),
            "-sS".to_string(),
            "--max-time".to_string(),
            self.timeout_seconds.to_string(),
            target,
        ];
        let output = run_subprocess(
            "recon:http-fingerprint",
            &self.binary,
            &args,
            None,
            cancel,
            "Install curl or pass {\"binary\":\"/path/to/curl\"}.",
        )?;
        let stdout = String::from_utf8(output.stdout)
            .context("recon:http-fingerprint emitted non-UTF8 output")?;
        parse_http_fingerprint(&stdout)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NmapParseResult {
    pub(crate) hosts: Vec<NmapHost>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NmapHost {
    pub(crate) address: String,
    pub(crate) hostname: Option<String>,
    pub(crate) services: Vec<NmapService>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NmapService {
    pub(crate) port: u16,
    pub(crate) proto: String,
    pub(crate) state: String,
    pub(crate) name: Option<String>,
    pub(crate) banner: Option<String>,
}
