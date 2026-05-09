use super::*;

#[derive(Debug, Clone)]
pub(crate) struct HttpFingerprintInput {
    pub(crate) target: String,
    pub(crate) binary: String,
    pub(crate) timeout_seconds: u64,
}

impl HttpFingerprintInput {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            target: required_string(input, "target", "recon:http-fingerprint requires a target.")?,
            binary: http_fingerprint_binary(input)?,
            timeout_seconds: http_fingerprint_timeout_seconds(input)?,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReconHttpFingerprinter {
    pub(crate) target: String,
    pub(crate) binary: String,
    pub(crate) timeout_seconds: u64,
}

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

fn http_fingerprint_binary(input: &Value) -> Result<String> {
    Ok(
        optional_string(input, &["binary", "curlBinary", "scannerBin"])?
            .unwrap_or_else(|| "curl".to_string()),
    )
}

fn http_fingerprint_timeout_seconds(input: &Value) -> Result<u64> {
    Ok(optional_u64(input, &["timeoutSeconds", "timeout_seconds"])?.unwrap_or(10))
}
