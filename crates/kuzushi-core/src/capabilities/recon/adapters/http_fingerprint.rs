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
    pub(crate) binary: String,
    pub(crate) timeout_seconds: u64,
}

impl ReconHttpFingerprinter {
    pub(crate) fn from_input(input: &HttpFingerprintInput) -> Self {
        Self {
            binary: input.binary.clone(),
            timeout_seconds: input.timeout_seconds,
        }
    }

    /// Fetch exactly one URL. Redirects are deliberately not followed here:
    /// `-L` would send the next request before anything could weigh the host it
    /// names against `.kuzushi/scope.toml`, and would leave the response
    /// attributed to the endpoint that had only pointed elsewhere.
    pub(crate) fn fetch(&self, url: &str, cancel: &ScanCancellation) -> Result<HttpFingerprint> {
        let args = vec![
            "-i".to_string(),
            "-sS".to_string(),
            "--max-time".to_string(),
            self.timeout_seconds.to_string(),
            url.to_string(),
        ];
        let output = run_subprocess(
            "recon:http-fingerprint",
            &self.binary,
            &args,
            None,
            cancel,
            "Install curl or pass {\"binary\":\"/path/to/curl\"}.",
            self.timeout_seconds,
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
    recon_timeout(input, 10)
}
