use super::prelude::*;
use super::*;

impl ReconSubdomainEnumerator {
    pub(crate) fn from_input(input: &SubdomainInput) -> Self {
        Self {
            domain: input.domain.clone(),
            source: input.source,
            binary: input.binary.clone(),
            timeout_seconds: input.timeout_seconds,
        }
    }

    pub(crate) fn enumerate(&self, cancel: &ScanCancellation) -> Result<Vec<String>> {
        let mut subdomains = BTreeSet::new();
        if matches!(self.source, SubdomainSource::Crtsh | SubdomainSource::Both) {
            for value in self.fetch_crtsh(cancel)? {
                subdomains.insert(value);
            }
        }
        if matches!(
            self.source,
            SubdomainSource::Wayback | SubdomainSource::Both
        ) {
            for value in self.fetch_wayback(cancel)? {
                subdomains.insert(value);
            }
        }
        Ok(subdomains.into_iter().collect())
    }

    pub(crate) fn fetch_crtsh(&self, cancel: &ScanCancellation) -> Result<Vec<String>> {
        let url = format!("https://crt.sh/?q=%25.{}&output=json", self.domain);
        let stdout = self.run_curl(&url, cancel)?;
        parse_crtsh_subdomains(&stdout, &self.domain)
    }

    pub(crate) fn fetch_wayback(&self, cancel: &ScanCancellation) -> Result<Vec<String>> {
        let url = format!(
            "https://web.archive.org/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey",
            self.domain
        );
        let stdout = self.run_curl(&url, cancel)?;
        parse_wayback_subdomains(&stdout, &self.domain)
    }

    pub(crate) fn run_curl(&self, url: &str, cancel: &ScanCancellation) -> Result<String> {
        let args = vec![
            "-fsSL".to_string(),
            "--max-time".to_string(),
            self.timeout_seconds.to_string(),
            url.to_string(),
        ];
        let output = run_subprocess(
            "recon:subdomain",
            &self.binary,
            &args,
            None,
            cancel,
            "Install curl or pass {\"binary\":\"/path/to/curl\"}.",
        )?;
        String::from_utf8(output.stdout).context("recon:subdomain source emitted non-UTF8 output")
    }
}

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
            binary: optional_string(input, &["binary", "curlBinary", "scannerBin"])?
                .unwrap_or_else(|| "curl".to_string()),
            timeout_seconds: optional_u64(input, &["timeoutSeconds", "timeout_seconds"])?
                .unwrap_or(10),
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReconHttpFingerprinter {
    pub(crate) target: String,
    pub(crate) binary: String,
    pub(crate) timeout_seconds: u64,
}
