use super::*;

impl ReconNmapScanner {
    pub(crate) fn from_input(input: &NmapInput) -> Self {
        Self {
            target: input.target.clone(),
            ports: input.ports.clone(),
            binary: input.binary.clone(),
        }
    }

    pub(crate) fn scan(&self, cancel: &ScanCancellation) -> Result<NmapParseResult> {
        let mut args = vec!["-oG".to_string(), "-".to_string()];
        match self.ports.trim() {
            "" => {}
            "top100" => {
                args.push("--top-ports".to_string());
                args.push("100".to_string());
            }
            "top1000" => {
                args.push("--top-ports".to_string());
                args.push("1000".to_string());
            }
            ports => {
                args.push("-p".to_string());
                args.push(ports.to_string());
            }
        }
        args.push(self.target.clone());

        let output = run_subprocess(
            "recon:nmap",
            &self.binary,
            &args,
            None,
            cancel,
            "Install nmap first (`brew install nmap`, `apt install nmap`) or pass {\"binary\":\"/path/to/nmap\"}.",
        )?;
        let stdout =
            String::from_utf8(output.stdout).context("recon:nmap emitted non-UTF8 output")?;
        parse_nmap_grepable(&stdout)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubdomainSource {
    Crtsh,
    Wayback,
    Both,
}

impl SubdomainSource {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "crtsh" => Ok(Self::Crtsh),
            "wayback" => Ok(Self::Wayback),
            "both" | "" => Ok(Self::Both),
            other => anyhow::bail!(
                "recon:subdomain source must be one of crtsh, wayback, or both; got {other:?}"
            ),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Crtsh => "crtsh",
            Self::Wayback => "wayback",
            Self::Both => "both",
        }
    }

    pub(crate) fn includes(self, source: Self) -> bool {
        self == Self::Both || self == source
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SubdomainInput {
    pub(crate) domain: String,
    pub(crate) source: SubdomainSource,
    pub(crate) binary: String,
    pub(crate) timeout_seconds: u64,
}

impl SubdomainInput {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            domain: required_string(input, "domain", "recon:subdomain requires a domain.")?,
            source: SubdomainSource::parse(
                optional_string(input, &["source"])?
                    .unwrap_or_else(|| "both".to_string())
                    .as_str(),
            )?,
            binary: optional_string(input, &["binary", "curlBinary", "scannerBin"])?
                .unwrap_or_else(|| "curl".to_string()),
            timeout_seconds: optional_u64(input, &["timeoutSeconds", "timeout_seconds"])?
                .unwrap_or(20),
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReconSubdomainEnumerator {
    pub(crate) domain: String,
    pub(crate) source: SubdomainSource,
    pub(crate) binary: String,
    pub(crate) timeout_seconds: u64,
}
