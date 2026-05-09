use super::*;

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
        for fetcher in subdomain_fetchers_for(self.source) {
            subdomains.extend(fetcher(self, cancel)?);
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

type SubdomainFetcher = fn(&ReconSubdomainEnumerator, &ScanCancellation) -> Result<Vec<String>>;

const SUBDOMAIN_FETCHERS: &[(SubdomainSource, SubdomainFetcher)] = &[
    (
        SubdomainSource::Crtsh,
        ReconSubdomainEnumerator::fetch_crtsh,
    ),
    (
        SubdomainSource::Wayback,
        ReconSubdomainEnumerator::fetch_wayback,
    ),
];

fn subdomain_fetchers_for(source: SubdomainSource) -> impl Iterator<Item = SubdomainFetcher> {
    SUBDOMAIN_FETCHERS
        .iter()
        .filter(move |(candidate, _)| source.includes(*candidate))
        .map(|(_, fetcher)| *fetcher)
}
