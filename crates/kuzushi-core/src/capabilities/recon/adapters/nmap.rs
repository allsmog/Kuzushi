use super::*;

#[derive(Debug, Clone)]
pub(crate) struct NmapInput {
    pub(crate) target: String,
    pub(crate) ports: String,
    pub(crate) binary: String,
    pub(crate) timeout_seconds: u64,
}

impl NmapInput {
    pub(crate) fn from_tool_input(input: &Value) -> Result<Self> {
        let target = required_string(input, "target", "recon:nmap requires a target.")?;
        anyhow::ensure!(
            !target.starts_with('-')
                && target.len() <= 256
                && !target.chars().any(char::is_whitespace),
            "Nmap target must be one bounded host or network expression, without option flags or whitespace"
        );
        Ok(Self {
            target,
            ports: checked_recon_ports(
                optional_string(input, &["ports"])?.unwrap_or_else(|| "top100".to_string()),
            )?,
            binary: optional_string(input, &["binary", "nmapBinary", "scannerBin"])?
                .unwrap_or_else(|| "nmap".to_string()),
            timeout_seconds: recon_timeout(input, 60)?,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReconNmapScanner {
    pub(crate) target: String,
    pub(crate) ports: String,
    pub(crate) binary: String,
    pub(crate) timeout_seconds: u64,
}

impl ReconNmapScanner {
    pub(crate) fn from_input(input: &NmapInput) -> Self {
        Self {
            target: input.target.clone(),
            ports: input.ports.clone(),
            binary: input.binary.clone(),
            timeout_seconds: input.timeout_seconds,
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
            self.timeout_seconds,
        )?;
        let stdout =
            String::from_utf8(output.stdout).context("recon:nmap emitted non-UTF8 output")?;
        parse_nmap_grepable(&stdout)
    }
}
