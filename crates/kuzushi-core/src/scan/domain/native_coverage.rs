use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NativeEngineCoverage {
    pub engine: String,
    pub scope: Option<String>,
    pub findings_count: usize,
    pub scan_errors: Vec<String>,
    #[serde(default)]
    pub disposition: NativeEngineDisposition,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeEngineDisposition {
    #[default]
    Complete,
    Failed,
    Canceled,
    Interrupted,
    NotStarted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NativeScanCoverage {
    #[serde(deserialize_with = "coverage_schema_version")]
    pub schema_version: u32,
    pub engines: Vec<NativeEngineCoverage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_binding: Option<NativeSourceBindingReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NativeSourceBindingReceipt {
    pub snapshot_hash: String,
    pub tree_hash: String,
    pub authenticated: bool,
    pub captured_files: usize,
    pub captured_bytes: usize,
    pub max_capture_bytes: usize,
    pub limitation: Option<String>,
}

fn native_engine_has_gaps(engine: &NativeEngineCoverage) -> bool {
    engine.disposition != NativeEngineDisposition::Complete || !engine.scan_errors.is_empty()
}

fn coverage_schema_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u32, D::Error> {
    let version = u32::deserialize(deserializer)?;
    match version {
        1..=3 => Ok(version),
        _ => Err(serde::de::Error::custom(
            "unsupported native coverage schema version",
        )),
    }
}

impl Default for NativeScanCoverage {
    fn default() -> Self {
        Self {
            schema_version: 3,
            engines: Vec::new(),
            source_binding: None,
        }
    }
}

impl NativeScanCoverage {
    pub(crate) fn has_gaps(&self) -> bool {
        self.has_source_gap() || self.engines.iter().any(native_engine_has_gaps)
    }

    pub(crate) fn has_source_gap(&self) -> bool {
        self.source_binding
            .as_ref()
            .is_some_and(|source| !source.authenticated)
    }

    pub(crate) fn require_source_binding(&self) -> Result<()> {
        anyhow::ensure!(
            !self.has_source_gap(),
            "Native observation source binding unavailable: {}. Raw observations retained.",
            self.source_binding
                .as_ref()
                .and_then(|source| source.limitation.as_deref())
                .unwrap_or("No authenticated captured source")
        );
        Ok(())
    }

    pub(crate) fn engine_has_gaps(&self, id: &str) -> bool {
        self.engines
            .iter()
            .filter(|engine| engine.engine == id)
            .any(|engine| !engine.scan_errors.is_empty() || self.has_source_gap())
    }

    fn source_detail(&self, id: &str) -> Option<String> {
        self.source_binding
            .as_ref()
            .filter(|source| !source.authenticated)
            .filter(|_| self.engines.iter().any(|engine| engine.engine == id))
            .map(|source| {
                format!(
                    "Observation source binding unavailable: {}",
                    source
                        .limitation
                        .as_deref()
                        .unwrap_or("No authenticated captured source was retained")
                )
            })
    }

    pub(crate) fn engine_detail(&self, id: &str) -> Option<String> {
        let details = [self.engine_coverage_detail(id), self.source_detail(id)]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        (!details.is_empty()).then(|| details.join("; "))
    }

    fn engine_coverage_detail(&self, id: &str) -> Option<String> {
        let count = self.engine_gap_count(id);
        let unstarted = self.engine_unstarted_detail(id);
        if count == 0 {
            return unstarted;
        }
        let preview = self.engine_gap_preview(id);
        let more = if count > preview.len() {
            format!(
                "; {} more retained in native-coverage.json",
                count - preview.len()
            )
        } else {
            String::new()
        };
        Some(
            format!(
                "Incomplete coverage: {} report(s); {}{}",
                count,
                preview.join("; "),
                more,
            ) + &unstarted
                .map(|detail| format!("; {detail}"))
                .unwrap_or_default(),
        )
    }

    fn engine_unstarted_detail(&self, id: &str) -> Option<String> {
        let jobs = self
            .engines
            .iter()
            .filter(|job| {
                job.engine == id && job.disposition == NativeEngineDisposition::NotStarted
            })
            .collect::<Vec<_>>();
        if jobs.is_empty() {
            return None;
        }
        let scopes = jobs
            .iter()
            .take(3)
            .map(|job| bounded_gap(job.scope.as_deref().unwrap_or("repository")))
            .collect::<Vec<_>>();
        Some(format!(
            "Not started: {} scope job(s) ({}). No automatic retry.",
            jobs.len(),
            scopes.join(", ")
        ))
    }

    fn engine_gap_count(&self, id: &str) -> usize {
        self.engines
            .iter()
            .filter(|engine| engine.engine == id)
            .fold(0usize, |count, engine| {
                count.saturating_add(engine.scan_errors.len())
            })
    }

    fn engine_gap_preview(&self, id: &str) -> Vec<String> {
        self.engines
            .iter()
            .filter(|engine| engine.engine == id)
            .flat_map(|engine| {
                engine.scan_errors.iter().map(move |error| {
                    format!(
                        "{}: {}",
                        engine.scope.as_deref().unwrap_or("repository"),
                        bounded_gap(error)
                    )
                })
            })
            .take(3)
            .collect()
    }
}

#[derive(Debug)]
pub(crate) struct NativeScanFailure {
    pub report: NativeScanReport,
    pub status: crate::run_lifecycle::RunItemStatus,
    pub cause: anyhow::Error,
}

impl std::fmt::Display for NativeScanFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let unstarted = self
            .report
            .coverage
            .engines
            .iter()
            .filter(|job| job.disposition == NativeEngineDisposition::NotStarted)
            .count();
        write!(formatter, "Native scan {}: {}; {} observation(s) retained in run {}. {} planned job(s) not started. No automatic retry.",
            self.status.label(), self.cause, self.report.run.findings_count, self.report.run.id, unstarted)
    }
}

impl std::error::Error for NativeScanFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

pub(crate) fn native_scan_failure(error: &anyhow::Error) -> Option<&NativeScanFailure> {
    error.chain().find_map(|cause| cause.downcast_ref())
}

fn bounded_gap(error: &str) -> String {
    let mut chars = error.lines().next().unwrap_or("unspecified gap").chars();
    let mut preview = chars.by_ref().take(240).collect::<String>();
    if chars.next().is_some() || error.contains('\n') {
        preview.push('…');
    }
    preview
}

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub(crate) struct NativeScanReport {
    pub run: crate::scan::ScanRun,
    pub coverage: NativeScanCoverage,
}
