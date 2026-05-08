use super::prelude::*;
use super::*;

impl RunTraceStep {
    pub fn new(n: usize, kind: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            n,
            kind: kind.into(),
            label: label.into(),
            latency_ms: None,
            cost_usd: None,
        }
    }

    pub fn with_latency_ms(mut self, latency_ms: Option<u64>) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    pub fn with_cost_usd(mut self, cost_usd: Option<f64>) -> Self {
        self.cost_usd = cost_usd;
        self
    }
}

pub fn new_run_id(prefix: &str) -> String {
    let prefix = prefix
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_ascii_lowercase();
    let prefix = if prefix.is_empty() { "run" } else { &prefix };
    let suffix = Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}-{}", now_unix(), &suffix[..12])
}

pub fn runs_root(target: impl AsRef<Path>) -> PathBuf {
    target.as_ref().join(".kuzushi").join("runs")
}

pub fn run_dir(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    runs_root(target).join(run_id)
}

pub fn write_run_summary(target: impl AsRef<Path>, summary: &RunSummary) -> Result<PathBuf> {
    let dir = run_dir(target, &summary.run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join("summary.json");
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(summary)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub fn load_run_summary(target: impl AsRef<Path>, run_id: &str) -> Result<RunSummary> {
    let path = run_dir(target, run_id).join("summary.json");
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    serde_json::from_str(&body).with_context(|| format!("Could not parse {}", path.display()))
}

pub fn list_run_summaries(target: impl AsRef<Path>) -> Result<Vec<RunSummary>> {
    let root = runs_root(target);
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut summaries = collect_run_summaries(&root)?;
    sort_run_summaries(&mut summaries);
    Ok(summaries)
}

pub(crate) fn collect_run_summaries(root: &Path) -> Result<Vec<RunSummary>> {
    let mut summaries = Vec::new();
    for entry in
        fs::read_dir(&root).with_context(|| format!("Could not read {}", root.display()))?
    {
        let entry = entry?;
        if let Some(summary) = read_run_summary_entry(&entry) {
            summaries.push(summary);
        }
    }
    Ok(summaries)
}

pub(crate) fn read_run_summary_entry(entry: &fs::DirEntry) -> Option<RunSummary> {
    if !is_directory_entry(entry) {
        return None;
    }
    let summary_path = entry.path().join("summary.json");
    read_run_summary_file(&summary_path)
}

pub(crate) fn is_directory_entry(entry: &fs::DirEntry) -> bool {
    entry
        .file_type()
        .map(|file_type| file_type.is_dir())
        .unwrap_or(false)
}

pub(crate) fn read_run_summary_file(summary_path: &Path) -> Option<RunSummary> {
    let body = fs::read_to_string(summary_path).ok()?;
    serde_json::from_str::<RunSummary>(&body).ok()
}

pub(crate) fn sort_run_summaries(summaries: &mut [RunSummary]) {
    summaries.sort_by(|left, right| right.run_id.cmp(&left.run_id));
}
