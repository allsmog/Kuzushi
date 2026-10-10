use super::*;
use source::CitationSources;

pub(super) struct GroundingPass {
    pub(super) selected: usize,
    pub(super) checked: usize,
    pub(super) excluded: usize,
    pub(super) has_more: bool,
    pub(super) counts: BTreeMap<&'static str, usize>,
    pub(super) newly_drifted: Vec<String>,
    pub(super) inspections: Vec<Value>,
    pub(super) bytes: usize,
    pub(super) reserved_bytes: usize,
    pub(super) stopped: Option<String>,
}

impl GroundingPass {
    fn empty() -> Self {
        Self {
            selected: 0,
            checked: 0,
            excluded: 0,
            has_more: false,
            counts: BTreeMap::new(),
            newly_drifted: Vec::new(),
            inspections: Vec::new(),
            bytes: 0,
            reserved_bytes: 0,
            stopped: None,
        }
    }
    pub(super) fn partial(&self) -> bool {
        self.has_more
            || self.stopped.is_some()
            || self.counts.get("unavailable").copied().unwrap_or(0) > 0
    }
}

pub(super) fn inspect_candidates(
    ctx: &ToolExecutionContext<'_>,
    store: &FindingStore,
    root: &std::path::Path,
    limits: limits::GroundingLimits,
    git: &Value,
) -> Result<GroundingPass> {
    let mut pass = GroundingPass::empty();
    if ctx.is_cancelled() {
        pass.stopped = Some("Citation inspection canceled before selection.".into());
        return Ok(pass);
    }
    let (candidates, has_more) = store.grounding_candidate_window(limits.findings)?;
    let mut sources = CitationSources::new(root, limits);
    pass.selected = candidates.len();
    pass.has_more = has_more;
    inspect_window(ctx, store, candidates, git, &mut sources, &mut pass);
    pass.bytes = sources.bytes;
    pass.reserved_bytes = sources.reserved_bytes;
    Ok(pass)
}

fn inspect_window(
    ctx: &ToolExecutionContext<'_>,
    store: &FindingStore,
    candidates: Vec<Finding>,
    git: &Value,
    sources: &mut CitationSources<'_>,
    pass: &mut GroundingPass,
) {
    for finding in candidates {
        if ctx.is_cancelled() {
            pass.stopped =
                Some("Citation inspection canceled; completed checks are retained.".into());
            break;
        }
        if !inspect_or_stop(store, &finding, git, sources, pass) {
            break;
        }
    }
}

fn inspect_or_stop(
    store: &FindingStore,
    finding: &Finding,
    git: &Value,
    sources: &mut CitationSources<'_>,
    pass: &mut GroundingPass,
) -> bool {
    match inspect_one(store, finding, git, sources, pass) {
        Ok(()) => true,
        Err(error) => {
            pass.stopped = Some(format!("Citation audit stopped: {error:#}"));
            false
        }
    }
}

fn inspect_one(
    store: &FindingStore,
    finding: &Finding,
    git: &Value,
    sources: &mut CitationSources<'_>,
    pass: &mut GroundingPass,
) -> Result<()> {
    if !store.finding_is_relevant(finding)? {
        pass.excluded += 1;
        return Ok(());
    }
    let revision = git["sha"].as_str();
    let (status, source) = sources.inspect(finding, revision);
    pass.checked += 1;
    *pass.counts.entry(status.label()).or_default() += 1;
    pass.inspections.push(json!({"fingerprint":finding.fingerprint,"generation":finding.id,"line":finding.start_line,"status":status,"source":source}));
    if audit::audit_drift(store, finding, &status, &source, git)? {
        pass.newly_drifted.push(finding.fingerprint.clone());
    }
    Ok(())
}
