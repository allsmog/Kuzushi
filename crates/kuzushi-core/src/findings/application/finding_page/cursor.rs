use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

const CURSOR_MAX_BYTES: usize = 512;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageCursor {
    version: u8,
    binding: String,
    offset: usize,
}

pub(super) fn query_binding(
    workspace: &WorkspaceTarget,
    filter: &FindingListFilter,
    policy: IdentityFoldPolicy,
    order: FindingPageOrder,
    report: &FindingListReport,
    runs: &BTreeMap<String, RunSummary>,
    membership: Option<&BatchPageMembership>,
) -> Result<String> {
    // Run bookkeeping advances the projection without changing this query.
    // Bind materialized finding facts and decisions, preserving actual drift
    // checks while permitting a fresh headless invocation for the next page.
    let signature = format!(
        "page-content-v1:{:?}:{filter:?}:{policy:?}:{order:?}",
        workspace.root()
    );
    let mut digest = Sha256::new();
    digest.update(signature.as_bytes());
    if let Some(membership) = membership {
        digest.update(&membership.signature);
    }
    digest.update(serde_json::to_vec(&report.aliases)?);
    digest.update(serde_json::to_vec(&report.review_decisions)?);
    for finding in &report.findings {
        digest.update(serde_json::to_vec(finding)?);
        let run = finding.scan_id.as_ref().and_then(|id| runs.get(id));
        digest.update(serde_json::to_vec(&run)?);
    }
    Ok(URL_SAFE_NO_PAD.encode(digest.finalize()))
}

pub(super) fn page_offset(cursor: Option<&str>, binding: &str) -> Result<usize> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    anyhow::ensure!(
        cursor.len() <= CURSOR_MAX_BYTES,
        "Finding page cursor is too long"
    );
    let decoded = URL_SAFE_NO_PAD
        .decode(cursor)
        .context("Invalid finding page cursor; reload the first page")?;
    let cursor: PageCursor = serde_json::from_slice(&decoded)
        .context("Invalid finding page cursor; reload the first page")?;
    anyhow::ensure!(
        cursor.version == 1,
        "Unsupported finding page cursor version; reload the first page"
    );
    anyhow::ensure!(
        cursor.binding == binding,
        "Findings or query changed; reload the first page"
    );
    Ok(cursor.offset)
}

fn encode_cursor(binding: &str, offset: usize) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&PageCursor {
        version: 1,
        binding: binding.to_owned(),
        offset,
    })?))
}

pub(super) fn window_report(
    mut report: FindingListReport,
    limit: usize,
    offset: usize,
    binding: &str,
    watermark: u64,
    order: FindingPageOrder,
) -> Result<FindingListPage> {
    anyhow::ensure!(
        offset <= report.count,
        "Finding page is outside the matching ledger; reload the first page"
    );
    anyhow::ensure!(
        limit > 0 || offset == 0,
        "A continued finding page needs a positive limit"
    );
    report.findings = report
        .findings
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect();
    report.aliases = report
        .aliases
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect();
    let page = page_metadata(&report, limit, offset, binding, watermark, order)?;
    Ok(FindingListPage { report, page })
}

fn page_metadata(
    report: &FindingListReport,
    limit: usize,
    offset: usize,
    binding: &str,
    watermark: u64,
    order: FindingPageOrder,
) -> Result<FindingPageMetadata> {
    let loaded = report.findings.len();
    let end = offset.saturating_add(loaded);
    Ok(FindingPageMetadata {
        offset,
        loaded,
        total: report.count,
        watermark,
        order,
        next_cursor: next_cursor(binding, end, report.count, loaded)?,
        previous_cursor: previous_cursor(binding, offset, limit)?,
        anchors: report.findings.iter().map(finding_page_anchor).collect(),
        continuity_anchors: report
            .findings
            .iter()
            .map(finding_page_continuity_anchor)
            .collect(),
    })
}

fn next_cursor(binding: &str, end: usize, total: usize, loaded: usize) -> Result<Option<String>> {
    (end < total && loaded > 0)
        .then(|| encode_cursor(binding, end))
        .transpose()
}

fn previous_cursor(binding: &str, offset: usize, limit: usize) -> Result<Option<String>> {
    (offset > 0)
        .then(|| encode_cursor(binding, offset.saturating_sub(limit)))
        .transpose()
}
