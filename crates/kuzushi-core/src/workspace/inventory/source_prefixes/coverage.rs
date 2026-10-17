use super::*;

const MAX_DISCLOSED_PATHS: usize = 128;

pub(super) struct SourceCoverage {
    pub(super) indexed_files: usize,
    attempted_files: usize,
    inspected_bytes: usize,
    included_text_bytes: usize,
    incomplete_utf8_prefix_bytes: usize,
    reserved_bytes: usize,
    max_bytes: usize,
    limits: SourcePrefixLimits,
    omitted_count: usize,
    omissions: Vec<Value>,
    truncated_count: usize,
    truncated_paths: Vec<String>,
    partial: bool,
}

impl SourceCoverage {
    pub(super) fn new(inventory: &RepositoryInventory, limits: SourcePrefixLimits) -> Self {
        let inspected = inventory
            .inspection
            .as_ref()
            .map_or(0, |value| value.inspected_bytes);
        let remaining =
            crate::workspace::inventory::MAX_REPOSITORY_INSPECTED_BYTES.saturating_sub(inspected);
        Self {
            indexed_files: 0,
            limits,
            attempted_files: 0,
            inspected_bytes: 0,
            included_text_bytes: 0,
            incomplete_utf8_prefix_bytes: 0,
            reserved_bytes: 0,
            max_bytes: remaining.min(limits.max_bytes),
            omitted_count: 0,
            omissions: Vec::new(),
            truncated_count: 0,
            truncated_paths: Vec::new(),
            partial: inventory.truncation.is_some() || inventory.inspection.is_none(),
        }
    }

    pub(super) fn next_file_limit(&mut self, relative: &str) -> Option<usize> {
        if self.attempted_files >= self.limits.max_files {
            self.partial = true;
            self.omit(relative, "source file limit reached");
            return None;
        }
        let remaining = self.max_bytes.saturating_sub(self.reserved_bytes);
        if remaining == 0 {
            self.partial = true;
            self.omit(relative, "source byte budget exhausted");
            return None;
        }
        self.attempted_files += 1;
        let limit = remaining.min(self.limits.max_file_bytes);
        self.reserved_bytes += limit;
        Some(limit)
    }

    pub(super) fn omit(&mut self, relative: &str, reason: &str) {
        self.partial = true;
        self.exclude(relative, reason);
    }

    pub(super) fn exclude(&mut self, relative: &str, reason: &str) {
        self.omitted_count += 1;
        if self.omissions.len() < MAX_DISCLOSED_PATHS {
            self.omissions
                .push(json!({"path":relative,"reason":reason}));
        }
    }

    pub(super) fn record_bytes(
        &mut self,
        relative: &str,
        bytes: usize,
        truncated: bool,
        reserved: usize,
    ) {
        self.inspected_bytes += bytes;
        self.reserved_bytes = self
            .reserved_bytes
            .saturating_sub(reserved.saturating_sub(bytes));
        if !truncated {
            return;
        }
        self.partial = true;
        self.truncated_count += 1;
        if self.truncated_paths.len() < MAX_DISCLOSED_PATHS {
            self.truncated_paths.push(relative.into());
        }
    }

    pub(super) fn record_text(&mut self, included: usize, incomplete: usize) {
        self.included_text_bytes += included;
        self.incomplete_utf8_prefix_bytes += incomplete;
    }

    pub(super) fn receipt(self, inventory: &RepositoryInventory) -> Value {
        json!({
            "schemaVersion":1,"status":if self.partial {"partial"} else {"bounded"},
            "completeRepositoryCoverage":false,"indexedFiles":self.indexed_files,
            "attemptedFiles":self.attempted_files,"inspectedSourceBytes":self.inspected_bytes,
            "includedSourceTextBytes":self.included_text_bytes,
            "incompleteUtf8PrefixBytes":self.incomplete_utf8_prefix_bytes,
            "reservedSourceBytes":self.reserved_bytes,
            "maxSourceFiles":self.limits.max_files,"maxSourceBytes":self.max_bytes,"maxFileBytes":self.limits.max_file_bytes,
            "omittedSourceFiles":self.omitted_count,"omissions":self.omissions,
            "additionalOmissions":self.omitted_count.saturating_sub(MAX_DISCLOSED_PATHS),
            "truncatedSourceFiles":self.truncated_count,"truncatedPaths":self.truncated_paths,
            "additionalTruncatedPaths":self.truncated_count.saturating_sub(MAX_DISCLOSED_PATHS),
            "maxCombinedInspectedBytes":crate::workspace::inventory::MAX_REPOSITORY_INSPECTED_BYTES,
            "inventory":inventory_receipt(inventory)
        })
    }
}

fn inventory_receipt(inventory: &RepositoryInventory) -> Value {
    let inspection = inventory.inspection.as_ref();
    json!({
        "entries":inspection.map(|row|row.entries),"maxEntries":inspection.map(|row|row.max_entries),
        "inspectedBytes":inspection.map(|row|row.inspected_bytes),
        "enumeration":inspection.map(|row|&row.enumeration),
        "truncation":inventory.truncation.as_ref().map(|row|&row.reason),
        "omittedPaths":inspection.map(|row|row.omitted_paths.len()),
        "omissions":inspection.map(|row|row.omitted_paths.iter().take(MAX_DISCLOSED_PATHS).collect::<Vec<_>>()),
        "truncatedFiles":inspection.map(|row|row.truncated_files.len()),
        "truncatedPaths":inspection.map(|row|row.truncated_files.iter().take(MAX_DISCLOSED_PATHS).collect::<Vec<_>>()),
    })
}
