use super::*;

impl WhiteboxArtifacts {
    pub(in crate::modules) fn append_output_lines(&self, lines: &mut Vec<String>) {
        lines.push(
            "  Mode: whitebox-static (static-only; verify, dynamic analysis, PoC, and patch disabled)"
                .to_string(),
        );
        self.append_static_ranking_line(lines);
        self.append_static_narrative_line(lines);
        self.append_static_variants_line(lines);
        self.append_candidate_rule_line(lines);
        self.append_suppression_line(lines);
        self.append_diff_line(lines);
    }

    pub(in crate::modules) fn append_static_ranking_line(&self, lines: &mut Vec<String>) {
        let Some(top) = self
            .static_ranking
            .as_ref()
            .and_then(|ranking| ranking.pointer("/ranked/0"))
        else {
            return;
        };
        let score = top
            .pointer("/impact/total")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        let title = top
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("top static-impact finding");
        lines.push(format!("  Static ranking: top score {score} · {title}"));
    }

    pub(in crate::modules) fn append_static_narrative_line(&self, lines: &mut Vec<String>) {
        let Some(top) = self
            .static_narratives
            .as_ref()
            .and_then(|narratives| narratives.pointer("/narratives/0"))
        else {
            return;
        };
        let location = top
            .get("location")
            .and_then(Value::as_str)
            .unwrap_or("top static finding");
        lines.push(format!(
            "  Static narrative: trigger path summarized for {location}"
        ));
    }

    pub(in crate::modules) fn append_static_variants_line(&self, lines: &mut Vec<String>) {
        let Some(count) = optional_positive_count(&self.static_variants, "count") else {
            return;
        };
        lines.push(format!(
            "  Static variants: {count} code-cited candidate(s), none confirmed by inheritance"
        ));
    }

    pub(in crate::modules) fn append_candidate_rule_line(&self, lines: &mut Vec<String>) {
        let Some(count) = optional_positive_count(&self.candidate_semgrep_rules, "count") else {
            return;
        };
        let fixture_checked = self
            .candidate_semgrep_rules
            .as_ref()
            .and_then(|rules| rules.get("validationPassed"))
            .and_then(Value::as_u64)
            .unwrap_or_default();
        lines.push(format!(
            "  Candidate Semgrep rules: {count} disabled candidate(s), {fixture_checked} fixture-checked"
        ));
    }

    pub(in crate::modules) fn append_suppression_line(&self, lines: &mut Vec<String>) {
        let Some(suppression_report) = self.whitebox_suppressions.as_ref() else {
            return;
        };
        let suppressed = json_u64(suppression_report, "suppressedCount");
        let stale = json_u64(suppression_report, "staleCount");
        if suppressed > 0 || stale > 0 {
            lines.push(format!(
                "  False-positive memory: {suppressed} active suppression match(es), {stale} stale; findings remain visible in audit/report output"
            ));
        }
    }

    pub(in crate::modules) fn append_diff_line(&self, lines: &mut Vec<String>) {
        let Some(diff_report) = self.whitebox_diff.as_ref() else {
            return;
        };
        let changed_files = json_pointer_u64(diff_report, "/summary/changedFiles");
        let new_findings = json_pointer_u64(diff_report, "/summary/newFindings");
        let changed_context = json_pointer_u64(diff_report, "/summary/changedContextFindings");
        let fixed = json_pointer_u64(diff_report, "/summary/fixedFindings");
        lines.push(format!(
            "  Diff scope: {changed_files} changed file(s), {new_findings} new, {changed_context} changed-context, {fixed} fixed"
        ));
    }
}
