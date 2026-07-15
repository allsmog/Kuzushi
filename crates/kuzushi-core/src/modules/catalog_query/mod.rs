//! Typed `key:value` search grammar over the tool catalog, mirroring the
//! findings filter grammar. Shared across CLI, shell, and scan so the three
//! modes can never diverge on how `find phase:scan runtime:agentic taint`
//! resolves.

use crate::modules::{ModuleKind, ModuleMetadata, RuntimeRequirement, ToolDescriptor, ToolPhase};
use crate::query::{tokenize_filter_expression, FilterToken};
use crate::text::fuzzy::subsequence_score;
use crate::workspace::ToolShelf;
use anyhow::Result;

/// Runtime bucket a tool falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFilter {
    /// Uses an agent runtime (`Always` or `InputAware`).
    Agentic,
    /// Never uses an agent runtime.
    Static,
}

impl RuntimeFilter {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "agentic" | "agent" | "llm" | "ai" => Ok(Self::Agentic),
            "static" | "native" | "deterministic" => Ok(Self::Static),
            other => {
                anyhow::bail!("unknown runtime filter {other:?}; expected one of: agentic, static")
            }
        }
    }

    fn matches(self, requirement: RuntimeRequirement) -> bool {
        match self {
            Self::Agentic => matches!(
                requirement,
                RuntimeRequirement::Always | RuntimeRequirement::InputAware
            ),
            Self::Static => matches!(requirement, RuntimeRequirement::Never),
        }
    }
}

fn parse_module_kind(value: &str) -> Result<ModuleKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "offense" => Ok(ModuleKind::Offense),
        "intel" => Ok(ModuleKind::Intel),
        "governance" => Ok(ModuleKind::Governance),
        "defense" => Ok(ModuleKind::Defense),
        "internal" => Ok(ModuleKind::Internal),
        "catalog" => Ok(ModuleKind::Catalog),
        "config" => Ok(ModuleKind::Config),
        "context" => Ok(ModuleKind::Context),
        "scan" => Ok(ModuleKind::Scan),
        "findings" => Ok(ModuleKind::Findings),
        "triage" => Ok(ModuleKind::Triage),
        "workspace" => Ok(ModuleKind::Workspace),
        other => anyhow::bail!(
            "unknown kind {other:?}; kind: accepts a module category \
             (offense, intel, governance, defense, internal, catalog, config, \
             context, scan, findings, triage, workspace). For a free-text search, \
             drop the `kind:` prefix."
        ),
    }
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "1" | "on" => Ok(true),
        "no" | "false" | "0" | "off" => Ok(false),
        other => anyhow::bail!("expected yes/no, got {other:?}"),
    }
}

/// A parsed tool catalog query. Empty fields impose no constraint; an empty
/// query matches every tool.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolQuery {
    phases: Vec<ToolPhase>,
    runtime: Vec<RuntimeFilter>,
    kinds: Vec<ModuleKind>,
    module_ids: Vec<String>,
    headless: Option<bool>,
    fav_only: bool,
    recent_only: bool,
    text_terms: Vec<String>,
}

impl ToolQuery {
    pub fn parse(expr: &str) -> Result<Self> {
        let mut query = Self::default();
        for token in tokenize_filter_expression(expr)? {
            query.apply_token(token)?;
        }
        Ok(query)
    }

    fn apply_token(&mut self, token: FilterToken) -> Result<()> {
        let Some(key) = token.key else {
            self.text_terms.push(token.raw.to_ascii_lowercase());
            return Ok(());
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "phase" => self.apply_phases(&token.values)?,
            "runtime" => self.apply_runtime(&token.values)?,
            "kind" => self.apply_kinds(&token.values)?,
            "module" | "mod" | "id" => self
                .module_ids
                .extend(token.values.iter().map(|value| value.to_ascii_lowercase())),
            "headless" => self.headless = Some(parse_single_bool(&token.values)?),
            "fav" | "favorite" | "favourite" => self.fav_only = parse_single_bool(&token.values)?,
            "recent" | "recents" => self.recent_only = parse_single_bool(&token.values)?,
            other => anyhow::bail!(
                "unknown tool query key {other:?}; valid keys: \
                 phase, runtime, kind, module, headless, fav, recent"
            ),
        }
        Ok(())
    }

    fn apply_phases(&mut self, values: &[String]) -> Result<()> {
        for value in values {
            let phase = ToolPhase::parse(value).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown phase {value:?}; expected one of map, scan, review, prove, fix, operate (hunt and confirm are deprecated aliases)"
                )
            })?;
            self.phases.push(phase);
        }
        Ok(())
    }

    fn apply_runtime(&mut self, values: &[String]) -> Result<()> {
        for value in values {
            self.runtime.push(RuntimeFilter::parse(value)?);
        }
        Ok(())
    }

    fn apply_kinds(&mut self, values: &[String]) -> Result<()> {
        for value in values {
            self.kinds.push(parse_module_kind(value)?);
        }
        Ok(())
    }

    /// True when `tool` (belonging to `module`) satisfies every constraint.
    pub fn matches(
        &self,
        module: &ModuleMetadata,
        tool: &ToolDescriptor,
        shelf: &ToolShelf,
    ) -> bool {
        self.phase_matches(tool)
            && self.runtime_matches(tool)
            && self.kind_matches(module)
            && self.module_matches(module)
            && self.headless_matches(tool)
            && self.shelf_matches(tool, shelf)
            && self.text_matches(module, tool)
    }

    /// Fuzzy score for intra-group ordering; `None` when a free-text term fails
    /// to match. Constraint-only queries score 0.
    pub fn score(&self, module: &ModuleMetadata, tool: &ToolDescriptor) -> Option<i32> {
        let haystack = haystack(module, tool);
        let mut total = 0;
        for term in &self.text_terms {
            total += subsequence_score(&haystack, term)?;
        }
        Some(total)
    }

    fn phase_matches(&self, tool: &ToolDescriptor) -> bool {
        self.phases.is_empty() || self.phases.contains(&tool.phase)
    }

    fn runtime_matches(&self, tool: &ToolDescriptor) -> bool {
        self.runtime.is_empty()
            || self
                .runtime
                .iter()
                .any(|filter| filter.matches(tool.runtime_requirement))
    }

    fn kind_matches(&self, module: &ModuleMetadata) -> bool {
        self.kinds.is_empty() || self.kinds.contains(&module.kind)
    }

    fn module_matches(&self, module: &ModuleMetadata) -> bool {
        let id = module.id.to_ascii_lowercase();
        self.module_ids.is_empty() || self.module_ids.iter().any(|needle| id.contains(needle))
    }

    fn headless_matches(&self, tool: &ToolDescriptor) -> bool {
        self.headless
            .is_none_or(|expected| tool.headless == expected)
    }

    fn shelf_matches(&self, tool: &ToolDescriptor, shelf: &ToolShelf) -> bool {
        (!self.fav_only || shelf.is_favorite(&tool.name))
            && (!self.recent_only || shelf.last_used(&tool.name).is_some())
    }

    fn text_matches(&self, module: &ModuleMetadata, tool: &ToolDescriptor) -> bool {
        if self.text_terms.is_empty() {
            return true;
        }
        let haystack = haystack(module, tool);
        self.text_terms
            .iter()
            .all(|term| subsequence_score(&haystack, term).is_some())
    }
}

fn parse_single_bool(values: &[String]) -> Result<bool> {
    match values {
        [value] => parse_bool(value),
        _ => anyhow::bail!("expected a single yes/no value"),
    }
}

fn haystack(module: &ModuleMetadata, tool: &ToolDescriptor) -> String {
    format!("{} {} {}", tool.name, tool.description, module.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::ModuleKind;

    fn module() -> ModuleMetadata {
        ModuleMetadata {
            id: "taint-iris-next".to_string(),
            name: "Taint Iris Next".to_string(),
            kind: ModuleKind::Offense,
            description: "taint tracking".to_string(),
        }
    }

    fn tool() -> ToolDescriptor {
        let mut descriptor = crate::modules::tool_with_options(
            "taint-iris-next:hunt",
            "hunt taint flows with an agent",
            Vec::new(),
        );
        descriptor.phase = ToolPhase::Scan;
        descriptor.runtime_requirement = RuntimeRequirement::Always;
        descriptor
    }

    #[test]
    fn empty_query_matches_all() {
        let query = ToolQuery::parse("").unwrap();
        assert!(query.matches(&module(), &tool(), &ToolShelf::default()));
    }

    #[test]
    fn phase_filter_matches_and_rejects() {
        let scan = ToolQuery::parse("phase:scan").unwrap();
        assert!(scan.matches(&module(), &tool(), &ToolShelf::default()));
        let legacy_hunt = ToolQuery::parse("phase:hunt").unwrap();
        assert!(legacy_hunt.matches(&module(), &tool(), &ToolShelf::default()));
        let map = ToolQuery::parse("phase:map").unwrap();
        assert!(!map.matches(&module(), &tool(), &ToolShelf::default()));
        assert!(ToolQuery::parse("phase:2").is_err());
    }

    #[test]
    fn runtime_agentic_covers_always_and_input_aware() {
        let query = ToolQuery::parse("runtime:agentic").unwrap();
        let mut always = tool();
        always.runtime_requirement = RuntimeRequirement::Always;
        let mut input_aware = tool();
        input_aware.runtime_requirement = RuntimeRequirement::InputAware;
        let mut never = tool();
        never.runtime_requirement = RuntimeRequirement::Never;
        let shelf = ToolShelf::default();
        assert!(query.matches(&module(), &always, &shelf));
        assert!(query.matches(&module(), &input_aware, &shelf));
        assert!(!query.matches(&module(), &never, &shelf));
    }

    #[test]
    fn unknown_key_lists_valid_keys() {
        let error = ToolQuery::parse("bogus:1").unwrap_err().to_string();
        assert!(error.contains("valid keys"), "{error}");
    }

    #[test]
    fn kind_taint_is_a_helpful_error() {
        let error = ToolQuery::parse("kind:taint").unwrap_err().to_string();
        assert!(error.contains("free-text"), "{error}");
    }

    #[test]
    fn free_text_uses_fuzzy_and_scores() {
        let query = ToolQuery::parse("hunt").unwrap();
        assert!(query.matches(&module(), &tool(), &ToolShelf::default()));
        assert!(query.score(&module(), &tool()).is_some());
        let miss = ToolQuery::parse("zzzz").unwrap();
        assert!(!miss.matches(&module(), &tool(), &ToolShelf::default()));
        assert!(miss.score(&module(), &tool()).is_none());
    }

    #[test]
    fn fav_only_needs_shelf_membership() {
        let query = ToolQuery::parse("fav:yes").unwrap();
        let mut shelf = ToolShelf::default();
        assert!(!query.matches(&module(), &tool(), &shelf));
        shelf.toggle_favorite("taint-iris-next:hunt");
        assert!(query.matches(&module(), &tool(), &shelf));
    }
}
