pub(crate) use super::prelude::*;
pub(crate) use super::*;
use std::collections::BTreeMap;

use kuzushi_core::modules::ModuleKind;

pub(super) const CATALOG_ORDER: &[&str] = &["OFFENSE", "INTEL", "GOVERNANCE", "DEFENSE"];

impl ShellApp {
    pub fn catalog_module_count(&self) -> usize {
        self.registry.modules().count()
    }

    pub fn catalog_cursor_module_id(&self) -> Option<String> {
        let modules = self.catalog_module_ids();
        modules
            .get(self.catalog_cursor.min(modules.len().saturating_sub(1)))
            .cloned()
    }

    pub fn move_catalog_cursor(&mut self, delta: i32) {
        let total = self.catalog_module_count();
        if total == 0 {
            self.catalog_cursor = 0;
            return;
        }
        let total = total as i32;
        let mut next = self.catalog_cursor as i32 + delta;
        while next < 0 {
            next += total;
        }
        self.catalog_cursor = (next % total) as usize;
    }

    fn catalog_module_ids(&self) -> Vec<String> {
        let mut grouped: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        for module in self.registry.modules() {
            let id = module.metadata().id.clone();
            grouped
                .entry(catalog_category(&id, module.metadata().kind))
                .or_default()
                .push(id);
        }

        let mut ordered = Vec::new();
        for category in CATALOG_ORDER {
            if let Some(rows) = grouped.get(category) {
                ordered.extend(rows.iter().cloned());
            }
        }
        ordered
    }
}

pub(super) fn catalog_category(id: &str, kind: ModuleKind) -> &'static str {
    match id {
        "semgrep"
        | "sast"
        | "codeql"
        | "agentic-sast"
        | "carlini-threat-hunt"
        | "secret-scan"
        | "iac-scan"
        | "dep-hygiene"
        | "taint-iris"
        | "taint-iris-next"
        | "variant"
        | "ndiff"
        | "x-ray"
        | "chrome-rce"
        | "prompt-armor"
        | "vuln-scout"
        | "vendor-assessment" => "OFFENSE",
        "context" | "recon" | "threat-model" | "randori" => "INTEL",
        "config" | "shinsa" | "tob" => "GOVERNANCE",
        "triage" | "verify" | "patch" | "findings" => "DEFENSE",
        _ => match kind {
            ModuleKind::Offense => "OFFENSE",
            ModuleKind::Intel => "INTEL",
            ModuleKind::Governance => "GOVERNANCE",
            ModuleKind::Defense => "DEFENSE",
            _ => "OFFENSE",
        },
    }
}
