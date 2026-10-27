use super::{SbomComponent, SbomDependencyEdge, SbomScanReport};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const ROOT_RECORD: &str = "root";
type Packages<'a> = BTreeMap<String, &'a SbomComponent>;
type SourceNames<'a> = BTreeMap<(&'a str, &'a str), BTreeSet<String>>;

pub(super) struct ExportGraph<'a> {
    pub(super) packages: Packages<'a>,
    pub(super) resolved: Vec<ResolvedDependency>,
    omitted: Vec<OmittedDependency>,
    component_records: usize,
}

pub(super) struct ResolvedDependency {
    pub(super) from: String,
    pub(super) to: String,
    pub(super) source: String,
}

struct OmittedDependency {
    edge: SbomDependencyEdge,
    from_candidates: Vec<String>,
    to_candidates: Vec<String>,
}

impl<'a> ExportGraph<'a> {
    pub(super) fn new(report: &'a SbomScanReport) -> Self {
        let (packages, names) = package_catalog(&report.components);
        let mut graph = Self {
            packages,
            resolved: vec![],
            omitted: vec![],
            component_records: report.components.len(),
        };
        for edge in &report.dependencies {
            match resolve_edge(edge, &names) {
                Ok(link) => graph.resolved.push(link),
                Err(omission) => graph.omitted.push(omission),
            }
        }
        graph
    }

    pub(super) fn omitted_count(&self) -> usize {
        self.omitted.len()
    }

    pub(super) fn omitted_json(&self, render_ref: fn(&str) -> String) -> Vec<Value> {
        self.omitted
            .iter()
            .map(|item| item.to_json(render_ref))
            .collect()
    }

    pub(super) fn diagnostics(&self, render_ref: fn(&str) -> String) -> Value {
        json!({
            "componentRecordCount": self.component_records,
            "uniqueComponentCount": self.packages.len(),
            "dependencyRelationshipCount": self.resolved.len(),
            "omittedRelationshipCount": self.omitted.len(),
            "omittedRelationships": self.omitted_json(render_ref),
        })
    }
}

impl OmittedDependency {
    fn to_json(&self, render_ref: fn(&str) -> String) -> Value {
        json!({
            "from": self.edge.from, "to": self.edge.to, "source": self.edge.source,
            "fromCandidates": self.from_candidates.iter().map(|id| render_ref(id)).collect::<Vec<_>>(),
            "toCandidates": self.to_candidates.iter().map(|id| render_ref(id)).collect::<Vec<_>>(),
        })
    }
}

fn package_catalog(components: &[SbomComponent]) -> (Packages<'_>, SourceNames<'_>) {
    let mut packages = BTreeMap::new();
    let mut names = SourceNames::new();
    for component in components {
        let id = component_record_digest(component);
        packages.insert(id.clone(), component);
        names
            .entry((component.manifest_path.as_str(), component.name.as_str()))
            .or_default()
            .insert(id);
    }
    (packages, names)
}

fn component_record_digest(component: &SbomComponent) -> String {
    let identity = json!([
        component.ecosystem,
        component.name,
        component.version,
        component.manifest_path,
        component.scope,
        component.package_url,
    ]);
    kuzushi_mcp_common::cache::sha256_hex_bytes(identity.to_string().as_bytes())
}

fn candidates(names: &SourceNames<'_>, source: &str, name: &str) -> Vec<String> {
    names
        .get(&(source, name))
        .into_iter()
        .flatten()
        .cloned()
        .collect()
}

fn resolve_edge(
    edge: &SbomDependencyEdge,
    names: &SourceNames<'_>,
) -> Result<ResolvedDependency, OmittedDependency> {
    let mut from = candidates(names, &edge.source, &edge.from);
    if edge.from == ROOT_RECORD {
        from.push(ROOT_RECORD.into());
    }
    let to = candidates(names, &edge.source, &edge.to);
    let ([from_id], [to_id]) = (from.as_slice(), to.as_slice()) else {
        return Err(OmittedDependency {
            edge: edge.clone(),
            from_candidates: from,
            to_candidates: to,
        });
    };
    Ok(ResolvedDependency {
        from: from_id.clone(),
        to: to_id.clone(),
        source: edge.source.clone(),
    })
}
