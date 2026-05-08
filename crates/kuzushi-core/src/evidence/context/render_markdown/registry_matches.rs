use super::*;

pub(super) fn push_registry_matches(out: &mut String, registry: &[StaticRegistryMatch]) {
    let by_kind = group_registry_by_kind(registry);
    for (kind, label) in registry_section_labels() {
        let Some(matches) = by_kind.get(&kind) else {
            continue;
        };
        if matches.is_empty() {
            continue;
        }
        out.push_str(label);
        out.push_str(" (registry):\n");
        for registry_match in matches.iter().take(8) {
            push_registry_match(out, registry_match);
        }
        out.push_str("\n");
    }
}

fn registry_section_labels() -> [(StaticRegistryKind, &'static str); 4] {
    [
        (StaticRegistryKind::Source, "**Known sources**"),
        (StaticRegistryKind::Sink, "**Known sinks**"),
        (StaticRegistryKind::Sanitizer, "**Known sanitizers**"),
        (StaticRegistryKind::Guard, "**Known guards**"),
    ]
}

fn push_registry_match(out: &mut String, registry_match: &StaticRegistryMatch) {
    out.push_str("- `");
    out.push_str(&registry_match.entry.pattern);
    out.push_str("`");
    if !registry_match.entry.cwe.is_empty() {
        out.push_str(" (");
        out.push_str(&registry_match.entry.cwe.join(", "));
        out.push_str(")");
    }
    if !registry_match.entry.rationale.is_empty() {
        out.push_str(" - ");
        out.push_str(&registry_match.entry.rationale);
    }
    out.push_str("\n");
}
