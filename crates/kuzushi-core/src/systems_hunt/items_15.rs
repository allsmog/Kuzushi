use super::prelude::*;
use super::*;

pub(crate) fn build_surface_pack(
    target: &Path,
    surface: &RankedSystemsSurface,
) -> Result<SystemsSurfacePack> {
    let body = fs::read_to_string(target.join(&surface.file_path)).unwrap_or_default();
    let mut unsafe_sites = Vec::new();
    let mut resource_provenance_sites = Vec::new();
    let mut hardening_sites = Vec::new();
    let mut input_sites = Vec::new();

    for (idx, line) in body.lines().enumerate() {
        let line_number = (idx + 1) as u32;
        let location = SystemsCodeLocation {
            file_path: surface.file_path.clone(),
            line: line_number,
            snippet: trim_line(line),
            reason: None,
        };
        let lower = line.to_ascii_lowercase();
        if lower.contains("unsafe")
            || lower.contains("memcpy")
            || lower.contains("copy_from")
            || lower.contains("*mut")
            || lower.contains("*const")
        {
            unsafe_sites.push(SystemsCodeLocation {
                reason: Some("unsafe memory operation".to_string()),
                ..location.clone()
            });
        }
        if lower.contains("shared")
            || lower.contains("splice")
            || lower.contains("pipe")
            || lower.contains("iov")
            || lower.contains("scatter")
        {
            resource_provenance_sites.push(SystemsCodeLocation {
                reason: Some("resource provenance or aliasing signal".to_string()),
                ..location.clone()
            });
        }
        if lower.contains("check")
            || lower.contains("validate")
            || lower.contains("guard")
            || lower.contains("assert")
        {
            hardening_sites.push(SystemsCodeLocation {
                reason: Some("hardening or guard signal".to_string()),
                ..location.clone()
            });
        }
        if lower.contains("recv")
            || lower.contains("read")
            || lower.contains("packet")
            || lower.contains("request")
        {
            input_sites.push(SystemsCodeLocation {
                reason: Some("attacker input boundary signal".to_string()),
                ..location
            });
        }
    }

    Ok(SystemsSurfacePack {
        surface_id: surface.id.clone(),
        anchor_file_path: surface.file_path.clone(),
        anchor_start_line: surface.start_line,
        related_files: vec![surface.file_path.clone()],
        unsafe_sites: unsafe_sites.into_iter().take(12).collect(),
        resource_provenance_sites: resource_provenance_sites.into_iter().take(12).collect(),
        hardening_sites: hardening_sites.into_iter().take(12).collect(),
        input_sites: input_sites.into_iter().take(12).collect(),
        helper_templates: helper_templates_for(surface),
    })
}

pub(crate) fn helper_templates_for(surface: &RankedSystemsSurface) -> Vec<SystemsHelperTemplate> {
    let mut templates = Vec::new();
    if surface
        .domains
        .iter()
        .any(|domain| domain == "integer-boundary")
    {
        templates.push(SystemsHelperTemplate {
            id: "signed-wraparound".to_string(),
            title: "Signed or narrow counter wraparound".to_string(),
            rationale: "Check whether arithmetic reaches allocation, copy, or sentinel decisions."
                .to_string(),
        });
    }
    if surface
        .domains
        .iter()
        .any(|domain| domain == "resource-provenance")
    {
        templates.push(SystemsHelperTemplate {
            id: "shared-backing-resource".to_string(),
            title: "Shared backing resource provenance".to_string(),
            rationale: "Track whether shared backing storage crosses a writable alias boundary."
                .to_string(),
        });
    }
    if surface
        .domains
        .iter()
        .any(|domain| domain == "unsafe-memory")
    {
        templates.push(SystemsHelperTemplate {
            id: "stack-length-copy".to_string(),
            title: "Length-controlled memory copy".to_string(),
            rationale: "Check whether attacker-controlled length dominates destination capacity."
                .to_string(),
        });
    }
    templates
}
