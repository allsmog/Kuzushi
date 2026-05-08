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
        classify_surface_line(
            surface,
            line_number,
            line,
            &mut unsafe_sites,
            &mut resource_provenance_sites,
            &mut hardening_sites,
            &mut input_sites,
        );
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

fn classify_surface_line(
    surface: &RankedSystemsSurface,
    line_number: u32,
    line: &str,
    unsafe_sites: &mut Vec<SystemsCodeLocation>,
    resource_provenance_sites: &mut Vec<SystemsCodeLocation>,
    hardening_sites: &mut Vec<SystemsCodeLocation>,
    input_sites: &mut Vec<SystemsCodeLocation>,
) {
    let location = SystemsCodeLocation {
        file_path: surface.file_path.clone(),
        line: line_number,
        snippet: trim_line(line),
        reason: None,
    };
    let lower = line.to_ascii_lowercase();
    push_surface_signal(
        &lower,
        &["unsafe", "memcpy", "copy_from", "*mut", "*const"],
        "unsafe memory operation",
        &location,
        unsafe_sites,
    );
    push_surface_signal(
        &lower,
        &["shared", "splice", "pipe", "iov", "scatter"],
        "resource provenance or aliasing signal",
        &location,
        resource_provenance_sites,
    );
    push_surface_signal(
        &lower,
        &["check", "validate", "guard", "assert"],
        "hardening or guard signal",
        &location,
        hardening_sites,
    );
    push_surface_signal(
        &lower,
        &["recv", "read", "packet", "request"],
        "attacker input boundary signal",
        &location,
        input_sites,
    );
}

fn push_surface_signal(
    lower: &str,
    needles: &[&str],
    reason: &str,
    location: &SystemsCodeLocation,
    sites: &mut Vec<SystemsCodeLocation>,
) {
    if needles.iter().any(|needle| lower.contains(needle)) {
        sites.push(SystemsCodeLocation {
            reason: Some(reason.to_string()),
            ..location.clone()
        });
    }
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
