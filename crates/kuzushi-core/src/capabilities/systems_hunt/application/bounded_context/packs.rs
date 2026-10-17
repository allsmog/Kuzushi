use super::*;

pub(super) fn from_prefixes(
    surfaces: &[RankedSystemsSurface],
    files: &[SourcePrefix],
    canceled: &dyn Fn() -> bool,
) -> Result<(Vec<SystemsSurfacePack>, usize)> {
    let files: BTreeMap<_, _> = files
        .iter()
        .map(|file| (file.relative.as_str(), file.text.as_str()))
        .collect();
    let mut packs = Vec::new();
    let mut limited = 0;
    for surface in surfaces {
        anyhow::ensure!(!canceled(), "systems context packs canceled");
        let body = files
            .get(surface.file_path.as_str())
            .context("ranked source prefix missing")?;
        let (pack, clipped) = build_pack(surface, body);
        limited += usize::from(clipped);
        packs.push(pack);
    }
    Ok((packs, limited))
}

fn build_pack(surface: &RankedSystemsSurface, body: &str) -> (SystemsSurfacePack, bool) {
    let mut pack = SystemsSurfacePack {
        surface_id: surface.id.clone(),
        anchor_file_path: surface.file_path.clone(),
        anchor_start_line: surface.start_line,
        related_files: vec![surface.file_path.clone()],
        unsafe_sites: Vec::new(),
        resource_provenance_sites: Vec::new(),
        hardening_sites: Vec::new(),
        input_sites: Vec::new(),
        helper_templates: helper_templates_for(surface),
    };
    let mut clipped = false;
    for (index, line) in body.lines().enumerate() {
        clipped |= record_sites(&mut pack, line, (index + 1) as u32);
    }
    (pack, clipped)
}

fn record_sites(pack: &mut SystemsSurfacePack, line: &str, number: u32) -> bool {
    let lower = line.to_ascii_lowercase();
    let path = pack.anchor_file_path.clone();
    let categories: [(&[&str], &str, &mut Vec<SystemsCodeLocation>); 4] = [
        (
            &["unsafe", "memcpy", "copy_from", "*mut", "*const"],
            "unsafe memory operation",
            &mut pack.unsafe_sites,
        ),
        (
            &["shared", "splice", "pipe", "iov", "scatter"],
            "resource provenance or aliasing signal",
            &mut pack.resource_provenance_sites,
        ),
        (
            &["check", "validate", "guard", "assert"],
            "hardening or guard signal",
            &mut pack.hardening_sites,
        ),
        (
            &["recv", "read", "packet", "request"],
            "input boundary signal",
            &mut pack.input_sites,
        ),
    ];
    let mut clipped = false;
    for (needles, reason, sites) in categories {
        if contains_any(&lower, needles) {
            clipped |= push_site(sites, &path, line, number, reason);
        }
    }
    clipped
}

fn push_site(
    sites: &mut Vec<SystemsCodeLocation>,
    path: &str,
    line: &str,
    number: u32,
    reason: &str,
) -> bool {
    if sites.len() >= 12 {
        return true;
    }
    sites.push(SystemsCodeLocation {
        file_path: path.into(),
        line: number,
        snippet: ranking::clip_line(line),
        reason: Some(reason.into()),
    });
    false
}
