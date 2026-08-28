use crate::scene3d::VizPage;
use crate::ui_view_models::{DfdKind, DfdSecurityKind};

pub(super) const SCENE_TEXT_LIMIT: usize = 4_000;

pub(super) fn page_slug(page: VizPage) -> &'static str {
    match page {
        VizPage::AttackSurface => "attack-surface",
        VizPage::AttackPath => "attack-path",
        VizPage::Summary => "summary",
        VizPage::Dfd => "dfd",
        VizPage::EntryPoints => "entry-points",
        VizPage::Components => "components",
        VizPage::Heatmap => "heatmap",
        VizPage::ExploitChain => "exploit-chain",
        VizPage::Worklist => "worklist",
    }
}

pub(super) fn dfd_kind_label(kind: DfdKind) -> &'static str {
    match kind {
        DfdKind::Entity => "entity",
        DfdKind::Process => "process",
        DfdKind::Store => "store",
    }
}

pub(super) fn security_kind_label(kind: DfdSecurityKind) -> &'static str {
    match kind {
        DfdSecurityKind::EntryPoint => "entry-point",
        DfdSecurityKind::RoleGate => "role-gate",
        DfdSecurityKind::ExternalSink => "external-sink",
        DfdSecurityKind::TrustedCaller => "trusted-caller",
        DfdSecurityKind::Asset => "asset",
        DfdSecurityKind::Threat => "threat",
    }
}

pub(super) fn bounded_text(text: &str) -> String {
    let mut chars = text.chars();
    let bounded = chars.by_ref().take(SCENE_TEXT_LIMIT).collect::<String>();
    if chars.next().is_some() {
        format!("{bounded}...")
    } else {
        bounded
    }
}
