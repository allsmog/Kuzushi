use super::*;
use crate::theme::{ColorDepth, ThemeConfig};

pub(super) const REFERENCE_SHA256: &str =
    "fad7e9bc324572ccf3e03b2e5c71878d1a6eba2795493f4a12005f0178a6f545";
pub(super) const SIZES: [(u16, u16); 4] = [(60, 20), (80, 24), (120, 36), (160, 40)];

#[derive(Debug, Clone, Copy)]
pub(super) struct PhaseCompositionContract {
    pub(super) page: WorkbenchPage,
    pub(super) phase: kuzushi_core::WorkflowPhase,
    pub(super) slug: &'static str,
    pub(super) sections: &'static [&'static str],
    pub(super) complete_command: &'static str,
    pub(super) compact_command: &'static str,
}

pub(super) const CONTRACTS: [PhaseCompositionContract; 4] = [
    PhaseCompositionContract {
        page: WorkbenchPage::Terrain,
        phase: kuzushi_core::WorkflowPhase::Map,
        slug: "map",
        sections: &["MAP · RECON", "RECON", "TELEMETRY"],
        complete_command: "context:build",
        compact_command: "context:build",
    },
    PhaseCompositionContract {
        page: WorkbenchPage::Coverage,
        phase: kuzushi_core::WorkflowPhase::Hunt,
        slug: "hunt",
        sections: &["SOURCE", "HUNT", "REVIEW QUEUE", "FINDINGS HEATMAP"],
        complete_command: "recommend",
        compact_command: "findings list",
    },
    PhaseCompositionContract {
        page: WorkbenchPage::Review,
        phase: kuzushi_core::WorkflowPhase::Confirm,
        slug: "confirm",
        sections: &[
            "FINDING",
            "ATTACK PATH",
            "DATA-FLOW LADDER",
            "PROOF · REPLAY",
        ],
        complete_command: "verify F-0001",
        compact_command: "verify F-0001",
    },
    PhaseCompositionContract {
        page: WorkbenchPage::Ship,
        phase: kuzushi_core::WorkflowPhase::Fix,
        slug: "fix",
        sections: &["BREAKDOWN REPORT", "ATTACK TREE", "DFD", "REMEDIATION"],
        complete_command: "findings export report.sarif sarif",
        compact_command: "findings export report.sarif sarif",
    },
];

impl PhaseCompositionContract {
    pub(super) const fn command_for_width(self, width: u16) -> &'static str {
        if width < 80 {
            self.compact_command
        } else {
            self.complete_command
        }
    }

    pub(super) const fn plain_truth_atom(self) -> &'static str {
        match self.phase {
            kuzushi_core::WorkflowPhase::Map => "indexing bounded source roots",
            kuzushi_core::WorkflowPhase::Hunt => "no hunt proposals",
            kuzushi_core::WorkflowPhase::Confirm => "replay verify-phase-run",
            kuzushi_core::WorkflowPhase::Fix => "patch staged for review",
        }
    }

    pub(super) const fn plain_command_for_width(self, width: u16) -> &'static str {
        match self.phase {
            kuzushi_core::WorkflowPhase::Hunt => "recommend",
            _ => self.command_for_width(width),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum TerminalProfile {
    TrueColor,
    Indexed,
    HighContrast,
    NoColor,
}

impl TerminalProfile {
    pub(super) const ALL: [Self; 4] = [
        Self::TrueColor,
        Self::Indexed,
        Self::HighContrast,
        Self::NoColor,
    ];

    pub(super) const fn config(self) -> ThemeConfig {
        match self {
            Self::TrueColor => profile(ColorDepth::TrueColor, false, false),
            Self::Indexed => profile(ColorDepth::Ansi256, false, false),
            Self::HighContrast => profile(ColorDepth::TrueColor, true, false),
            Self::NoColor => profile(ColorDepth::None, false, true),
        }
    }
}

const fn profile(color_depth: ColorDepth, high_contrast: bool, no_color: bool) -> ThemeConfig {
    ThemeConfig {
        high_contrast,
        no_color,
        reduced_motion: true,
        color_depth,
    }
}
