use super::*;
use crate::theme::{ColorDepth, ThemeConfig};

pub(super) const COCKPIT_SPINE_CONTRACT: &str = "cockpit-spine-v1";
pub(super) const SIZES: [(u16, u16); 6] =
    [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)];

#[derive(Debug, Clone, Copy)]
pub(super) struct PhaseCompositionContract {
    pub(super) page: WorkbenchPage,
    pub(super) phase: kuzushi_core::WorkflowPhase,
    pub(super) slug: &'static str,
    pub(super) complete_command: &'static str,
    pub(super) compact_command: &'static str,
}

pub(super) const CONTRACTS: [PhaseCompositionContract; 5] = [
    PhaseCompositionContract {
        page: WorkbenchPage::Map,
        phase: kuzushi_core::WorkflowPhase::Map,
        slug: "map",
        complete_command: "z open terrain",
        compact_command: "z open terrain",
    },
    PhaseCompositionContract {
        page: WorkbenchPage::Scan,
        phase: kuzushi_core::WorkflowPhase::Scan,
        slug: "scan",
        complete_command: "run sast:scan {}",
        compact_command: "run sast:scan {}",
    },
    PhaseCompositionContract {
        page: WorkbenchPage::Review,
        phase: kuzushi_core::WorkflowPhase::Review,
        slug: "review",
        complete_command: "patch F-0001",
        compact_command: "patch F-0001",
    },
    PhaseCompositionContract {
        page: WorkbenchPage::Prove,
        phase: kuzushi_core::WorkflowPhase::Prove,
        slug: "prove",
        complete_command: "verify F-0001",
        compact_command: "verify F-0001",
    },
    PhaseCompositionContract {
        page: WorkbenchPage::Fix,
        phase: kuzushi_core::WorkflowPhase::Fix,
        slug: "fix",
        complete_command: "report",
        compact_command: "report",
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
            kuzushi_core::WorkflowPhase::Map => "context:present",
            kuzushi_core::WorkflowPhase::Scan => "scan-phase-run",
            kuzushi_core::WorkflowPhase::Review => "s1",
            kuzushi_core::WorkflowPhase::Prove => "replay verify-phase-run",
            kuzushi_core::WorkflowPhase::Fix => "Staged for approval",
        }
    }

    pub(super) const fn plain_command_for_width(self, width: u16) -> &'static str {
        self.command_for_width(width)
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
