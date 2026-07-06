//! Small value types for the depth-stack navigation: the depth level, the
//! focused Depth-1 pane, the drawer tab, and the reducer's clamp bounds / effects.

/// Which of the three zoom levels the review surface is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkbenchDepth {
    List,
    Finding,
    Record,
}

/// Focused pane at [`WorkbenchDepth::Finding`]. `Tab` cycles
/// `Spine → Ladder → Drawer → Spine`; the ladder is the focal default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingPane {
    Spine,
    Ladder,
    Drawer,
}

impl FindingPane {
    pub fn next(self) -> Self {
        match self {
            Self::Spine => Self::Ladder,
            Self::Ladder => Self::Drawer,
            Self::Drawer => Self::Spine,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Spine => Self::Drawer,
            Self::Ladder => Self::Spine,
            Self::Drawer => Self::Ladder,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Spine => "SPINE",
            Self::Ladder => "LADDER",
            Self::Drawer => "DRAWER",
        }
    }
}

/// The four Depth-1 drawer tabs. `Triage`/`Proof` hold sub-agent triage-log and
/// proof-level promotion records; `Log`/`Code` hold raw scanner output and the
/// finding's source snippet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawerTab {
    Triage,
    Proof,
    Log,
    Code,
}

impl DrawerTab {
    pub const ALL: [Self; 4] = [Self::Triage, Self::Proof, Self::Log, Self::Code];

    pub fn label(self) -> &'static str {
        match self {
            Self::Triage => "triage",
            Self::Proof => "proof",
            Self::Log => "log",
            Self::Code => "code",
        }
    }

    pub fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Self {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|tab| *tab == self).unwrap_or(0)
    }
}

/// Item counts for the current model so the reducer can clamp its own cursors
/// without reaching into view data. Finding *selection* is clamped app-side.
#[derive(Debug, Clone, Copy)]
pub struct NavBounds {
    pub legs: usize,
    pub drawer_rows: usize,
}

/// What a key asks the host to do beyond in-view navigation. Everything the
/// reducer can do itself resolves to `Handled`; anything touching finding
/// selection or leaving the view is handed back to `ShellApp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavEffect {
    Handled,
    Ignored,
    /// Move the finding selection by the sign of the delta (List/Spine `j/k`,
    /// lateral `J/K`). The reducer has already reset per-finding nav state.
    SelectStep(isize),
    /// Jump the finding selection to the first (`true`) or last row.
    SelectJump(bool),
    /// `Esc` at the list root with the peek closed — let the app leave the view.
    Leave,
    /// `y` in record zoom — the app decides how to surface the full text.
    Yank,
}
