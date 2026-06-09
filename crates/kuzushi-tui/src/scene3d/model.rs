//! Scene primitives and the catalogue of demo scenes. Camera-agnostic: a
//! `Scene` is just a bag of points and edges plus header copy; the renderer
//! applies the camera and colours.

use crate::scene3d::Vec3;

/// Semantic colour for a scene primitive. Mapped to a concrete terminal RGB
/// (with depth dimming) by the renderer, so this 3D layer stays theme-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SceneColor {
    Wire,
    Accent,
    Critical,
    High,
    Medium,
    Low,
    Info,
    Success,
    Muted,
}

/// A shaded splat: a filled disc in screen space. With a `normal` it gets
/// Lambert lighting (so surfaces read as solid and lit); without one it's a
/// flat depth-faded dot (graph nodes, markers). `size` is a fraction of the
/// scene's half-extent, scaled to pixels at render time.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Splat {
    pub at: Vec3,
    pub normal: Option<Vec3>,
    pub color: SceneColor,
    pub size: f32,
}

/// How an edge is drawn. `Wire` is a thin depth-faded structural line;
/// `Thread` is a thick additive-glow line for the hero flow/breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    Wire,
    Thread,
}

/// A line segment between two scene points.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SceneEdge {
    pub from: Vec3,
    pub to: Vec3,
    pub color: SceneColor,
    pub kind: EdgeKind,
}

/// A short text label anchored to a 3D point (node names, source/sink).
#[derive(Debug, Clone, PartialEq)]
pub struct SceneLabel {
    pub at: Vec3,
    pub text: String,
    pub color: SceneColor,
}

/// A fully-built, camera-agnostic scene plus the copy shown in the header.
#[derive(Debug, Clone, PartialEq)]
pub struct Scene {
    pub splats: Vec<Splat>,
    pub edges: Vec<SceneEdge>,
    pub labels: Vec<SceneLabel>,
    pub title: &'static str,
    pub subtitle: String,
}

/// The pages of the security-visualization gallery, cycled with `Tab`. The
/// first is a 3D attack-surface terrain (rendered into a half-block
/// framebuffer); the rest are 2D box-drawing diagrams. All dummy data for now,
/// shaped so real findings / taint-iris / threat-model artifacts drop in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VizPage {
    /// 3D shaded terrain — height is severity-weighted risk density; peaks are
    /// where the attack surface is hottest.
    AttackSurface,
    /// 2D source→sink taint flow as a staged horizontal diagram.
    AttackPath,
    /// 2D data-flow diagram: actors/processes/stores across trust zones.
    Dfd,
    /// 2D severity × module heatmap grid.
    Heatmap,
    /// 2D exploit chain / attack tree from entry to impact.
    ExploitChain,
}

impl VizPage {
    pub const ALL: [VizPage; 5] = [
        VizPage::AttackSurface,
        VizPage::AttackPath,
        VizPage::Dfd,
        VizPage::Heatmap,
        VizPage::ExploitChain,
    ];

    pub fn label(self) -> &'static str {
        match self {
            VizPage::AttackSurface => "attack surface (3D terrain)",
            VizPage::AttackPath => "attack path",
            VizPage::Dfd => "data-flow diagram",
            VizPage::Heatmap => "findings heatmap",
            VizPage::ExploitChain => "exploit chain",
        }
    }

    /// Only the attack-surface page is rendered in 3D (half-block framebuffer).
    pub fn is_3d(self) -> bool {
        matches!(self, VizPage::AttackSurface)
    }

    /// Pages drawn frame-level (the 3D framebuffer terrain, plus the Canvas
    /// graph/tree diagrams) rather than as shared text lines. Attack-path and
    /// the heatmap stay line-based — they read fine as styled text.
    pub fn is_frame_rendered(self) -> bool {
        matches!(
            self,
            VizPage::AttackSurface | VizPage::Dfd | VizPage::ExploitChain
        )
    }

    /// The 3D page animates (idle spin); the 2D diagrams are static.
    pub fn is_animated(self) -> bool {
        self.is_3d()
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|p| *p == self).unwrap_or(0)
    }

    /// Next page in the cycle, wrapping around.
    pub fn next(self) -> VizPage {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    /// Previous page in the cycle, wrapping around.
    pub fn prev(self) -> VizPage {
        Self::ALL[(self.index() + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

impl Default for VizPage {
    fn default() -> Self {
        VizPage::AttackSurface
    }
}
