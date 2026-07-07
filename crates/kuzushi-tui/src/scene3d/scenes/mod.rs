//! Geometry for the 3D attack-surface terrain — the gallery's only 3D page.
//! Terminal drawing lives in `scene3d::render`. The other gallery pages are 2D
//! box-drawing diagrams rendered as styled lines, not 3D.

mod terrain;

use crate::scene3d::{Scene, SceneColor, SceneLabel, Splat, Vec3};

pub(crate) use terrain::attack_surface_scene;

/// A lit surface sample — its `normal` drives Lambert shading in the renderer.
pub(super) fn surfel(at: Vec3, normal: Vec3, color: SceneColor, size: f32) -> Splat {
    Splat {
        at,
        normal: Some(normal),
        color,
        size,
    }
}

/// A text label anchored to a 3D point.
pub(super) fn label(at: Vec3, text: &str, color: SceneColor) -> SceneLabel {
    SceneLabel {
        at,
        text: text.to_string(),
        color,
    }
}
