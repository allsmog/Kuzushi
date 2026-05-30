//! 3D geometry for the TUI scene view's attack-surface terrain page.
//!
//! This layer is intentionally pure and side-effect-free: it builds the terrain
//! scene from a `RiskByModule` view model (see `scenes::attack_surface_scene`)
//! and projects it to 2D framebuffer coordinates. Terminal drawing (half-block
//! rasterization, colours, depth dimming) lives in `render`/`raster`. Keeping
//! the math here means the projection is unit-testable without a terminal, per
//! the Clean Code baseline.

mod math;
mod model;
mod raster;
mod render;
mod scenes;

pub use math::{dot, normalize, project, view_space, Camera, Projected, Vec3};
pub use model::{EdgeKind, Scene, SceneColor, SceneEdge, SceneLabel, Splat, VizPage};
pub use raster::Framebuffer;
pub use render::{brighten, default_palette, render_to_framebuffer, Projector, BACKGROUND};
pub(crate) use scenes::attack_surface_scene;

#[cfg(test)]
mod tests;
