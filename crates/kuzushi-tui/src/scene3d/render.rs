//! Pure scene→framebuffer rasterizer: perspective projection to pixels,
//! z-buffered discs, Lambert-shaded surfels, depth fog and additive-glow
//! threads. No ratatui dependency; the palette follows the active terminal
//! theme so high-contrast mode also covers frame-rendered scenes.

use crate::scene3d::{
    dot, normalize, project, view_space, Camera, EdgeKind, Framebuffer, Scene, SceneColor,
    SceneEdge, Splat, Vec3,
};

/// Scene half-extent mapped to the smaller framebuffer half-dimension. Smaller
/// = the subject fills more of the frame; larger leaves more margin. Tuned so
/// the terrain sits comfortably in the pane rather than filling it edge-to-edge.
const HALF_EXTENT: f32 = 2.0;
const AMBIENT: f32 = 0.34;
const DIFFUSE: f32 = 0.80;

/// Background colour (matches the TUI theme's terminal background).
pub const BACKGROUND: [f32; 3] = [0.043, 0.051, 0.063];

/// Linear RGB for each semantic scene colour. Mirrors the TUI theme palette,
/// kept here so the rasterizer is self-contained and reproducible off-screen.
pub fn default_palette(color: SceneColor) -> [f32; 3] {
    match color {
        SceneColor::Wire => [0.46, 0.52, 0.62],
        SceneColor::Accent => [0.498, 0.722, 1.0],
        SceneColor::Critical => [0.886, 0.361, 0.361],
        SceneColor::High => [1.0, 0.545, 0.545],
        SceneColor::Medium => [0.886, 0.757, 0.290],
        SceneColor::Low => [0.498, 0.722, 1.0],
        SceneColor::Info => [0.651, 0.804, 1.0],
        SceneColor::Success => [0.341, 0.769, 0.475],
        SceneColor::Muted => [0.490, 0.529, 0.580],
    }
}

pub fn active_palette(color: SceneColor) -> [f32; 3] {
    if crate::theme::active_theme().high_contrast {
        return high_contrast_palette(color);
    }
    default_palette(color)
}

fn high_contrast_palette(color: SceneColor) -> [f32; 3] {
    match color {
        SceneColor::Wire | SceneColor::Muted => [0.81, 0.84, 0.88],
        SceneColor::Accent | SceneColor::Low | SceneColor::Info => [1.0, 1.0, 1.0],
        SceneColor::Critical | SceneColor::High => [1.0, 0.43, 0.43],
        SceneColor::Medium => [1.0, 0.86, 0.30],
        SceneColor::Success => [0.42, 0.92, 0.58],
    }
}

/// Scene→pixel mapping: uniform scale (square pixels → round spheres) centred in
/// the framebuffer, with y flipped to screen space.
pub struct Projector {
    cam: Camera,
    scale: f32,
    cx: f32,
    cy: f32,
}

impl Projector {
    pub fn new(cam: Camera, width: usize, height: usize) -> Self {
        let scale = width.min(height) as f32 / (2.0 * HALF_EXTENT);
        Self {
            cam,
            scale,
            cx: width as f32 / 2.0,
            cy: height as f32 / 2.0,
        }
    }

    /// Pixel `(x, y, depth)` for a scene point, or `None` when clipped.
    pub fn pixel(&self, v: Vec3) -> Option<(f32, f32, f32)> {
        project(self.cam, v).map(|p| {
            (
                self.cx + p.x * self.scale,
                self.cy - p.y * self.scale,
                p.depth,
            )
        })
    }
}

/// Rasterise a scene into a fresh `width × height` pixel framebuffer.
///
/// Draw order is layered for legibility: an additive glow halo goes down first
/// (behind everything), then structural wires, then shaded surfaces, then the
/// opaque thread cores, and finally the node balls on top — so a flow reads as
/// "balls connected by a glowing edge", not a bare squiggle. Pure, so the exact
/// pixels are reproducible and unit-testable off-screen.
pub fn render_to_framebuffer(
    scene: &Scene,
    cam: Camera,
    width: usize,
    height: usize,
) -> Framebuffer {
    let mut fb = Framebuffer::new(width, height, BACKGROUND);
    let proj = Projector::new(cam, width, height);
    let light = normalize(Vec3::new(0.4, 0.75, 0.55));
    draw_thread_glows(&mut fb, &proj, scene);
    draw_wires(&mut fb, &proj, scene);
    draw_surfaces(&mut fb, &proj, scene, cam, light);
    draw_thread_cores(&mut fb, &proj, scene);
    draw_nodes(&mut fb, &proj, scene, cam, light);
    fb
}

fn draw_thread_glows(fb: &mut Framebuffer, proj: &Projector, scene: &Scene) {
    for edge in scene.edges.iter().filter(|e| e.kind == EdgeKind::Thread) {
        draw_thread_glow(fb, proj, edge);
    }
}

fn draw_wires(fb: &mut Framebuffer, proj: &Projector, scene: &Scene) {
    for edge in scene.edges.iter().filter(|e| e.kind == EdgeKind::Wire) {
        draw_wire(fb, proj, edge);
    }
}

/// Lambert-shaded surface samples (the normal-carrying splats).
fn draw_surfaces(fb: &mut Framebuffer, proj: &Projector, scene: &Scene, cam: Camera, light: Vec3) {
    for splat in scene.splats.iter().filter(|s| s.normal.is_some()) {
        draw_splat(fb, proj, splat, cam, light);
    }
}

fn draw_thread_cores(fb: &mut Framebuffer, proj: &Projector, scene: &Scene) {
    for edge in scene.edges.iter().filter(|e| e.kind == EdgeKind::Thread) {
        draw_thread_core(fb, proj, edge);
    }
}

/// Free-floating node balls (the normal-less splats), drawn last/on top.
fn draw_nodes(fb: &mut Framebuffer, proj: &Projector, scene: &Scene, cam: Camera, light: Vec3) {
    for splat in scene.splats.iter().filter(|s| s.normal.is_none()) {
        draw_splat(fb, proj, splat, cam, light);
    }
}

fn draw_wire(fb: &mut Framebuffer, proj: &Projector, edge: &SceneEdge) {
    let (Some(a), Some(b)) = (proj.pixel(edge.from), proj.pixel(edge.to)) else {
        return;
    };
    let color = fog(active_palette(edge.color), (a.2 + b.2) / 2.0);
    fb.segment(a, b, 0.6, color);
}

fn draw_splat(fb: &mut Framebuffer, proj: &Projector, splat: &Splat, cam: Camera, light: Vec3) {
    let Some((px, py, depth)) = proj.pixel(splat.at) else {
        return;
    };
    match splat.normal {
        // Surface samples: flat-shaded facet at a steady radius so a surface
        // fills without holes.
        Some(n) => {
            let lit = mul(active_palette(splat.color), shading(Some(n), cam, light));
            let radius = (splat.size * proj.scale).max(0.6);
            fb.disc(px, py, depth, radius, fog(lit, depth));
        }
        // Free-floating node: a glossy 3D ball with perspective size.
        None => {
            let radius = (splat.size * proj.scale * (0.6 + 0.6 * depth)).max(0.9);
            let base = fog(active_palette(splat.color), depth);
            fb.shaded_ball(px, py, depth, radius, base);
        }
    }
}

/// Lambert term for a surfel; flat (1.0) for normal-less dots.
fn shading(normal: Option<Vec3>, cam: Camera, light: Vec3) -> f32 {
    match normal {
        Some(n) => AMBIENT + DIFFUSE * dot(normalize(view_space(cam, n)), light).max(0.0),
        None => 1.0,
    }
}

fn draw_thread_core(fb: &mut Framebuffer, proj: &Projector, edge: &SceneEdge) {
    let (Some(a), Some(b)) = (proj.pixel(edge.from), proj.pixel(edge.to)) else {
        return;
    };
    fb.segment(a, b, 1.2, brighten(active_palette(edge.color)));
}

fn draw_thread_glow(fb: &mut Framebuffer, proj: &Projector, edge: &SceneEdge) {
    let (Some(a), Some(b)) = (proj.pixel(edge.from), proj.pixel(edge.to)) else {
        return;
    };
    fb.glow_segment((a.0, a.1), (b.0, b.1), 3.2, active_palette(edge.color), 0.5);
}

fn mul(c: [f32; 3], k: f32) -> [f32; 3] {
    [c[0] * k, c[1] * k, c[2] * k]
}

fn fog(base: [f32; 3], depth: f32) -> [f32; 3] {
    let vis = 0.52 + 0.48 * depth.clamp(0.0, 1.0);
    [
        BACKGROUND[0] + (base[0] - BACKGROUND[0]) * vis,
        BACKGROUND[1] + (base[1] - BACKGROUND[1]) * vis,
        BACKGROUND[2] + (base[2] - BACKGROUND[2]) * vis,
    ]
}

/// Lift a colour toward white for hero threads and labels.
pub fn brighten(c: [f32; 3]) -> [f32; 3] {
    [
        (c[0] * 1.15 + 0.12).min(1.0),
        (c[1] * 1.15 + 0.12).min(1.0),
        (c[2] * 1.15 + 0.12).min(1.0),
    ]
}
