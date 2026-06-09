//! Attack surface as a shaded relief terrain. Height is severity-weighted
//! finding density per module: lit peaks are the hottest modules, dark valleys
//! are clean code. Bumps come from the real `RiskByModule` model (one bump per
//! module, height ∝ score); no findings → a near-flat plane.

use super::{label, surfel};
use crate::scene3d::{normalize, Scene, SceneColor, Splat, Vec3};
use crate::ui_view_models::RiskByModule;

const GRID: usize = 48;
const EXTENT: f32 = 1.3;
const MAX_BUMPS: usize = 7;

/// Deterministic, well-spread bump centres in `[-0.8, 0.8]²`; the hottest module
/// takes the first (front-left) slot so the labelled peak reads clearly.
const SLOTS: [(f32, f32); MAX_BUMPS] = [
    (-0.5, -0.4),
    (0.55, 0.35),
    (0.1, 0.72),
    (-0.65, 0.5),
    (0.6, -0.5),
    (-0.15, 0.0),
    (0.35, -0.05),
];

struct Bump {
    cx: f32,
    cz: f32,
    height: f32,
    width: f32,
}

struct Terrain {
    bumps: Vec<Bump>,
    base: f32,
}

impl Terrain {
    fn height(&self, x: f32, z: f32) -> f32 {
        self.base
            + self
                .bumps
                .iter()
                .map(|b| b.height * (-((x - b.cx).powi(2) + (z - b.cz).powi(2)) / b.width).exp())
                .sum::<f32>()
    }

    fn normal(&self, x: f32, z: f32) -> Vec3 {
        const E: f32 = 0.03;
        let dx = self.height(x + E, z) - self.height(x - E, z);
        let dz = self.height(x, z + E) - self.height(x, z - E);
        normalize(Vec3::new(-dx, 2.0 * E, -dz))
    }
}

pub(crate) fn attack_surface_scene(model: &RiskByModule) -> Scene {
    let terrain = build_terrain(model);
    let peak = peak_node(&terrain);
    let (subtitle, peak_label) = match model.modules.first() {
        Some(top) => (
            format!(
                "risk density · {} modules · hottest = {}",
                model.modules.len(),
                top.module
            ),
            top.module.clone(),
        ),
        None => (
            "no findings yet — run `scan` to populate".to_string(),
            String::new(),
        ),
    };
    let mut labels = Vec::new();
    if !peak_label.is_empty() {
        labels.push(label(
            Vec3::new(peak.x, peak.y + 0.12, peak.z),
            &peak_label,
            SceneColor::Critical,
        ));
    }
    Scene {
        splats: surface_splats(&terrain),
        edges: Vec::new(),
        labels,
        title: "ATTACK SURFACE",
        subtitle,
    }
}

fn build_terrain(model: &RiskByModule) -> Terrain {
    if model.modules.is_empty() {
        return Terrain {
            bumps: Vec::new(),
            base: -0.05,
        };
    }
    let max_score = model
        .modules
        .iter()
        .map(|m| m.score)
        .fold(1.0_f32, f32::max);
    let bumps = model
        .modules
        .iter()
        .take(MAX_BUMPS)
        .zip(SLOTS)
        .map(|(module, (cx, cz))| Bump {
            cx,
            cz,
            height: 0.35 + 0.95 * (module.score / max_score),
            width: 0.20,
        })
        .collect();
    Terrain { bumps, base: -0.35 }
}

fn coord(k: usize) -> f32 {
    -EXTENT + 2.0 * EXTENT * k as f32 / (GRID - 1) as f32
}

fn surface_splats(terrain: &Terrain) -> Vec<Splat> {
    let mut splats = Vec::with_capacity(GRID * GRID);
    for i in 0..GRID {
        for j in 0..GRID {
            let (x, z) = (coord(i), coord(j));
            let at = Vec3::new(x, terrain.height(x, z), z);
            splats.push(surfel(at, terrain.normal(x, z), height_color(at.y), 0.09));
        }
    }
    splats
}

fn height_color(height: f32) -> SceneColor {
    if height > 0.55 {
        SceneColor::Critical
    } else if height > 0.30 {
        SceneColor::High
    } else if height > 0.12 {
        SceneColor::Medium
    } else if height > -0.05 {
        SceneColor::Low
    } else {
        SceneColor::Info
    }
}

fn peak_node(terrain: &Terrain) -> Vec3 {
    let mut best = Vec3::new(0.0, terrain.height(0.0, 0.0), 0.0);
    for i in 0..GRID {
        for j in 0..GRID {
            let (x, z) = (coord(i), coord(j));
            let y = terrain.height(x, z);
            if y > best.y {
                best = Vec3::new(x, y, z);
            }
        }
    }
    best
}
