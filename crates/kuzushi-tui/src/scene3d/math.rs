//! Pure 3D math: vectors, an orbiting camera, and perspective projection.
//! No allocation, no IO — just the arithmetic the renderer needs per frame.

/// A point in scene space. Right-handed; +z points toward the camera.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vec3 {
    pub const fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x, y, z }
    }
}

/// Dot product.
pub fn dot(a: Vec3, b: Vec3) -> f32 {
    a.x * b.x + a.y * b.y + a.z * b.z
}

/// Unit vector, or the input unchanged when it's ~zero-length.
pub fn normalize(v: Vec3) -> Vec3 {
    let len = dot(v, v).sqrt();
    if len <= 1e-6 {
        v
    } else {
        Vec3::new(v.x / len, v.y / len, v.z / len)
    }
}

/// Orbiting eye. `yaw`/`pitch` are radians; `distance` is how far the eye sits
/// from the origin along +z. The scene rotates under a fixed eye.
#[derive(Debug, Clone, Copy)]
pub struct Camera {
    pub yaw: f32,
    pub pitch: f32,
    pub distance: f32,
}

/// A scene point flattened to canvas space. `depth` is a `0..=1` cue (1.0 =
/// nearest the camera) so the renderer can dim distant geometry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Projected {
    pub x: f32,
    pub y: f32,
    pub depth: f32,
}

/// Half-range used to normalise view-space z into the `depth` cue.
const DEPTH_RADIUS: f32 = 2.2;
/// Anything closer to the eye than this is treated as behind it (clipped).
const NEAR_PLANE: f32 = 0.05;

fn rotate_yaw(v: Vec3, angle: f32) -> Vec3 {
    let (s, c) = angle.sin_cos();
    Vec3::new(v.x * c + v.z * s, v.y, -v.x * s + v.z * c)
}

fn rotate_pitch(v: Vec3, angle: f32) -> Vec3 {
    let (s, c) = angle.sin_cos();
    Vec3::new(v.x, v.y * c - v.z * s, v.y * s + v.z * c)
}

/// Rotate a point into view space using the camera's yaw then pitch.
pub fn view_space(cam: Camera, v: Vec3) -> Vec3 {
    rotate_pitch(rotate_yaw(v, cam.yaw), cam.pitch)
}

fn depth_cue(z: f32) -> f32 {
    ((z + DEPTH_RADIUS) / (2.0 * DEPTH_RADIUS)).clamp(0.0, 1.0)
}

/// Perspective-project a point. Returns `None` when the point sits on or
/// behind the eye, where the divide would invert or blow up.
pub fn project(cam: Camera, v: Vec3) -> Option<Projected> {
    let view = view_space(cam, v);
    let denom = cam.distance - view.z;
    if denom <= NEAR_PLANE {
        return None;
    }
    let factor = cam.distance / denom;
    Some(Projected {
        x: view.x * factor,
        y: view.y * factor,
        depth: depth_cue(view.z),
    })
}
