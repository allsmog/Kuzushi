//! A tiny half-block framebuffer with a z-buffer.
//!
//! The scene renderer rasterises into this — two square "pixels" per character
//! cell (top/bottom of a `▀`) — then reads pixels back to emit coloured spans.
//! That gives solid, shaded, *occluded* 3D instead of the see-through braille
//! wireframe. Colours are linear `[f32; 3]` in `0..=1`; the renderer owns the
//! theme→rgb conversion. Pure and unit-testable: no ratatui, no IO.

/// `depth` convention throughout: larger = nearer the camera, so the z-test
/// keeps the maximum and nearer geometry wins.
pub struct Framebuffer {
    pub width: usize,
    pub height: usize,
    bg: [f32; 3],
    color: Vec<[f32; 3]>,
    depth: Vec<f32>,
}

impl Framebuffer {
    pub fn new(width: usize, height: usize, bg: [f32; 3]) -> Self {
        let count = width * height;
        Self {
            width,
            height,
            bg,
            color: vec![bg; count],
            depth: vec![f32::NEG_INFINITY; count],
        }
    }

    pub fn pixel(&self, x: usize, y: usize) -> [f32; 3] {
        self.color
            .get(y * self.width + x)
            .copied()
            .unwrap_or(self.bg)
    }

    fn index(&self, x: i32, y: i32) -> Option<usize> {
        if x < 0 || y < 0 {
            return None;
        }
        let (x, y) = (x as usize, y as usize);
        (x < self.width && y < self.height).then_some(y * self.width + x)
    }

    /// Depth-tested opaque write; nearer (greater depth) wins.
    pub fn put(&mut self, x: i32, y: i32, depth: f32, rgb: [f32; 3]) {
        if let Some(i) = self.index(x, y) {
            if depth >= self.depth[i] {
                self.depth[i] = depth;
                self.color[i] = rgb;
            }
        }
    }

    /// Additive light, ignoring the z-buffer — for glow drawn after the solids.
    pub fn add(&mut self, x: i32, y: i32, rgb: [f32; 3], k: f32) {
        if let Some(i) = self.index(x, y) {
            let c = self.color[i];
            self.color[i] = [
                (c[0] + rgb[0] * k).min(1.0),
                (c[1] + rgb[1] * k).min(1.0),
                (c[2] + rgb[2] * k).min(1.0),
            ];
        }
    }

    /// Filled, depth-tested disc — surface facets and thick line bodies.
    pub fn disc(&mut self, cx: f32, cy: f32, depth: f32, radius: f32, rgb: [f32; 3]) {
        self.for_disc(cx, cy, radius, |fb, x, y, _| fb.put(x, y, depth, rgb));
    }

    /// Depth-tested *shaded sphere* — a graph node rendered as a glossy 3D ball
    /// (per-pixel Lambert + a small specular highlight) rather than a flat dot.
    /// Lit from a fixed screen-space light so every node catches the same sheen.
    pub fn shaded_ball(&mut self, cx: f32, cy: f32, depth: f32, radius: f32, base: [f32; 3]) {
        const LIGHT: (f32, f32, f32) = (-0.42, -0.55, 0.72);
        let r = radius.max(0.8);
        self.for_disc(cx, cy, r, |fb, x, y, d2| {
            let (nx, ny) = ((x as f32 - cx) / r, (y as f32 - cy) / r);
            let nz = (1.0 - (d2 / (r * r)).min(1.0)).sqrt();
            let diffuse = (nx * LIGHT.0 + ny * LIGHT.1 + nz * LIGHT.2).max(0.0);
            let intensity = 0.25 + 0.75 * diffuse;
            let spec = diffuse.powf(16.0) * 0.5;
            fb.put(x, y, depth, [
                (base[0] * intensity + spec).min(1.0),
                (base[1] * intensity + spec).min(1.0),
                (base[2] * intensity + spec).min(1.0),
            ]);
        });
    }

    /// Soft additive glow with quadratic falloff to the rim.
    pub fn glow(&mut self, cx: f32, cy: f32, radius: f32, rgb: [f32; 3], intensity: f32) {
        let r2 = radius.max(0.5).powi(2);
        self.for_disc(cx, cy, radius, |fb, x, y, d2| {
            fb.add(x, y, rgb, intensity * (1.0 - d2 / r2).max(0.0))
        });
    }

    fn for_disc<F: FnMut(&mut Self, i32, i32, f32)>(&mut self, cx: f32, cy: f32, radius: f32, mut f: F) {
        let r = radius.max(0.5);
        let r2 = r * r;
        for y in (cy - r).floor() as i32..=(cy + r).ceil() as i32 {
            for x in (cx - r).floor() as i32..=(cx + r).ceil() as i32 {
                let (dx, dy) = (x as f32 - cx, y as f32 - cy);
                let d2 = dx * dx + dy * dy;
                if d2 <= r2 {
                    f(self, x, y, d2);
                }
            }
        }
    }

    /// Depth-tested thick segment, swept from discs along the line.
    pub fn segment(&mut self, a: (f32, f32, f32), b: (f32, f32, f32), radius: f32, rgb: [f32; 3]) {
        let steps = segment_steps(a.0, a.1, b.0, b.1);
        for s in 0..=steps {
            let t = s as f32 / steps as f32;
            self.disc(lerp(a.0, b.0, t), lerp(a.1, b.1, t), lerp(a.2, b.2, t), radius, rgb);
        }
    }

    /// Additive glow swept along a segment (z-ignoring) — hero threads.
    pub fn glow_segment(&mut self, a: (f32, f32), b: (f32, f32), radius: f32, rgb: [f32; 3], intensity: f32) {
        let steps = segment_steps(a.0, a.1, b.0, b.1);
        for s in 0..=steps {
            let t = s as f32 / steps as f32;
            self.glow(lerp(a.0, b.0, t), lerp(a.1, b.1, t), radius, rgb, intensity);
        }
    }
}

fn segment_steps(ax: f32, ay: f32, bx: f32, by: f32) -> usize {
    let (dx, dy) = (bx - ax, by - ay);
    ((dx * dx + dy * dy).sqrt().ceil() as usize).max(1)
}

fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

#[cfg(test)]
mod tests {
    use super::*;

    const BG: [f32; 3] = [0.0, 0.0, 0.0];
    const RED: [f32; 3] = [1.0, 0.0, 0.0];
    const GREEN: [f32; 3] = [0.0, 1.0, 0.0];

    #[test]
    fn untouched_pixels_keep_the_background() {
        let fb = Framebuffer::new(4, 4, BG);
        assert_eq!(fb.pixel(2, 2), BG);
    }

    #[test]
    fn nearer_writes_win_the_z_test() {
        let mut fb = Framebuffer::new(4, 4, BG);
        fb.put(1, 1, 0.2, RED);
        fb.put(1, 1, 0.8, GREEN); // nearer (greater depth)
        assert_eq!(fb.pixel(1, 1), GREEN);
        fb.put(1, 1, 0.1, RED); // farther — rejected
        assert_eq!(fb.pixel(1, 1), GREEN);
    }

    #[test]
    fn disc_fills_its_centre() {
        let mut fb = Framebuffer::new(8, 8, BG);
        fb.disc(4.0, 4.0, 0.5, 1.5, RED);
        assert_eq!(fb.pixel(4, 4), RED);
    }

    #[test]
    fn writes_outside_bounds_are_ignored() {
        let mut fb = Framebuffer::new(4, 4, BG);
        fb.put(-1, 2, 1.0, RED);
        fb.put(10, 2, 1.0, RED);
        // No panic, and in-bounds pixels are untouched.
        assert_eq!(fb.pixel(2, 2), BG);
    }
}
