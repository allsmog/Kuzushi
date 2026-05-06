use std::env;
use std::sync::atomic::{AtomicU8, Ordering};

use kuzushi_core::Severity;
use ratatui::prelude::{Color, Modifier, Style};

pub const STATUS_SEPARATOR: &str = " · ";
pub const RULE_CHAR: &str = "─";

const PALETTE_UNINIT: u8 = 0;
const PALETTE_FULL: u8 = 1;
const PALETTE_NONE: u8 = 2;

static PALETTE: AtomicU8 = AtomicU8::new(PALETTE_UNINIT);

fn detect_palette() -> u8 {
    // NO_COLOR (https://no-color.org/) — any non-empty value disables colour.
    if let Some(value) = env::var_os("NO_COLOR") {
        if !value.is_empty() {
            return PALETTE_NONE;
        }
    }
    if matches!(env::var("TERM").as_deref(), Ok("dumb")) {
        return PALETTE_NONE;
    }
    if env::var_os("KUZUSHI_NO_COLOR").is_some() {
        return PALETTE_NONE;
    }
    PALETTE_FULL
}

fn palette() -> u8 {
    let cached = PALETTE.load(Ordering::Relaxed);
    if cached != PALETTE_UNINIT {
        return cached;
    }
    let detected = detect_palette();
    PALETTE.store(detected, Ordering::Relaxed);
    detected
}

fn fg(color: Color) -> Style {
    if palette() == PALETTE_NONE {
        Style::default()
    } else {
        Style::default().fg(color)
    }
}

pub fn primary() -> Style {
    fg(Color::Rgb(207, 214, 224))
}

pub fn muted() -> Style {
    fg(Color::Rgb(125, 135, 148))
}

pub fn subtle() -> Style {
    fg(Color::Rgb(61, 70, 84))
}

pub fn label() -> Style {
    if palette() == PALETTE_NONE {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Rgb(166, 205, 255))
            .add_modifier(Modifier::BOLD)
    }
}

pub fn heading() -> Style {
    if palette() == PALETTE_NONE {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    }
}

pub fn accent() -> Style {
    fg(Color::Rgb(127, 184, 255))
}

pub fn success() -> Style {
    fg(Color::Rgb(87, 196, 121))
}

pub fn warn() -> Style {
    fg(Color::Rgb(226, 193, 74))
}

pub fn danger() -> Style {
    fg(Color::Rgb(226, 92, 92))
}

pub fn selection() -> Style {
    if palette() == PALETTE_NONE {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Rgb(166, 205, 255))
            .add_modifier(Modifier::BOLD)
    }
}

pub fn severity(severity: Severity) -> Style {
    if palette() == PALETTE_NONE {
        return match severity {
            Severity::Critical | Severity::High => Style::default().add_modifier(Modifier::BOLD),
            _ => Style::default(),
        };
    }
    match severity {
        Severity::Critical => danger().add_modifier(Modifier::BOLD),
        Severity::High => fg(Color::Rgb(255, 138, 109)),
        Severity::Medium => warn(),
        Severity::Low | Severity::Info => accent(),
        Severity::Unknown => muted(),
    }
}
