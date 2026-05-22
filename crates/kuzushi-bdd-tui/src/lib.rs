//! BDD harness for the Kuzushi shell's first-run onboarding flow.
//!
//! Scenarios live under `features/`; step definitions are split across
//! `steps/`. Each scenario spins up a real `kuzushi shell` binary inside
//! a dedicated `tmux` session against a fresh tempdir so we can drive
//! arrow-key / Space / Enter input through `tmux send-keys` and verify
//! the rendered output with `tmux capture-pane`.

pub mod tmux_harness;
pub mod world;

pub mod steps {
    pub mod artifacts;
    pub mod background;
    pub mod ui;
}

pub use world::OnboardingWorld;
