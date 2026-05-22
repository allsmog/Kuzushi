use cucumber::World;
use kuzushi_bdd_tui::OnboardingWorld;
use std::path::PathBuf;

// Pull every step definition into the binary so cucumber's inventory
// macros pick them up at link time.
#[allow(unused_imports)]
use kuzushi_bdd_tui::steps::{artifacts as _artifacts, background as _bg, ui as _ui};

fn main() {
    let features = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("features");
    futures::executor::block_on(OnboardingWorld::run(features));
}
