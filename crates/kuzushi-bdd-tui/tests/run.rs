use cucumber::World;
use kuzushi_bdd_tui::OnboardingWorld;
use std::path::PathBuf;

// Pull every step definition into the binary so cucumber's inventory
// macros pick them up at link time.
#[allow(unused_imports)]
use kuzushi_bdd_tui::steps::{
    artifacts as _artifacts, background as _bg, cockpit_resize as _cockpit_resize,
    operator_questions as _operator_questions, ui as _ui, workbench_modes as _workbench_modes,
};

fn main() {
    let features = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("features");
    // Every scenario owns a real tmux session and Kuzushi process. Run them
    // sequentially so terminal capture and short deterministic jobs cannot
    // race each other under CI load.
    futures::executor::block_on(
        OnboardingWorld::cucumber()
            .max_concurrent_scenarios(1)
            .run_and_exit(features),
    );
}
