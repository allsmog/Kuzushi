use crate::tmux_harness::TmuxSession;
use crate::OnboardingWorld;
use cucumber::{given, when};
use std::time::Duration;

#[given("a fresh kuzushi workspace")]
async fn fresh_workspace(world: &mut OnboardingWorld) {
    world.ensure_binary();
    world.env.clear();
}

#[given("no model is configured")]
async fn no_model(world: &mut OnboardingWorld) {
    world.env.remove("KUZUSHI_V2_CONFIG_MODEL");
    world.env.remove("ANTHROPIC_API_KEY");
    world.env.remove("OPENAI_API_KEY");
}

#[given(regex = r#"^the model is set to "([^"]+)"$"#)]
async fn model_set_to(world: &mut OnboardingWorld, model: String) {
    world
        .env
        .insert("KUZUSHI_V2_CONFIG_MODEL".to_string(), model);
}

#[given(regex = r#"^the env var "([^"]+)" is set to "([^"]*)"$"#)]
async fn env_set(world: &mut OnboardingWorld, key: String, value: String) {
    world.env.insert(key, value);
}

#[given("a model and auth are configured")]
async fn model_and_auth(world: &mut OnboardingWorld) {
    world.env.insert(
        "KUZUSHI_V2_CONFIG_MODEL".to_string(),
        "anthropic:claude-sonnet-4-6".to_string(),
    );
    world
        .env
        .insert("ANTHROPIC_API_KEY".to_string(), "stub-key".to_string());
}

#[when("I launch the shell")]
async fn launch_shell(world: &mut OnboardingWorld) {
    world.ensure_binary();
    let binary = world.binary.to_string_lossy().into_owned();
    let session = TmuxSession::launch(&binary, world.env.clone())
        .expect("tmux session must launch — install tmux and rebuild the CLI if this fails");
    // Give the binary a moment to render its first frame.
    std::thread::sleep(Duration::from_millis(800));
    world.session = Some(session);
}
