use crate::tmux_harness::{ArtifactSeed, TmuxSession};
use crate::OnboardingWorld;
use cucumber::{given, when};
use std::time::Duration;

#[given("a fresh kuzushi workspace")]
async fn fresh_workspace(world: &mut OnboardingWorld) {
    world.ensure_binary();
    world.env.clear();
    world.pending_seeds.clear();
    world.terminal_size = None;
}

#[given(regex = r#"^a (\d+) by (\d+) terminal$"#)]
async fn terminal_size(world: &mut OnboardingWorld, width: u16, height: u16) {
    world.terminal_size = Some((width, height));
}

#[given(regex = r#"^the artifact "([^"]+)" is seeded with "(.+)"$"#)]
async fn seed_artifact_file(world: &mut OnboardingWorld, relative: String, body: String) {
    world.pending_seeds.push(ArtifactSeed::File {
        relative,
        body: body.replace("\\\"", "\""),
    });
}

#[given(regex = r#"^the directory "([^"]+)" is seeded with a placeholder file$"#)]
async fn seed_artifact_dir(world: &mut OnboardingWorld, relative: String) {
    world.pending_seeds.push(ArtifactSeed::Dir {
        relative,
        placeholder: "stub".to_string(),
    });
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
    let seeds = std::mem::take(&mut world.pending_seeds);
    let session = TmuxSession::launch_with_seeds(&binary, world.env.clone(), &seeds)
        .expect("tmux session must launch — install tmux and rebuild the CLI if this fails");
    // Give the binary a moment to render its first frame.
    std::thread::sleep(Duration::from_millis(800));
    world.session = Some(session);
}

#[when("I launch the shell without a target")]
async fn launch_shell_without_target(world: &mut OnboardingWorld) {
    world.ensure_binary();
    let binary = world.binary.to_string_lossy().into_owned();
    world.pending_seeds.clear();
    let size = world.terminal_size.unwrap_or((200, 50));
    let session = TmuxSession::launch_targetless_sized(&binary, world.env.clone(), size)
        .expect("tmux session must launch — install tmux and rebuild the CLI if this fails");
    std::thread::sleep(Duration::from_millis(800));
    world.session = Some(session);
}
