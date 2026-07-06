use crate::OnboardingWorld;
use cucumber::then;
use std::time::{Duration, Instant};

#[then(regex = r#"^the file "([^"]+)" eventually exists$"#)]
async fn file_exists(world: &mut OnboardingWorld, relative: String) {
    let target = world.require_session().target.clone();
    let path = target.join(&relative);
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if path.is_file() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("file `{}` was never written within 30s", path.display());
}

#[then(regex = r#"^the config file contains "([^"]+)"$"#)]
async fn config_contains(world: &mut OnboardingWorld, needle: String) {
    let home = world.require_session().home.clone();
    let path = home.join(".kuzushi/v3/config.toml");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(body) = std::fs::read_to_string(&path) {
            if body.contains(&needle) {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let body = std::fs::read_to_string(&path).unwrap_or_default();
    panic!(
        "config at {} never contained `{needle}`. body:\n{body}",
        path.display()
    );
}
