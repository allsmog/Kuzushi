use super::*;

pub(crate) fn analyze_dockerfile(target: &Path, path: &Path, raw: &str) -> Vec<IacScanFinding> {
    let mut findings = Vec::new();
    let mut user_state = DockerfileUserState::default();

    for (index, line) in raw.lines().enumerate() {
        let line_no = line_no(index);
        let trimmed = strip_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        user_state.observe(trimmed, &lower);
        findings.extend(dockerfile_line_findings(
            target, path, line_no, trimmed, &lower,
        ));
    }

    if user_state.needs_non_root_finding() {
        findings.push(IacScanFinding::new(
            target,
            path,
            1,
            IacScanKind::Dockerfile,
            "iac-scan/dockerfile-missing-non-root-user",
            Severity::Medium,
            "Dockerfile does not set a non-root runtime USER",
            "no non-root USER instruction found",
        ));
    }

    findings
}

#[derive(Default)]
struct DockerfileUserState {
    saw_user: bool,
    saw_non_root_user: bool,
}

impl DockerfileUserState {
    fn observe(&mut self, trimmed: &str, lower: &str) {
        if !lower.starts_with("user ") {
            return;
        }
        self.saw_user = true;
        let user = trimmed[5..].trim();
        if user != "0" && !user.eq_ignore_ascii_case("root") {
            self.saw_non_root_user = true;
        }
    }

    fn needs_non_root_finding(&self) -> bool {
        !self.saw_user || !self.saw_non_root_user
    }
}

fn dockerfile_line_findings(
    target: &Path,
    path: &Path,
    line_no: u32,
    trimmed: &str,
    lower: &str,
) -> Vec<IacScanFinding> {
    [
        floating_image_finding(target, path, line_no, trimmed, lower),
        unpinned_image_finding(target, path, line_no, trimmed, lower),
        root_user_finding(target, path, line_no, trimmed, lower),
        remote_add_finding(target, path, line_no, trimmed, lower),
        broad_copy_finding(target, path, line_no, trimmed, lower),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn floating_image_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    trimmed: &str,
    lower: &str,
) -> Option<IacScanFinding> {
    let image = lower.starts_with("from ").then(|| from_image(trimmed))?;
    image_uses_latest_tag(image).then(|| {
        dockerfile_finding(
            target,
            path,
            line_no,
            "iac-scan/dockerfile-floating-image",
            Severity::Medium,
            "Dockerfile pins a base image to the mutable latest tag",
            trimmed,
        )
    })
}

fn unpinned_image_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    trimmed: &str,
    lower: &str,
) -> Option<IacScanFinding> {
    let image = lower.starts_with("from ").then(|| from_image(trimmed))?;
    image_lacks_explicit_tag_or_digest(image).then(|| {
        dockerfile_finding(
            target,
            path,
            line_no,
            "iac-scan/dockerfile-unpinned-image",
            Severity::Medium,
            "Dockerfile base image has no explicit tag or digest",
            trimmed,
        )
    })
}

fn root_user_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    trimmed: &str,
    lower: &str,
) -> Option<IacScanFinding> {
    let user = lower.starts_with("user ").then(|| trimmed[5..].trim())?;
    (user == "0" || user.eq_ignore_ascii_case("root")).then(|| {
        dockerfile_finding(
            target,
            path,
            line_no,
            "iac-scan/dockerfile-root-user",
            Severity::High,
            "Dockerfile explicitly runs the container as root",
            trimmed,
        )
    })
}

fn remote_add_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    trimmed: &str,
    lower: &str,
) -> Option<IacScanFinding> {
    (lower.starts_with("add http://") || lower.starts_with("add https://")).then(|| {
        dockerfile_finding(
            target,
            path,
            line_no,
            "iac-scan/dockerfile-remote-add",
            Severity::Medium,
            "Dockerfile downloads remote content with ADD during image build",
            trimmed,
        )
    })
}

fn broad_copy_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    trimmed: &str,
    lower: &str,
) -> Option<IacScanFinding> {
    (lower.starts_with("copy . ") || lower == "copy .").then(|| {
        dockerfile_finding(
            target,
            path,
            line_no,
            "iac-scan/dockerfile-broad-copy",
            Severity::Low,
            "Dockerfile copies the full build context into the image",
            trimmed,
        )
    })
}

fn dockerfile_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    rule_id: &'static str,
    severity: Severity,
    message: &'static str,
    evidence: &str,
) -> IacScanFinding {
    IacScanFinding::new(
        target,
        path,
        line_no,
        IacScanKind::Dockerfile,
        rule_id,
        severity,
        message,
        evidence,
    )
}

fn from_image(line: &str) -> &str {
    line[5..]
        .split_whitespace()
        .find(|token| !token.starts_with("--"))
        .unwrap_or("")
}

fn image_uses_latest_tag(image: &str) -> bool {
    image
        .rsplit_once(':')
        .is_some_and(|(_, tag)| tag.eq_ignore_ascii_case("latest"))
}

fn image_lacks_explicit_tag_or_digest(image: &str) -> bool {
    if image.is_empty() || image == "scratch" || image.contains('@') || image.starts_with('$') {
        return false;
    }
    !image
        .rsplit_once('/')
        .map_or(image, |(_, last_segment)| last_segment)
        .contains(':')
}
