use super::*;
use crate::workspace::{NestedProjectKind, NestedProjectScope, NestedProjectScopeTree};

mod component_signals;
use component_signals::ComponentSignals;

pub(crate) fn component_recommendations(
    target: &Path,
    tree: &NestedProjectScopeTree,
    inventory: &RepositoryInventory,
    attack_surface: &AttackSurfaceMap,
) -> Vec<ComponentRecommendation> {
    let mut components = tree
        .non_root_scopes()
        .filter(|scope| recommendable_component_scope(scope.kind))
        .map(|scope| component_recommendation(target, scope, inventory, attack_surface))
        .collect::<Vec<_>>();
    components.sort_by(component_sort_order);
    components
}

fn classify(scope: &NestedProjectScope, signals: &ComponentSignals) -> ComponentClass {
    component_class_rules(scope, signals)
        .into_iter()
        .find_map(|(matched, class)| matched.then_some(class))
        .unwrap_or(ComponentClass::Library)
}

fn component_class_rules(
    scope: &NestedProjectScope,
    signals: &ComponentSignals,
) -> [(bool, ComponentClass); 5] {
    [
        (
            test_fixture_scope(&scope.rel_path),
            ComponentClass::TestFixture,
        ),
        (
            signals.iac_files > 0 && signals.source_files == 0,
            ComponentClass::Infra,
        ),
        (signals.has_web_stack(), ComponentClass::WebApp),
        (signals.has_service_surface(), ComponentClass::ServiceApi),
        (
            scope.kind == NestedProjectKind::EntrypointCluster || signals.entrypoints > 0,
            ComponentClass::CliBinary,
        ),
    ]
}

fn component_recommendation(
    target: &Path,
    scope: &NestedProjectScope,
    inventory: &RepositoryInventory,
    attack_surface: &AttackSurfaceMap,
) -> ComponentRecommendation {
    let signals = ComponentSignals::for_scope(scope, inventory, attack_surface);
    let class = classify(scope, &signals);
    let tier = component_tier(class, &signals);
    let tasks = scanner_tasks_for_component(class, &signals);
    ComponentRecommendation {
        scope_id: scope.id.clone(),
        rel_path: scope.rel_path.clone(),
        class,
        risk_score: signals.risk_score(),
        tier,
        reasons: component_reasons(scope, class, &signals),
        recommended_tools: recommended_tools_for_tasks(&tasks),
        next_input: scoped_scan_input(target, scope, class, &tasks),
    }
}

fn recommendable_component_scope(kind: NestedProjectKind) -> bool {
    matches!(
        kind,
        NestedProjectKind::Submodule
            | NestedProjectKind::PackageRoot
            | NestedProjectKind::EntrypointCluster
    )
}

fn test_fixture_scope(rel_path: &str) -> bool {
    let normalized = rel_path.trim_matches('/').to_ascii_lowercase();
    normalized == "test"
        || normalized == "tests"
        || normalized.starts_with("test/")
        || normalized.starts_with("tests/")
        || normalized.contains("/test/")
        || normalized.contains("/tests/")
        || normalized.contains("fixture")
}

fn component_tier(class: ComponentClass, signals: &ComponentSignals) -> ComponentTier {
    if signals.risk_score() >= 70
        || matches!(class, ComponentClass::WebApp | ComponentClass::ServiceApi)
    {
        return ComponentTier::High;
    }
    if signals.risk_score() >= 35 || signals.entrypoints > 0 || signals.dependency_manifests > 0 {
        return ComponentTier::Medium;
    }
    ComponentTier::Low
}

fn scanner_tasks_for_component(class: ComponentClass, signals: &ComponentSignals) -> Vec<String> {
    let tasks = match class {
        ComponentClass::WebApp | ComponentClass::ServiceApi => {
            vec!["semgrep", "dep-hygiene", "taint-iris-next", "secret-scan"]
        }
        ComponentClass::CliBinary => vec!["semgrep", "dep-hygiene", "secret-scan"],
        ComponentClass::Infra => vec!["iac-scan", "secret-scan"],
        ComponentClass::Library => vec!["semgrep", "dep-hygiene", "secret-scan"],
        ComponentClass::TestFixture => vec!["secret-scan"],
    };
    tasks
        .into_iter()
        .filter(|task| task_applicable(task, signals))
        .map(str::to_string)
        .collect()
}

fn task_applicable(task: &str, signals: &ComponentSignals) -> bool {
    match task {
        "dep-hygiene" => signals.dependency_manifests > 0,
        "iac-scan" => signals.iac_files > 0,
        "taint-iris-next" => signals.routes > 0 || signals.entrypoints > 0,
        _ => true,
    }
}

fn recommended_tools_for_tasks(tasks: &[String]) -> Vec<String> {
    tasks
        .iter()
        .map(|task| match task.as_str() {
            "dep-hygiene" => "dep-hygiene:check",
            "iac-scan" => "iac-scan:scan",
            "secret-scan" => "secret-scan:scan",
            "taint-iris-next" => "taint-iris-next:hunt",
            "semgrep" => "semgrep:scan",
            other => other,
        })
        .map(str::to_string)
        .collect()
}

fn scoped_scan_input(
    target: &Path,
    scope: &NestedProjectScope,
    class: ComponentClass,
    tasks: &[String],
) -> Value {
    json!({
        "target": target.display().to_string(),
        "paths": [scope.rel_path.clone()],
        "taskMode": "manual",
        "tasks": tasks,
        "component": {
            "scopeId": scope.id,
            "relPath": scope.rel_path,
            "class": class.label(),
        }
    })
}

fn component_reasons(
    scope: &NestedProjectScope,
    class: ComponentClass,
    signals: &ComponentSignals,
) -> Vec<String> {
    let mut reasons = vec![format!("{} component at {}", class.label(), scope.rel_path)];
    push_count_reason(&mut reasons, signals.routes, "route");
    push_count_reason(&mut reasons, signals.entrypoints, "entrypoint");
    push_count_reason(
        &mut reasons,
        signals.dependency_manifests,
        "dependency manifest",
    );
    push_count_reason(&mut reasons, signals.iac_files, "IaC/config file");
    if signals.high_risk_surfaces > 0 {
        reasons.push(format!(
            "{} high-risk attack-surface signal(s)",
            signals.high_risk_surfaces
        ));
    }
    reasons
}

fn push_count_reason(reasons: &mut Vec<String>, count: usize, label: &str) {
    if count > 0 {
        reasons.push(format!(
            "{count} {label}{}",
            if count == 1 { "" } else { "s" }
        ));
    }
}

fn component_sort_order(
    left: &ComponentRecommendation,
    right: &ComponentRecommendation,
) -> std::cmp::Ordering {
    left.tier
        .sort_key()
        .cmp(&right.tier.sort_key())
        .then_with(|| right.risk_score.cmp(&left.risk_score))
        .then_with(|| left.rel_path.cmp(&right.rel_path))
}

#[cfg(test)]
mod tests;
