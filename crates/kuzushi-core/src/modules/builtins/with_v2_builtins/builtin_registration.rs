use super::*;

impl ModuleRegistry {
    pub fn with_v2_builtins() -> Self {
        let mut registry = Self::default();

        register_foundation_modules(&mut registry);
        register_workspace_catalog_modules(&mut registry);
        register_security_modules(&mut registry);
        plugin_adapters::register_modules(&mut registry);
        register_deferred_adapter_modules(&mut registry);

        registry
    }

    pub fn register(&mut self, builtin: BuiltinModule) {
        for tool in builtin.tools() {
            self.tools.insert(tool.name.clone(), tool.clone());
        }
        self.modules.insert(builtin.metadata().id.clone(), builtin);
    }
}

fn register_workspace_catalog_modules(registry: &mut ModuleRegistry) {
    registry.register(workspace_module());
    registry.register(module_recommender_module());
}

fn register_foundation_modules(registry: &mut ModuleRegistry) {
    registry.register(catalog_module());
    registry.register(config_module());
    registry.register(router_module());
    registry.register(full_mode_module());
    registry.register(classifier_gate_module());
    registry.register(deep_audit_module());
    registry.register(smoke_module());
    context::register_context_modules(registry);
}

fn register_security_modules(registry: &mut ModuleRegistry) {
    registry.register(sast_module());
    native_scanners::register_modules(registry);
    registry.register(agentic_sast_module());
    registry.register(offense_review_module());
    registry.register(carlini_threat_hunt_module().deferred());
    registry.register(taint_iris_module());
    registry.register(taint_iris_next_module());
    registry.register(systems_hunt_module());
    registry.register(uaf_hunt_module().deferred());
    registry.register(pwn_module().deferred());
    registry.register(threat_intel_module());
    registry.register(triage_module());
    registry.register(verify_module());
    registry.register(patch_module());
    registry.register(findings_module());
    registry.register(report_module());
    registry.register(threat_model_module());
    registry.register(x_ray_module());
    registry.register(threat_leads_module());
    registry.register(vendor_assessment::module().deferred());
    registry.register(chrome_rce::module().deferred());
    registry.register(dep_hygiene_module());
    registry.register(secret_scan_module());
    registry.register(pipeline_module());
    registry.register(variant_module());
    registry.register(ndiff_module());
    registry.register(randori_module());
}

fn register_deferred_adapter_modules(registry: &mut ModuleRegistry) {
    registry.register(prompt_armor::module().deferred());
    registry.register(recon_module().deferred());
    registry.register(bounty_module());
}
