use super::*;

impl ModuleRegistry {
    pub fn with_v2_builtins() -> Self {
        let mut registry = Self::default();

        registry.register(catalog_module());
        registry.register(config_module());
        registry.register(router_module());
        registry.register(full_mode_module());
        registry.register(classifier_gate_module());
        registry.register(deep_audit_module());
        registry.register(smoke_module());
        registry.register(workspace_module());
        context::register_context_modules(&mut registry);
        registry.register(sast_module());
        native_scanners::register_modules(&mut registry);
        registry.register(agentic_sast_module());
        registry.register(carlini_threat_hunt_module());
        registry.register(taint_iris_module());
        registry.register(taint_iris_next_module());
        registry.register(systems_hunt_module());
        registry.register(uaf_hunt_module());
        registry.register(pwn_module());
        registry.register(threat_intel_module());
        registry.register(triage_module());
        registry.register(verify_module());
        registry.register(patch_module());
        registry.register(findings_module());
        registry.register(threat_model_module());
        registry.register(x_ray_module());
        registry.register(vendor_assessment::module());
        registry.register(chrome_rce::module());
        registry.register(dep_hygiene_module());
        registry.register(secret_scan_module());
        registry.register(pipeline_module());
        registry.register(variant_module());
        registry.register(ndiff_module());
        registry.register(randori_module());
        plugin_adapters::register_modules(&mut registry);
        registry.register(prompt_armor::module());
        registry.register(recon_module());

        registry
    }

    pub fn register(&mut self, builtin: BuiltinModule) {
        for tool in builtin.tools() {
            self.tools.insert(tool.name.clone(), tool.clone());
        }
        self.modules.insert(builtin.metadata().id.clone(), builtin);
    }
}
