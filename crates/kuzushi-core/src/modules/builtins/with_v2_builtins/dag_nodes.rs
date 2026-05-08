use super::*;

impl ModuleRegistry {
    pub(in crate::modules) fn is_registered_dag_node(&self, name: &str) -> bool {
        self.all_modules()
            .flat_map(BuiltinModule::dag_nodes)
            .any(|node| node.id == name)
    }
}
