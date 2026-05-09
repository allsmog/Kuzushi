#[derive(Debug, Clone)]
pub(crate) struct DfdNode {
    pub(crate) id: String,
    pub(crate) node_type: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) trust_zone: String,
}
