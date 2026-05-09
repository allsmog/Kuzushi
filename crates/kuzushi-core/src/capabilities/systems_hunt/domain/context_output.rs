use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SystemsContextOutput {
    pub surfaces: Vec<RankedSystemsSurface>,
    pub surface_packs: Vec<SystemsSurfacePack>,
    pub metadata: SystemsContextMetadata,
}
