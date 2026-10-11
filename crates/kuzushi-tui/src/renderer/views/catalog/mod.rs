use super::*;
pub(in crate::renderer) use super::*;
use crate::ui_view_models::AttackSurfaceRiskModel;

pub(in crate::renderer) use catalog_lines::*;
pub(in crate::renderer) use home_lines::*;
pub(in crate::renderer) use recommend_lines::*;
mod catalog_lines;
mod home_lines;
mod recommend_lines;
mod recommend_reader;
pub(crate) use catalog_lines::catalog_lines;
pub(crate) use home_lines::home_lines;
pub(crate) use recommend_lines::recommend_lines;
pub(crate) use recommend_reader::{recommendation_max_scroll, recommendation_page_rows};

fn attack_surface_risk_line(surface: &AttackSurfaceRiskModel, width: u16) -> Line<'static> {
    detail(
        "surface risk",
        &fit(&surface.summary, detail_value_width(width)),
    )
}

fn detail_value_width(width: u16) -> usize {
    (width as usize).saturating_sub(20).max(12)
}
