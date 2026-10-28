use super::*;

mod components;
pub(in crate::renderer::views) mod diagram;
pub(in crate::renderer::views) mod diagrams;
mod entry_points;
mod gallery;
mod gallery_layout;
mod gallery_reading;
mod line_page;
mod render_scene_view;
mod scene_color;
mod worklist;

pub(in crate::renderer) use diagram::{DfdDiagram, TreeDiagram};
pub(crate) use entry_points::entry_point_page_scroll;
pub(crate) use gallery::{
    map_summary_plain_lines, scene_line_page_viewport_lines, scene_page_lines,
};
pub(in crate::renderer::views) use gallery_layout::map_canvas_sections;
pub(crate) use gallery_layout::{
    dfd_detail_scroll, map_gallery_page_rows, scene_page_rows, summary_page_rows,
};
pub(crate) use line_page::PageDirection;
pub(crate) use render_scene_view::{render_embedded_map_gallery, render_scene_view};

pub(crate) use gallery_reading::{
    capture_gallery_reading, gallery_line_offset, restore_gallery_reading,
};
