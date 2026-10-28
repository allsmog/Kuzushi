use super::{split_columns, split_rows_bottom, PhaseSurfaceId, Rect, MIN_MULTI_REGION_COLUMNS};

pub(super) fn solve(
    body: PhaseSurfaceId,
    summary: PhaseSurfaceId,
    receipt: PhaseSurfaceId,
    area: Rect,
) -> Vec<(PhaseSurfaceId, Rect)> {
    if area.width < MIN_MULTI_REGION_COLUMNS || area.height < 10 {
        return vec![(body, area)];
    }
    let columns = split_columns(area, &[64, 36]);
    let summary_rows = (area.height / 3).clamp(4, 6);
    let (top, bottom) = split_rows_bottom(columns[1], area.height - summary_rows);
    vec![(body, columns[0]), (summary, top), (receipt, bottom)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn composition() -> super::super::Composition {
        super::super::Composition::ReadingSidebar {
            body: PhaseSurfaceId::ScanEngines,
            summary: PhaseSurfaceId::ScanDelta,
            receipt: PhaseSurfaceId::ScanReceipt,
        }
    }

    #[test]
    fn jobs_own_the_reading_width_and_sidebar_does_not_waste_a_column() {
        for (width, height) in [(160, 38), (120, 26), (96, 79), (80, 14)] {
            let area = Rect::new(3, 5, width, height);
            let regions = composition().solve(area);
            assert_eq!(regions.len(), 3);
            let body = regions[0].1;
            let summary = regions[1].1;
            let receipt = regions[2].1;
            assert!(body.width > area.width / 2);
            assert_eq!(body.height, area.height);
            assert!(summary.height <= 6);
            assert_eq!(body.right(), summary.x);
            assert_eq!(summary.bottom(), receipt.y);
            assert_eq!(receipt.bottom(), area.bottom());
            assert_eq!(receipt.right(), area.right());
            assert_eq!(
                body.width * body.height
                    + summary.width * summary.height
                    + receipt.width * receipt.height,
                area.width * area.height
            );
        }
    }

    #[test]
    fn small_readers_keep_jobs_and_empty_areas_remain_empty() {
        for area in [Rect::new(0, 0, 60, 20), Rect::new(0, 0, 120, 9)] {
            assert_eq!(
                composition().solve(area),
                vec![(PhaseSurfaceId::ScanEngines, area)]
            );
        }
        assert!(composition().solve(Rect::default()).is_empty());
    }
}
