pub(in crate::renderer) use super::*;
use crate::renderer::shared::tables::fit_table_widths;

pub(crate) fn option_table_widths(width: u16) -> Vec<usize> {
    fit_table_widths(
        width as usize,
        [16, 10, 9, 5, 5, 16, 40],
        [5, 3, 3, 1, 3, 3, 6],
    )
    .to_vec()
}

pub(crate) fn sast_task_table_widths(width: u16) -> Vec<usize> {
    fit_table_widths(width as usize, [5, 24, 6, 18, 40], [3, 8, 3, 6, 8]).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::renderer::shared::tables::table_width;

    #[test]
    fn option_and_sast_widths_fit_supported_terminal_widths() {
        for width in [40, 60, 80, 104] {
            assert_eq!(table_width(&option_table_widths(width)), width as usize);
            assert_eq!(table_width(&sast_task_table_widths(width)), width as usize);
        }
    }
}
