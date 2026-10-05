//! Maximum-weight one-to-one assignment, with one zero-weight dummy per row.
//! Hungarian potentials keep assignment deterministic without greedy reuse.
pub(crate) fn maximum_weight_assignment(weights: &[Vec<i128>]) -> Vec<Option<usize>> {
    if weights.is_empty() {
        return Vec::new();
    }
    let real_columns = weights[0].len();
    let columns = real_columns + weights.len();
    let mut solver = Assignment {
        weights,
        row_potential: vec![0; weights.len() + 1],
        column_potential: vec![0; columns + 1],
        rows: vec![0; columns + 1],
        previous: vec![0; columns + 1],
    };
    for row in 1..=weights.len() {
        solver.augment(row);
    }
    solver.assignments(real_columns)
}

struct Assignment<'a> {
    weights: &'a [Vec<i128>],
    row_potential: Vec<i128>,
    column_potential: Vec<i128>,
    rows: Vec<usize>,
    previous: Vec<usize>,
}

impl Assignment<'_> {
    fn assignments(&self, real_columns: usize) -> Vec<Option<usize>> {
        let mut result = vec![None; self.weights.len()];
        for column in 1..=real_columns {
            if self.rows[column] != 0 {
                result[self.rows[column] - 1] = Some(column - 1);
            }
        }
        result
    }

    fn augment(&mut self, row: usize) {
        self.rows[0] = row;
        let mut column = 0;
        let mut minimum = vec![i128::MAX / 4; self.rows.len()];
        let mut used = vec![false; self.rows.len()];
        loop {
            used[column] = true;
            self.relax(column, &mut minimum, &used);
            let next = (1..self.rows.len())
                .filter(|&j| !used[j])
                .min_by_key(|&j| minimum[j])
                .unwrap();
            self.shift_potentials(minimum[next], &mut minimum, &used);
            column = next;
            if self.rows[column] == 0 {
                break;
            }
        }
        self.reassign(column);
    }

    fn relax(&mut self, column: usize, minimum: &mut [i128], used: &[bool]) {
        let row = self.rows[column];
        for j in (1..self.rows.len()).filter(|&j| !used[j]) {
            let weight = self.weights[row - 1].get(j - 1).copied().unwrap_or(0);
            let reduced = -weight - self.row_potential[row] - self.column_potential[j];
            if reduced < minimum[j] {
                minimum[j] = reduced;
                self.previous[j] = column;
            }
        }
    }

    fn shift_potentials(&mut self, delta: i128, minimum: &mut [i128], used: &[bool]) {
        for j in 0..self.rows.len() {
            if used[j] {
                self.row_potential[self.rows[j]] += delta;
                self.column_potential[j] -= delta;
            } else {
                minimum[j] -= delta;
            }
        }
    }

    fn reassign(&mut self, mut column: usize) {
        while column != 0 {
            let previous = self.previous[column];
            self.rows[column] = self.rows[previous];
            column = previous;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brute_force(weights: &[Vec<i128>], row: usize, used: u64) -> i128 {
        if row == weights.len() {
            return 0;
        }
        let mut best = brute_force(weights, row + 1, used);
        for column in 0..weights[row].len() {
            if used & (1 << column) == 0 {
                best = best.max(
                    weights[row][column] + brute_force(weights, row + 1, used | (1 << column)),
                );
            }
        }
        best
    }

    #[test]
    fn all_small_weighted_graphs_agree_with_exhaustive_matching() {
        for bits in 0u64..4096 {
            let weights: Vec<Vec<i128>> = (0..3)
                .map(|row| {
                    (0..2)
                        .map(|col| ((bits >> ((row * 2 + col) * 2)) & 3) as i128)
                        .collect()
                })
                .collect();
            let assignment = maximum_weight_assignment(&weights);
            let score: i128 = assignment
                .iter()
                .enumerate()
                .map(|(row, column)| column.map_or(0, |col| weights[row][col]))
                .sum();
            assert_eq!(score, brute_force(&weights, 0, 0), "{weights:?}");
        }
    }

    #[test]
    fn scarce_match_is_reassigned_instead_of_greedily_lost() {
        let weights = vec![vec![100, 99], vec![98, 0]];
        assert_eq!(maximum_weight_assignment(&weights), vec![Some(1), Some(0)]);
    }
}
