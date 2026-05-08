#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn chain_severity_rank_and_label_are_stable() {
        assert_eq!(ChainSeverity::Critical.rank(), 0);
        assert_eq!(ChainSeverity::High.rank(), 1);
        assert_eq!(ChainSeverity::Medium.rank(), 2);

        assert_eq!(ChainSeverity::Critical.label(), "CRIT");
        assert_eq!(ChainSeverity::High.label(), "HIGH");
        assert_eq!(ChainSeverity::Medium.label(), "MED");
    }
}
