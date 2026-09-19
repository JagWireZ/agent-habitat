//! Resource-limit config: CPU/memory caps enforced at VM launch
//! (`crates/vm`). No separate "disk limit" field -- the workspace
//! staging directory is bind-mounted, not a fixed-size built image, so
//! its size is simply bounded by host disk space (per
//! `docs/decisions/0005-storage-layer.md`'s Correction section).

use std::fmt;

/// CPU/memory caps applied to a session's microVM at launch.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResourceLimitsConfig {
    pub cpus: f64,
    pub memory_mb: u64,
}

impl Default for ResourceLimitsConfig {
    fn default() -> Self {
        // Enough headroom for a typical build/test workload without assuming a beefy host.
        ResourceLimitsConfig {
            cpus: 2.0,
            memory_mb: 2048,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLimitsError {
    pub message: String,
}

impl fmt::Display for ResourceLimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "resource_limits: {}", self.message)
    }
}

impl std::error::Error for ResourceLimitsError {}

impl ResourceLimitsConfig {
    /// Parses a `cpus` scalar (e.g. `"2"`, `"1.5"`). A hard error on
    /// anything non-numeric or not strictly positive -- never silently
    /// clamped to the default.
    pub fn parse_cpus(value: &str) -> Result<f64, ResourceLimitsError> {
        let cpus: f64 = value.trim().parse().map_err(|_| ResourceLimitsError {
            message: format!("cpus: expected a positive number, got {value:?}"),
        })?;
        // Negated `>` (not `<= 0.0`) so a NaN input (accepted by f64::parse) is
        // also rejected -- `NaN <= 0.0` is false and would let it through.
        #[allow(clippy::neg_cmp_op_on_partial_ord)]
        if !(cpus > 0.0) {
            return Err(ResourceLimitsError {
                message: format!("cpus: must be greater than 0, got {value:?}"),
            });
        }
        Ok(cpus)
    }

    /// Parses a `memory_mb` scalar. A hard error on anything non-numeric
    /// or zero.
    pub fn parse_memory_mb(value: &str) -> Result<u64, ResourceLimitsError> {
        let mb: u64 = value.trim().parse().map_err(|_| ResourceLimitsError {
            message: format!("memory_mb: expected a positive whole number, got {value:?}"),
        })?;
        if mb == 0 {
            return Err(ResourceLimitsError {
                message: format!("memory_mb: must be greater than 0, got {value:?}"),
            });
        }
        Ok(mb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible_and_nonzero() {
        let d = ResourceLimitsConfig::default();
        assert!(d.cpus > 0.0);
        assert!(d.memory_mb > 0);
    }

    #[test]
    fn parses_valid_cpus() {
        assert_eq!(ResourceLimitsConfig::parse_cpus("2").unwrap(), 2.0);
        assert_eq!(ResourceLimitsConfig::parse_cpus("1.5").unwrap(), 1.5);
    }

    #[test]
    fn rejects_non_numeric_or_non_positive_cpus() {
        assert!(ResourceLimitsConfig::parse_cpus("abc").is_err());
        assert!(ResourceLimitsConfig::parse_cpus("0").is_err());
        assert!(ResourceLimitsConfig::parse_cpus("-1").is_err());
    }

    #[test]
    fn parses_valid_memory_mb() {
        assert_eq!(ResourceLimitsConfig::parse_memory_mb("4096").unwrap(), 4096);
    }

    #[test]
    fn rejects_non_numeric_or_zero_memory_mb() {
        assert!(ResourceLimitsConfig::parse_memory_mb("abc").is_err());
        assert!(ResourceLimitsConfig::parse_memory_mb("0").is_err());
    }
}
