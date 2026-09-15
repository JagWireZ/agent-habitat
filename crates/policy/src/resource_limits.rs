//! Resource-limit config: CPU/memory caps enforced at VM launch (Phase 3,
//! `crates/vm`). There is deliberately no separate "disk limit" field
//! here -- the disk cap is just the size of the session's disk image,
//! already fixed at build time by `habitat-workspace`'s
//! `pipeline::BuildRequest::image_size_mb` (Phase 2); duplicating that as
//! a second config knob would give two places to keep in sync for one
//! value.
//!
//! Same "hand-rolled slice now, Phase 7 owns the full schema" note as
//! `crate::config`'s doc comment: Phase 7 assembles the operator-facing
//! `--config` file and may add per-project overrides beyond these two
//! fields; this crate only defines what Phase 3 actually reads today.

use std::fmt;

/// CPU/memory caps applied to a session's microVM at launch.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResourceLimitsConfig {
    pub cpus: f64,
    pub memory_mb: u64,
}

impl Default for ResourceLimitsConfig {
    fn default() -> Self {
        // Sensible defaults for a single-operator coding-agent session --
        // enough headroom for a typical build/test workload without
        // assuming a beefy host. Per-project overrides are a Phase 7
        // concern; this is only the built-in fallback.
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
        // Written as a negated `>` rather than `<= 0.0` so a NaN input
        // (e.g. a literal "NaN" string, which `f64::parse` accepts) is
        // also rejected -- `NaN <= 0.0` is false, which would wrongly
        // let it through.
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
