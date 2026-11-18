//! Additive-Increase / Multiplicative-Decrease (AIMD) rate controller for the
//! raw SYN engine.
//!
//! # Design
//!
//! The controller tracks the ratio of responses received to probes sent over an
//! exponential moving average (EMA) window.  When the response ratio drops below
//! a configurable threshold (default 80 %) it applies a multiplicative decrease
//! (`rate /= decrease_factor`).  When the ratio stays above the threshold it
//! applies an additive increase (`rate += step_pps`).  Both `min_pps` and
//! `max_pps` clamp the resulting rate.
//!
//! Explicit target-politeness feedback bypasses the normal ratio logic:
//! ICMP-error bursts and tarpit-like SYN-open pressure always trigger a
//! multiplicative decrease, including when the response ratio is too low for
//! the ordinary silent-path floor to act.
//!
//! # Thread safety
//!
//! `AimdController` is `!Send`; it must live entirely in the TX thread.  The TX
//! thread calls `update()` after draining each response batch; no locking is
//! required.

/// Explicit target-politeness feedback for one AIMD update window.
#[derive(Clone, Copy, Debug, Default)]
pub struct AimdFeedback {
    /// ICMP Destination Unreachable (or equivalent) messages observed in the
    /// window.  A ratio at or above `AimdConfig::icmp_error_threshold` forces a
    /// multiplicative decrease.
    pub icmp_errors: u64,
    /// The coordinator observed a high-density SYN-open host in this window.
    /// This is a tarpit/SYN-proxy signal and forces a multiplicative decrease.
    pub tarpit_pressure: bool,
}

/// Configuration for the AIMD rate controller.
#[derive(Clone, Debug)]
pub struct AimdConfig {
    /// Initial transmit rate in packets per second.  Also the additive ceiling.
    pub initial_pps: u64,
    /// Lower bound: AIMD will never go below this rate.
    pub min_pps: u64,
    /// Upper bound: additive increase stops here.
    pub max_pps: u64,
    /// Additive increase step in packets per second applied each update that is
    /// above the response-rate threshold.
    pub step_pps: u64,
    /// Multiplicative decrease factor applied on loss.  The rate is divided by
    /// this value.  Typical value: 2.0.
    pub decrease_factor: f64,
    /// Response ratio below which a multiplicative decrease is triggered.
    /// Expressed as a fraction in [0, 1].  Typical value: 0.80.
    pub loss_threshold: f64,
    /// ICMP-error ratio at or above which a multiplicative decrease is forced.
    /// Expressed as a fraction in [0, 1].  Typical value: 0.05.
    pub icmp_error_threshold: f64,
    /// EMA smoothing coefficient α in [0, 1].  Higher means more weight on
    /// recent observations.  Typical value: 0.25.
    pub ema_alpha: f64,
}

impl Default for AimdConfig {
    fn default() -> Self {
        Self {
            initial_pps: 0, // 0 means unlimited; override before use
            min_pps: 100,
            max_pps: u64::MAX,
            step_pps: 100,
            decrease_factor: 2.0,
            loss_threshold: 0.80,
            icmp_error_threshold: 0.05,
            ema_alpha: 0.25,
        }
    }
}

/// AIMD rate controller state.
#[derive(Debug)]
pub struct AimdController {
    cfg: AimdConfig,
    /// Current rate in packets per second.
    rate: u64,
    /// EMA of the response ratio (responses / probes sent), initialised to 1.0.
    ema_ratio: f64,
    /// Whether AIMD is actually active.  When `initial_pps == 0` (unlimited)
    /// the controller is a no-op.
    enabled: bool,
}

impl AimdController {
    /// Create a new controller from the given configuration.
    ///
    /// The configured floor is clamped to the ceiling so a low `--rate` cap can
    /// never be exceeded by the minimum-rate default.
    pub fn new(cfg: AimdConfig) -> Self {
        let enabled = cfg.initial_pps > 0;
        let max_pps = if cfg.max_pps == 0 || cfg.max_pps == u64::MAX {
            cfg.initial_pps.max(1)
        } else {
            cfg.max_pps
        };
        let min_pps = cfg.min_pps.min(max_pps).max(1);
        let cfg = AimdConfig {
            min_pps,
            max_pps,
            ..cfg
        };
        let rate = if enabled {
            cfg.initial_pps.clamp(min_pps, max_pps)
        } else {
            0
        };
        Self {
            cfg,
            rate,
            ema_ratio: 1.0,
            enabled,
        }
    }

    /// Return the current transmit rate in packets per second.
    ///
    /// A return value of `0` means unlimited (AIMD disabled).
    pub fn rate_pps(&self) -> u64 {
        if self.enabled { self.rate } else { 0 }
    }

    /// Update the controller with the number of probes sent and responses
    /// received since the last call.  Returns the new rate.
    ///
    /// `sent` must be > 0; if `sent == 0` the controller is left unchanged.
    pub fn update(&mut self, sent: u64, received: u64) -> u64 {
        self.update_with_feedback(sent, received, AimdFeedback::default())
    }

    /// Update the controller with response counts and explicit
    /// target-politeness feedback.
    pub fn update_with_feedback(
        &mut self,
        sent: u64,
        received: u64,
        feedback: AimdFeedback,
    ) -> u64 {
        if !self.enabled || sent == 0 {
            return self.rate_pps();
        }

        let icmp_ratio = feedback.icmp_errors as f64 / sent as f64;
        if feedback.icmp_errors > 0 && icmp_ratio >= self.cfg.icmp_error_threshold {
            self.apply_decrease();
            return self.rate;
        }
        if feedback.tarpit_pressure {
            self.apply_decrease();
            return self.rate;
        }

        // A silent path answers nothing regardless of the transmit rate: sub
        // 1-percent response samples carry no congestion signal and a decrease
        // would just stall the scan (firewalls and NATs commonly drop RST
        // replies).  Freeze the rate instead; partial responses still feed the
        // regular AIMD logic.  Explicit ICMP/tarpit feedback above bypasses
        // this floor because it is direct evidence of target pressure.
        let ratio = (received as f64) / (sent as f64);
        if ratio < 0.01 {
            return self.rate_pps();
        }

        self.ema_ratio = self.cfg.ema_alpha * ratio + (1.0 - self.cfg.ema_alpha) * self.ema_ratio;

        if self.ema_ratio < self.cfg.loss_threshold {
            self.apply_decrease();
        } else {
            // Additive increase
            self.rate = self
                .rate
                .saturating_add(self.cfg.step_pps)
                .clamp(self.cfg.min_pps, self.cfg.max_pps);
        }

        self.rate
    }

    fn apply_decrease(&mut self) {
        let new_rate = ((self.rate as f64) / self.cfg.decrease_factor).round() as u64;
        self.rate = new_rate.clamp(self.cfg.min_pps, self.cfg.max_pps);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller(initial: u64) -> AimdController {
        AimdController::new(AimdConfig {
            initial_pps: initial,
            min_pps: 100,
            max_pps: 10_000,
            step_pps: 100,
            decrease_factor: 2.0,
            loss_threshold: 0.80,
            icmp_error_threshold: 0.05,
            ema_alpha: 1.0, // instant EMA for deterministic tests
        })
    }

    #[test]
    fn additive_increase_on_full_response_rate() {
        let mut ctrl = controller(1000);
        for i in 1..=5 {
            let new_rate = ctrl.update(100, 100);
            assert_eq!(new_rate, 1000 + i * 100, "step {i}");
        }
    }

    #[test]
    fn multiplicative_decrease_on_loss() {
        let mut ctrl = controller(1000);
        // 50% response ratio → below 80% threshold → halve the rate
        let new_rate = ctrl.update(100, 50);
        assert_eq!(new_rate, 500);
    }

    #[test]
    fn zero_received_freezes_rate() {
        let mut ctrl = controller(1000);
        // A silent path is not congestion evidence; keep the configured rate.
        ctrl.update(1000, 0);
        ctrl.update(4096, 1);
        assert_eq!(ctrl.rate_pps(), 1000);
    }

    #[test]
    fn icmp_error_burst_decreases_even_without_responses() {
        let mut ctrl = controller(1000);
        ctrl.update_with_feedback(
            100,
            0,
            AimdFeedback {
                icmp_errors: 10,
                tarpit_pressure: false,
            },
        );
        assert_eq!(ctrl.rate_pps(), 500);
    }

    #[test]
    fn icmp_error_pressure_overrides_a_healthy_response_ratio() {
        let mut ctrl = controller(1000);
        ctrl.update_with_feedback(
            100,
            100,
            AimdFeedback {
                icmp_errors: 5,
                tarpit_pressure: false,
            },
        );
        assert_eq!(ctrl.rate_pps(), 500);
    }

    #[test]
    fn sparse_icmp_errors_do_not_break_the_silent_path_floor() {
        let mut ctrl = controller(1000);
        ctrl.update_with_feedback(
            1000,
            0,
            AimdFeedback {
                icmp_errors: 1,
                tarpit_pressure: false,
            },
        );
        assert_eq!(ctrl.rate_pps(), 1000);
    }

    #[test]
    fn tarpit_pressure_decreases_the_rate() {
        let mut ctrl = controller(1000);
        ctrl.update_with_feedback(
            100,
            100,
            AimdFeedback {
                icmp_errors: 0,
                tarpit_pressure: true,
            },
        );
        assert_eq!(ctrl.rate_pps(), 500);
    }

    #[test]
    fn minimum_rate_is_clamped_to_the_configured_ceiling() {
        let ctrl = AimdController::new(AimdConfig {
            initial_pps: 20,
            min_pps: 100,
            max_pps: 20,
            step_pps: 10,
            decrease_factor: 2.0,
            loss_threshold: 0.80,
            icmp_error_threshold: 0.05,
            ema_alpha: 1.0,
        });
        assert_eq!(ctrl.rate_pps(), 20);
    }

    #[test]
    fn rate_clamps_to_min() {
        let mut ctrl = controller(200);
        // Force several decreases with heavy partial loss
        for _ in 0..10 {
            ctrl.update(100, 1);
        }
        assert_eq!(ctrl.rate_pps(), 100, "must not go below min_pps");
    }

    #[test]
    fn rate_clamps_to_max() {
        let mut ctrl = controller(1000);
        // Force many increases
        for _ in 0..200 {
            ctrl.update(100, 100);
        }
        assert_eq!(ctrl.rate_pps(), 10_000, "must not exceed max_pps");
    }

    #[test]
    fn zero_initial_rate_is_disabled() {
        let mut ctrl = AimdController::new(AimdConfig {
            initial_pps: 0,
            ..AimdConfig::default()
        });
        ctrl.update(1000, 0); // severe loss
        assert_eq!(ctrl.rate_pps(), 0, "unlimited mode must stay unlimited");
    }

    #[test]
    fn zero_sent_is_a_no_op() {
        let mut ctrl = controller(1000);
        let rate_before = ctrl.rate_pps();
        ctrl.update(0, 0);
        assert_eq!(ctrl.rate_pps(), rate_before);
    }
}
