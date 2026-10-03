//! Event throttling for RuuviTag measurements.
//!
//! Limits how often measurements are emitted per device, to reduce output
//! volume when tags broadcast frequently but data changes slowly.

use crate::mac_address::MacAddress;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A throttle that limits the rate of events per device (identified by MAC address).
///
/// Each device is tracked independently, allowing at most one event per `interval`
/// duration. The first event for a device is always allowed.
///
/// Stale entries (devices that haven't been seen in a long time) are automatically
/// cleaned up to prevent memory leaks.
///
/// Uses `MacAddress` (6-byte array) instead of String for efficient storage
/// and zero-allocation lookups.
#[derive(Debug)]
pub struct Throttle {
    /// Minimum time between events for each device
    interval: Duration,
    /// Last event time for each MAC address (using efficient MacAddress keys)
    last_seen: HashMap<MacAddress, Instant>,
    /// Counter for periodic cleanup
    check_count: usize,
}

/// Threshold multiplier for stale entry cleanup.
/// Entries older than `CLEANUP_THRESHOLD_MULTIPLIER * interval` are considered stale.
const CLEANUP_THRESHOLD_MULTIPLIER: u32 = 10;

/// Number of `should_emit` calls between cleanup checks.
const CLEANUP_CHECK_INTERVAL: usize = 100;

/// Minimum number of tracked devices before cleanup is considered.
/// Most RuuviTag deployments have fewer than 20 devices, so we only
/// clean up when we have significantly more entries than expected.
const CLEANUP_SIZE_THRESHOLD: usize = 50;

impl Throttle {
    /// Create a new throttle with the specified minimum interval between events.
    ///
    /// # Example
    /// ```
    /// use std::time::Duration;
    /// use ruuvitag_listener::throttle::Throttle;
    ///
    /// let throttle = Throttle::new(Duration::from_secs(3));
    /// ```
    pub fn new(interval: Duration) -> Self {
        Throttle {
            interval,
            last_seen: HashMap::new(),
            check_count: 0,
        }
    }

    /// Check if an event from the given MAC address should be allowed.
    ///
    /// Returns `true` if enough time has passed since the last event from this
    /// device (or if this is the first event). If `true` is returned, the
    /// internal timer for this device is reset.
    ///
    /// Periodically cleans up stale entries to prevent memory leaks.
    pub fn should_emit(&mut self, mac: MacAddress) -> bool {
        // Periodically clean up stale entries, but only if we have enough
        // entries to make it worthwhile
        self.check_count += 1;
        if self.check_count >= CLEANUP_CHECK_INTERVAL {
            self.check_count = 0;
            if self.last_seen.len() > CLEANUP_SIZE_THRESHOLD {
                self.cleanup_stale();
            }
        }

        let now = Instant::now();

        // Use entry API for zero-allocation updates on existing keys
        use std::collections::hash_map::Entry;
        match self.last_seen.entry(mac) {
            Entry::Occupied(mut entry) => {
                if now.duration_since(*entry.get()) < self.interval {
                    false
                } else {
                    entry.insert(now);
                    true
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(now);
                true
            }
        }
    }

    /// Remove stale entries from the throttle.
    ///
    /// Entries are considered stale if they haven't been updated in more than
    /// `CLEANUP_THRESHOLD_MULTIPLIER * interval` time. This prevents memory
    /// leaks when devices stop broadcasting or are removed.
    fn cleanup_stale(&mut self) {
        if self.interval == Duration::ZERO {
            // No cleanup needed for zero interval
            return;
        }

        let threshold = self.interval * CLEANUP_THRESHOLD_MULTIPLIER;
        let now = Instant::now();

        self.last_seen
            .retain(|_mac, last_seen| now.duration_since(*last_seen) <= threshold);
    }
}

/// Error returned when a duration string fails to parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseDurationError {
    /// The input was empty or contained only whitespace.
    #[error("empty duration")]
    Empty,
    /// A segment was not a non-negative integer followed by a unit.
    #[error("invalid number `{token}`")]
    InvalidNumber { token: String },
    /// A unit was not one of `h`, `m`, `s`, or `ms`.
    #[error("unknown unit `{token}`")]
    UnknownUnit { token: String },
    /// A segment in a compound duration was missing its unit.
    #[error("missing unit after `{token}`")]
    MissingUnit { token: String },
    /// The duration exceeds the range of [`std::time::Duration`].
    #[error("duration overflows")]
    Overflow,
}

/// Parse a duration from a human-readable string.
///
/// Supports a single value with an optional suffix, or a compound
/// expression of several values:
/// - `h`: hours
/// - `m`: minutes
/// - `s`: seconds (also the default without a suffix)
/// - `ms`: milliseconds
///
/// Whitespace may appear between the digits and the unit, and between
/// components. A bare number without a unit is only interpreted as
/// seconds when it is the entire input; in a compound expression every
/// component must carry a unit.
///
/// # Examples
/// ```
/// use ruuvitag_listener::throttle::parse_duration;
/// use ruuvitag_listener::throttle::ParseDurationError;
/// use std::time::Duration;
///
/// assert_eq!(parse_duration("3s").unwrap(), Duration::from_secs(3));
/// assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
/// assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
/// assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
/// assert_eq!(parse_duration("1h 30m").unwrap(), Duration::from_secs(5400));
/// assert_eq!(parse_duration("10").unwrap(), Duration::from_secs(10));
/// assert_eq!(
///     parse_duration("1h30"),
///     Err(ParseDurationError::MissingUnit { token: "30".to_string() })
/// );
/// ```
pub fn parse_duration(src: &str) -> Result<Duration, ParseDurationError> {
    let trimmed = src.trim();

    if trimmed.is_empty() {
        return Err(ParseDurationError::Empty);
    }

    let mut total = Duration::ZERO;
    let mut rest = trimmed;
    let mut first = true;

    while !rest.is_empty() {
        rest = rest.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            break;
        }

        let digits_len = rest.chars().take_while(char::is_ascii_digit).count();
        if digits_len == 0 {
            let token = rest.split_whitespace().next().unwrap_or(rest);
            return Err(ParseDurationError::InvalidNumber {
                token: token.to_string(),
            });
        }

        // Whitespace between the digits and the unit is allowed.
        let after_digits = &rest[digits_len..];
        let gap_len = after_digits
            .chars()
            .take_while(|c| matches!(c, ' ' | '\t'))
            .count();
        let unit_start = digits_len + gap_len;
        let unit_len = rest[unit_start..]
            .chars()
            .take_while(|c| c.is_ascii_lowercase())
            .count();
        let unit = &rest[unit_start..unit_start + unit_len];
        let remainder = &rest[unit_start + unit_len..];

        let component = if unit.is_empty() {
            if first && remainder.chars().all(char::is_whitespace) {
                // A bare number for the entire input is seconds.
                // The token is all ASCII digits, so a parse failure is
                // magnitude overflow.
                let secs: u64 = rest[..digits_len]
                    .parse()
                    .map_err(|_| ParseDurationError::Overflow)?;
                Duration::new(secs, 0)
            } else if remainder.starts_with([' ', '\t'])
                || remainder.is_empty()
                || remainder.starts_with(|c: char| c.is_ascii_digit())
            {
                return Err(ParseDurationError::MissingUnit {
                    token: rest[..digits_len].to_string(),
                });
            } else {
                // Non-digit junk right after the digits, e.g. `1.5s`.
                let token = rest.split_whitespace().next().unwrap_or(rest);
                return Err(ParseDurationError::InvalidNumber {
                    token: token.to_string(),
                });
            }
        } else {
            // The token digits are all ASCII digits, so a parse failure
            // is magnitude overflow.
            let digits: u64 = rest[..digits_len]
                .parse()
                .map_err(|_| ParseDurationError::Overflow)?;
            match unit {
                "h" => Duration::new(
                    digits
                        .checked_mul(3600)
                        .ok_or(ParseDurationError::Overflow)?,
                    0,
                ),
                "m" => Duration::new(
                    digits.checked_mul(60).ok_or(ParseDurationError::Overflow)?,
                    0,
                ),
                "s" => Duration::new(digits, 0),
                "ms" => Duration::new(digits / 1000, (digits % 1000 * 1_000_000) as u32),
                _ => {
                    return Err(ParseDurationError::UnknownUnit {
                        token: rest[..digits_len + unit_len].to_string(),
                    });
                }
            }
        };

        first = false;
        total = total
            .checked_add(component)
            .ok_or(ParseDurationError::Overflow)?;
        rest = remainder;
    }

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC1: MacAddress = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    const MAC2: MacAddress = MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    const MAC_ZERO: MacAddress = MacAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    #[test]
    fn allows_first_event_and_blocks_repeats_per_device() {
        let mut throttle = Throttle::new(Duration::from_secs(1));
        assert!(throttle.should_emit(MAC1));
        assert!(throttle.should_emit(MAC2));
        assert!(!throttle.should_emit(MAC1));
        assert!(!throttle.should_emit(MAC2));
    }

    #[test]
    fn allows_every_event_with_zero_interval() {
        let mut throttle = Throttle::new(Duration::ZERO);
        assert!(throttle.should_emit(MAC1));
        assert!(throttle.should_emit(MAC1));
    }

    #[test]
    fn allows_event_after_interval_passes() {
        let mut throttle = Throttle::new(Duration::from_millis(10));
        assert!(throttle.should_emit(MAC1));
        assert!(!throttle.should_emit(MAC1));

        // Wait for the interval to pass
        std::thread::sleep(Duration::from_millis(15));

        // Should now be allowed again
        assert!(throttle.should_emit(MAC1));
    }

    #[test]
    fn tracks_many_devices_independently() {
        let mut throttle = Throttle::new(Duration::from_secs(1));

        let macs: Vec<MacAddress> = (0u8..100)
            .map(|i| MacAddress([i, i.wrapping_add(1), 0xCC, 0xDD, 0xEE, 0xFF]))
            .collect();

        // First event from each should be allowed
        for mac in &macs {
            assert!(
                throttle.should_emit(*mac),
                "First event for {} should be allowed",
                mac
            );
        }

        // Second event from each should be blocked
        for mac in &macs {
            assert!(
                !throttle.should_emit(*mac),
                "Second event for {} should be blocked",
                mac
            );
        }
    }

    #[test]
    fn treats_zero_mac_as_valid_key() {
        let mut throttle = Throttle::new(Duration::from_secs(1));

        // Zero address is a valid key
        assert!(throttle.should_emit(MAC_ZERO));
        assert!(!throttle.should_emit(MAC_ZERO));
    }

    #[test]
    fn resets_timer_on_emit() {
        let mut throttle = Throttle::new(Duration::from_millis(20));

        assert!(throttle.should_emit(MAC1));

        // Wait partial interval
        std::thread::sleep(Duration::from_millis(15));
        assert!(!throttle.should_emit(MAC1));

        // Wait for full interval from first emit
        std::thread::sleep(Duration::from_millis(10));
        assert!(throttle.should_emit(MAC1)); // Allowed - timer reset here

        // Immediately after, should be blocked again
        assert!(!throttle.should_emit(MAC1));
    }

    #[test]
    fn blocked_event_does_not_reset_timer() {
        let mut throttle = Throttle::new(Duration::from_millis(30));

        assert!(throttle.should_emit(MAC1)); // t=0, timer starts

        std::thread::sleep(Duration::from_millis(10));
        assert!(!throttle.should_emit(MAC1)); // t=10, blocked, timer NOT reset

        std::thread::sleep(Duration::from_millis(10));
        assert!(!throttle.should_emit(MAC1)); // t=20, still blocked

        std::thread::sleep(Duration::from_millis(15));
        // t=35, now past the 30ms interval from t=0
        assert!(throttle.should_emit(MAC1)); // Should be allowed
    }

    #[test]
    fn parses_valid_durations() {
        let cases = [
            ("3s", Duration::from_secs(3)),
            ("30s", Duration::from_secs(30)),
            ("0s", Duration::from_secs(0)),
            ("0", Duration::from_secs(0)),
            ("1m", Duration::from_secs(60)),
            ("5m", Duration::from_secs(300)),
            ("1h", Duration::from_secs(3600)),
            ("2h", Duration::from_secs(7200)),
            ("500ms", Duration::from_millis(500)),
            ("1000ms", Duration::from_millis(1000)),
            ("10", Duration::from_secs(10)),
            (" 3s ", Duration::from_secs(3)),
            ("3 s", Duration::from_secs(3)),
            ("1h30m", Duration::from_secs(5400)),
            ("1h 30m", Duration::from_secs(5400)),
            ("2m500ms", Duration::from_millis(120_500)),
            ("90s", Duration::from_secs(90)),
            ("1h30m10s", Duration::from_secs(5410)),
            ("1h\t30m", Duration::from_secs(5400)),
        ];
        for (src, expected) in cases {
            assert_eq!(parse_duration(src).unwrap(), expected, "{src:?}");
        }
    }

    #[test]
    fn rejects_invalid_durations() {
        use ParseDurationError::*;

        let cases = [
            ("", Empty),
            ("   ", Empty),
            (
                "abc",
                InvalidNumber {
                    token: "abc".to_string(),
                },
            ),
            (
                "1.5s",
                InvalidNumber {
                    token: "1.5s".to_string(),
                },
            ),
            (
                "-5s",
                InvalidNumber {
                    token: "-5s".to_string(),
                },
            ),
            (
                "1h30",
                MissingUnit {
                    token: "30".to_string(),
                },
            ),
            (
                "1h 30",
                MissingUnit {
                    token: "30".to_string(),
                },
            ),
            (
                "5x",
                UnknownUnit {
                    token: "5x".to_string(),
                },
            ),
            (
                "5min",
                UnknownUnit {
                    token: "5min".to_string(),
                },
            ),
            ("99999999999999999999h", Overflow),
            ("18446744073709551616s", Overflow),
        ];
        for (src, expected) in cases {
            assert_eq!(parse_duration(src), Err(expected), "{src:?}");
        }
    }

    #[test]
    fn overflow_components_sum_to_overflow() {
        use ParseDurationError::*;

        assert_eq!(
            parse_duration("9223372036854775808h 9223372036854775808h"),
            Err(Overflow)
        );
        assert_eq!(parse_duration("18446744073709551615s1s"), Err(Overflow));
        // Each component fits, but the sum overflows.
        assert_eq!(
            parse_duration("99999999999999999999h")
                .unwrap_err()
                .to_string(),
            "duration overflows"
        );
    }

    #[test]
    fn overflow_does_not_panic_in_debug() {
        // Huge values exercise checked arithmetic without panicking.
        for src in [
            "99999999999999999999h",
            "18446744073709551616s",
            "18446744073709551615m",
            "18446744073709551615s1s",
        ] {
            assert_eq!(parse_duration(src), Err(ParseDurationError::Overflow));
        }
    }

    #[test]
    fn cleanup_removes_stale_entries() {
        let mut throttle = Throttle::new(Duration::from_millis(10));

        assert!(throttle.should_emit(MAC1));
        assert!(throttle.should_emit(MAC2));

        // Verify both are tracked
        assert_eq!(throttle.last_seen.len(), 2);

        // Manually set one entry to be very old (simulating stale device)
        let old_time = Instant::now() - Duration::from_millis(200); // 20x the interval
        throttle.last_seen.insert(MAC1, old_time);

        // Trigger cleanup
        throttle.cleanup_stale();

        // Stale entry should be removed, active entry should remain
        assert!(!throttle.last_seen.contains_key(&MAC1));
        assert!(throttle.last_seen.contains_key(&MAC2));
    }

    #[test]
    fn cleanup_preserves_recent_entries() {
        let mut throttle = Throttle::new(Duration::from_millis(10));

        assert!(throttle.should_emit(MAC1));
        assert!(throttle.should_emit(MAC2));

        // Both entries are recent, cleanup should preserve both
        throttle.cleanup_stale();

        assert!(throttle.last_seen.contains_key(&MAC1));
        assert!(throttle.last_seen.contains_key(&MAC2));
    }

    #[test]
    fn cleanup_is_noop_for_zero_interval() {
        let mut throttle = Throttle::new(Duration::ZERO);

        assert!(throttle.should_emit(MAC1));
        assert_eq!(throttle.last_seen.len(), 1);

        // Cleanup with zero interval should be a no-op
        throttle.cleanup_stale();

        // Entry should still be there
        assert!(throttle.last_seen.contains_key(&MAC1));
    }

    #[test]
    fn periodic_cleanup_removes_stale_entries() {
        let mut throttle = Throttle::new(Duration::from_millis(10));

        let old_time = Instant::now() - Duration::from_millis(200);
        throttle.last_seen.insert(MAC1, old_time);

        // Add enough entries to exceed CLEANUP_SIZE_THRESHOLD
        for i in 0..(CLEANUP_SIZE_THRESHOLD + 10) as u8 {
            let mac = MacAddress([i, i.wrapping_add(1), 0x00, 0x00, 0x00, 0x00]);
            throttle.should_emit(mac);
        }

        let trigger_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Call should_emit enough times to trigger cleanup check
        for _ in 0..CLEANUP_CHECK_INTERVAL {
            throttle.should_emit(trigger_mac);
        }

        // Stale entry should be cleaned up
        assert!(!throttle.last_seen.contains_key(&MAC1));
    }

    #[test]
    fn no_cleanup_below_size_threshold() {
        let mut throttle = Throttle::new(Duration::from_millis(10));

        let old_time = Instant::now() - Duration::from_millis(200);
        throttle.last_seen.insert(MAC1, old_time);

        // Add fewer entries than CLEANUP_SIZE_THRESHOLD
        for i in 0..10u8 {
            let mac = MacAddress([i, 0x00, 0x00, 0x00, 0x00, 0x00]);
            throttle.should_emit(mac);
        }

        let trigger_mac = MacAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Trigger check interval multiple times
        for _ in 0..CLEANUP_CHECK_INTERVAL * 2 {
            throttle.should_emit(trigger_mac);
        }

        // Stale entry should still exist (cleanup was skipped due to size threshold)
        assert!(throttle.last_seen.contains_key(&MAC1));
    }

    #[test]
    fn cleanup_on_empty_map_is_noop() {
        let mut throttle = Throttle::new(Duration::from_secs(1));

        // Cleanup on empty map should not panic
        throttle.cleanup_stale();
        assert_eq!(throttle.last_seen.len(), 0);
    }
}
