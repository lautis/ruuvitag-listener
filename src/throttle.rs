//! Event throttling for RuuviTag measurements.
//!
//! This module provides per-device throttling to limit how often measurements
//! are emitted for each individual RuuviTag. This is useful for reducing output
//! volume when tags broadcast frequently but data changes slowly.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A throttle that limits the rate of events per device (identified by MAC address).
///
/// Each device is tracked independently, allowing at most one event per `interval`
/// duration. The first event for a device is always allowed.
///
/// Stale entries (devices that haven't been seen in a long time) are automatically
/// cleaned up to prevent memory leaks.
#[derive(Debug)]
pub struct Throttle {
    /// Minimum time between events for each device
    interval: Duration,
    /// Last event time for each MAC address
    last_seen: HashMap<String, Instant>,
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
    /// # Arguments
    /// * `interval` - Minimum duration between events for each device
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
    ///
    /// # Arguments
    /// * `mac` - The MAC address of the device
    ///
    /// # Returns
    /// `true` if the event should be emitted, `false` if it should be throttled
    pub fn should_emit(&mut self, mac: &str) -> bool {
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

        match self.last_seen.get(mac) {
            Some(last) if now.duration_since(*last) < self.interval => false,
            _ => {
                self.last_seen.insert(mac.to_string(), now);
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

/// Parse a duration from a human-readable string.
///
/// Supports the following suffixes:
/// - `s` or no suffix: seconds
/// - `m`: minutes  
/// - `h`: hours
/// - `ms`: milliseconds
///
/// # Arguments
/// * `src` - A string like "3s", "1m", "500ms", or "30"
///
/// # Returns
/// A Result containing the parsed Duration or an error message.
///
/// # Examples
/// ```
/// use ruuvitag_listener::throttle::parse_duration;
/// use std::time::Duration;
///
/// assert_eq!(parse_duration("3s").unwrap(), Duration::from_secs(3));
/// assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
/// assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
/// ```
pub fn parse_duration(src: &str) -> Result<Duration, String> {
    let src = src.trim();

    if src.is_empty() {
        return Err("empty duration string".to_string());
    }

    // Try parsing with different suffixes
    if let Some(num) = src.strip_suffix("ms") {
        let millis: u64 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid milliseconds: {}", num))?;
        return Ok(Duration::from_millis(millis));
    }

    if let Some(num) = src.strip_suffix('h') {
        let hours: u64 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid hours: {}", num))?;
        return Ok(Duration::from_secs(hours * 3600));
    }

    if let Some(num) = src.strip_suffix('m') {
        let minutes: u64 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid minutes: {}", num))?;
        return Ok(Duration::from_secs(minutes * 60));
    }

    if let Some(num) = src.strip_suffix('s') {
        let secs: u64 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid seconds: {}", num))?;
        return Ok(Duration::from_secs(secs));
    }

    // No suffix, treat as seconds
    let secs: u64 = src
        .parse()
        .map_err(|_| format!("invalid duration: {}", src))?;
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_throttle_first_event_allowed() {
        let mut throttle = Throttle::new(Duration::from_secs(1));
        assert!(throttle.should_emit("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_throttle_immediate_second_event_blocked() {
        let mut throttle = Throttle::new(Duration::from_secs(1));
        assert!(throttle.should_emit("AA:BB:CC:DD:EE:FF"));
        assert!(!throttle.should_emit("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_throttle_different_devices_independent() {
        let mut throttle = Throttle::new(Duration::from_secs(1));
        assert!(throttle.should_emit("AA:BB:CC:DD:EE:FF"));
        assert!(throttle.should_emit("11:22:33:44:55:66"));
        assert!(!throttle.should_emit("AA:BB:CC:DD:EE:FF"));
        assert!(!throttle.should_emit("11:22:33:44:55:66"));
    }

    #[test]
    fn test_throttle_zero_interval() {
        let mut throttle = Throttle::new(Duration::ZERO);
        assert!(throttle.should_emit("AA:BB:CC:DD:EE:FF"));
        assert!(throttle.should_emit("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_throttle_allowed_after_interval_passes() {
        let mut throttle = Throttle::new(Duration::from_millis(10));
        assert!(throttle.should_emit("AA:BB:CC:DD:EE:FF"));
        assert!(!throttle.should_emit("AA:BB:CC:DD:EE:FF"));

        // Wait for the interval to pass
        std::thread::sleep(Duration::from_millis(15));

        // Should now be allowed again
        assert!(throttle.should_emit("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn test_throttle_multiple_rapid_events_only_first_allowed() {
        let mut throttle = Throttle::new(Duration::from_secs(1));
        let mac = "AA:BB:CC:DD:EE:FF";

        // First event allowed
        assert!(throttle.should_emit(mac));

        // All subsequent rapid events blocked
        for _ in 0..10 {
            assert!(!throttle.should_emit(mac));
        }
    }

    #[test]
    fn test_throttle_alternating_devices() {
        let mut throttle = Throttle::new(Duration::from_secs(1));
        let mac1 = "AA:BB:CC:DD:EE:FF";
        let mac2 = "11:22:33:44:55:66";

        // First events from each device allowed
        assert!(throttle.should_emit(mac1));
        assert!(throttle.should_emit(mac2));

        // Alternating rapid events all blocked
        assert!(!throttle.should_emit(mac1));
        assert!(!throttle.should_emit(mac2));
        assert!(!throttle.should_emit(mac1));
        assert!(!throttle.should_emit(mac2));
    }

    #[test]
    fn test_throttle_many_devices() {
        let mut throttle = Throttle::new(Duration::from_secs(1));

        // Create 100 different MAC addresses
        let macs: Vec<String> = (0..100)
            .map(|i| format!("{:02X}:{:02X}:CC:DD:EE:FF", i / 256, i % 256))
            .collect();

        // First event from each should be allowed
        for mac in &macs {
            assert!(
                throttle.should_emit(mac),
                "First event for {} should be allowed",
                mac
            );
        }

        // Second event from each should be blocked
        for mac in &macs {
            assert!(
                !throttle.should_emit(mac),
                "Second event for {} should be blocked",
                mac
            );
        }
    }

    #[test]
    fn test_throttle_empty_mac_address() {
        let mut throttle = Throttle::new(Duration::from_secs(1));

        // Empty string is a valid key
        assert!(throttle.should_emit(""));
        assert!(!throttle.should_emit(""));
    }

    #[test]
    fn test_throttle_timer_resets_on_emit() {
        let mut throttle = Throttle::new(Duration::from_millis(20));
        let mac = "AA:BB:CC:DD:EE:FF";

        assert!(throttle.should_emit(mac));

        // Wait partial interval
        std::thread::sleep(Duration::from_millis(15));
        assert!(!throttle.should_emit(mac));

        // Wait for full interval from first emit
        std::thread::sleep(Duration::from_millis(10));
        assert!(throttle.should_emit(mac)); // Allowed - timer reset here

        // Immediately after, should be blocked again
        assert!(!throttle.should_emit(mac));
    }

    #[test]
    fn test_throttle_blocked_event_does_not_reset_timer() {
        let mut throttle = Throttle::new(Duration::from_millis(30));
        let mac = "AA:BB:CC:DD:EE:FF";

        assert!(throttle.should_emit(mac)); // t=0, timer starts

        std::thread::sleep(Duration::from_millis(10));
        assert!(!throttle.should_emit(mac)); // t=10, blocked, timer NOT reset

        std::thread::sleep(Duration::from_millis(10));
        assert!(!throttle.should_emit(mac)); // t=20, still blocked

        std::thread::sleep(Duration::from_millis(15));
        // t=35, now past the 30ms interval from t=0
        assert!(throttle.should_emit(mac)); // Should be allowed
    }

    #[test]
    fn test_throttle_case_sensitive_mac() {
        let mut throttle = Throttle::new(Duration::from_secs(1));

        // MAC addresses are case-sensitive (as strings)
        assert!(throttle.should_emit("AA:BB:CC:DD:EE:FF"));
        assert!(throttle.should_emit("aa:bb:cc:dd:ee:ff")); // Different key

        assert!(!throttle.should_emit("AA:BB:CC:DD:EE:FF"));
        assert!(!throttle.should_emit("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("3s").unwrap(), Duration::from_secs(3));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("0s").unwrap(), Duration::from_secs(0));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn test_parse_duration_milliseconds() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(
            parse_duration("1000ms").unwrap(),
            Duration::from_millis(1000)
        );
    }

    #[test]
    fn test_parse_duration_no_suffix() {
        assert_eq!(parse_duration("10").unwrap(), Duration::from_secs(10));
    }

    #[test]
    fn test_parse_duration_with_whitespace() {
        assert_eq!(parse_duration(" 3s ").unwrap(), Duration::from_secs(3));
        assert_eq!(parse_duration("3 s").unwrap(), Duration::from_secs(3));
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("-1s").is_err());
    }

    #[test]
    fn test_throttle_cleanup_stale_entries() {
        let mut throttle = Throttle::new(Duration::from_millis(10));
        let mac1 = "AA:BB:CC:DD:EE:FF";
        let mac2 = "11:22:33:44:55:66";

        // Add entries for two devices
        assert!(throttle.should_emit(mac1));
        assert!(throttle.should_emit(mac2));

        // Verify both are tracked
        assert_eq!(throttle.last_seen.len(), 2);

        // Manually set one entry to be very old (simulating stale device)
        let old_time = Instant::now() - Duration::from_millis(200); // 20x the interval
        throttle.last_seen.insert(mac1.to_string(), old_time);

        // Trigger cleanup
        throttle.cleanup_stale();

        // Stale entry should be removed, active entry should remain
        assert!(!throttle.last_seen.contains_key(mac1));
        assert!(throttle.last_seen.contains_key(mac2));
    }

    #[test]
    fn test_throttle_cleanup_preserves_recent_entries() {
        let mut throttle = Throttle::new(Duration::from_millis(10));
        let mac1 = "AA:BB:CC:DD:EE:FF";
        let mac2 = "11:22:33:44:55:66";

        assert!(throttle.should_emit(mac1));
        assert!(throttle.should_emit(mac2));

        // Both entries are recent, cleanup should preserve both
        throttle.cleanup_stale();

        assert!(throttle.last_seen.contains_key(mac1));
        assert!(throttle.last_seen.contains_key(mac2));
    }

    #[test]
    fn test_throttle_cleanup_zero_interval() {
        let mut throttle = Throttle::new(Duration::ZERO);
        let mac = "AA:BB:CC:DD:EE:FF";

        assert!(throttle.should_emit(mac));
        assert_eq!(throttle.last_seen.len(), 1);

        // Cleanup with zero interval should be a no-op
        throttle.cleanup_stale();

        // Entry should still be there
        assert!(throttle.last_seen.contains_key(mac));
    }

    #[test]
    fn test_throttle_periodic_cleanup() {
        let mut throttle = Throttle::new(Duration::from_millis(10));
        let stale_mac = "AA:BB:CC:DD:EE:FF";

        // Add a stale entry
        let old_time = Instant::now() - Duration::from_millis(200);
        throttle.last_seen.insert(stale_mac.to_string(), old_time);

        // Add enough entries to exceed CLEANUP_SIZE_THRESHOLD
        for i in 0..CLEANUP_SIZE_THRESHOLD + 10 {
            let mac = format!("{:02X}:{:02X}:00:00:00:00", i / 256, i % 256);
            throttle.should_emit(&mac);
        }

        // Call should_emit enough times to trigger cleanup check
        for _ in 0..CLEANUP_CHECK_INTERVAL {
            throttle.should_emit("FF:FF:FF:FF:FF:FF");
        }

        // Stale entry should be cleaned up
        assert!(!throttle.last_seen.contains_key(stale_mac));
    }

    #[test]
    fn test_throttle_no_cleanup_below_size_threshold() {
        let mut throttle = Throttle::new(Duration::from_millis(10));
        let stale_mac = "AA:BB:CC:DD:EE:FF";

        // Add a stale entry
        let old_time = Instant::now() - Duration::from_millis(200);
        throttle.last_seen.insert(stale_mac.to_string(), old_time);

        // Add fewer entries than CLEANUP_SIZE_THRESHOLD
        for i in 0..10 {
            let mac = format!("{:02X}:00:00:00:00:00", i);
            throttle.should_emit(&mac);
        }

        // Trigger check interval multiple times
        for _ in 0..CLEANUP_CHECK_INTERVAL * 2 {
            throttle.should_emit("FF:FF:FF:FF:FF:FF");
        }

        // Stale entry should still exist (cleanup was skipped due to size threshold)
        assert!(throttle.last_seen.contains_key(stale_mac));
    }

    #[test]
    fn test_throttle_cleanup_empty_map() {
        let mut throttle = Throttle::new(Duration::from_secs(1));

        // Cleanup on empty map should not panic
        throttle.cleanup_stale();
        assert_eq!(throttle.last_seen.len(), 0);
    }
}
