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
#[derive(Debug)]
pub struct Throttle {
    /// Minimum time between events for each device
    interval: Duration,
    /// Last event time for each MAC address
    last_seen: HashMap<String, Instant>,
}

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
        }
    }

    /// Check if an event from the given MAC address should be allowed.
    ///
    /// Returns `true` if enough time has passed since the last event from this
    /// device (or if this is the first event). If `true` is returned, the
    /// internal timer for this device is reset.
    ///
    /// # Arguments
    /// * `mac` - The MAC address of the device
    ///
    /// # Returns
    /// `true` if the event should be emitted, `false` if it should be throttled
    pub fn should_emit(&mut self, mac: &str) -> bool {
        let now = Instant::now();

        match self.last_seen.get(mac) {
            Some(last) if now.duration_since(*last) < self.interval => false,
            _ => {
                self.last_seen.insert(mac.to_string(), now);
                true
            }
        }
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
}
