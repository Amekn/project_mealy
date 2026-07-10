//! Authenticated API adapter foundations.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Security-relevant listener limits for the future HTTP adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiConfig {
    /// Loopback listener address.
    pub bind: SocketAddr,
    /// Maximum accepted request body in bytes.
    pub maximum_body_bytes: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            maximum_body_bytes: 1024 * 1024,
        }
    }
}

impl ApiConfig {
    /// Returns whether the configured listener remains local-only.
    #[must_use]
    pub fn is_loopback(self) -> bool {
        self.bind.ip().is_loopback()
    }
}

#[cfg(test)]
mod tests {
    use super::ApiConfig;

    #[test]
    fn default_listener_is_loopback_only() {
        assert!(ApiConfig::default().is_loopback());
    }
}
