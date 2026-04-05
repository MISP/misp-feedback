use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;

/// CIDR matcher using HashMap-per-prefix-length strategy.
/// For each prefix length, we store a map from network bits to list indices.
pub struct CidrMatcher {
    /// v4_maps[prefix_len] maps masked-IP (as u32) -> list indices
    v4_maps: Vec<HashMap<u32, Vec<usize>>>,
    /// v6_maps[prefix_len] maps masked-IP (as u128) -> list indices
    v6_maps: Vec<HashMap<u128, Vec<usize>>>,
}

impl CidrMatcher {
    pub fn new() -> Self {
        Self {
            v4_maps: (0..=32).map(|_| HashMap::new()).collect(),
            v6_maps: (0..=128).map(|_| HashMap::new()).collect(),
        }
    }

    pub fn add_entries(&mut self, entries: &[String], list_idx: usize) {
        for entry in entries {
            let entry = entry.trim();
            let net: IpNet = match entry.parse() {
                Ok(n) => n,
                Err(_) => {
                    // Try parsing as a bare IP (treat as /32 or /128)
                    match entry.parse::<IpAddr>() {
                        Ok(IpAddr::V4(ip)) => IpNet::new(IpAddr::V4(ip), 32).unwrap(),
                        Ok(IpAddr::V6(ip)) => IpNet::new(IpAddr::V6(ip), 128).unwrap(),
                        Err(_) => {
                            tracing::warn!(entry = %entry, "Invalid CIDR entry, skipping");
                            continue;
                        }
                    }
                }
            };

            match net {
                IpNet::V4(net) => {
                    let prefix_len = net.prefix_len() as usize;
                    let bits = u32::from(net.network());
                    self.v4_maps[prefix_len]
                        .entry(bits)
                        .or_default()
                        .push(list_idx);
                }
                IpNet::V6(net) => {
                    let prefix_len = net.prefix_len() as usize;
                    let bits = u128::from(net.network());
                    self.v6_maps[prefix_len]
                        .entry(bits)
                        .or_default()
                        .push(list_idx);
                }
            }
        }
    }

    pub fn lookup(&self, value: &str) -> Vec<usize> {
        let ip: IpAddr = match value.trim().parse() {
            Ok(ip) => ip,
            Err(_) => return Vec::new(),
        };

        let mut result = Vec::new();

        match ip {
            IpAddr::V4(ip) => {
                let bits = u32::from(ip);
                for prefix_len in (0..=32).rev() {
                    let mask = if prefix_len == 0 {
                        0u32
                    } else {
                        !0u32 << (32 - prefix_len)
                    };
                    let masked = bits & mask;
                    if let Some(indices) = self.v4_maps[prefix_len].get(&masked) {
                        result.extend(indices);
                    }
                }
            }
            IpAddr::V6(ip) => {
                let bits = u128::from(ip);
                for prefix_len in (0..=128).rev() {
                    let mask = if prefix_len == 0 {
                        0u128
                    } else {
                        !0u128 << (128 - prefix_len)
                    };
                    let masked = bits & mask;
                    if let Some(indices) = self.v6_maps[prefix_len].get(&masked) {
                        result.extend(indices);
                    }
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_cidr_match() {
        let mut m = CidrMatcher::new();
        m.add_entries(&["10.0.0.0/8".into()], 0);
        assert_eq!(m.lookup("10.1.2.3"), vec![0]);
        assert!(m.lookup("11.0.0.1").is_empty());
    }

    #[test]
    fn ipv4_exact_match() {
        let mut m = CidrMatcher::new();
        m.add_entries(&["8.8.8.8/32".into()], 0);
        assert_eq!(m.lookup("8.8.8.8"), vec![0]);
        assert!(m.lookup("8.8.8.9").is_empty());
    }

    #[test]
    fn bare_ip_treated_as_host() {
        let mut m = CidrMatcher::new();
        m.add_entries(&["8.8.8.8".into()], 0);
        assert_eq!(m.lookup("8.8.8.8"), vec![0]);
    }

    #[test]
    fn ipv6_match() {
        let mut m = CidrMatcher::new();
        m.add_entries(&["2001:db8::/32".into()], 0);
        assert_eq!(m.lookup("2001:db8::1"), vec![0]);
        assert!(m.lookup("2001:db9::1").is_empty());
    }

    #[test]
    fn non_ip_returns_empty() {
        let mut m = CidrMatcher::new();
        m.add_entries(&["10.0.0.0/8".into()], 0);
        assert!(m.lookup("google.com").is_empty());
    }

    #[test]
    fn multiple_ranges() {
        let mut m = CidrMatcher::new();
        m.add_entries(&["8.8.8.0/24".into()], 0);
        m.add_entries(&["8.8.0.0/16".into()], 1);
        let mut result = m.lookup("8.8.8.8");
        result.sort();
        assert_eq!(result, vec![0, 1]);
    }
}
