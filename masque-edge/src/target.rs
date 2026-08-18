use std::{fmt, net::SocketAddr};

use anyhow::{bail, Context, Result};
use percent_encoding::percent_decode_str;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub async fn resolve(&self, allow_private: bool) -> Result<SocketAddr> {
        tokio::net::lookup_host(self.authority())
            .await
            .with_context(|| format!("failed to resolve {}", self))?
            .find(|address| allow_private || is_public_destination(address.ip()))
            .with_context(|| format!("no addresses found for {}", self))
    }
}

impl fmt::Display for Target {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.authority())
    }
}

pub fn from_authority(authority: &str) -> Result<Target> {
    if authority.starts_with('[') {
        let closing = authority
            .find(']')
            .context("IPv6 CONNECT authority is missing closing bracket")?;
        let host = &authority[1..closing];
        let port = authority
            .get(closing + 1..)
            .and_then(|suffix| suffix.strip_prefix(':'))
            .context("CONNECT authority is missing port")?;
        return build_target(host, port);
    }

    let (host, port) = authority
        .rsplit_once(':')
        .context("CONNECT authority must be host:port")?;
    if host.contains(':') {
        bail!("IPv6 CONNECT authority must use brackets");
    }
    build_target(host, port)
}

pub fn from_connect_udp_path(path: &str) -> Result<Target> {
    let segments: Vec<_> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.len() < 2 {
        bail!("CONNECT-UDP path is missing target_host/target_port");
    }

    let encoded_host = segments[segments.len() - 2];
    let port = segments[segments.len() - 1];
    let host = percent_decode_str(encoded_host)
        .decode_utf8()
        .context("CONNECT-UDP target_host is not UTF-8")?;
    build_target(&host, port)
}

fn build_target(host: &str, port: &str) -> Result<Target> {
    if host.is_empty() {
        bail!("target host is empty");
    }
    let port: u16 = port.parse().context("target port is invalid")?;
    if port == 0 {
        bail!("target port 0 is not allowed");
    }
    Ok(Target {
        host: host.to_owned(),
        port,
    })
}

fn is_public_destination(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(address) => {
            let octets = address.octets();
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_documentation()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)))
        }
        std::net::IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_destination(std::net::IpAddr::V4(mapped));
            }
            let segments = address.segments();
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_authorities() {
        assert_eq!(
            from_authority("example.com:443").unwrap(),
            Target {
                host: "example.com".into(),
                port: 443
            }
        );
        assert_eq!(
            from_authority("[2001:db8::1]:8443").unwrap(),
            Target {
                host: "2001:db8::1".into(),
                port: 8443
            }
        );
    }

    #[test]
    fn parses_rfc_9298_paths() {
        assert_eq!(
            from_connect_udp_path("/.well-known/masque/udp/example.com/443/").unwrap(),
            Target {
                host: "example.com".into(),
                port: 443
            }
        );
        assert_eq!(
            from_connect_udp_path("/.well-known/masque/udp/2001%3Adb8%3A%3A1/53/").unwrap(),
            Target {
                host: "2001:db8::1".into(),
                port: 53
            }
        );
    }

    #[test]
    fn rejects_missing_and_zero_ports() {
        assert!(from_authority("example.com").is_err());
        assert!(from_connect_udp_path("/udp/example.com/0/").is_err());
    }

    #[test]
    fn rejects_non_public_destination_ranges() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !is_public_destination(address.parse().unwrap()),
                "{address}"
            );
        }
        assert!(is_public_destination("1.1.1.1".parse().unwrap()));
        assert!(is_public_destination(
            "2606:4700:4700::1111".parse().unwrap()
        ));
    }
}
