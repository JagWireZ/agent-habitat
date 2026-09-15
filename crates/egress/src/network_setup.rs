//! Network setup utilities for egress proxy.

/// Build the Podman `--network` and `--dns` flags for the guest.
///
/// The guest uses a `pasta` network driver provided by `passt`. To make the
/// host loopback address reachable from the guest we add the `--map-host-loopback`
/// sub‑option. The same address is also used for the DNS forwarder.
///
/// Returns a vector of arguments suitable for passing to `podman run`.
pub fn build_network_flags(proxy_ip: &str) -> Vec<String> {
    // The pasta driver expects its options after a colon, separated by commas.
    // We pass the map‑host‑loopback option which makes the guest see the
    // host's loopback interface at `proxy_ip`.
    let pasta_option = format!("pasta:--map-host-loopback={}", proxy_ip);
    vec!["--network".into(), pasta_option, "--dns".into(), proxy_ip.into()]
}

/// Build nftables rule that redirects guest HTTPS traffic to the local proxy.
///
/// * `pasta_interface` – name of the interface created by the `pasta` driver.
/// * `proxy_port` – the port on which the egress proxy listens.
///
/// The rule is added to the `nat` table, `prerouting` chain and matches TCP
/// traffic destined for port 443, redirecting it to the proxy listening port.
pub fn build_egress_firewall_rules(pasta_interface: &str, proxy_port: u16) -> String {
    format!(
        "add rule ip nat prerouting iifname {} tcp dport 443 redirect to {}",
        pasta_interface, proxy_port
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_flags_contains_map_host_loopback() {
        let proxy_ip = "10.0.0.1";
        let flags = build_network_flags(proxy_ip);
        // Expect exactly four entries.
        assert_eq!(flags.len(), 4);
        assert_eq!(flags[0], "--network");
        assert!(flags[1].contains("--map-host-loopback"), "network flag missing map-host-loopback");
        assert_eq!(flags[2], "--dns");
        assert_eq!(flags[3], proxy_ip);
    }

    #[test]
    fn egress_firewall_rule_is_correct() {
        let iface = "pasta0";
        let port = 8443;
        let rule = build_egress_firewall_rules(iface, port);
        assert!(rule.contains("nat prerouting"), "rule should be in nat prerouting chain");
        assert!(rule.contains("tcp dport 443"), "rule should match HTTPS port");
        assert!(rule.contains(&port.to_string()), "rule should redirect to given proxy port");
    }
}
