//! Construction of the guest-network configuration used at VM launch time
//! (`docs/decisions/0004-networking-layer.md`). Lives in the egress crate
//! rather than `crates/vm` because "the proxy is the only reachable
//! address" is egress policy, not launcher concern.
//!
//! Pure string/argv construction, unit-tested here. Real enforcement
//! against a booted guest is confirmed on real hardware by
//! `tests/manual/validate-egress.sh`: an allowlisted destination
//! succeeds, a non-allowlisted destination and an allowlist-lookalike
//! are both blocked, and neither a direct-IP nor a direct-to-8.8.8.8
//! DNS bypass can route around the proxy.

use std::net::SocketAddr;

/// `--network` value that gives the guest a real `passt`-backed interface
/// instead of libkrun's default TSI mode, which is invisible to host-side
/// network policy.
///
/// Not sufficient by itself for `crun-krun`: without the
/// [`KRUN_USE_PASST_ANNOTATION`] annotation, libkrun silently falls back to
/// TSI regardless of this flag (confirmed on real hardware — the guest
/// booted with `tsi_hijack`/`PF_TSI*` instead of a real virtio-net device).
///
/// Do not change this to `pasta:-T,all,-U,all` — `-T`/`-U` auto-forward the
/// guest's own listening ports to the host and conflict with Podman's
/// explicit `--publish` forward for the same port, which reset SSH on real
/// hardware.
pub const NETWORK_MODE: &str = "pasta";

/// Fixed address the guest uses to reach the host's loopback (proxy, DNS
/// forwarder), paired with `pasta:--map-host-loopback=...` in
/// [`build_network_flags`], which translates traffic to this address into
/// the host's real `127.0.0.1`.
///
/// A fixed link-local address, not the host's LAN gateway: `pasta` defaults
/// `--map-host-loopback` to the observed default gateway if omitted, which
/// ties this to a physical-network-specific address (e.g. `192.168.1.1`)
/// this project shouldn't depend on. `169.254.0.0/16` matches the
/// convention Podman uses for `host.containers.internal`.
pub const HOST_LOOPBACK_ADDR: &str = "169.254.1.1";

/// OCI annotation that tells `crun-krun` to attach a real `passt`-backed
/// virtio-net device instead of falling back to TSI; `--network pasta`
/// alone only configures Podman's side, not libkrun's.
///
/// Only exists from `crun` 1.27.1 onward — AlmaLinux 10's
/// `crun-krun-1.27-2.el10_2` predates it and silently ignores it, still
/// booting under TSI. This crate can't detect that mismatch itself;
/// `tests/manual/validate-vm-launch.sh` checks for `tsi_hijack`/`PF_TSI*`.
pub const KRUN_USE_PASST_ANNOTATION: &str = "krun.use_passt";

/// Port `crate::dns`'s forwarder must listen on: a guest's resolver always
/// queries port 53 (`--dns` carries no port), so binding anywhere else
/// leaves the guest with nowhere to send queries — indistinguishable from
/// everything being blocked (hit once in `validate-egress.sh` when the
/// forwarder briefly used port 5300).
pub const DNS_LISTEN_PORT: u16 = 53;

/// Address `crate::dns::run` must bind to for the guest to reach it via
/// [`build_network_flags`]'s `--dns` value.
pub fn dns_listen_addr(proxy_addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(proxy_addr.ip(), DNS_LISTEN_PORT)
}

/// Builds the `podman run` flags for `pasta`-backed networking with DNS
/// pinned to the local proxy path (`crate::dns`).
///
/// `--dns` points at [`HOST_LOOPBACK_ADDR`], not the proxy's own bind
/// address — pointing it at the proxy's literal IP (e.g. `127.0.0.1`)
/// resolves to the guest's own loopback instead of the host's. No
/// `proxy_addr` parameter is needed since the guest side only depends on
/// `HOST_LOOPBACK_ADDR` and `pasta`'s translation of it.
///
/// Bundles [`KRUN_USE_PASST_ANNOTATION`] alongside `--network`/`--dns`
/// since omitting it silently leaves the guest on TSI networking.
///
/// Restricting what the guest can actually reach is a separate step — see
/// [`build_egress_firewall_rules`].
pub fn build_network_flags() -> Vec<String> {
    vec![
        "--network".to_string(),
        format!("{NETWORK_MODE}:--map-host-loopback={HOST_LOOPBACK_ADDR}"),
        "--dns".to_string(),
        HOST_LOOPBACK_ADDR.to_string(),
        "--annotation".to_string(),
        format!("{KRUN_USE_PASST_ANNOTATION}=1"),
    ]
}

/// nftables table/chain name for the egress-restriction ruleset, named
/// distinctly so it's identifiable in `nft list ruleset` output.
pub const FIREWALL_TABLE: &str = "habitat_egress";

/// Port the guest's outbound TLS connections dial (`https://` is always
/// 443 from the guest's side); [`build_egress_firewall_rules`]'s DNAT rule
/// redirects this to `proxy_addr`.
const GUEST_TLS_PORT: u16 = 443;

/// Builds the nftables ruleset restricting a session's `pasta` interface to
/// reach `proxy_addr` and nothing else: a `nat` table DNATing the guest's
/// outbound `:443` to `proxy_addr`, then a default-deny filter table
/// accepting only the (rewritten) proxy address/port.
///
/// The DNAT rule is required, not optional: `crate::proxy::run` is a
/// transparent SNI relay with no CONNECT/explicit-proxy mode, so a guest's
/// ordinary `curl https://` must be redirected to it — without this rule
/// it dials the real destination IP on 443 and is dropped, including for
/// allowlisted destinations (this exact failure mode was hit on real
/// hardware). The `nat` table runs at `priority -100` so its rewrite
/// happens before the filter table's `priority 0` chain evaluates the
/// destination.
///
/// `proxy_addr` is typically the host's own loopback (e.g.
/// `127.0.0.1:8443`), but this ruleset applies inside the guest's own
/// netns, where `127.0.0.1` means the guest's own loopback — so a
/// loopback `proxy_addr` is rewritten to [`HOST_LOOPBACK_ADDR`] for both
/// the DNAT target and the filter accept rule, matching
/// [`build_network_flags`]'s `--map-host-loopback` value. Using the
/// literal loopback IP here made every destination fail closed on real
/// hardware.
///
/// Also accepts [`DNS_LISTEN_PORT`] at the same guest-visible address —
/// without it the default-deny policy blocks the guest's own DNS queries,
/// which hangs `curl` on resolution for every destination rather than
/// failing visibly (confirmed on real hardware).
///
/// Also accepts `ct state established,related`, unconditional on
/// interface/address: the guest's SSH exec channel
/// (`docs/decisions/0008-guest-exec-channel.md`) is inbound, but its reply
/// traffic still passes through this `hook output` chain and needs this
/// rule or the channel breaks (confirmed on real hardware — SSH hung at
/// the banner exchange without it).
///
/// Also unconditionally accepts `oifname "lo"`, ahead of even
/// established/related: `pasta` mirrors the host's own address onto its
/// guest-side interface, so Podman's `--publish` port-forward into the
/// guest connects to that same address and gets routed via `lo` rather
/// than the pasta interface — as a brand-new flow it matches neither the
/// interface-scoped accept rules nor established/related. Without this
/// rule the exec channel's own initiating SYN never gets out (confirmed on
/// real hardware). Loopback traffic never reaches an external destination,
/// so accepting it doesn't weaken the bypass-prevention this ruleset
/// exists for.
pub fn build_egress_firewall_rules(pasta_interface: &str, proxy_addr: SocketAddr) -> String {
    let guest_visible_ip = if proxy_addr.ip().is_loopback() {
        HOST_LOOPBACK_ADDR
            .parse()
            .expect("HOST_LOOPBACK_ADDR is a valid IP literal")
    } else {
        proxy_addr.ip()
    };
    format!(
        "table inet {table}_nat {{\n\
         \x20   chain egress_nat {{\n\
         \x20       type nat hook output priority -100; policy accept;\n\
         \x20       oifname \"{iface}\" tcp dport {tls_port} dnat ip to {ip}:{port}\n\
         \x20   }}\n\
         }}\n\
         table inet {table} {{\n\
         \x20   chain egress {{\n\
         \x20       type filter hook output priority 0; policy drop;\n\
         \x20       oifname \"lo\" accept\n\
         \x20       ct state established,related accept\n\
         \x20       oifname \"{iface}\" ip daddr {ip} tcp dport {port} accept\n\
         \x20       oifname \"{iface}\" ip daddr {ip} udp dport {port} accept\n\
         \x20       oifname \"{iface}\" ip daddr {ip} tcp dport {dns_port} accept\n\
         \x20       oifname \"{iface}\" ip daddr {ip} udp dport {dns_port} accept\n\
         \x20   }}\n\
         }}\n",
        table = FIREWALL_TABLE,
        iface = pasta_interface,
        ip = guest_visible_ip,
        port = proxy_addr.port(),
        tls_port = GUEST_TLS_PORT,
        dns_port = DNS_LISTEN_PORT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_addr() -> SocketAddr {
        "127.0.0.1:8443".parse().unwrap()
    }

    #[test]
    fn network_flags_use_pasta_with_the_map_host_loopback_suboption() {
        let flags = build_network_flags();
        let idx = flags.iter().position(|a| a == "--network").unwrap();
        assert_eq!(
            flags[idx + 1],
            format!("{NETWORK_MODE}:--map-host-loopback={HOST_LOOPBACK_ADDR}")
        );
    }

    #[test]
    fn dns_listen_addr_uses_the_proxy_ip_on_port_53() {
        let addr = dns_listen_addr(proxy_addr());
        assert_eq!(addr, "127.0.0.1:53".parse().unwrap());
    }

    #[test]
    fn network_flags_pin_dns_to_the_host_loopback_map_address_not_the_proxy_ip() {
        let flags = build_network_flags();
        let idx = flags.iter().position(|a| a == "--dns").unwrap();
        assert_eq!(flags[idx + 1], HOST_LOOPBACK_ADDR);
    }

    #[test]
    fn network_flags_include_the_krun_use_passt_annotation() {
        let flags = build_network_flags();
        let idx = flags
            .iter()
            .position(|a| a == "--annotation")
            .expect("--annotation flag must be present");
        assert_eq!(
            flags[idx + 1],
            format!("{KRUN_USE_PASST_ANNOTATION}=1")
        );
    }

    #[test]
    fn firewall_rules_default_to_dropping_all_output() {
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains("policy drop"));
    }

    #[test]
    fn firewall_rules_accept_only_the_proxy_address_and_port() {
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains(HOST_LOOPBACK_ADDR));
        assert!(rules.contains("8443"));
        assert!(rules.contains("oifname \"pasta0\""));
    }

    #[test]
    fn firewall_rules_translate_loopback_proxy_to_host_loopback_addr() {
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(!rules.contains("127.0.0.1"));
        assert!(rules.contains(&format!("dnat ip to {HOST_LOOPBACK_ADDR}:8443")));
        assert!(rules.contains(&format!("ip daddr {HOST_LOOPBACK_ADDR} tcp dport 8443")));
    }

    #[test]
    fn firewall_rules_keep_a_non_loopback_proxy_ip_unchanged() {
        let addr: SocketAddr = "203.0.113.5:8443".parse().unwrap();
        let rules = build_egress_firewall_rules("pasta0", addr);
        assert!(rules.contains("203.0.113.5"));
        assert!(!rules.contains(HOST_LOOPBACK_ADDR));
    }

    #[test]
    fn firewall_rules_also_accept_dns_to_the_guest_visible_address() {
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains(&format!("ip daddr {HOST_LOOPBACK_ADDR} tcp dport 53 accept")));
        assert!(rules.contains(&format!("ip daddr {HOST_LOOPBACK_ADDR} udp dport 53 accept")));
    }

    #[test]
    fn firewall_rules_are_scoped_to_a_distinctly_named_table() {
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains(&format!("table inet {FIREWALL_TABLE}")));
    }

    #[test]
    fn firewall_rules_dnat_the_guests_own_tls_port_to_the_proxy() {
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains("type nat hook output"));
        assert!(rules.contains(&format!("tcp dport 443 dnat ip to {HOST_LOOPBACK_ADDR}:8443")));
    }

    #[test]
    fn firewall_rules_nat_table_is_scoped_to_the_pasta_interface() {
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains("oifname \"pasta0\" tcp dport 443 dnat"));
    }

    #[test]
    fn firewall_rules_accept_loopback_traffic_unconditionally() {
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains("oifname \"lo\" accept"));
    }

    #[test]
    fn firewall_rules_accept_established_and_related_connections() {
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains("ct state established,related accept"));
    }

    #[test]
    fn firewall_rules_dnat_disambiguates_the_address_family() {
        // nft rejects a bare `dnat to` in an `inet`-family table as
        // ambiguous between IPv4/IPv6, even when the address is IPv4 here.
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains("dnat ip to"));
        assert!(!rules.contains("dnat to"));
    }
}
