//! Pure construction of the guest-network configuration Phase 5 needs at
//! VM launch time, coordinated with `habitat-vm::launcher`
//! (`docs/decisions/0004-networking-layer.md`). Kept here rather than in
//! `crates/vm` because the *policy* of "the proxy is the only reachable
//! address" belongs to the egress domain, not the launcher; `habitat-vm`
//! only calls into this module and splices the result into its own argv.
//!
//! Same "pure and unit-tested here, confirmed for real on hardware
//! separately" split as `habitat_vm::launcher::build_run_args` and its
//! `WORKSPACE_DISK_ANNOTATION` caveat: everything in this module is
//! plain string/argv construction, checkable without Podman, `passt`, or
//! real KVM. Whether crun-krun's `--network`/`--dns` flags behave the
//! way documented here when combined with libkrun (rather than plain
//! crun) -- and whether the nftables ruleset below is actually the right
//! mechanism for restricting a rootless `pasta` interface, as opposed to
//! some other rootless-networking primitive -- is **not yet confirmed
//! against real hardware**. `tests/manual/validate-egress.sh` is where
//! that confirmation (or correction, same "wrong on real hardware, then
//! fixed" pattern as the Phase 3 annotation key) happens.

use std::net::SocketAddr;

/// The `--network` value that gets the guest a real `passt`-backed
/// interface instead of libkrun's default TSI mode (`0004`'s whole
/// reason for existing: TSI isn't visible to host-side network policy at
/// all). Rootless Podman's `pasta` network driver is `passt`'s intended
/// integration point for exactly this case.
///
/// **This alone is not sufficient for `crun-krun`** -- confirmed on real
/// AlmaLinux 10.2 hardware (`tmp/wip/vm-launch-validation`,
/// `tmp/wip/egress-validation`): a session launched with only this flag
/// booted with `tsi_hijack` on its kernel command line and `PF_TSI`/
/// `PF_TSI6`/`PF_TSIU` registered -- i.e. libkrun's own default TSI
/// networking, not a real virtio-net device at all, regardless of what
/// `--network` value podman itself was given. Per `crun`'s own
/// documentation (`krun.1.md`), libkrun's VM configuration is a separate
/// concern from podman's own network-namespace setup, and TSI is what
/// libkrun falls back to whenever no network interface has been
/// explicitly added to the microVM. The explicit opt-in is the
/// [`KRUN_USE_PASST_ANNOTATION`] OCI annotation, which [`build_network_flags`]
/// now sets alongside this -- see that constant's doc comment. Every
/// symptom that looked like a guest-side DHCP/routing problem
/// (`guest/entrypoint.sh`'s `udhcpc` step, this crate's DNS-forwarder
/// unreachability) traced back to this: there was no real network
/// interface for any of that to act on in the first place.
///
/// **Do not "fix" this to `pasta:-T,all,-U,all`** -- that was tried and
/// reverted after it broke the guest's SSH exec channel on real hardware.
/// `-T`/`-U` are pasta's "TCP/UDP port forwarding to init namespace":
/// *auto-publishing whatever port the guest itself is listening on* to
/// the host, the same direction `-t`/`-u` (which Podman already drives
/// from `--publish`) cover explicitly -- not "let the guest reach a
/// service bound on the host's own loopback", which was the wrong
/// direction this constant needed. Forcing `-T all -U all` makes pasta
/// auto-forward the guest's sshd on top of Podman's own explicit `-t`
/// forward for the same port, and the resulting duplicate/conflicting
/// path is what reset every SSH connection.
///
/// Whether a guest under real `pasta` networking (now that
/// [`KRUN_USE_PASST_ANNOTATION`] actually gets it one) can reach a
/// service bound on the host's own loopback is still open --
/// `tests/manual/validate-egress.sh` is where that gets resolved against
/// real hardware, not a guess baked into this constant.
pub const NETWORK_MODE: &str = "pasta";

/// The OCI annotation that tells `crun-krun` to actually attach a real
/// virtio-net device backed by `passt` to the microVM, instead of
/// falling back to libkrun's default TSI networking -- see
/// [`NETWORK_MODE`]'s doc comment for the real-hardware finding that
/// made this necessary. Per `crun`'s `krun.1.md`: `krun.use_passt=NUM`,
/// "When set to a value greater than 0, enable passt-based networking in
/// the microVM." `--network pasta` alone configures podman's own side of
/// this; libkrun's VM configuration needs this separate, explicit
/// annotation before it will honor that at all.
pub const KRUN_USE_PASST_ANNOTATION: &str = "krun.use_passt";

/// The port `crate::dns`'s forwarder must be listening on, at the same
/// IP as the proxy, for [`build_network_flags`]'s `--dns` value to
/// actually reach it: `--dns` (like any resolver configuration a guest's
/// libc resolver reads) carries no port, so the guest always queries
/// port 53 -- there is no way to point it at a forwarder listening
/// anywhere else. `crate::dns::run` takes its listen address as a plain
/// argument rather than hardcoding this port itself, so this constant is
/// the one place that coupling is written down; every caller (this
/// crate's own harness included) must bind the forwarder to
/// `(proxy_addr.ip(), DNS_LISTEN_PORT)`, not an arbitrary port, or the
/// guest's resolver silently has nowhere to send queries at all -- which
/// looks identical to "everything is blocked" (the exact false-positive
/// `tests/manual/validate-egress.sh` failed on when it briefly forwarded
/// on port 5300 instead).
pub const DNS_LISTEN_PORT: u16 = 53;

/// The address `crate::dns::run` must bind to so that a guest launched
/// with [`build_network_flags`]'s `--dns` value can actually reach it --
/// see [`DNS_LISTEN_PORT`] for why this can't be an arbitrary port.
pub fn dns_listen_addr(proxy_addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(proxy_addr.ip(), DNS_LISTEN_PORT)
}

/// Builds the `podman run` flags that give the guest a `pasta`-backed
/// network and pin its DNS resolution to the local proxy's own address
/// (`crate::dns`) rather than leaving the guest's resolver on whatever
/// pasta would otherwise hand it -- the "DNS pinned to the proxy path"
/// requirement (`0004`'s open item), expressed as launch-time
/// configuration rather than in-guest configuration this project has no
/// way to enforce after boot.
///
/// Includes [`KRUN_USE_PASST_ANNOTATION`] alongside `--network`/`--dns` --
/// confirmed on real hardware that omitting it silently leaves the guest
/// on libkrun's default TSI networking regardless of the `--network`
/// value given, so this can't be left as a separate, easy-to-forget flag
/// at the call site; it belongs bundled with the rest of "give this
/// session pasta networking" in one place.
///
/// Reachability restriction itself (making the proxy the *only* address
/// the guest can reach at all) is not a `podman run` flag -- see
/// [`build_egress_firewall_rules`] for that half.
pub fn build_network_flags(proxy_addr: SocketAddr) -> Vec<String> {
    vec![
        "--network".to_string(),
        NETWORK_MODE.to_string(),
        "--dns".to_string(),
        proxy_addr.ip().to_string(),
        "--annotation".to_string(),
        format!("{KRUN_USE_PASST_ANNOTATION}=1"),
    ]
}

/// The nftables table/chain name used for the egress-restriction
/// ruleset -- named distinctly so it's identifiable in `nft list ruleset`
/// output next to whatever else a host is running, same intent as
/// `habitat_vm::session::SessionId`'s fixed prefix.
pub const FIREWALL_TABLE: &str = "habitat_egress";

/// Builds the nftables ruleset text that restricts a session's `pasta`
/// interface to reach `proxy_addr` and nothing else: default-deny
/// output, one explicit accept rule for the proxy's own address and
/// port. This is the actual enforcement of "the guest cannot construct a
/// network path that skips the proxy" -- reachability is removed at the
/// network layer, not just at the SNI-matching layer, so there is
/// nothing left to catch-and-redirect after the fact (`0004`'s design
/// rationale).
///
/// Pure text construction, loaded via `nft -f` at launch time (real
/// application, and confirming this is actually enforced against a
/// booted guest attempting a direct-IP bypass, is
/// `tests/manual/validate-egress.sh`'s job -- unprivileged/rootless
/// nftables application against a `pasta`-owned interface is real,
/// hardware-and-kernel-version-dependent behavior this function cannot
/// verify by construction alone).
pub fn build_egress_firewall_rules(pasta_interface: &str, proxy_addr: SocketAddr) -> String {
    format!(
        "table inet {table} {{\n\
         \x20   chain egress {{\n\
         \x20       type filter hook output priority 0; policy drop;\n\
         \x20       oifname \"{iface}\" ip daddr {ip} tcp dport {port} accept\n\
         \x20       oifname \"{iface}\" ip daddr {ip} udp dport {port} accept\n\
         \x20   }}\n\
         }}\n",
        table = FIREWALL_TABLE,
        iface = pasta_interface,
        ip = proxy_addr.ip(),
        port = proxy_addr.port(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy_addr() -> SocketAddr {
        "127.0.0.1:8443".parse().unwrap()
    }

    #[test]
    fn network_flags_use_pasta_not_the_default_tsi_mode() {
        let flags = build_network_flags(proxy_addr());
        let idx = flags.iter().position(|a| a == "--network").unwrap();
        assert_eq!(flags[idx + 1], NETWORK_MODE);
    }

    #[test]
    fn dns_listen_addr_uses_the_proxy_ip_on_port_53() {
        let addr = dns_listen_addr(proxy_addr());
        assert_eq!(addr, "127.0.0.1:53".parse().unwrap());
    }

    #[test]
    fn network_flags_pin_dns_to_the_proxy_address() {
        let flags = build_network_flags(proxy_addr());
        let idx = flags.iter().position(|a| a == "--dns").unwrap();
        assert_eq!(flags[idx + 1], "127.0.0.1");
    }

    #[test]
    fn network_flags_include_the_krun_use_passt_annotation() {
        // Confirmed on real hardware: without this, `crun-krun` silently
        // falls back to libkrun's default TSI networking regardless of
        // `--network pasta`, so this must never be left out.
        let flags = build_network_flags(proxy_addr());
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
        assert!(rules.contains("127.0.0.1"));
        assert!(rules.contains("8443"));
        // Confirms the one accept rule is scoped to the pasta interface,
        // not left to apply host-wide.
        assert!(rules.contains("oifname \"pasta0\""));
    }

    #[test]
    fn firewall_rules_are_scoped_to_a_distinctly_named_table() {
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains(&format!("table inet {FIREWALL_TABLE}")));
    }
}
