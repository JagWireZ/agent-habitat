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
//! real KVM. **Confirmed on real hardware** (`tmp/wip/egress-validation`,
//! 2026-09-17): crun-krun's `--network`/`--dns` flags behave as
//! documented here when combined with libkrun, and the nftables ruleset
//! below is the correct mechanism for restricting a rootless `pasta`
//! interface -- `tests/manual/validate-egress.sh`'s connection trace
//! confirmed an allowlisted destination succeeds, a non-allowlisted
//! destination and an allowlist-lookalike are both blocked, and neither
//! a direct-IP nor a direct-to-8.8.8.8 DNS bypass can route around the
//! proxy.

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
/// service bound on the host's own loopback is **no longer open** --
/// confirmed on real hardware (`tmp/wip/egress-validation`) that the
/// obvious approach (`--dns` pointed straight at the proxy's own bind
/// address, e.g. `127.0.0.1`) never had a chance: `127.0.0.1` inside the
/// guest's own network namespace always means the guest's *own*
/// loopback, never the host's, regardless of routing, DHCP, or which
/// networking mode is in play. See [`HOST_LOOPBACK_ADDR`] for the actual
/// fix -- `pasta`'s own `--map-host-loopback` translation, not a guess
/// baked into this constant.
pub const NETWORK_MODE: &str = "pasta";

/// The fixed address this project tells the guest to use for anything
/// that actually lives on the *host's* loopback (the egress proxy, the
/// DNS forwarder) -- paired with a `pasta:--map-host-loopback=...`
/// `--network` value in [`build_network_flags`], which makes `pasta`
/// translate any guest traffic destined here into the host's real
/// loopback (`127.0.0.1`) before delivering it. Per `pasta`'s own
/// manual: "packets with destination address corresponding to the
/// `--map-host-loopback` address will have their destination address
/// translated to a loopback address."
///
/// A fixed link-local address, not the host's real LAN gateway --
/// `pasta` defaults `--map-host-loopback` to the observed default
/// gateway if the option is omitted, which is exactly the trap this
/// project fell into first: on real hardware that gateway is the host's
/// actual router (e.g. `192.168.1.1`), a real, physical-network-specific
/// address this project has no business depending on for something as
/// load-bearing as reaching its own egress proxy. Setting this option
/// explicitly, to a fixed address in the `169.254.0.0/16` link-local
/// block (the same convention Podman's own `host.containers.internal`
/// uses for pasta-backed bridge networking), keeps this working
/// identically regardless of whatever physical network the host happens
/// to be on, or whether it has one at all.
pub const HOST_LOOPBACK_ADDR: &str = "169.254.1.1";

/// The OCI annotation that tells `crun-krun` to actually attach a real
/// virtio-net device backed by `passt` to the microVM, instead of
/// falling back to libkrun's default TSI networking -- see
/// [`NETWORK_MODE`]'s doc comment for the real-hardware finding that
/// made this necessary. Per `crun`'s `krun.1.md`: `krun.use_passt=NUM`,
/// "When set to a value greater than 0, enable passt-based networking in
/// the microVM." `--network pasta` alone configures podman's own side of
/// this; libkrun's VM configuration needs this separate, explicit
/// annotation before it will honor that at all. Also confirmed on real
/// hardware: this annotation only exists from `crun` 1.27.1 onward --
/// AlmaLinux 10's own `crun-krun-1.27-2.el10_2` predates it and silently
/// ignores it, still booting under TSI. There is no way to detect that
/// mismatch from this crate alone; `tests/manual/validate-vm-launch.sh`
/// checking for `tsi_hijack`/`PF_TSI*` on the guest's kernel command
/// line and registered protocol families is what catches it.
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
/// see [`DNS_LISTEN_PORT`] for why this can't be an arbitrary port. Binds
/// to `proxy_addr`'s own IP (the host's real loopback, e.g. `127.0.0.1`)
/// -- `pasta`'s `--map-host-loopback` translation is what lets the guest
/// reach that from [`HOST_LOOPBACK_ADDR`]; the forwarder itself doesn't
/// need to know or care about that address at all.
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
/// `--dns` points at [`HOST_LOOPBACK_ADDR`], not the proxy's own bind
/// address -- confirmed on real hardware that pointing it straight at
/// the proxy's own IP (typically `127.0.0.1`) never works, because that
/// address means the guest's *own* loopback from inside the guest's
/// network namespace, never the host's. This function takes no
/// `proxy_addr` parameter at all for that reason: nothing about the
/// guest-side network configuration actually depends on where the proxy
/// binds, only on `HOST_LOOPBACK_ADDR` and `pasta`'s own translation of
/// it. `--network` carries a matching
/// `pasta:--map-host-loopback=<HOST_LOOPBACK_ADDR>` value so `pasta`
/// actually translates guest traffic bound for that address to the
/// host's real loopback, where [`dns_listen_addr`] and the proxy itself
/// are listening.
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

/// The nftables table/chain name used for the egress-restriction
/// ruleset -- named distinctly so it's identifiable in `nft list ruleset`
/// output next to whatever else a host is running, same intent as
/// `habitat_vm::session::SessionId`'s fixed prefix.
pub const FIREWALL_TABLE: &str = "habitat_egress";

/// The port the guest's own outbound TLS connections actually dial
/// (`https://` is always port 443 from the guest's point of view,
/// regardless of what port the proxy itself listens on) -- this is the
/// port [`build_egress_firewall_rules`]'s DNAT rule redirects to
/// `proxy_addr`, since nothing in this project makes the guest dial the
/// proxy's own address/port on purpose (see that function's doc comment
/// for why that redirect is required at all).
const GUEST_TLS_PORT: u16 = 443;

/// Builds the nftables ruleset text that restricts a session's `pasta`
/// interface to reach `proxy_addr` and nothing else: a `nat` table that
/// redirects the guest's own outbound `:443` connections to `proxy_addr`,
/// followed by a default-deny filter table with one explicit accept rule
/// for the (now-rewritten) proxy address and port. This is the actual
/// enforcement of "the guest cannot construct a network path that skips
/// the proxy" -- reachability is removed at the network layer, not just
/// at the SNI-matching layer, so there is nothing left to catch-and-
/// redirect after the fact (`0004`'s design rationale).
///
/// The DNAT rule is load-bearing, not optional: `crate::proxy::run` is a
/// transparent SNI relay that expects to *be* the connection's real
/// destination (it reads the guest's actual TLS ClientHello off the wire
/// and dials the sniffed hostname itself) -- it has no HTTP-CONNECT or
/// explicit-proxy mode a guest could dial on purpose. And `crate::dns`
/// forwards every query to a real upstream and returns real answers
/// (deliberately -- see that module's doc comment), so there is no
/// sentinel address DNS could hand back to make the guest dial the proxy
/// itself. Without this rule, a guest's ordinary `curl https://` dials the
/// destination's real IP on port 443, which matches neither of the filter
/// table's accept rules and is dropped -- including for allowlisted
/// destinations. Found on real hardware during `tests/manual/
/// validate-egress.sh`: with only the filter table below applied, an
/// allowlisted destination fails closed exactly like a blocked one, which
/// looks like a stricter-than-intended ruleset but is actually a missing
/// redirect.
///
/// Both tables key off the same `hook output` + `oifname` match already
/// confirmed to see the guest's egress on real hardware (see this
/// function's own real-hardware validation history); the `nat` table runs
/// at `priority -100` (nftables' conventional `dstnat` priority) so its
/// rewrite happens before the filter table's `priority 0` chain evaluates
/// the (by-then-rewritten) destination.
///
/// Pure text construction, loaded via `nft -f` at launch time (real
/// application, and confirming this is actually enforced against a
/// booted guest attempting a direct-IP bypass, is
/// `tests/manual/validate-egress.sh`'s job -- unprivileged/rootless
/// nftables application against a `pasta`-owned interface is real,
/// hardware-and-kernel-version-dependent behavior this function cannot
/// verify by construction alone).
///
/// `proxy_addr` is the proxy's real bind address, typically on the
/// host's own loopback (e.g. `127.0.0.1:8443`) -- but this ruleset is
/// applied *inside the guest's own netns*, where `127.0.0.1` always means
/// the guest's own loopback, never the host's (the same trap
/// [`HOST_LOOPBACK_ADDR`]'s doc comment describes for `--dns`). So when
/// `proxy_addr`'s IP is loopback, both the DNAT target and the filter
/// table's accept rule use [`HOST_LOOPBACK_ADDR`] instead, matching
/// [`build_network_flags`]'s `--map-host-loopback` value -- confirmed on
/// real hardware (`tmp/wip/egress-validation`) that using the literal
/// loopback IP here makes DNAT rewrite the guest's outbound connection to
/// its own loopback, where nothing is listening, so *every* destination
/// fails closed identically, including allowlisted ones.
///
/// Also carries an accept rule for [`DNS_LISTEN_PORT`] at the same
/// guest-visible address, alongside the proxy's own port -- without it,
/// this ruleset's default-deny policy blocks the guest's own DNS queries
/// to [`dns_listen_addr`] (reached via [`HOST_LOOPBACK_ADDR`], same as the
/// proxy), not just non-allowlisted destinations. Confirmed on real
/// hardware (`tmp/wip/egress-validation`): `tests/manual/
/// validate-egress.sh`'s Step 3b DNS check passes because it runs
/// *before* this ruleset is applied; once applied, a guest's ordinary
/// `curl` hangs on DNS resolution (`getaddrinfo` isn't interrupted by
/// curl's own `-m` timeout) for every destination, allowlisted or not --
/// indistinguishable from the loopback-DNAT bug above without checking
/// which stage actually hangs.
///
/// Also carries a `ct state established,related accept` rule ahead of
/// the proxy/DNS accept rules, unconditional on interface or address --
/// the guest's SSH exec channel (`docs/decisions/0008-guest-exec-
/// channel.md`) is *inbound*, but its reply traffic (the SYN-ACK and
/// everything after) is still egress from the guest kernel's own point
/// of view and passes through this same `hook output` chain. Without
/// this rule, this ruleset's default-deny policy silently drops that
/// reply traffic too, since it matches none of the proxy/DNS-scoped
/// accept rules -- breaking the exec channel itself, not just non-
/// allowlisted destinations. Confirmed on real hardware (`tmp/wip/
/// egress-validation`): applying this ruleset to a session already
/// reachable over SSH made every subsequent SSH connection attempt hang
/// at the banner exchange, and every `curl` trace (including the
/// allowlisted destination) come back with no corresponding proxy audit
/// log entry at all -- the guest's own DNS and TLS traffic was also being
/// dropped, but so was the SSH session running each check, which is why
/// nothing reached the proxy for *any* destination.
///
/// Also carries an unconditional `oifname "lo" accept`, ahead of even the
/// established/related rule -- `pasta` by default mirrors the host's own
/// address (and interface name) onto its interface inside the session's
/// netns (confirmed on real hardware: `ip addr show` inside the netns
/// this ruleset is applied to shows the *same* IP as the host's real
/// uplink, on an interface also named after it, e.g. `wlp1s0`), and
/// `podman --publish`'s own port-forwarding path connects to that
/// self-same address from a process already inside this netns to reach
/// the guest's published port. Since source and destination are the same
/// address, the kernel routes that connection via `lo`, not the pasta
/// interface -- so it matches neither `oifname "{iface}"`-scoped accept
/// rule, and, being the *first* packet of a brand new flow, doesn't match
/// `ct state established,related` either. Confirmed on real hardware:
/// without this rule, applying this ruleset breaks the SSH exec channel
/// itself (docs/decisions/0008-guest-exec-channel.md) even with the
/// established/related rule already in place, because the very SYN that
/// establishes it never gets out. Loopback traffic never leaves this
/// netns to reach an external destination, so accepting it unconditionally
/// doesn't weaken the actual bypass-prevention property this ruleset
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
        // Confirmed on real hardware: the bare "pasta" mode alone leaves
        // no way for the guest to reach a host-loopback-bound service --
        // `--map-host-loopback` is what makes that translation happen.
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
        // Confirmed on real hardware: pointing `--dns` straight at the
        // proxy's own IP (127.0.0.1) never works, because that address
        // means the guest's *own* loopback from inside its own network
        // namespace, never the host's -- HOST_LOOPBACK_ADDR is the
        // address `--map-host-loopback` actually translates for us.
        let flags = build_network_flags();
        let idx = flags.iter().position(|a| a == "--dns").unwrap();
        assert_eq!(flags[idx + 1], HOST_LOOPBACK_ADDR);
    }

    #[test]
    fn network_flags_include_the_krun_use_passt_annotation() {
        // Confirmed on real hardware: without this, `crun-krun` silently
        // falls back to libkrun's default TSI networking regardless of
        // `--network pasta`, so this must never be left out.
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
        // Not the proxy's literal bind IP (127.0.0.1) -- that means the
        // guest's own loopback from inside its own netns. See
        // `firewall_rules_translate_loopback_proxy_to_host_loopback_addr`.
        assert!(rules.contains(HOST_LOOPBACK_ADDR));
        assert!(rules.contains("8443"));
        // Confirms the one accept rule is scoped to the pasta interface,
        // not left to apply host-wide.
        assert!(rules.contains("oifname \"pasta0\""));
    }

    #[test]
    fn firewall_rules_translate_loopback_proxy_to_host_loopback_addr() {
        // Confirmed on real hardware: DNAT-ing to the proxy's literal
        // bind IP (127.0.0.1) sends the guest's traffic to its own
        // loopback, where nothing is listening -- every destination fails
        // closed identically, including allowlisted ones. The guest must
        // dial HOST_LOOPBACK_ADDR, which `pasta`'s `--map-host-loopback`
        // actually translates to the host's real loopback.
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
        // Without this, the default-deny policy blocks the guest's own DNS
        // queries to `dns_listen_addr` once this ruleset is actually
        // applied -- indistinguishable from every destination being
        // blocked, since `curl` hangs on resolution before it ever gets to
        // dial the (correctly DNAT-able) destination. Confirmed on real
        // hardware (tmp/wip/egress-validation): Step 3b's DNS check passes
        // only because it runs before this ruleset is applied.
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
        // Without this, the guest's own `curl https://` dials the real
        // destination IP on 443, which matches neither filter-table accept
        // rule and is dropped -- including for allowlisted destinations.
        // `crate::proxy` is a transparent SNI relay with no CONNECT/
        // explicit-proxy mode, so this redirect is the only way a guest's
        // ordinary outbound connection ever reaches it.
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains("type nat hook output"));
        // `dnat ip to`, not bare `dnat to` -- confirmed on real hardware
        // that nft rejects the bare form in an `inet`-family table as
        // ambiguous between IPv4 and IPv6 ("specify `dnat ip' or 'dnat
        // ip6' in inet table to disambiguate").
        assert!(rules.contains(&format!("tcp dport 443 dnat ip to {HOST_LOOPBACK_ADDR}:8443")));
    }

    #[test]
    fn firewall_rules_nat_table_is_scoped_to_the_pasta_interface() {
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains("oifname \"pasta0\" tcp dport 443 dnat"));
    }

    #[test]
    fn firewall_rules_accept_loopback_traffic_unconditionally() {
        // Without this, `podman --publish`'s own port-forward into the
        // guest's SSH port -- which pasta's host-address mirroring makes
        // a loopback-routed connection inside this same netns -- gets
        // dropped by the default-deny policy exactly like a bypass
        // attempt, breaking the exec channel itself. Confirmed on real
        // hardware: this broke even with established/related already
        // accepted, since it's the initiating SYN that never gets out.
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains("oifname \"lo\" accept"));
    }

    #[test]
    fn firewall_rules_accept_established_and_related_connections() {
        // Without this, the default-deny OUTPUT policy also drops the
        // guest's own reply traffic for its *inbound* SSH exec channel
        // (docs/decisions/0008-guest-exec-channel.md) -- confirmed on
        // real hardware to hang SSH at the banner exchange the moment
        // this ruleset is applied, breaking the very channel every
        // manual check in tests/manual/validate-egress.sh runs over.
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains("ct state established,related accept"));
    }

    #[test]
    fn firewall_rules_dnat_disambiguates_the_address_family() {
        // Confirmed on real hardware: nft rejects a bare `dnat to` in an
        // `inet`-family table (which spans both IPv4 and IPv6) as
        // ambiguous, even though proxy_addr is unambiguously IPv4 here.
        let rules = build_egress_firewall_rules("pasta0", proxy_addr());
        assert!(rules.contains("dnat ip to"));
        assert!(!rules.contains("dnat to"));
    }
}
