//! Prints the nftables ruleset `network_setup::build_egress_firewall_rules`
//! generates for a given pasta interface and proxy address, for
//! `tests/manual/validate-egress.sh` Step 4 to pipe straight into
//! `nft -f -`. Kept as a thin example (rather than duplicating the format
//! string in the shell script, the way Step 4's instructions used to ask
//! a human to do by hand) so the script always applies the exact ruleset
//! this crate actually builds, not a hand-copied approximation of it.
//!
//! Usage:
//!   cargo run -p habitat-egress --example print_firewall_rules -- \
//!       --iface pasta0 --proxy-addr 127.0.0.1:8443

use habitat_egress::network_setup;
use std::net::SocketAddr;

fn die(message: &str) -> ! {
    eprintln!("print_firewall_rules: {message}");
    std::process::exit(2);
}

fn main() {
    let mut iface = None;
    let mut proxy_addr = None;

    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut next = || argv.next().unwrap_or_else(|| die(&format!("{flag} needs a value")));
        match flag.as_str() {
            "--iface" => iface = Some(next()),
            "--proxy-addr" => proxy_addr = Some(next()),
            other => die(&format!("unrecognized flag: {other}")),
        }
    }

    let iface = iface.unwrap_or_else(|| die("--iface is required"));
    let proxy_addr: SocketAddr = proxy_addr
        .unwrap_or_else(|| die("--proxy-addr is required"))
        .parse()
        .unwrap_or_else(|e| die(&format!("--proxy-addr: {e}")));

    print!("{}", network_setup::build_egress_firewall_rules(&iface, proxy_addr));
}
