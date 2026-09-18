//! Prints the nftables ruleset `network_setup::build_egress_firewall_rules`
//! generates, for `tests/manual/validate-egress.sh` to pipe into `nft -f -`
//! so the script always applies the exact ruleset this crate builds.
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
