//! Harness that runs `habitat-egress`'s proxy and DNS forwarder against
//! real sockets, for `tests/manual/validate-egress.sh`.
//!
//! Usage:
//!   cargo run -p habitat-egress --example egress_harness -- \
//!       --proxy-addr 127.0.0.1:8443 --dns-addr 127.0.0.1:5300 \
//!       --audit-log /path/to/audit.jsonl [--project-config /path/to/config.yaml]
//!
//! Prints a line starting with `READY` once both sockets are bound, then
//! blocks forever; stop with SIGTERM/SIGKILL.

use habitat_audit::FileAuditSink;
use habitat_egress::dialer::SystemDialer;
use habitat_egress::network_setup;
use habitat_egress::{dns, proxy};
use habitat_policy::{config, egress_allowlist};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

struct Args {
    proxy_addr: SocketAddr,
    dns_addr: SocketAddr,
    upstream_dns: String,
    audit_log: PathBuf,
    project_config: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut proxy_addr = None;
    let mut dns_addr = None;
    let mut upstream_dns = dns::DEFAULT_UPSTREAM_DNS.to_string();
    let mut audit_log = None;
    let mut project_config = None;

    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut next = || argv.next().unwrap_or_else(|| die(&format!("{flag} needs a value")));
        match flag.as_str() {
            "--proxy-addr" => proxy_addr = Some(next()),
            "--dns-addr" => dns_addr = Some(next()),
            "--upstream-dns" => upstream_dns = next(),
            "--audit-log" => audit_log = Some(PathBuf::from(next())),
            "--project-config" => project_config = Some(PathBuf::from(next())),
            other => die(&format!("unrecognized flag: {other}")),
        }
    }

    let proxy_addr = proxy_addr
        .unwrap_or_else(|| die("--proxy-addr is required"))
        .parse()
        .unwrap_or_else(|e| die(&format!("--proxy-addr: {e}")));
    let dns_addr = dns_addr
        .unwrap_or_else(|| die("--dns-addr is required"))
        .parse()
        .unwrap_or_else(|e| die(&format!("--dns-addr: {e}")));
    let audit_log = audit_log.unwrap_or_else(|| die("--audit-log is required"));

    Args {
        proxy_addr,
        dns_addr,
        upstream_dns,
        audit_log,
        project_config,
    }
}

fn die(message: &str) -> ! {
    eprintln!("egress_harness: {message}");
    std::process::exit(2);
}

fn main() {
    let args = parse_args();

    let project_additions = match &args.project_config {
        Some(path) => config::load(path)
            .unwrap_or_else(|e| die(&format!("--project-config: {e}")))
            .egress_allowlist_additions,
        None => Vec::new(),
    };
    let allowlist = egress_allowlist::effective_entries(&project_additions);
    eprintln!(
        "egress_harness: effective allowlist has {} entries ({})",
        allowlist.len(),
        args.project_config
            .as_ref()
            .map(|p| format!("defaults + {}", p.display()))
            .unwrap_or_else(|| "built-in defaults only".to_string())
    );

    // Bind both sockets up front so a port-in-use failure is reported
    // before printing READY.
    let proxy_listener =
        TcpListener::bind(args.proxy_addr).unwrap_or_else(|e| die(&format!("proxy bind: {e}")));
    let dns_socket = std::net::UdpSocket::bind(args.dns_addr)
        .unwrap_or_else(|e| die(&format!("dns bind: {e}")));
    drop(dns_socket); // handed straight back to dns::run below

    let audit = Arc::new(FileAuditSink::new(&args.audit_log));
    let dialer = Arc::new(SystemDialer);
    let running = Arc::new(AtomicBool::new(true));

    let dns_addr = args.dns_addr;
    let upstream_dns = args.upstream_dns.clone();
    let dns_running = Arc::clone(&running);
    let dns_thread = thread::spawn(move || {
        if let Err(e) = dns::run(dns_addr, &upstream_dns, dns_running) {
            eprintln!("egress_harness: dns forwarder exited: {e}");
        }
    });

    println!(
        "READY proxy={} dns={} audit_log={} table={}",
        args.proxy_addr,
        args.dns_addr,
        args.audit_log.display(),
        network_setup::FIREWALL_TABLE
    );

    // proxy::run owns its own bind step, so drop this listener right
    // before it re-binds the same address.
    drop(proxy_listener);
    if let Err(e) = proxy::run(args.proxy_addr, allowlist, dialer, audit) {
        die(&format!("proxy accept loop exited: {e}"));
    }

    running.store(false, std::sync::atomic::Ordering::SeqCst);
    let _ = dns_thread.join();
}
