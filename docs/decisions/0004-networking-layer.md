# 0004. Networking layer: `passt` virtual interface, default-deny egress filtered by destination at the proxy

Status: accepted
Date: 2026-09-14

## Context

libkrun's default networking mode is TSI (transparent socket
impersonation), which proxies guest socket calls directly rather than
giving the guest a real network interface. That's convenient, but it
isn't visible to normal host firewall rules -- a compromised or
misbehaving guest's traffic wouldn't be something host-side network
policy could see or restrict at all, which would undermine the
egress-restriction design in `docs/plan.md` Section 2.3 (default-deny
egress, allowlisting only AI provider APIs and standard package
registries).

Separately, filtering has to happen at the point where the connection is
actually carried, and by destination rather than by IP: package
registries and AI provider APIs sit behind rotating IPs, and fully
intercepting traffic to inspect it would break certificate verification
in agent tooling.

## Decision

The guest's network is provided by `passt`, not libkrun's default TSI
mode. `passt` gives the guest a real virtual network interface, so host-
side network policy can actually see and restrict its traffic. The
guest's network configuration is set up so that a local proxy is the
*only* address it can reach at all -- there's no route to anything else
to filter in the first place, which is a stronger form of "the agent
can't route around it" than intercepting-and-redirecting traffic after
the fact. Filtering at the proxy happens at the point where a secure
connection is being negotiated (destination-based, e.g. SNI), not by IP,
so tools that verify certificates still work normally. By default, only
major AI provider APIs and standard package registries are reachable;
everything else is blocked, extendable per project.

## Consequences

- Egress enforcement happens at the local proxy that actually carries
  guest traffic -- never only inside the guest, and never assumed to hold
  for a network path that hasn't actually been shown to be the one
  carrying it (AGENTS.md Section 2, invariant 6).
- Default-deny egress, filtered by destination at connection setup, is a
  non-negotiable invariant (AGENTS.md Section 2, invariant 7).
- The "verify before trusting" validation this needs (AGENTS.md Section 3)
  is a concrete connection trace confirming allowed and blocked
  destinations are actually intercepted at the proxy hand-off -- before
  trusting the ruleset, and re-run after any change.
- **Open item:** DNS resolution inside the guest under `passt` needs to be
  pinned to the proxy path too -- a leftover default resolver would be a
  way for the network restriction to quietly leak. This must be verified,
  not assumed, before v1 ships (`docs/plan.md` Section 2.3 Open item;
  AGENTS.md Section 3).
