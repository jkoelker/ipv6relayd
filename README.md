# ipv6relayd

ipv6relayd is an IPv6 control-plane relay for routed (non-bridged) networks. It keeps downstream LANs usable when the upstream link will not delegate a prefix and only provides a single /64.

Some ISPs (especially CGNAT or fixed-wireless) refuse to hand out PD. A /64 on the WAN cannot be stretched across routed segments, so hosts on downstream LANs lose IPv6. ipv6relayd sits between upstream and downstream interfaces and proxies the three protocols that make IPv6 work:
- Router Advertisements with RDNSS/DNSSL/PREF64 rewrites and unsolicited RA timers
- DHCPv6 relay with upstream autodiscovery, Interface-ID/Remote-ID injection, and optional DNS overrides
- Neighbor Discovery bridge with learned + static bindings and `passive` interfaces for monitor-only ports

Typical scenario:
- Upstream: only a single /64, no prefix delegation.
- Downstream: one or more routed LANs needing SLAAC, DNS info, and neighbor discovery.
- Solution: run ipv6relayd on the router; it relays RA, DHCPv6, and NDP between interfaces so each LAN keeps functioning even without PD.

## Quick Start
```bash
go build ./cmd/ipv6relayd
sudo ./ipv6relayd run --upstream wan --downstream lan0 --downstream lan1  # needs CAP_NET_ADMIN and CAP_NET_RAW
```

Most users only need to tell the daemon which interface faces upstream and which ones point downstream. The CLI flags wire those directly into the minimal config schema: `--upstream` must be provided once and `--downstream` can be repeated.

If you prefer a file (for DNS rewrites, DHCP tweaks, etc.), generate one and pass `-config`:

```bash
./ipv6relayd config write -o ipv6relayd.yaml
sudo ./ipv6relayd run -config ipv6relayd.yaml
```

Minimal YAML:
```yaml
---
upstream:
  ifname: wan
downstreams:
  - ifname: lan0
```

When `dhcpv6.upstream` is omitted the relay follows the upstream default route and falls back to ff02::1:547 if it cannot find a server. `ipv6relayd config default` emits the same schema the daemon loads (YAML or JSON).

### Optional knobs
- `ra.*_rewrite` rewrites upstream RDNSS/DNSSL/PREF64 options.
- `dhcpv6.override_dns` / `override_domain_search` inject answers on unauthenticated replies; set `force_reply_dns_rewrite` to force rewrites.
- `dhcpv6.remote_id.enterprise_id` (plus `{ifname}`/`{mac}` templates) controls Remote-ID payloads.
- Per-interface `link_local`, `address_hints`, and `passive` flags cover unusual topologies without touching code.

See `docs/design.md` for architecture notes; packet samples used in tests live under `info/`.

## Development
- `make lint` — golangci-lint + gofmt/goimports/gci inside the devkit container.
- `make test` — `go test` for every package except `integration/`.
- `make integration` — privileged podman/docker run that exercises the namespace-based suite.
- `make shell` — interactive devkit shell with the repo mounted at `/workspace`.
