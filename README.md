# NordVPN Best-Server Finder

Live benchmarking and ranking of NordVPN OpenVPN **TCP** servers, built for a specific
routing need: finding the fastest real endpoints near Chicago, IL, with Fargo, ND as a
secondary target. It always measures against fresh data instead of trusting NordVPN's
bundled `.ovpn` files or any cached city list, both of which go stale within weeks.

**Report-only.** This tool produces CSV/Markdown reports — hostnames, IPs, ports,
latency, jitter, TCP handshake times. It does not generate or push any router/firewall
configuration, and it never touches NordVPN account credentials. Turning a ranked
endpoint into a working tunnel is a manual step you do yourself in your own VPN client
or router.

## Quick start

Requires Windows PowerShell 5.1+.

```powershell
.\scripts\Find-BestNordVPNServersLive.ps1 -RefreshData [-Traceroute] [-Cities Chicago,Fargo]
```

- `-RefreshData` re-downloads NordVPN's official config bundle and the city-label data.
  Use it on every real scan — the cached copy goes stale.
- `-Cities` accepts any city names present in the label data; `Chicago,Fargo` is just
  the default used during development.
- `-Traceroute` adds a traceroute last-hop lookup for endpoints outside the requested
  cities (useful for spotting virtual/geo-IP-only locations — see the Fargo note below).
- `-SweepSubnets` (optional, opt-in) probes unlisted IPs inside the same /24s as known
  servers. It sends a large number of connection attempts to NordVPN's infrastructure,
  so it's off by default — see `docs/decisions.md` (ADR-005) before enabling it.

Each run writes a timestamped folder under `results/`:

```
results/<yyyy-MM-dd-HHmm>-live-scan/
├── ranked.csv               per-city rank, with a Source column
├── stage1-all-endpoints.csv every endpoint tested in the first pass
└── summary.txt              run parameters and reachability counts
```

## Layout

```
scripts/
├── Find-BestNordVPNServersLive.ps1   current TCP scanner (live data)
├── known-good-ips.txt                manually-added endpoints, always benchmarked
├── Find-BestNordVPNUDPServers.ps1    older UDP scanner (ICMP-based, pre-dates the
│                                      live-discovery approach)
└── archive/                          superseded scanner versions, kept for history
results/                              one folder per scan run (see above)
docs/
├── architecture.md                   system layout and data flow
├── decisions.md                      architecture decision records (ADR-001..005)
└── CLAUDE_HANDOFF.md                 session-by-session project log
```

`ovpn_tcp/` and `ovpn_udp/` (NordVPN's official `.ovpn` profile bundle) and
`results/_cache/` are intentionally **not** tracked in this repo — they contain
NordVPN's shared TLS-auth key material and are large, re-downloadable binaries. The
scanner re-fetches what it needs directly from NordVPN's CDN when run with
`-RefreshData`; a local copy of the bundle is only a convenience, not a dependency.

## Why "live" data matters here

NordVPN's official `.ovpn` bundle changes weekly: servers get added and retired, and a
locally-saved copy or a third-party mirror snapshot can miss both. This project treats
any such data as a convenience cache, never ground truth — every ranking pulls the
current bundle and does live DNS/TCP tests before ranking anything. See
`docs/decisions.md` for the specific incidents (stale CSVs, a blocked API endpoint,
label lag) that led to this approach.

## The Fargo note

NordVPN's five advertised Fargo, ND servers geolocate as Fargo in IP-geolocation
databases, but their network route and latency match Chicago servers — they're almost
certainly a virtual location rather than physical presence in Fargo. Whether that
satisfies a "Fargo server" requirement is a judgment call, not a technical one; this
project treats *geolocates as Fargo* as sufficient (see ADR-004 in `docs/decisions.md`
for the full reasoning and the physical-presence fallback options that were considered
and shelved).

## Known limitations

- Indexing NordVPN's ~37,000-entry config bundle takes several minutes in PowerShell
  5.1 — this could be optimized.
- ICMP (ping) is unreliable for ranking: several regions filter it entirely, and
  parallel ping bursts trigger false packet-loss readings. TCP connect success/latency
  is the more reliable signal, and is what ranking is based on.
- No in-tunnel throughput test exists yet — that would require an OpenVPN client and
  valid account credentials, which this project deliberately avoids handling.

## Contributing

Issues and PRs are welcome — extending discovery to other target cities, improving
scan performance, or adding a throughput-test mode (designed so it never needs to store
credentials) are all reasonable directions. Please keep the report-only scope: this
project should never gain the ability to write device/router configuration directly.

## License

MIT — see `LICENSE`.
