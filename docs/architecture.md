# Architecture — NordVPN Best-Server Finder (D:\ovpn)

## System overview

A set of Windows PowerShell 5.1 scripts plus NordVPN OpenVPN profile data, used to find and
rank NordVPN servers (TCP first) near Chicago, IL and Fargo, ND. Output is reports only
(see decisions.md ADR-001). It must never write device configs or handle account
credentials.

## Layout

```
D:\ovpn\
├── ovpn_tcp\     19,024 profiles (9,512 servers × .tcp + .tcp_2.6), downloaded 2026-07-28
├── ovpn_udp\     19,026 profiles (9,513 servers × .udp + .udp_2.6), same bundle
├── scripts\
│   ├── Find-BestNordVPNServersLive.ps1  — CURRENT TCP scanner (live data, ADR-005)
│   ├── known-good-ips.txt               — manual endpoints, always ranked
│   ├── Find-BestNordVPNUDPServers.ps1   — UDP scanner, ICMP only, stale-CSV era
│   └── archive\  V1, V2, V3 of the old TCP scanner (V3 needs stale AllServers.csv)
├── results\
│   ├── _cache\                          nordcdn-ovpn.zip + gluetun-nordvpn.json (-RefreshData re-downloads)
│   ├── udp-scan-NordVPN-Results\        older UDP scan output
│   ├── 2026-09-23-tcp-live-scan\        session 1 report (scratch method in method\)
│   └── yyyy-MM-dd-HHmm-live-scan\       one folder per run of the live scanner
└── docs\         CLAUDE_HANDOFF.md, architecture.md, decisions.md, README-FOR-CLAUDE.md
```

Run from anywhere: `.\scripts\Find-BestNordVPNServersLive.ps1 [-RefreshData] [-SweepSubnets
[-SweepCidr24 a.b.c.0/24,...]] [-Traceroute] [-Cities Chicago,Fargo]`. Use `-RefreshData`
on every real scan, since the cached bundle goes stale.

## Data flow (Find-BestNordVPNServersLive.ps1)

```
nordcdn ovpn.zip (official, today) ──► every TCP remote IP:port, both profile styles
gluetun nordvpn.json (city labels, snapshot — can lag weeks) ──► hostname → city
        │
        ▼  discovery (each endpoint tagged with Source)
  official-city    label ∈ Cities, in today's bundle
  official-subnet  in today's bundle, inside a /24 holding a target-city server
  subnet-sweep     opt-in: non-listed IP in those /24s answering on 1231-1234/80
  manual           scripts\known-good-ips.txt
        │
        ▼
stage 1: 2 TCP connects per endpoint, 24-way parallel (no ICMP here — see issues)
        ▼
stage 2: top N per city + ALL manual entries, SEQUENTIAL: 20 pings + 10 TCP connects
        ▼
non-official-city IPs: ip-api.com batch geo-IP; with -Traceroute, last visible hop + its geo
        ▼
results\<stamp>-live-scan\  stage1-all-endpoints.csv, ranked.csv (per-city rank), summary.txt
```

## Known data-quality issues

- **Stale location CSV:** `AllServers.csv` doesn't match local hostnames (ADR-002).
- **IP on `remote` line:** configs put a bare IP on `remote`; the hostname only appears in a
  comment. V3 handles this with a comment-hostname fallback.
- **Multiple remotes per profile:** legacy `.tcp.ovpn` has 4 `remote` lines (ports 1231–1234,
  `remote-random`); `.tcp_2.6.ovpn` has one (port 80). The archived V3 parsed only the first
  `remote` (port 1231) and defaulted to 443. The live scanner tests every remote line.
- **City-label lag:** the mirror snapshot misses servers added after it. On 2026-09-23 that
  was 11 Chicago-subnet servers, which the `official-subnet` source now catches (ADR-005).
- **No reverse DNS:** NordVPN IPs return NXDOMAIN for PTR, so identify an IP by searching the
  official bundle's `remote` lines, not by rDNS.
- **Local profiles go stale:** 104 of 284 Chicago servers in the local copy are gone from
  today's official bundle.
- **ICMP isn't reliable:** parallel pings fake packet loss (rate-limiting); Fargo, Minneapolis
  and Sioux Falls servers filter ICMP completely. TCP connect is the more reliable signal.
- **Virtual locations:** NordVPN Fargo/Minneapolis/Sioux Falls IPs geolocate to those cities
  but route like Chicago servers (ADR-004).
- **Network restriction:** `api.nordvpn.com` / `nordvpn.com` are blocked from this network;
  `nordcdn.com` works (ADR-003).
- **Scanner performance:** indexing the ~37k-entry bundle zip takes ~10 min in PS 5.1. A
  full run with a 3-subnet sweep plus traceroute took ~40 min.
- **Burst sensitivity:** a burst of connects to one /24 can depress its TCP success for
  minutes afterwards (ADR-005 consequences).
