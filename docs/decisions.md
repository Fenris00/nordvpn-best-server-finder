# Architecture Decision Records — NordVPN Best-Server Finder (D:\ovpn)

Numbers are sequential and never reused; a superseding ADR says so explicitly.

## ADR-001: Report-only — no pfSense, firewall, or router automation

**Context:** The end goal is a working NordVPN OpenVPN TCP client in the owner's pfSense. The
obvious "next step" after ranking servers would be generating or pushing pfSense config.

**Decision:** This project only researches and reports (IPs, ports, profiles, measurements).
The owner does all pfSense integration manually. No pfSense configs, no touching any network
device, no signing up for / provisioning any paid service. If an integration step looks
useful, propose it and stop.

**Consequences:** Outputs are CSV/Markdown reports, never device configs. Anything that would
require credentials (e.g. a real in-tunnel throughput test) is proposed, not done.

## ADR-002: Never trust local CSVs or old .ovpn bundles as ground truth

**Context:** The old `AllServers.csv` (152 records) listed 9 Chicago hostnames (`us6572`–`us6945`)
with zero matching local `.ovpn` files. The 2026-07-28 local `ovpn_tcp` copy also contains 104
Chicago servers that are gone from NordVPN's 2026-09-23 official bundle.

**Decision:** Every ranking starts from fresh data: today's official config bundle from
`downloads.nordcdn.com` for server existence + IP/port, and live DNS / TCP tests. Local files
are only a convenience copy.

**Consequences:** Each scan downloads ~84 MB. Stale local profiles are not auto-deleted —
that's the owner's call.

## ADR-003: City labels from the gluetun-servers mirror while api.nordvpn.com is blocked

**Context:** On 2026-09-23, `api.nordvpn.com` and `nordvpn.com` were unreachable from this
network (TLS handshake timeout; DNS resolves; `nordcdn.com` and GitHub work). The official
config bundle has no city data. MSTIC's NordVPN feed was last updated 2024-10 (rejected as
stale).

**Decision:** Use `qdm12/gluetun-servers` `pkg/servers/nordvpn.json` (a maintained mirror of
the NordVPN API, snapshot 2026-08-06) for hostname → city only, intersected with today's
official bundle so no retired server gets ranked.

**Consequences:** City labels can lag by weeks: a *new* Chicago server added after the snapshot
won't appear. Revisit if the API becomes reachable (ideally switch back to it).

## ADR-004: "Fargo" requirement needs a definition before tier 1–5 research

**Context:** Contrary to the kickoff assumption, NordVPN lists 5 Fargo servers (us12601–us12605,
216.183.109.0/24). Geo-IP databases place them in Fargo, but traceroute + RTT show the same
Chicago (Clouvider) path and latency as Chicago servers — i.e. almost certainly a virtual
location.

**Decision (settled 2026-09-23 by the owner):** "Fargo" means an IP that **geolocates as
Fargo, ND**, not physical presence there. The 5 NordVPN Fargo servers (us12601–us12605,
216.183.109.2/.12/.22/.32/.42, including the owner's daily driver `.22` = us12603) satisfy
this: ipinfo.io and ip-api.com both report them as Fargo, North Dakota. Their Chicago routing
is known and accepted; it doesn't affect the requirement.

**Consequences:**
- No further Fargo research is needed. The fallback hierarchy (1. other VPN providers,
  2. residential/mobile proxy networks, 3. Fargo/ND VPS or colo, 4. a personal device near
  Fargo, 5. nearest real NordVPN city as a suggestion) stays documented as a **future option
  only**.
- Revisit it only if genuine physical Fargo presence is actually required. Geo-IP databases
  follow the provider's declarations, so if they ever stop reporting 216.183.109.0/24 as
  Fargo, re-check before relying on it.

## ADR-005: Discovery = official bundle by city AND by subnet, plus a manual known-good list

**Context:** On 2026-09-23 the owner reported that `216.183.109.22`, the endpoint they use
daily, had been "missed" by session 1. Investigation showed it wasn't: `.22` is
`us12603.nordvpn.com`, which is in the official bundle and was benchmarked in session 1 (on
port 80 only, though, not on the owner's 1231–1234). Reverse DNS for NordVPN IPs returns
NXDOMAIN, which makes an IP easy to mistake for an unlisted one. Checking this turned up a
*different, real* gap: session 1 only saw servers the 2026-08-06 city mirror labelled Chicago
or Fargo. **11 servers in today's official bundle** sit inside Chicago /24s but have no label
in the mirror (added after the snapshot: us13503–13507, us14115, us14119–14122, us9719). All
of them geolocate to Chicago.

**Decision:** `scripts\Find-BestNordVPNServersLive.ps1` discovers endpoints from four tagged
sources:
1. `official-city`: mirror label ∩ today's bundle.
2. `official-subnet`: any bundle server inside a /24 that holds a target-city server,
   whatever its label. This is what closes the real gap, and it needs no scanning.
3. `subnet-sweep`: opt-in (`-SweepSubnets`, optionally limited with `-SweepCidr24`). Probes
   non-listed IPs in those /24s on 1231–1234 and 80, and includes responders even with no
   reverse DNS.
4. `manual`: `scripts\known-good-ips.txt`, always benchmarked and ranked, seeded with
   `216.183.109.22:1231-1234`.

Every endpoint in both profile styles is tested, not just the first `remote` line.
Non-`official-city` IPs get geo-IP, plus a traceroute last-hop check when `-Traceroute` is set.

**Consequences:**
- The sweep is opt-in because it sends thousands of connection attempts to NordVPN's
  infrastructure from the owner's IP.
- Sweep-only responders aren't in NordVPN's published list, so they could disappear without
  notice and may not accept the standard profile. The report flags them as such.
- Removing the subnet or manual sources would reintroduce the gap.
- Sweeping a /24 immediately before measuring hosts in it appears to trigger rate-limiting
  on NordVPN's side (2026-09-23: `.22` fell to 4–6/10, then recovered to 12/12). The script
  therefore measures manual entries first and waits 90 s after a sweep.
- **Addendum (2026-09-23):** decided not to sweep the other 11 Chicago /24s found via
  `official-subnet`. The 3-subnet sweep found 0 responders out of 3,585 probes, and ~13k more
  connects would add rate-limiting risk. Don't re-propose it without new evidence of unlisted
  servers.
