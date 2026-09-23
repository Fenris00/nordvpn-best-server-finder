# CLAUDE_HANDOFF — NordVPN Best-Server Finder (D:\ovpn)

Read this file first in any new session. Sections are appended, never rewritten; a later
section may say "supersedes §N".

## 1. Project scope (current)

Find and rank NordVPN OpenVPN servers (TCP first) for Chicago, IL (primary) and Fargo, ND
(fallback hierarchy), from live data, and report IPs/ports/measurements. Report-only: the
owner integrates into pfSense manually (decisions.md ADR-001).

## 2. Standing rules

See `docs/README-FOR-CLAUDE.md`.

## 3. Known constraints at kickoff (2026-09-23)

- Old `AllServers.csv` (152 records) is stale: 9 Chicago hostnames (`us6572`–`us6945`), zero
  matching local `.ovpn` files. Always pull fresh server data before ranking.
- `remote` lines can hold a bare IP; the hostname is only in a comment. The parser must handle
  both (V3 has a comment-hostname fallback).
- Kickoff assumption: NordVPN has no Fargo server. **See §4 — this turned out to be wrong.**
- `.tcp.ovpn` and `.tcp_2.6.ovpn` are not duplicates (different ports/settings). Keep both.

## 4. Session 1 — first live TCP scan (2026-09-23)

**Housekeeping earlier the same day:**
- Deleted `ovpn_udp.zip` after checking all 19,026 files byte-for-byte against `ovpn_udp\`
  (sent to the Recycle Bin), plus two empty results folders.
- Moved scripts into `scripts\`; older TCP versions V1 and V2 went to `scripts\archive\`.

**What was run:** a scratch benchmark (`results\2026-09-23-tcp-live-scan\method\`) rather than
the V3 script, because V3 needs the stale CSV.
- Stage 1: all 180 live Chicago hosts × 5 TCP endpoints = 900 targets.
- Sequential re-measure of the top candidates, plus 5 Fargo servers and 1 each in
  Minneapolis and Sioux Falls.
- tracert to Fargo, Minneapolis and Chicago.

**Data sources:**
- Official nordcdn `ovpn.zip`, Last-Modified 2026-09-23 13:03 GMT.
- gluetun-servers city labels (snapshot 2026-08-06).
- Live DNS, geo-IP lookups, ping, TCP and tracert.

**Found along the way:**
- `api.nordvpn.com` / `nordvpn.com` are blocked from this network (ADR-003).
- **NordVPN does list 5 Fargo servers** (us12601–us12605). Geo-IP places them in Fargo, but
  their route and RTT match Chicago (last hop is Clouvider, Chicago), so they're almost
  certainly a virtual location (ADR-004).
- 104 of 284 local Chicago profiles have been retired by NordVPN.
- V3 only tests the first `remote` port (1231) of legacy profiles, and its 443 default is wrong.
- Parallel ICMP produced fake 10–50% loss. Sequential pings showed 0–5%.

**Result:**
- Chicago top 5 are all within ~15 ms (≈212–221 ms RTT from this site). #1 is
  us11575.nordvpn.com, 202.49.186.230:1233.
- 895/900 endpoints accept TCP; only us9727 is dead.
- Full table in `results\2026-09-23-tcp-live-scan\REPORT.md`.

**Verification gate:**
- Measurements were actually run; the timestamps are in the CSVs.
- **Not verified:** a working OpenVPN tunnel or throughput. No OpenVPN client is installed,
  and the test would need the owner's service credentials.
- The Fargo "virtual" conclusion rests on tracert + RTT, not on a provider statement.

**Not yet done:**
- Fargo fallback tiers 1–5. These are paused pending the owner's answer to ADR-004.
- Promoting the scratch method into `scripts\` (replacing the stale-CSV dependency).
- No git repo yet.

## 5. Session 2: "missed" known-good IP, discovery widened (2026-09-23)

**Asked:** the owner's daily-driver endpoint `216.183.109.22:1231-1234` was believed to have
been missed by §4. The request was to add a subnet sweep plus a known-good input, and to
benchmark `.22`.

**Found:**
- **The premise was wrong.** `.22` is `us12603.nordvpn.com`: officially listed, in today's
  bundle and in the local files, and benchmarked in §4, though only on port 80. It has no
  reverse DNS, which is normal for NordVPN IPs and makes it look unlisted.
- **A real, different gap:** 11 servers in today's bundle sit in Chicago /24s but were
  missing from the 08-06 city snapshot, so §4 never saw them. Fixed with the
  `official-subnet` discovery source (ADR-005).
- **The sweep found nothing unlisted.** 3,585 probes across 216.183.109.0/24,
  202.49.186.0/24 and 193.228.206.0/24 got 0 responders.
- **`.22` is tied with its 4 Fargo siblings** (within ~5 ms), not uniquely better. Its port
  1234 was the best Fargo endpoint in the main run.
- `.22` ports 1231–1233 briefly dropped to 4–6/10, right after the sweep hit its /24. They
  were back to 12/12 at 20:21 UTC. Most likely our own traffic triggered rate-limiting.

**Changed:**
- `scripts\Find-BestNordVPNServersLive.ps1` (new) has 4 tagged discovery sources, tests every
  `remote` port in both profile styles, and runs a parallel TCP stage 1 followed by a
  sequential stage 2. It adds geo-IP and traceroute for non-official-city IPs, and outputs to
  `results\<stamp>-live-scan\`.
- `scripts\known-good-ips.txt` (new), seeded with `.22:1231-1234`.
- The old V3 script moved to `scripts\archive\`.
- `results\_cache\` holds the downloaded bundle and city data.
- Docs: ADR-005 added; architecture.md layout, data flow and issues updated.

**Verification gate:**
- A full script run completed (2026-09-23 20:02–20:23 UTC, output in
  `results\2026-09-23-2002-live-scan\`). It produced a ranked table, geo-IP data and a
  traceroute last hop for `.22`.
- The later fix (manual entries measured first, plus a 90 s cool-down after a sweep) is
  **only syntax-checked, not re-run.**
- Bundle indexing took roughly 10 minutes in PS 5.1, which needs optimising.
- The "downloaded" time the script prints is the cache file's copy time, not NordVPN's
  Last-Modified time.

**Not yet done:**
- ADR-004 is still open, so Fargo fallback tiers 1–5 haven't started.
- The other 11 Chicago /24s weren't swept.
- No throughput test yet (needs an OpenVPN client plus credentials).
- No git repo yet.

## 6. Phase 1 close-out (2026-09-23)

**Decided:**
- The wider Chicago sweep is skipped (ADR-005 addendum).
- Git is initialised. It ignores `ovpn_tcp/`, `ovpn_udp/` (NordVPN key/cert material),
  `results/_cache/`, and `results/*/source-data/`. The last one was added beyond the
  requested list: it held a 5.9 MB copy of the same re-downloadable gluetun JSON as the
  cache.

**Secret scan before the first commit:** no keys, certs, tokens or emails in the 28
committed files, and `known-good-ips.txt` holds only a public NordVPN IP. Two minor findings,
both committed as they are, since the repo is local-only with no remote:
- The pre-existing `results/udp-scan-NordVPN-Results/*` hold `C:\Users\<username>\...`
  paths (Windows username). Strip that column before any public push.
- The session-1 report names the LAN gateway, a private IP.

**State at close:** the live scanner, the known-good list and the Chicago + Fargo rankings
are all in place, and every result is tagged by discovery source. The project stays
report-only (ADR-001).

**Still open, not resolved by this close-out:** ADR-004 (does "Fargo" mean *geolocates to*
or *physically exits near*). Fargo fallback tiers 1–5 stay unstarted until the owner answers.
NordVPN's Fargo servers do satisfy the geolocation meaning.

**For future sessions:**
- Re-run the scanner from any directory:
  `.\scripts\Find-BestNordVPNServersLive.ps1 -RefreshData [-Traceroute] [-Cities Chicago,Fargo]`.
  - `-RefreshData` re-downloads the official bundle and the city data. Without it, the
    cached copies in `results\_cache\` are used, and those go stale.
  - `-SweepSubnets` is opt-in. See the ADR-005 addendum before using it.
- Each run writes `results\<yyyy-MM-dd-HHmm>-live-scan\` containing `ranked.csv` (rank per
  city, with a Source column), `stage1-all-endpoints.csv` and `summary.txt`. Commit these;
  they're small.
- Add any endpoint that has been validated in real use to `scripts\known-good-ips.txt`
  (`IP:PORTS  # note`). It gets benchmarked first and ranked on every run.
- Known gaps:
  - The post-sweep cool-down and manual-first ordering are syntax-checked but not re-run.
  - Bundle indexing takes ~10 minutes in PS 5.1.
  - The printed "downloaded" time is the cache file's copy time.
  - No in-tunnel throughput test.
