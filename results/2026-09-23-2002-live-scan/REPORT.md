# NordVPN TCP Report — 2026-09-23 20:02–20:23 UTC (session 2)

IPs rotate, so these numbers are valid for this timestamp only. They were measured from this
PC, where the RTT floor to Chicago is about 210 ms. Produced by
`scripts\Find-BestNordVPNServersLive.ps1 -SweepSubnets -SweepCidr24 216.183.109.0/24,202.49.186.0/24,193.228.206.0/24 -Traceroute`.

**Source column:**
- `official-city`: NordVPN server labelled with the city, in today's bundle.
- `official-subnet`: in today's bundle and in a city /24, but newer than the city snapshot.
- `subnet-sweep`: responded, but isn't in any official list.
- `manual`: from `scripts\known-good-ips.txt`.

## 1. What is 216.183.109.22?

- **It is `us12603.nordvpn.com`**, a current, officially listed NordVPN server. It's in
  today's official bundle (published 2026-09-23 13:03 GMT) with exactly ports 1231–1234
  (`.tcp`), 80 (`.tcp_2.6`), and 1231–1234 / 53 for UDP.
- Your local `ovpn_tcp` and `ovpn_udp` already hold all 4 profiles for it.
- Reverse DNS is NXDOMAIN, which is normal for NordVPN IPs. Forward DNS for
  `us12603.nordvpn.com` resolves to `.22`.
- **Session 1 did not miss it.** It was benchmarked on port 80 only (220.2 ms, 10/10). Your
  ports 1231–1234 weren't tested then; they are now.
- It's not an unlisted IP that could vanish unannounced. It carries the same risk as any
  NordVPN server: they retire servers routinely, and 104 Chicago ones were retired between
  07-28 and 09-23.
- Geo-IP says Fargo, ND. The last visible hop is 193.239.236.5 (Clouvider, Chicago), the same
  as the Chicago servers, so it's physically Chicago in all likelihood (ADR-004).

## 2. Fargo — .22 side by side with its siblings

Two clean measurement windows (10 connects per endpoint each, sequential):

| Endpoint | 19:46 UTC median / success | 20:21 UTC median / success (interleaved) |
|---|---|---|
| **216.183.109.22:1231 (us12603, yours)** | 223.1 ms, 10/10 | 222.7 ms, 12/12 |
| **216.183.109.22:1232** | 223.3 ms, 10/10 | — |
| **216.183.109.22:1233** | 228.1 ms, 10/10 | — |
| **216.183.109.22:1234** | 224.5 ms, 10/10 | 216.3 ms, 12/12 |
| 216.183.109.32:1231 (us12604) | 222.7 ms, 10/10 | 221.0 ms, 12/12 |
| 216.183.109.12:1231 (us12602) | 225.9 ms, 10/10 | 219.2 ms, 12/12 |

The 19:46 run gave these per-server medians across all 5 ports:

| Server | Median |
|---|---|
| us12604 | 221.7 ms |
| us12605 | 222.4 ms |
| **us12603 (.22)** | 223.3 ms |
| us12601 | 224.3 ms |
| us12602 | 226.8 ms |

**Verdict:** your impression is confirmed. `.22` performs well, but it's **statistically tied**
with the other 4 Fargo servers (within ~5 ms), not uniquely better. On ping-free TCP numbers,
its port 1234 was the single best Fargo endpoint in the main run (211.7 ms, 10/10).

**Transient dip, disclosed:**
- In the main run (≈20:10 UTC), `.22` ports 1231/1232/1233 got only 4, 6 and 4 successes out
  of 10.
- They were measured last, right after the sweep had sent ~1,200 connects into
  216.183.109.0/24, and after 30 back-to-back connects to `.22`.
- At 20:19, port 1231 was still 6/10. At 20:21, everything was 12/12.
- Most likely this was rate-limiting triggered by our own test traffic, but a brief
  server-side issue can't be excluded.
- The script now measures manual entries first and waits 90 s after a sweep. That fix has
  been syntax-checked but **not yet validated by a full re-run**.
- The main run's `ranked.csv` still contains those degraded rows as measured.

## 3. Chicago — top 5 (main run, sequential)

| Rank | Source | Hostname | IP | Port | Proto | Avg Latency | Loss | TCP Handshake | Notes |
|---|---|---|---|---|---|---|---|---|---|
| 1 | official-city | us11570.nordvpn.com | 202.49.186.170 | 1231 | TCP | 300.9 ms | 0% | 214.3 ms | ping was on a slow path during the test, while TCP was fast |
| 2 | official-city | us11525.nordvpn.com | 193.228.206.110 | 1232 | TCP | 218 ms | 0% | 220.5 ms | also best in stage 1 (211 ms) |
| 3 | official-city | us11574.nordvpn.com | 202.49.186.218 | 1233 | TCP | 212 ms | 0% | 221.9 ms | |
| 4 | official-city | us11530.nordvpn.com | 193.228.206.170 | 1233 | TCP | 220.5 ms | 0% | 222.6 ms | also top 3 in session 1 |
| 5 | official-city | us11553.nordvpn.com | 216.183.125.206 | 1231 | TCP | 227.3 ms | 0% | 222.6 ms | also top 5 in session 1 |

- The ranking is by TCP handshake, with ICMP as a tie-breaker. Ranks 2–5 sit within ~2 ms,
  which is noise.
- **us11530 and us11553 made the top 5 in both sessions**, so they're the most consistent
  picks.
- Session 1's #1 (us11575) and #2 (us11561) are still fine (us11561 came 6th today). The
  order shuffles between runs.

## 4. Discovery results

| Source | Endpoints | Reachable | Notes |
|---|---|---|---|
| official-city | 925 | 920 | us9727 dead on all ports again |
| official-subnet (new since 08-06) | 55 (11 servers) | 50 | us9719 dead; all geolocate to Chicago; best was us14121 187.14.233.82:1233 at 229.1 ms, not top 10 |
| subnet-sweep | 3,585 probes | **0 responders** | No unlisted servers in 216.183.109.0/24, 202.49.186.0/24 or 193.228.206.0/24 |
| manual | 4 | 4 | .22:1231–1234 |

The official bundle turned out to be complete for the swept ranges. The only real gap was
city-label lag (the 11 newer servers), which `official-subnet` now covers without any scanning.

## Not done / caveats

- No in-tunnel throughput test: it needs an OpenVPN client plus your credentials.
- The Chicago /24s outside the two named ones were **not** swept (11 more /24s, ~13k probes).
- ADR-004 (what "Fargo" should mean) is still open, and fallback tiers 1–5 haven't started.
