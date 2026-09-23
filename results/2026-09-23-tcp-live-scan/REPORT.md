# NordVPN TCP Best-Server Report — 2026-09-23 (19:06–19:20 UTC)

NordVPN IPs rotate. Treat everything below as valid for this timestamp only.

**Measured from:** this Windows PC (LAN gateway [LAN gateway — redacted]). Path to the US goes via
Marseille → GTT → Chicago; baseline RTT to Chicago is ~210 ms. Results only apply to
pfSense if pfSense sits on the same uplink.

## Data sources (and how fresh each is)

| Source | Used for | Freshness |
|---|---|---|
| `downloads.nordcdn.com/configs/archives/servers/ovpn.zip` (official) | Which servers exist today; IP + port on `remote` lines | Last-Modified 2026-09-23 13:03 GMT |
| `qdm12/gluetun-servers` `pkg/servers/nordvpn.json` (third-party mirror of NordVPN API) | City label per hostname | Snapshot 2026-08-06 04:33 UTC — **~7 weeks old** |
| Live DNS | Confirm hostname → IP | Live |
| ipinfo.io + ip-api.com | Geo-IP of Fargo / Minneapolis / Chicago IPs | Live |
| ICMP (ping.exe), TCP connect, tracert | Benchmarks | Live |

`api.nordvpn.com` and `nordvpn.com` are **unreachable from this network** (TLS handshake
times out; DNS resolves; `nordcdn.com` works). WebFetch to the API also failed. So there is
no fully live city list — the city labels come from the 2026-08-06 mirror, cross-checked
against today's official bundle.

## 1. Chicago, IL — ranked (top 5)

Sequential re-measure (20 pings, 10 TCP connects each) at 2026-09-23 19:12 UTC.

| Rank | Hostname | IP | Port | Protocol | Avg Latency | Packet Loss | TCP Handshake (median) | Notes |
|---|---|---|---|---|---|---|---|---|
| 1 | us11575.nordvpn.com | 202.49.186.230 | 1233 | TCP | 212 ms (210/225, jitter 2.6) | 0% | 218.3 ms | legacy `.tcp` profile; 1231–1234 all open |
| 2 | us11561.nordvpn.com | 202.49.186.62 | 80 | TCP | 212 ms (210/219, jitter 2.8) | 0% | 223.2 ms | `.tcp_2.6` profile (OpenVPN 2.6) |
| 3 | us11530.nordvpn.com | 193.228.206.170 | 1233 | TCP | 221 ms (219/232, jitter 3.1) | 0% | 224.6 ms | best in parallel stage-2 run |
| 4 | us11571.nordvpn.com | 202.49.186.182 | 1232 | TCP | 213 ms (210/217, jitter 1.5) | 5% (1/20) | 227.7 ms | full tracert confirmed via Chicago/Clouvider |
| 5 | us11536.nordvpn.com | 216.183.125.2 | 1231 | TCP | 212 ms (210/218, jitter 1.9) | 0% | 232.5 ms | |

**Read this before picking:** the whole top 5 sits within ~15 ms, which is close to the noise
at a 210 ms baseline. Any of them is a reasonable choice; prefer one on the port your profile
variant uses (80 for `_2.6`, 1231–1234 for legacy).

Scan totals: 284 Chicago hosts in the 08-06 snapshot → **180 still in today's bundle**
(104 retired since your local `ovpn_tcp` copy of 2026-07-28). 900 endpoints (host × port)
tested; **895 accepted TCP**. Only `us9727.nordvpn.com` (181.215.172.148) failed on every
port. 5 endpoints filtered ICMP. Full data: `chicago-stage1.csv`, `chicago-ranked.csv`,
`sequential.csv`.

**Not done: tunnel throughput/jitter test.** Needs an OpenVPN client (not installed) and
your NordVPN service credentials, which are out of scope for me to hold. Ping jitter above
is ICMP only, not in-tunnel.

## 2. Fargo, ND

**Tier 0 (NordVPN itself) — the "no Fargo server" assumption was wrong, with a caveat.**

NordVPN lists 5 Fargo servers, all present in today's official bundle and in your local
`ovpn_tcp`:

| Hostname | IP | Port | TCP Handshake (median) | Ping |
|---|---|---|---|---|
| us12602.nordvpn.com | 216.183.109.12 | 80 (2.6) | 217.7 ms, 10/10 | ICMP filtered |
| us12601.nordvpn.com | 216.183.109.2 | 80 (2.6) / 1231 | 221.3 / 219.9 ms, 10/10 | ICMP filtered |
| us12603.nordvpn.com | 216.183.109.22 | 80 (2.6) | 220.2 ms, 10/10 | ICMP filtered |
| us12605.nordvpn.com | 216.183.109.42 | 80 (2.6) | 222.1 ms, 10/10 | ICMP filtered |
| us12604.nordvpn.com | 216.183.109.32 | 80 (2.6) | 226.0 ms, 10/10 | ICMP filtered |

- **Geo-IP says Fargo:** ipinfo.io and ip-api.com both report 216.183.109.2 as Fargo, North
  Dakota (AS136787 PacketHub S.A., NordVPN's hosting entity).
- **Physical location looks like Chicago (virtual location):** tracert to the Fargo IP takes
  the *identical* path as Chicago server 202.49.186.182 — GTT `cr9-chi1` → 207.162.201.159
  (GTT, Chicago) → 193.239.236.5 (**Clouvider, Chicago**) — and the TCP handshake is the same
  ~220 ms as Chicago. A real Fargo box would add latency after Chicago. The same holds for
  NordVPN's Minneapolis (216.183.105.2) and Sioux Falls (216.183.123.2) servers.
- This is strong evidence, not proof (an MPLS tunnel could hide hops), but the RTT equality
  agrees with it.

**So:** if you need an IP that *geolocates* to Fargo, NordVPN's Fargo servers deliver that.
If you need the traffic to *physically exit in/near Fargo*, they almost certainly don't.
Fallback tiers 1–5 were **not started** — waiting on your call about which one you need.
