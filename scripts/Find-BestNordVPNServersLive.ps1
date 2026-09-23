#requires -version 5.1

<#
.SYNOPSIS
    Ranks NordVPN OpenVPN TCP endpoints for target cities from LIVE data.
    Report-only (docs\decisions.md ADR-001): never writes device configs.

.DESCRIPTION
    Supersedes the stale-CSV scanners in scripts\archive\. Candidate endpoints come
    from four discovery sources, each tagged in the output:

      official-city    Hostname labelled with a target city in the gluetun-servers
                       mirror AND present in today's official nordcdn config bundle.
      official-subnet  In today's bundle, inside a /24 that holds a target-city server,
                       but not labelled with that city in the mirror (usually a server
                       added after the mirror snapshot). ADR-005.
      subnet-sweep     (opt-in, -SweepSubnets) An IP in one of those /24s that answers
                       on an OpenVPN TCP port but is in no official list.
      manual           Listed in -KnownGoodFile. Always benchmarked and ranked.

    Endpoints = every remote IP:port in both profile styles (.tcp.ovpn has 1231-1234,
    .tcp_2.6.ovpn has 80). Stage 1 is a parallel TCP-connect pass (no ICMP: parallel
    pings get rate-limited and fake packet loss). Stage 2 re-measures the best
    endpoints plus every manual entry SEQUENTIALLY: 20 pings + 10 TCP connects.

    Non-official IPs (official-subnet / subnet-sweep / manual) get geo-IP (ip-api.com
    batch) and, with -Traceroute, a tracert last-visible-hop check, so the
    virtual-location caveat (ADR-004) is applied consistently.

.NOTES
    TCP connect proves the port is open, not that OpenVPN auth/TLS will succeed.
    Latency is measured from THIS machine; only meaningful for pfSense if it shares
    the uplink. api.nordvpn.com is blocked on the owner's network (ADR-003), so city
    labels come from the gluetun-servers mirror and can lag by weeks.
#>

[CmdletBinding()]
param(
    [string[]]$Cities = @('Chicago', 'Fargo'),
    [string]$KnownGoodFile = (Join-Path $PSScriptRoot 'known-good-ips.txt'),
    [string]$OutputRoot = (Join-Path (Split-Path $PSScriptRoot -Parent) 'results'),
    [string]$CacheFolder = (Join-Path (Split-Path $PSScriptRoot -Parent) 'results\_cache'),
    [switch]$RefreshData,
    [switch]$SweepSubnets,
    [int[]]$SweepPorts = @(1231, 1232, 1233, 1234, 80),
    [string[]]$SweepCidr24 = @(),   # e.g. '216.183.109.0/24'; limits -SweepSubnets to these
    [int]$Stage2PerCity = 10,
    [int]$Stage2Pings = 20,
    [int]$Stage2TcpSamples = 10,
    [int]$TcpTimeoutMs = 3000,
    [int]$Parallelism = 24,
    [switch]$Traceroute
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$BundleUrl = 'https://downloads.nordcdn.com/configs/archives/servers/ovpn.zip'
$CityDataUrl = 'https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/nordvpn.json'

function Write-Section($text) { Write-Host ''; Write-Host ('=' * 60); Write-Host $text; Write-Host ('=' * 60) }

function Get-CachedFile([string]$Url, [string]$Path) {
    if ($RefreshData -or -not (Test-Path -LiteralPath $Path)) {
        Write-Host "Downloading $Url"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        (New-Object Net.WebClient).DownloadFile($Url, $Path)
    }
    Get-Item -LiteralPath $Path
}

function Get-Subnet24([string]$Ip) { $Ip -replace '\.\d+$', '' }

function Read-KnownGood([string]$Path) {
    # Format, one per line:  IP:PORTS  [# note]   PORTS = 1231-1234 | 80 | 1231,80
    $list = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $Path)) { return $list }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $t = ($line -replace '#.*$', '').Trim()
        if (-not $t) { continue }
        $note = if ($line -match '#\s*(.*)$') { $matches[1].Trim() } else { '' }
        if ($t -notmatch '^(\d{1,3}(?:\.\d{1,3}){3}):([\d,\-]+)$') { Write-Warning "Skipping unparseable known-good line: $line"; continue }
        $ip = $matches[1]
        foreach ($part in $matches[2] -split ',') {
            if ($part -match '^(\d+)-(\d+)$') { $ports = [int]$matches[1]..[int]$matches[2] } else { $ports = @([int]$part) }
            foreach ($p in $ports) { $list.Add([pscustomobject]@{ IP = $ip; Port = $p; Note = $note }) }
        }
    }
    $list
}

# ---------------------------------------------------------------- probes
$tcpProbe = {
    param($ip, $port, $samples, $timeoutMs, $gapMs)
    $t = @()
    for ($i = 0; $i -lt $samples; $i++) {
        $cl = New-Object System.Net.Sockets.TcpClient
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $iar = $cl.BeginConnect($ip, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($timeoutMs, $false)) { $cl.EndConnect($iar); $t += $sw.Elapsed.TotalMilliseconds }
        } catch {} finally { $cl.Close() }
        if ($gapMs) { Start-Sleep -Milliseconds $gapMs }
    }
    $s = @($t | Sort-Object)
    [pscustomobject]@{
        TcpOk = $s.Count; TcpTried = $samples
        TcpMedianMs = if ($s) { [math]::Round($s[[int][math]::Floor(($s.Count - 1) / 2)], 1) } else { $null }
    }
}

function Invoke-ParallelTcp($targets, [int]$samples) {
    $pool = [RunspaceFactory]::CreateRunspacePool(1, $Parallelism); $pool.Open()
    $jobs = foreach ($t in $targets) {
        $ps = [PowerShell]::Create().AddScript($tcpProbe).AddArgument($t.IP).AddArgument($t.Port).AddArgument($samples).AddArgument($TcpTimeoutMs).AddArgument(0)
        $ps.RunspacePool = $pool
        [pscustomobject]@{ T = $t; PS = $ps; H = $ps.BeginInvoke() }
    }
    $n = 0
    $out = foreach ($jb in $jobs) {
        $n++
        if (($n % 100) -eq 0) { Write-Progress -Activity 'TCP connect' -Status "$n / $($jobs.Count)" -PercentComplete (100 * $n / $jobs.Count) }
        $r = $jb.PS.EndInvoke($jb.H)[0]; $jb.PS.Dispose()
        $o = $jb.T.PSObject.Copy()
        foreach ($p in $r.PSObject.Properties) { $o | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force }
        $o
    }
    Write-Progress -Activity 'TCP connect' -Completed
    $pool.Close()
    $out
}

function Measure-Sequential($t) {
    $o = ping.exe -n $Stage2Pings -w 1000 $t.IP
    $all = $o -join ' '
    $lost = if ($all -match 'Lost = (\d+)') { [int]$matches[1] } else { $Stage2Pings }
    $rtts = @($o | Select-String 'time[=<](\d+)ms' | ForEach-Object { [double]$_.Matches[0].Groups[1].Value })
    $tcp = & $tcpProbe $t.IP $t.Port $Stage2TcpSamples $TcpTimeoutMs 200
    $filtered = ($rtts.Count -eq 0)
    $jit = if ($rtts.Count -ge 2) { [math]::Round((@(for ($k = 1; $k -lt $rtts.Count; $k++) { [math]::Abs($rtts[$k] - $rtts[$k - 1]) }) | Measure-Object -Average).Average, 1) } else { $null }
    $o2 = $t.PSObject.Copy()
    $add = [ordered]@{
        AvgLatencyMs = if ($filtered) { $null } else { [math]::Round(($rtts | Measure-Object -Average).Average, 1) }
        MinMaxMs = if ($filtered) { '' } else { "$(($rtts | Measure-Object -Minimum).Minimum)/$(($rtts | Measure-Object -Maximum).Maximum)" }
        JitterMs = $jit
        PacketLoss = if ($filtered) { 'ICMP filtered' } else { "$([math]::Round(100 * $lost / $Stage2Pings))%" }
        TcpHandshakeMs = $tcp.TcpMedianMs
        TcpSuccess = "$($tcp.TcpOk)/$($tcp.TcpTried)"
    }
    foreach ($k in $add.Keys) { $o2 | Add-Member -NotePropertyName $k -NotePropertyValue $add[$k] -Force }
    $o2
}

function Get-GeoBatch([string[]]$ips) {
    $map = @{}
    $ips = @($ips | Select-Object -Unique)
    for ($i = 0; $i -lt $ips.Count; $i += 100) {
        $chunk = $ips[$i..([math]::Min($i + 99, $ips.Count - 1))]
        try {
            $body = ConvertTo-Json @($chunk | ForEach-Object { @{ query = $_; fields = 'query,city,regionName,org' } })
            $res = Invoke-RestMethod -Method Post -Uri 'http://ip-api.com/batch' -Body $body -ContentType 'application/json' -TimeoutSec 30
            foreach ($r in $res) { $map[$r.query] = "$($r.city), $($r.regionName) ($($r.org))" }
        } catch { Write-Warning "Geo-IP lookup failed: $($_.Exception.Message)" }
        Start-Sleep -Seconds 2
    }
    $map
}

function Get-LastHop([string]$ip) {
    # Last responding hop that isn't the target itself; NordVPN servers often filter ICMP.
    $hops = @(tracert -d -h 20 -w 600 $ip | Select-String '^\s*\d+\s+.*?(\d{1,3}(?:\.\d{1,3}){3})\s*$' | ForEach-Object { $_.Matches[0].Groups[1].Value })
    $h = @($hops | Where-Object { $_ -ne $ip })
    if ($h) { $h[-1] } else { '' }
}

# ---------------------------------------------------------------- data
Write-Section 'NORDVPN LIVE SCANNER'
New-Item -ItemType Directory -Force -Path $CacheFolder | Out-Null
$zipFile = Get-CachedFile $BundleUrl (Join-Path $CacheFolder 'nordcdn-ovpn.zip')
$cityFile = Get-CachedFile $CityDataUrl (Join-Path $CacheFolder 'gluetun-nordvpn.json')
$cityJson = Get-Content -LiteralPath $cityFile.FullName -Raw | ConvertFrom-Json
$citySnapshot = [DateTimeOffset]::FromUnixTimeSeconds($cityJson.timestamp).UtcDateTime.ToString('yyyy-MM-dd HH:mm') + ' UTC'
Write-Host "Config bundle : $($zipFile.FullName) (downloaded $($zipFile.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) local)"
Write-Host "City labels   : gluetun snapshot $citySnapshot"

$cityOf = @{}
foreach ($srv in $cityJson.servers) { if ($srv.vpn -eq 'openvpn' -and $srv.hostname) { $cityOf[$srv.hostname] = $srv.city } }

# Index the official bundle: every TCP remote IP:port, both profile styles.
$official = New-Object System.Collections.Generic.List[object]
$zip = [IO.Compression.ZipFile]::OpenRead($zipFile.FullName)
try {
    foreach ($e in $zip.Entries) {
        if ($e.FullName -notmatch '^ovpn_tcp/(.+?\.nordvpn\.com)\.(tcp|tcp_2\.6)\.ovpn$') { continue }
        $hostName = $matches[1]; $style = $matches[2]
        $r = New-Object IO.StreamReader($e.Open()); $txt = $r.ReadToEnd(); $r.Close()
        foreach ($m in [regex]::Matches($txt, '(?m)^\s*remote\s+(\S+)\s+(\d+)')) {
            $official.Add([pscustomobject]@{ Hostname = $hostName; IP = $m.Groups[1].Value; Port = [int]$m.Groups[2].Value; Profile = $style; LabelCity = $cityOf[$hostName] })
        }
    }
} finally { $zip.Dispose() }
Write-Host "Official TCP endpoints today: $($official.Count) ($(@($official | Select-Object -ExpandProperty Hostname -Unique).Count) servers)"

# ---------------------------------------------------------------- discovery
Write-Section 'DISCOVERY'
$byEndpoint = @{}
function Add-Endpoint($ep) { $k = "$($ep.IP):$($ep.Port)"; if (-not $byEndpoint.ContainsKey($k)) { $byEndpoint[$k] = $ep } else { $byEndpoint[$k].Source += "+$($ep.Source)" } }

$cityEndpoints = @($official | Where-Object { $Cities -contains $_.LabelCity })
$subnetCity = @{}
foreach ($c in $cityEndpoints) { $subnetCity[(Get-Subnet24 $c.IP)] = $c.LabelCity }
# -SweepCidr24 limits the sweep to those /24s; without it, every target /24 is swept.
$sweepSet = @($SweepCidr24 | ForEach-Object { $_ -replace '\.0/24$', '' })
foreach ($s in $sweepSet) { if (-not $subnetCity.ContainsKey($s)) { $subnetCity[$s] = '(manual subnet)' } }
if (-not $sweepSet) { $sweepSet = @($subnetCity.Keys) }

foreach ($c in $cityEndpoints) {
    Add-Endpoint ([pscustomobject]@{ Source = 'official-city'; City = $c.LabelCity; Hostname = $c.Hostname; IP = $c.IP; Port = $c.Port; Profile = $c.Profile; Note = '' })
}
$subnetOnly = @($official | Where-Object { $subnetCity.ContainsKey((Get-Subnet24 $_.IP)) -and -not ($Cities -contains $_.LabelCity) })
foreach ($c in $subnetOnly) {
    $lbl = if ($c.LabelCity) { "labelled $($c.LabelCity)" } else { 'no city label in snapshot' }
    Add-Endpoint ([pscustomobject]@{ Source = 'official-subnet'; City = $subnetCity[(Get-Subnet24 $c.IP)]; Hostname = $c.Hostname; IP = $c.IP; Port = $c.Port; Profile = $c.Profile; Note = $lbl })
}
Write-Host "official-city   : $($cityEndpoints.Count) endpoints"
Write-Host "official-subnet : $($subnetOnly.Count) endpoints in $($subnetCity.Count) target /24s"

$officialIps = @{}; foreach ($o in $official) { $officialIps[$o.IP] = $o.Hostname }
if ($SweepSubnets) {
    $sweep = foreach ($s in $sweepSet) { foreach ($i in 1..254) { $ip = "$s.$i"; if (-not $officialIps.ContainsKey($ip)) { foreach ($p in $SweepPorts) { [pscustomobject]@{ IP = $ip; Port = $p } } } } }
    Write-Host "subnet-sweep    : probing $(@($sweep).Count) non-official IP:port pairs (1 connect each)..."
    $hits = @(Invoke-ParallelTcp $sweep 1 | Where-Object { $_.TcpOk -gt 0 })
    foreach ($h in $hits) {
        Add-Endpoint ([pscustomobject]@{ Source = 'subnet-sweep'; City = $subnetCity[(Get-Subnet24 $h.IP)]; Hostname = ''; IP = $h.IP; Port = $h.Port; Profile = if ($h.Port -eq 80) { 'tcp_2.6?' } else { 'tcp?' }; Note = 'answers on port; not in any official list' })
    }
    Write-Host "subnet-sweep    : $($hits.Count) responding non-official endpoints"
}

$manual = @(Read-KnownGood $KnownGoodFile)
foreach ($m in $manual) {
    $o = @($official | Where-Object { $_.IP -eq $m.IP -and $_.Port -eq $m.Port } | Select-Object -First 1)
    Add-Endpoint ([pscustomobject]@{
            Source = 'manual'; City = if ($o) { $o[0].LabelCity } else { '?' }; Hostname = if ($o) { $o[0].Hostname } elseif ($officialIps.ContainsKey($m.IP)) { $officialIps[$m.IP] + ' (port not in profile)' } else { '(not in official bundle)' }
            IP = $m.IP; Port = $m.Port; Profile = if ($o) { $o[0].Profile } else { '' }; Note = $m.Note
        })
}
Write-Host "manual          : $($manual.Count) endpoints from $KnownGoodFile"

$endpoints = @($byEndpoint.Values)

# ---------------------------------------------------------------- stage 1
$stamp = (Get-Date).ToUniversalTime()
Write-Section "STAGE 1: TCP connect x2, $($endpoints.Count) endpoints ($($stamp.ToString('u')))"
$s1 = @(Invoke-ParallelTcp $endpoints 2)
Write-Host "Reachable: $(@($s1 | Where-Object TcpOk -gt 0).Count) / $($s1.Count)"

# ---------------------------------------------------------------- stage 2
# Manual entries go FIRST: on 2026-09-23 the owner's IP, measured last right after a sweep of
# its /24, showed 4-6/10 connects that were 12/12 minutes later (likely our own burst traffic).
$pick = New-Object System.Collections.Generic.List[object]
$s1 | Where-Object { $_.Source -match 'manual' } | ForEach-Object { $pick.Add($_) }
foreach ($grp in ($s1 | Where-Object TcpOk -gt 0 | Group-Object City)) {
    $grp.Group | Sort-Object TcpMedianMs | Select-Object -First $Stage2PerCity | ForEach-Object { if (-not $pick.Contains($_)) { $pick.Add($_) } }
}
if ($SweepSubnets) { Write-Host 'Cooling down 90 s after the sweep before sequential measurement...'; Start-Sleep -Seconds 90 }
Write-Section "STAGE 2: sequential $Stage2Pings pings + $Stage2TcpSamples TCP connects, $($pick.Count) endpoints"
$i = 0
$s2 = foreach ($t in $pick) { $i++; Write-Progress -Activity 'Sequential measure' -Status "$i / $($pick.Count) $($t.IP):$($t.Port)" -PercentComplete (100 * $i / $pick.Count); Measure-Sequential $t }
Write-Progress -Activity 'Sequential measure' -Completed

# ---------------------------------------------------------------- verification of non-official IPs
$verifyIps = @($s2 | Where-Object { $_.Source -ne 'official-city' } | Select-Object -ExpandProperty IP -Unique)
$geo = Get-GeoBatch $verifyIps
$hop = @{}
if ($Traceroute) {
    foreach ($ip in $verifyIps) { Write-Host "tracert $ip ..."; $hop[$ip] = Get-LastHop $ip }
    $hopGeo = Get-GeoBatch @($hop.Values | Where-Object { $_ })
}

# ---------------------------------------------------------------- rank + output
$ranked = @($s2 | Sort-Object City,
    @{ e = { - [int](($_.TcpSuccess -split '/')[0]) } },
    @{ e = { if ($null -eq $_.TcpHandshakeMs) { 1e9 } else { $_.TcpHandshakeMs } } },
    @{ e = { if ($null -eq $_.AvgLatencyMs) { 1e9 } else { $_.AvgLatencyMs } } })
$rows = New-Object System.Collections.Generic.List[object]
foreach ($grp in ($ranked | Group-Object City)) {
    $rank = 0
    foreach ($x in $grp.Group) {
        $rank++
        $rows.Add([pscustomobject]@{
                City = $x.City; Rank = $rank; Source = $x.Source; Hostname = $x.Hostname; IP = $x.IP; Port = $x.Port; Protocol = 'TCP'; Profile = $x.Profile
                AvgLatencyMs = if ($null -eq $x.AvgLatencyMs) { 'ICMP filtered' } else { $x.AvgLatencyMs }; MinMaxMs = $x.MinMaxMs; JitterMs = $x.JitterMs
                PacketLoss = $x.PacketLoss; TcpHandshakeMs = $x.TcpHandshakeMs; TcpSuccess = $x.TcpSuccess
                GeoIP = $geo[$x.IP]; LastHop = if ($hop.ContainsKey($x.IP)) { "$($hop[$x.IP]) $($hopGeo[$hop[$x.IP]])" } else { '' }
                Note = $x.Note; MeasuredUtc = $stamp.ToString('yyyy-MM-dd HH:mm:ss')
            })
    }
}

$outDir = Join-Path $OutputRoot ($stamp.ToString('yyyy-MM-dd-HHmm') + '-live-scan')
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$s1 | Export-Csv (Join-Path $outDir 'stage1-all-endpoints.csv') -NoTypeInformation -Encoding UTF8
$rows | Export-Csv (Join-Path $outDir 'ranked.csv') -NoTypeInformation -Encoding UTF8
@(
    "NordVPN live scan  measured $($stamp.ToString('u'))"
    "Config bundle: $BundleUrl (file time $($zipFile.LastWriteTime.ToString('u')))"
    "City labels : gluetun snapshot $citySnapshot"
    "Cities: $($Cities -join ', ')   SweepSubnets: $SweepSubnets   Traceroute: $Traceroute"
    "Endpoints: $($endpoints.Count)  reachable: $(@($s1 | Where-Object TcpOk -gt 0).Count)"
    "Sources: " + (($endpoints | Group-Object { $_.Source } | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  ')
) | Set-Content -LiteralPath (Join-Path $outDir 'summary.txt') -Encoding UTF8

Write-Section 'RANKED'
$rows | Format-Table City, Rank, Source, Hostname, IP, Port, Profile, AvgLatencyMs, PacketLoss, TcpHandshakeMs, TcpSuccess -AutoSize | Out-String -Width 250 | Write-Host
Write-Host "Output: $outDir"
Write-Host 'TCP OK = port accepted a connection. It does NOT prove OpenVPN auth succeeds; verify finalists in pfSense.'
