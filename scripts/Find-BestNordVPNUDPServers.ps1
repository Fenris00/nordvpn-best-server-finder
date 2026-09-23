#requires -version 5.1

<#
.SYNOPSIS
    Finds the best NordVPN OpenVPN UDP servers in Chicago and Fargo,
    matches them against local .ovpn profiles, measures ICMP latency,
    and generates CSV reports.

.DESCRIPTION
    Designed for Windows PowerShell 5.1.

    Input:
        A folder containing NordVPN OpenVPN UDP profiles such as:

            usXXXX.nordvpn.com.udp.ovpn
            usXXXX.nordvpn.com.udp_2.6.ovpn

    Output:
        NordVPN-Results\
            All-Chicago-Fargo.csv
            Chicago-Servers.csv
            Fargo-Servers.csv
            Top-20-Servers.csv
            Missing-Local-Profiles.csv
            Scan-Summary.txt

.NOTES
    ICMP ping is NOT the same as OpenVPN UDP connectivity.

    A low ping means the server IP responds to ICMP.
    It does NOT guarantee that UDP/53, UDP/1194, UDP/1231-1234,
    or another OpenVPN port is reachable from your Nexlinks connection.

    After this script finds the best candidates, test the top profiles
    directly with pfSense/OpenVPN.

    PowerShell 5.1 compatible.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ProfileFolder = ".\ovpn_udp",

    [Parameter(Mandatory = $false)]
    [int]$PingCount = 2,

    [Parameter(Mandatory = $false)]
    [int]$PingTimeoutMs = 1000,

    [Parameter(Mandatory = $false)]
    [int]$TopN = 20,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeAllUS
)

# ============================================================
# CONFIGURATION
# ============================================================

$ErrorActionPreference = "Stop"

$Cities = @(
    "Chicago",
    "Fargo"
)

$OutputFolder = Join-Path (Get-Location) "NordVPN-Results"

$ApiUrl = "https://api.nordvpn.com/v1/servers?limit=20000&filters%5Bservers_technologies%5D%5Bidentifier%5D=openvpn_udp"

# ============================================================
# FUNCTIONS
# ============================================================

function Write-Banner {
    param([string]$Text)

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Get-PropertySafe {
    param(
        [object]$Object,
        [string]$Property
    )

    if ($null -eq $Object) {
        return $null
    }

    $p = $Object.PSObject.Properties[$Property]

    if ($null -ne $p) {
        return $p.Value
    }

    return $null
}

function Get-ServerCity {
    param([object]$Server)

    # Standard v1 API structure:
    # locations[0].country.city.name

    $locations = Get-PropertySafe $Server "locations"

    if ($null -eq $locations) {
        return $null
    }

    foreach ($location in $locations) {

        $country = Get-PropertySafe $location "country"

        if ($null -eq $country) {
            continue
        }

        $city = Get-PropertySafe $country "city"

        if ($null -ne $city) {
            $cityName = Get-PropertySafe $city "name"

            if ($cityName) {
                return [string]$cityName
            }
        }
    }

    return $null
}

function Get-ServerCountry {
    param([object]$Server)

    $locations = Get-PropertySafe $Server "locations"

    if ($null -eq $locations) {
        return $null
    }

    foreach ($location in $locations) {

        $country = Get-PropertySafe $location "country"

        if ($null -ne $country) {
            $countryName = Get-PropertySafe $country "name"

            if ($countryName) {
                return [string]$countryName
            }
        }
    }

    return $null
}

function Test-IsOpenVPNUDP {
    param([object]$Server)

    $technologies = Get-PropertySafe $Server "technologies"

    if ($null -eq $technologies) {
        return $false
    }

    foreach ($technology in $technologies) {

        $identifier = Get-PropertySafe $technology "identifier"

        if ($identifier -eq "openvpn_udp") {
            return $true
        }
    }

    return $false
}

function Test-ServerOnline {
    param([object]$Server)

    $status = Get-PropertySafe $Server "status"

    if ($null -eq $status) {
        # If API doesn't expose status, don't reject the server.
        return $true
    }

    if ($status -is [int]) {
        # NordVPN commonly represents online as 1.
        return ($status -eq 1)
    }

    $statusString = [string]$status

    return (
        $statusString -eq "online" -or
        $statusString -eq "1" -or
        $statusString -eq "Online"
    )
}

function Get-LocalProfiles {
    param(
        [string]$Folder
    )

    Write-Host "Scanning local .ovpn files..." -ForegroundColor Yellow

    if (-not (Test-Path -LiteralPath $Folder)) {
        throw "Profile folder does not exist: $Folder"
    }

    $files = Get-ChildItem `
        -LiteralPath $Folder `
        -Filter "*.ovpn" `
        -File `
        -ErrorAction Stop

    Write-Host "Found $($files.Count) .ovpn files." -ForegroundColor Green

    $profileMap = @{}

    foreach ($file in $files) {

        $hostname = $null

        # Expected:
        # us1234.nordvpn.com.udp.ovpn
        # us1234.nordvpn.com.udp_2.6.ovpn

        if ($file.Name -match "^(.+?)\.udp(?:_2\.6)?\.ovpn$") {
            $hostname = $matches[1]
        }

        if ([string]::IsNullOrWhiteSpace($hostname)) {
            continue
        }

        $profileType = "Legacy UDP"

        if ($file.Name -match "\.udp_2\.6\.ovpn$") {
            $profileType = "UDP 2.6"
        }

        # Extract remote entries from profile.
        $remoteEntries = @()

        try {
            $content = Get-Content -LiteralPath $file.FullName -ErrorAction Stop

            foreach ($line in $content) {

                $trimmed = $line.Trim()

                if ($trimmed -match "^remote\s+(\S+)\s+(\d+)") {

                    $remoteHost = $matches[1]
                    $remotePort = [int]$matches[2]

                    $remoteEntries += [PSCustomObject]@{
                        Host = $remoteHost
                        Port = $remotePort
                    }
                }
            }
        }
        catch {
            Write-Warning "Could not read: $($file.FullName)"
            continue
        }

        if (-not $profileMap.ContainsKey($hostname)) {
            $profileMap[$hostname] = @()
        }

        $profileMap[$hostname] += [PSCustomObject]@{
            Hostname       = $hostname
            ProfileType    = $profileType
            FileName       = $file.Name
            FullPath       = $file.FullName
            RemoteEntries  = $remoteEntries
        }
    }

    return $profileMap
}

function Test-PingServer {
    param(
        [string]$IPAddress,
        [int]$Count = 2,
        [int]$Timeout = 1000
    )

    if ([string]::IsNullOrWhiteSpace($IPAddress)) {
        return [PSCustomObject]@{
            Reachable = $false
            MinMs     = $null
            AvgMs     = $null
            MaxMs     = $null
        }
    }

    try {

        $ping = New-Object System.Net.NetworkInformation.Ping

        $times = New-Object System.Collections.Generic.List[int]

        for ($i = 1; $i -le $Count; $i++) {

            try {

                $reply = $ping.Send(
                    $IPAddress,
                    $Timeout
                )

                if ($reply.Status -eq "Success") {
                    $times.Add([int]$reply.RoundtripTime)
                }

            }
            catch {
                # Ignore individual failed ping
            }
        }

        $ping.Dispose()

        if ($times.Count -eq 0) {

            return [PSCustomObject]@{
                Reachable = $false
                MinMs     = $null
                AvgMs     = $null
                MaxMs     = $null
            }
        }

        return [PSCustomObject]@{
            Reachable = $true
            MinMs     = ($times | Measure-Object -Minimum).Minimum
            AvgMs     = [math]::Round(
                (($times | Measure-Object -Average).Average),
                1
            )
            MaxMs     = ($times | Measure-Object -Maximum).Maximum
        }
    }
    catch {

        return [PSCustomObject]@{
            Reachable = $false
            MinMs     = $null
            AvgMs     = $null
            MaxMs     = $null
        }
    }
}

function Resolve-ServerIP {
    param(
        [object]$Server
    )

    $station = Get-PropertySafe $Server "station"

    if (-not [string]::IsNullOrWhiteSpace([string]$station)) {
        return [string]$station
    }

    $hostname = Get-PropertySafe $Server "hostname"

    if ([string]::IsNullOrWhiteSpace([string]$hostname)) {
        return $null
    }

    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($hostname)

        foreach ($address in $addresses) {

            if ($address.AddressFamily -eq `
                [System.Net.Sockets.AddressFamily]::InterNetwork) {

                return $address.IPAddressToString
            }
        }
    }
    catch {
        return $null
    }

    return $null
}

function Get-ProfilePreferenceScore {
    param(
        [string]$ProfileType
    )

    # Prefer OpenVPN 2.6 profile because your pfSense is running
    # OpenVPN 2.6.x.

    if ($ProfileType -eq "UDP 2.6") {
        return 0
    }

    return 1
}

# ============================================================
# START
# ============================================================

Clear-Host

Write-Banner "NORDVPN CHICAGO + FARGO SERVER SCANNER"

Write-Host "PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
Write-Host "Profile folder     : $ProfileFolder" -ForegroundColor Gray
Write-Host "Ping count         : $PingCount" -ForegroundColor Gray
Write-Host "Ping timeout       : $PingTimeoutMs ms" -ForegroundColor Gray
Write-Host ""

# ============================================================
# CREATE OUTPUT DIRECTORY
# ============================================================

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

# ============================================================
# SCAN LOCAL PROFILES
# ============================================================

$ProfileMap = Get-LocalProfiles -Folder $ProfileFolder

# ============================================================
# DOWNLOAD NORDVPN SERVER DATA
# ============================================================

Write-Banner "DOWNLOADING CURRENT NORDVPN SERVER DATA"

Write-Host "API:" -ForegroundColor Gray
Write-Host $ApiUrl -ForegroundColor DarkGray
Write-Host ""

try {

    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12

    $response = Invoke-WebRequest `
        -Uri $ApiUrl `
        -UseBasicParsing `
        -Method GET `
        -TimeoutSec 90

    if ($response.StatusCode -ne 200) {
        throw "NordVPN API returned HTTP $($response.StatusCode)"
    }

    $servers = $response.Content | ConvertFrom-Json

}
catch {

    Write-Host ""
    Write-Host "FAILED TO DOWNLOAD NORDVPN SERVER DATA." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""

    exit 1
}

if ($null -eq $servers) {
    throw "NordVPN API returned no server data."
}

Write-Host "NordVPN records received: $($servers.Count)" -ForegroundColor Green

# ============================================================
# FILTER NORDVPN DATA
# ============================================================

Write-Banner "FILTERING CHICAGO + FARGO"

$targetServers = New-Object System.Collections.Generic.List[object]

foreach ($server in $servers) {

    $hostname = [string](Get-PropertySafe $server "hostname")

    if ([string]::IsNullOrWhiteSpace($hostname)) {
        continue
    }

    $country = Get-ServerCountry -Server $server
    $city = Get-ServerCity -Server $server

    if ($country -ne "United States") {
        continue
    }

    if ($city -notin $Cities) {
        continue
    }

    if (-not (Test-IsOpenVPNUDP -Server $server)) {
        continue
    }

    if (-not (Test-ServerOnline -Server $server)) {
        continue
    }

    $load = Get-PropertySafe $server "load"

    $station = Get-PropertySafe $server "station"

    $targetServers.Add(
        [PSCustomObject]@{
            Hostname = $hostname
            Country  = $country
            City     = $city
            IP       = [string]$station
            Load     = $load
            ServerID = Get-PropertySafe $server "id"
        }
    )
}

Write-Host ""
Write-Host "Matching online OpenVPN UDP servers:" -ForegroundColor Green

$cityGroups = $targetServers |
    Group-Object City |
    Sort-Object Name

foreach ($group in $cityGroups) {
    Write-Host ("  {0,-12} {1,6}" -f $group.Name, $group.Count)
}

Write-Host ""

if ($targetServers.Count -eq 0) {

    Write-Host "No Chicago/Fargo OpenVPN UDP servers were found." `
        -ForegroundColor Red

    exit 1
}

# ============================================================
# MATCH LOCAL PROFILES
# ============================================================

Write-Banner "MATCHING AGAINST YOUR LOCAL PROFILES"

$matched = New-Object System.Collections.Generic.List[object]
$missing = New-Object System.Collections.Generic.List[object]

foreach ($server in $targetServers) {

    $hostname = $server.Hostname

    if ($ProfileMap.ContainsKey($hostname)) {

        $profiles = $ProfileMap[$hostname]

        foreach ($profile in $profiles) {

            $matched.Add(
                [PSCustomObject]@{
                    Hostname      = $server.Hostname
                    City          = $server.City
                    Country       = $server.Country
                    ServerIP      = $server.IP
                    LoadPercent   = $server.Load
                    ServerID      = $server.ServerID

                    ProfileType   = $profile.ProfileType
                    FileName      = $profile.FileName
                    FullPath      = $profile.FullPath

                    RemoteEntries = (
                        $profile.RemoteEntries |
                        ForEach-Object {
                            "$($_.Host):$($_.Port)"
                        }
                    ) -join ";"

                    PingReachable = $false
                    PingMinMs     = $null
                    PingAvgMs     = $null
                    PingMaxMs     = $null
                }
            )
        }

    }
    else {

        $missing.Add(
            [PSCustomObject]@{
                Hostname    = $server.Hostname
                City        = $server.City
                Country     = $server.Country
                ServerIP    = $server.IP
                LoadPercent = $server.Load
                ServerID    = $server.ServerID
            }
        )
    }
}

Write-Host "NordVPN matching servers : $($targetServers.Count)" -ForegroundColor Gray
Write-Host "Local profiles matched   : $($matched.Count)" -ForegroundColor Green
Write-Host "Profiles missing locally : $($missing.Count)" -ForegroundColor Yellow
Write-Host ""

# ============================================================
# PING SERVERS
# ============================================================

Write-Banner "PINGING MATCHED SERVERS"

$total = $matched.Count
$current = 0

foreach ($item in $matched) {

    $current++

    $percent = [math]::Round(
        ($current / $total) * 100,
        0
    )

    Write-Progress `
        -Activity "Testing NordVPN server latency" `
        -Status "$current / $total - $($item.Hostname)" `
        -PercentComplete $percent

    $ping = Test-PingServer `
        -IPAddress $item.ServerIP `
        -Count $PingCount `
        -Timeout $PingTimeoutMs

    $item.PingReachable = $ping.Reachable
    $item.PingMinMs = $ping.MinMs
    $item.PingAvgMs = $ping.AvgMs
    $item.PingMaxMs = $ping.MaxMs
}

Write-Progress `
    -Activity "Testing NordVPN server latency" `
    -Completed

# ============================================================
# CALCULATE RANKING
# ============================================================

Write-Banner "CALCULATING SERVER RANKING"

$ranked = foreach ($item in $matched) {

    $profilePreference = Get-ProfilePreferenceScore `
        -ProfileType $item.ProfileType

    # --------------------------------------------------------
    # Ranking formula
    #
    # Lower is better.
    #
    # 50% = ping
    # 30% = NordVPN load
    # 20% = profile preference
    #
    # The profile preference is intentionally small.
    # A bad-latency 2.6 profile should NOT beat a very good
    # legacy profile merely because it is 2.6.
    # --------------------------------------------------------

    if ($null -eq $item.PingAvgMs) {
        $pingScore = 9999
    }
    else {
        $pingScore = [double]$item.PingAvgMs
    }

    if ($null -eq $item.LoadPercent) {
        $loadScore = 100
    }
    else {
        $loadScore = [double]$item.LoadPercent
    }

    $rankingScore = (
        ($pingScore * 0.50) +
        ($loadScore * 0.30) +
        ($profilePreference * 5)
    )

    [PSCustomObject]@{
        Hostname        = $item.Hostname
        City            = $item.City
        Country         = $item.Country
        ServerIP        = $item.ServerIP
        LoadPercent     = $item.LoadPercent

        PingReachable   = $item.PingReachable
        PingMinMs       = $item.PingMinMs
        PingAvgMs       = $item.PingAvgMs
        PingMaxMs       = $item.PingMaxMs

        ProfileType     = $item.ProfileType
        FileName        = $item.FileName
        FullPath        = $item.FullPath
        RemoteEntries   = $item.RemoteEntries

        RankingScore    = [math]::Round($rankingScore, 2)
    }
}

# Reachable first, then ranking score.

$ranked = $ranked |
    Sort-Object `
        @{Expression = {
            if ($_.PingReachable) { 0 } else { 1 }
        }}, `
        @{Expression = { $_.RankingScore }}

# Add rank.

$rank = 0

$rankedFinal = foreach ($item in $ranked) {

    $rank++

    [PSCustomObject]@{
        Rank            = $rank
        Hostname        = $item.Hostname
        City            = $item.City
        Country         = $item.Country
        ServerIP        = $item.ServerIP
        LoadPercent     = $item.LoadPercent

        PingReachable   = $item.PingReachable
        PingMinMs       = $item.PingMinMs
        PingAvgMs       = $item.PingAvgMs
        PingMaxMs       = $item.PingMaxMs

        ProfileType     = $item.ProfileType
        FileName        = $item.FileName
        FullPath        = $item.FullPath
        RemoteEntries   = $item.RemoteEntries

        RankingScore    = $item.RankingScore
    }
}

# ============================================================
# EXPORT REPORTS
# ============================================================

Write-Banner "EXPORTING REPORTS"

$allCsv = Join-Path `
    $OutputFolder `
    "All-Chicago-Fargo.csv"

$chicagoCsv = Join-Path `
    $OutputFolder `
    "Chicago-Servers.csv"

$fargoCsv = Join-Path `
    $OutputFolder `
    "Fargo-Servers.csv"

$topCsv = Join-Path `
    $OutputFolder `
    "Top-$TopN-Servers.csv"

$missingCsv = Join-Path `
    $OutputFolder `
    "Missing-Local-Profiles.csv"

$summaryTxt = Join-Path `
    $OutputFolder `
    "Scan-Summary.txt"

$rankedFinal |
    Export-Csv `
        -LiteralPath $allCsv `
        -NoTypeInformation `
        -Encoding UTF8

$rankedFinal |
    Where-Object { $_.City -eq "Chicago" } |
    Export-Csv `
        -LiteralPath $chicagoCsv `
        -NoTypeInformation `
        -Encoding UTF8

$rankedFinal |
    Where-Object { $_.City -eq "Fargo" } |
    Export-Csv `
        -LiteralPath $fargoCsv `
        -NoTypeInformation `
        -Encoding UTF8

$rankedFinal |
    Select-Object -First $TopN |
    Export-Csv `
        -LiteralPath $topCsv `
        -NoTypeInformation `
        -Encoding UTF8

$missing |
    Export-Csv `
        -LiteralPath $missingCsv `
        -NoTypeInformation `
        -Encoding UTF8

# ============================================================
# WRITE SUMMARY
# ============================================================

$best = $rankedFinal |
    Where-Object { $_.PingReachable } |
    Select-Object -First 1

$bestChicago = $rankedFinal |
    Where-Object {
        $_.City -eq "Chicago" -and
        $_.PingReachable
    } |
    Select-Object -First 1

$bestFargo = $rankedFinal |
    Where-Object {
        $_.City -eq "Fargo" -and
        $_.PingReachable
    } |
    Select-Object -First 1

$summary = @()

$summary += "NORDVPN SERVER SCAN"
$summary += "==================="
$summary += ""
$summary += "Scan time: $(Get-Date)"
$summary += "Profile folder: $ProfileFolder"
$summary += ""
$summary += "Local .ovpn files found: $($ProfileMap.Keys.Count) hostnames"
$summary += "NordVPN matching servers: $($targetServers.Count)"
$summary += "Local matching profiles: $($matched.Count)"
$summary += "Missing local profiles: $($missing.Count)"
$summary += ""

$summary += "BEST OVERALL"
$summary += "------------"

if ($null -ne $best) {

    $summary += "Rank: $($best.Rank)"
    $summary += "Hostname: $($best.Hostname)"
    $summary += "City: $($best.City)"
    $summary += "IP: $($best.ServerIP)"
    $summary += "Load: $($best.LoadPercent)%"
    $summary += "Ping: $($best.PingAvgMs) ms"
    $summary += "Profile: $($best.FileName)"
    $summary += "Path: $($best.FullPath)"
    $summary += "Score: $($best.RankingScore)"
}
else {
    $summary += "No reachable server found."
}

$summary += ""
$summary += "BEST CHICAGO"
$summary += "------------"

if ($null -ne $bestChicago) {

    $summary += "Hostname: $($bestChicago.Hostname)"
    $summary += "IP: $($bestChicago.ServerIP)"
    $summary += "Load: $($bestChicago.LoadPercent)%"
    $summary += "Ping: $($bestChicago.PingAvgMs) ms"
    $summary += "Profile: $($bestChicago.FileName)"
    $summary += "Path: $($bestChicago.FullPath)"
}
else {
    $summary += "No reachable Chicago server found."
}

$summary += ""
$summary += "BEST FARGO"
$summary += "----------"

if ($null -ne $bestFargo) {

    $summary += "Hostname: $($bestFargo.Hostname)"
    $summary += "IP: $($bestFargo.ServerIP)"
    $summary += "Load: $($bestFargo.LoadPercent)%"
    $summary += "Ping: $($bestFargo.PingAvgMs) ms"
    $summary += "Profile: $($bestFargo.FileName)"
    $summary += "Path: $($bestFargo.FullPath)"
}
else {
    $summary += "No reachable Fargo server found."
}

$summary += ""
$summary += "IMPORTANT"
$summary += "========="
$summary += "ICMP ping only measures IP latency."
$summary += "It does NOT prove that OpenVPN UDP works through Nexlinks."
$summary += "Test the top candidates in pfSense."
$summary += ""
$summary += "Generated files:"
$summary += $allCsv
$summary += $chicagoCsv
$summary += $fargoCsv
$summary += $topCsv
$summary += $missingCsv

$summary |
    Set-Content `
        -LiteralPath $summaryTxt `
        -Encoding UTF8

# ============================================================
# DISPLAY TOP RESULTS
# ============================================================

Write-Banner "TOP $TopN SERVERS"

$display = $rankedFinal |
    Select-Object -First $TopN |
    Select-Object `
        Rank,
        City,
        Hostname,
        ServerIP,
        LoadPercent,
        PingAvgMs,
        ProfileType,
        FileName

$display |
    Format-Table -AutoSize

Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host "SCAN COMPLETE" -ForegroundColor Green

Write-Host "============================================================" `
    -ForegroundColor Green

Write-Host ""
Write-Host "Results saved to:" -ForegroundColor Yellow
Write-Host $OutputFolder -ForegroundColor White
Write-Host ""

Write-Host "Best overall:" -ForegroundColor Cyan

if ($null -ne $best) {

    Write-Host "  $($best.Hostname)" -ForegroundColor White
    Write-Host "  City : $($best.City)" -ForegroundColor White
    Write-Host "  Load : $($best.LoadPercent)%" -ForegroundColor White
    Write-Host "  Ping : $($best.PingAvgMs) ms" -ForegroundColor White
    Write-Host "  File : $($best.FullPath)" -ForegroundColor White

}
else {

    Write-Host "  No reachable server found." -ForegroundColor Red
}

Write-Host ""
Write-Host "Next step:" -ForegroundColor Yellow
Write-Host "Take the top 5-10 candidates and test them individually in pfSense." `
    -ForegroundColor White
Write-Host ""