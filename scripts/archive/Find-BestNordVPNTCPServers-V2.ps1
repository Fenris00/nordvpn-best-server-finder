#requires -version 5.1

<#
.SYNOPSIS
    Finds and ranks NordVPN OpenVPN TCP profiles for Chicago and Fargo.

.DESCRIPTION
    PowerShell 5.1 compatible scanner designed for a large local ovpn_tcp
    directory. It supports a LOCAL JSON CACHE so repeated scans do not need
    to contact api.nordvpn.com.

    Workflow:
      1. Index local .ovpn files.
      2. Load NordVPN server metadata from -ServerDataFile when available.
      3. If cache is missing, optionally try the NordVPN API.
      4. Filter online US OpenVPN TCP servers in Chicago/Fargo.
      5. Match exact local .ovpn profiles.
      6. Measure ICMP latency.
      7. Test the actual TCP remote port from each matched profile.
      8. Rank reachable candidates.
      9. Export CSV/TXT reports and a shortlist of exact profile paths.

.NOTES
    ICMP ping is only a latency signal. TCP port reachability is stronger,
    but neither test proves that the complete OpenVPN authentication/TLS
    session will succeed. Always validate the finalists in pfSense.
#>

[CmdletBinding()]
param(
    [string]$ProfileFolder = ".\ovpn_tcp",
    [string]$ServerDataFile = ".\NordVPN-TCP-Servers.json",
    [int]$PingCount = 2,
    [int]$PingTimeoutMs = 1000,
    [int]$TcpTimeoutMs = 3000,
    [int]$TopN = 30,
    [switch]$NoApi,
    [switch]$RefreshServerData
)

$ErrorActionPreference = 'Stop'

$Cities = @('Chicago','Fargo')
$OutputFolder = Join-Path (Get-Location) 'NordVPN-TCP-Results'
$ApiUrl = 'https://api.nordvpn.com/v1/servers?limit=20000&filters%5Bservers_technologies%5D%5Bidentifier%5D=openvpn_tcp'

function Write-Banner {
    param([string]$Text)
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ''
}

function Get-PropertySafe {
    param([object]$Object,[string]$Property)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Property]
    if ($null -ne $p) { return $p.Value }
    return $null
}

function Get-ServerLocation {
    param([object]$Server)
    $locations = Get-PropertySafe $Server 'locations'
    if ($null -eq $locations) { return $null }
    foreach ($location in @($locations)) {
        $country = Get-PropertySafe $location 'country'
        if ($null -eq $country) { continue }
        $countryName = Get-PropertySafe $country 'name'
        $countryCode = Get-PropertySafe $country 'code'
        $city = Get-PropertySafe $country 'city'
        $cityName = if ($null -ne $city) { Get-PropertySafe $city 'name' } else { $null }
        return [PSCustomObject]@{
            Country = [string]$countryName
            CountryCode = [string]$countryCode
            City = [string]$cityName
        }
    }
    return $null
}

function Test-IsOpenVPNTCP {
    param([object]$Server)
    $technologies = Get-PropertySafe $Server 'technologies'
    foreach ($technology in @($technologies)) {
        $identifier = Get-PropertySafe $technology 'identifier'
        if ([string]$identifier -eq 'openvpn_tcp') { return $true }
    }
    return $false
}

function Test-ServerOnline {
    param([object]$Server)
    $status = Get-PropertySafe $Server 'status'
    if ($null -eq $status) { return $true }
    $s = [string]$status
    return ($s -eq 'online' -or $s -eq 'Online' -or $s -eq '1')
}

function Get-LocalProfiles {
    param([string]$Folder)
    Write-Host 'Scanning local TCP .ovpn files...' -ForegroundColor Yellow
    if (-not (Test-Path -LiteralPath $Folder)) { throw "Profile folder does not exist: $Folder" }
    $files = @(Get-ChildItem -LiteralPath $Folder -Filter '*.ovpn' -File -ErrorAction Stop)
    Write-Host "Found $($files.Count) .ovpn files." -ForegroundColor Green

    $map = @{}
    foreach ($file in $files) {
        $hostname = $null
        if ($file.Name -match '^(.+?)\.tcp(?:_2\.6)?\.ovpn$') { $hostname = $matches[1] }
        if ([string]::IsNullOrWhiteSpace($hostname)) { continue }

        $profileType = if ($file.Name -match '\.tcp_2\.6\.ovpn$') { 'TCP 2.6' } else { 'Legacy TCP' }
        $remoteEntries = @()
        try {
            foreach ($line in @(Get-Content -LiteralPath $file.FullName -ErrorAction Stop)) {
                $trimmed = $line.Trim()
                if ($trimmed -match '^remote\s+(\S+)\s+(\d+)') {
                    $remoteEntries += [PSCustomObject]@{ Host = $matches[1]; Port = [int]$matches[2] }
                }
            }
        } catch {
            Write-Warning "Could not read: $($file.FullName)"
            continue
        }

        if (-not $map.ContainsKey($hostname)) { $map[$hostname] = @() }
        $map[$hostname] += [PSCustomObject]@{
            Hostname = $hostname
            ProfileType = $profileType
            FileName = $file.Name
            FullPath = $file.FullName
            RemoteEntries = $remoteEntries
        }
    }
    return $map
}

function Test-PingServer {
    param([string]$IPAddress,[int]$Count = 2,[int]$Timeout = 1000)
    if ([string]::IsNullOrWhiteSpace($IPAddress)) {
        return [PSCustomObject]@{ Reachable=$false; MinMs=$null; AvgMs=$null; MaxMs=$null }
    }
    $ping = New-Object System.Net.NetworkInformation.Ping
    $times = New-Object 'System.Collections.Generic.List[int]'
    try {
        for ($i=1; $i -le $Count; $i++) {
            try {
                $reply = $ping.Send($IPAddress,$Timeout)
                if ($reply.Status -eq 'Success') { [void]$times.Add([int]$reply.RoundtripTime) }
            } catch {}
        }
    } finally { $ping.Dispose() }
    if ($times.Count -eq 0) { return [PSCustomObject]@{ Reachable=$false; MinMs=$null; AvgMs=$null; MaxMs=$null } }
    return [PSCustomObject]@{
        Reachable=$true
        MinMs=($times | Measure-Object -Minimum).Minimum
        AvgMs=[math]::Round(($times | Measure-Object -Average).Average,1)
        MaxMs=($times | Measure-Object -Maximum).Maximum
    }
}

function Test-TcpPort {
    param([string]$Host,[int]$Port,[int]$TimeoutMs=3000)
    if ([string]::IsNullOrWhiteSpace($Host) -or $Port -le 0) {
        return [PSCustomObject]@{ Reachable=$false; Host=$Host; Port=$Port; Error='Invalid host/port' }
    }
    $client = New-Object System.Net.Sockets.TcpClient
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $iar = $client.BeginConnect($Host,$Port,$null,$null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs,$false)) {
            return [PSCustomObject]@{ Reachable=$false; Host=$Host; Port=$Port; Error='Timeout' }
        }
        $client.EndConnect($iar)
        $sw.Stop()
        return [PSCustomObject]@{ Reachable=$true; Host=$Host; Port=$Port; Error=$null; ConnectMs=[math]::Round($sw.Elapsed.TotalMilliseconds,1) }
    } catch {
        return [PSCustomObject]@{ Reachable=$false; Host=$Host; Port=$Port; Error=$_.Exception.Message; ConnectMs=$null }
    } finally {
        $client.Close()
        $client.Dispose()
    }
}

function Get-RemoteTest {
    param([object]$RemoteEntries,[string]$FallbackHost,[int]$FallbackPort=443,[int]$TimeoutMs=3000)
    foreach ($entry in @($RemoteEntries)) {
        $r = Test-TcpPort -Host ([string]$entry.Host) -Port ([int]$entry.Port) -TimeoutMs $TimeoutMs
        if ($r.Reachable) { return $r }
    }
    $first = @($RemoteEntries) | Select-Object -First 1
    if ($null -ne $first) { return (Test-TcpPort -Host ([string]$first.Host) -Port ([int]$first.Port) -TimeoutMs $TimeoutMs) }
    return (Test-TcpPort -Host $FallbackHost -Port $FallbackPort -TimeoutMs $TimeoutMs)
}

function Get-ServerDataFromApi {
    param([string]$Url,[string]$Destination)
    Write-Host 'Trying NordVPN API...' -ForegroundColor Yellow
    $tmp = Join-Path $env:TEMP ("nordvpn_tcp_" + [guid]::NewGuid().ToString('N') + '.json')
    try {
        $args = @('--tlsv1.2','--http1.1','--location','--silent','--show-error','--fail','--retry','2','--retry-delay','2','--connect-timeout','20','--max-time','120','--output',$tmp,$Url)
        & curl.exe @args
        if ($LASTEXITCODE -ne 0) { throw "curl.exe failed with exit code $LASTEXITCODE" }
        $json = Get-Content -LiteralPath $tmp -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($json)) { throw 'API returned an empty response.' }
        $parsed = $json | ConvertFrom-Json
        $json | Set-Content -LiteralPath $Destination -Encoding UTF8
        return $parsed
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Get-ServerData {
    param([string]$CacheFile,[string]$Url,[switch]$NoApi,[switch]$Refresh)
    if ((Test-Path -LiteralPath $CacheFile) -and -not $Refresh) {
        Write-Host "Loading server metadata from local cache:" -ForegroundColor Green
        Write-Host "  $CacheFile" -ForegroundColor Gray
        $json = Get-Content -LiteralPath $CacheFile -Raw -ErrorAction Stop
        $data = $json | ConvertFrom-Json
        Write-Host "Cached records received: $(@($data).Count)" -ForegroundColor Green
        return @($data)
    }
    if ($NoApi) { throw "No local server-data cache found and -NoApi was specified. Put a TCP server JSON file at '$CacheFile'." }
    try {
        $data = Get-ServerDataFromApi -Url $Url -Destination $CacheFile
        Write-Host "NordVPN records received: $(@($data).Count)" -ForegroundColor Green
        Write-Host "Cached server metadata to: $CacheFile" -ForegroundColor Green
        return @($data)
    } catch {
        throw "Could not obtain NordVPN server metadata. API failed and no usable cache was available. Error: $($_.Exception.Message)"
    }
}

function Get-ProfilePreferenceScore {
    param([string]$ProfileType)
    if ($ProfileType -eq 'TCP 2.6') { return 0 }
    return 1
}

Clear-Host
Write-Banner 'NORDVPN TCP CHICAGO + FARGO SCANNER V2'
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
Write-Host "Profile folder     : $ProfileFolder" -ForegroundColor Gray
Write-Host "Server data cache  : $ServerDataFile" -ForegroundColor Gray
Write-Host "Ping count         : $PingCount" -ForegroundColor Gray
Write-Host "Ping timeout       : $PingTimeoutMs ms" -ForegroundColor Gray
Write-Host "TCP timeout        : $TcpTimeoutMs ms" -ForegroundColor Gray
Write-Host "Top N              : $TopN" -ForegroundColor Gray

if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
$ProfileMap = Get-LocalProfiles -Folder $ProfileFolder

Write-Banner 'LOADING NORDVPN SERVER METADATA'
$servers = Get-ServerData -CacheFile $ServerDataFile -Url $ApiUrl -NoApi:$NoApi -Refresh:$RefreshServerData

Write-Banner 'FILTERING CHICAGO + FARGO TCP SERVERS'
$targetServers = New-Object 'System.Collections.Generic.List[object]'
foreach ($server in @($servers)) {
    $hostname = [string](Get-PropertySafe $server 'hostname')
    if ([string]::IsNullOrWhiteSpace($hostname)) { continue }
    $loc = Get-ServerLocation $server
    if ($null -eq $loc) { continue }
    if ($loc.Country -ne 'United States') { continue }
    if ($loc.City -notin $Cities) { continue }
    if (-not (Test-IsOpenVPNTCP $server)) { continue }
    if (-not (Test-ServerOnline $server)) { continue }
    $station = [string](Get-PropertySafe $server 'station')
    $load = Get-PropertySafe $server 'load'
    $targetServers.Add([PSCustomObject]@{
        Hostname=$hostname; Country=$loc.Country; City=$loc.City; IP=$station; Load=$load; ServerID=Get-PropertySafe $server 'id'
    })
}
Write-Host "Matching online OpenVPN TCP servers:" -ForegroundColor Green
foreach ($g in @($targetServers | Group-Object City | Sort-Object Name)) { Write-Host ("  {0,-12} {1,6}" -f $g.Name,$g.Count) }
if ($targetServers.Count -eq 0) { throw 'No Chicago/Fargo OpenVPN TCP servers were found in the loaded metadata.' }

Write-Banner 'MATCHING AGAINST LOCAL TCP PROFILES'
$matched = New-Object 'System.Collections.Generic.List[object]'
$missing = New-Object 'System.Collections.Generic.List[object]'
foreach ($server in $targetServers) {
    if ($ProfileMap.ContainsKey($server.Hostname)) {
        foreach ($profile in @($ProfileMap[$server.Hostname])) {
            $matched.Add([PSCustomObject]@{
                Hostname=$server.Hostname; City=$server.City; Country=$server.Country; ServerIP=$server.IP; LoadPercent=$server.Load; ServerID=$server.ServerID
                ProfileType=$profile.ProfileType; FileName=$profile.FileName; FullPath=$profile.FullPath
                RemoteEntries=( @($profile.RemoteEntries | ForEach-Object { "$($_.Host):$($_.Port)" }) -join ';' )
                RemoteObjects=$profile.RemoteEntries
                PingReachable=$false; PingMinMs=$null; PingAvgMs=$null; PingMaxMs=$null
                TcpReachable=$false; TcpConnectMs=$null; TcpHost=$null; TcpPort=$null; TcpError=$null
            })
        }
    } else {
        $missing.Add([PSCustomObject]@{ Hostname=$server.Hostname; City=$server.City; Country=$server.Country; ServerIP=$server.IP; LoadPercent=$server.Load; ServerID=$server.ServerID })
    }
}
Write-Host "NordVPN matching servers : $($targetServers.Count)" -ForegroundColor Gray
Write-Host "Local profiles matched   : $($matched.Count)" -ForegroundColor Green
Write-Host "Profiles missing locally : $($missing.Count)" -ForegroundColor Yellow

Write-Banner 'TESTING ICMP + ACTUAL TCP PORT'
$total=$matched.Count; $current=0
foreach ($item in $matched) {
    $current++
    $percent=[math]::Round(($current/$total)*100,0)
    Write-Progress -Activity 'Testing NordVPN TCP candidates' -Status "$current / $total - $($item.Hostname)" -PercentComplete $percent
    $ping=Test-PingServer -IPAddress $item.ServerIP -Count $PingCount -Timeout $PingTimeoutMs
    $item.PingReachable=$ping.Reachable; $item.PingMinMs=$ping.MinMs; $item.PingAvgMs=$ping.AvgMs; $item.PingMaxMs=$ping.MaxMs
    $tcp=Get-RemoteTest -RemoteEntries $item.RemoteObjects -FallbackHost $item.Hostname -TimeoutMs $TcpTimeoutMs
    $item.TcpReachable=$tcp.Reachable; $item.TcpConnectMs=$tcp.ConnectMs; $item.TcpHost=$tcp.Host; $item.TcpPort=$tcp.Port; $item.TcpError=$tcp.Error
}
Write-Progress -Activity 'Testing NordVPN TCP candidates' -Completed

Write-Banner 'CALCULATING TCP RANKING'
$ranked = foreach ($item in $matched) {
    $profilePreference=Get-ProfilePreferenceScore $item.ProfileType
    $pingScore=if ($null -eq $item.PingAvgMs) { 9999 } else { [double]$item.PingAvgMs }
    $loadScore=if ($null -eq $item.LoadPercent) { 100 } else { [double]$item.LoadPercent }
    $tcpScore=if ($item.TcpReachable) { if ($null -eq $item.TcpConnectMs) { 0 } else { [double]$item.TcpConnectMs } } else { 5000 }
    # Connectivity gates first; then score. Lower is better.
    $rankingScore=(($pingScore*0.40)+($loadScore*0.25)+($tcpScore*0.30)+($profilePreference*5))
    [PSCustomObject]@{
        Hostname=$item.Hostname; City=$item.City; Country=$item.Country; ServerIP=$item.ServerIP; LoadPercent=$item.LoadPercent
        PingReachable=$item.PingReachable; PingMinMs=$item.PingMinMs; PingAvgMs=$item.PingAvgMs; PingMaxMs=$item.PingMaxMs
        TcpReachable=$item.TcpReachable; TcpConnectMs=$item.TcpConnectMs; TcpHost=$item.TcpHost; TcpPort=$item.TcpPort; TcpError=$item.TcpError
        ProfileType=$item.ProfileType; FileName=$item.FileName; FullPath=$item.FullPath; RemoteEntries=$item.RemoteEntries
        RankingScore=[math]::Round($rankingScore,2)
    }
}
$ranked=$ranked | Sort-Object @{Expression={if ($_.TcpReachable){0}else{1}}}, @{Expression={if ($_.PingReachable){0}else{1}}}, RankingScore
$rank=0
$rankedFinal=foreach($item in $ranked){$rank++;$item | Add-Member -NotePropertyName Rank -NotePropertyValue $rank -PassThru}

Write-Banner 'EXPORTING REPORTS'
$allCsv=Join-Path $OutputFolder 'All-Chicago-Fargo-TCP.csv'
$chicagoCsv=Join-Path $OutputFolder 'Chicago-TCP-Servers.csv'
$fargoCsv=Join-Path $OutputFolder 'Fargo-TCP-Servers.csv'
$topCsv=Join-Path $OutputFolder "Top-$TopN-TCP-Servers.csv"
$readyCsv=Join-Path $OutputFolder 'Top-TCP-Ready-for-pfSense.csv'
$missingCsv=Join-Path $OutputFolder 'Missing-Local-TCP-Profiles.csv'
$pathsTxt=Join-Path $OutputFolder 'Top-TCP-Profile-Paths.txt'
$summaryTxt=Join-Path $OutputFolder 'TCP-Scan-Summary.txt'
$rankedFinal | Select-Object Rank,* -ExcludeProperty Rank | Export-Csv -LiteralPath $allCsv -NoTypeInformation -Encoding UTF8
$rankedFinal | Where-Object {$_.City -eq 'Chicago'} | Export-Csv -LiteralPath $chicagoCsv -NoTypeInformation -Encoding UTF8
$rankedFinal | Where-Object {$_.City -eq 'Fargo'} | Export-Csv -LiteralPath $fargoCsv -NoTypeInformation -Encoding UTF8
$rankedFinal | Select-Object -First $TopN | Export-Csv -LiteralPath $topCsv -NoTypeInformation -Encoding UTF8
$rankedFinal | Where-Object {$_.TcpReachable -and $_.PingReachable} | Select-Object -First $TopN | Export-Csv -LiteralPath $readyCsv -NoTypeInformation -Encoding UTF8
$missing | Export-Csv -LiteralPath $missingCsv -NoTypeInformation -Encoding UTF8

$best=$rankedFinal | Where-Object {$_.TcpReachable -and $_.PingReachable} | Select-Object -First 1
$bestChicago=$rankedFinal | Where-Object {$_.City -eq 'Chicago' -and $_.TcpReachable -and $_.PingReachable} | Select-Object -First 1
$bestFargo=$rankedFinal | Where-Object {$_.City -eq 'Fargo' -and $_.TcpReachable -and $_.PingReachable} | Select-Object -First 1

$ready=$rankedFinal | Where-Object {$_.TcpReachable -and $_.PingReachable} | Select-Object -First $TopN
@($ready | ForEach-Object { $_.FullPath }) | Set-Content -LiteralPath $pathsTxt -Encoding UTF8

$summary=@()
$summary+='NORDVPN TCP SERVER SCAN V2';$summary+='==========================';$summary+='';$summary+="Scan time: $(Get-Date)";$summary+="Profile folder: $ProfileFolder";$summary+="Server data cache: $ServerDataFile";$summary+='';$summary+="Local profile hostnames: $($ProfileMap.Keys.Count)";$summary+="NordVPN matching servers: $($targetServers.Count)";$summary+="Local matching profiles: $($matched.Count)";$summary+="Missing local profiles: $($missing.Count)";$summary+="TCP reachable profiles: $(@($rankedFinal | Where-Object {$_.TcpReachable}).Count)";$summary+='';$summary+='BEST OVERALL';$summary+='============'
if($best){$summary+="Hostname: $($best.Hostname)";$summary+="City: $($best.City)";$summary+="IP: $($best.ServerIP)";$summary+="Load: $($best.LoadPercent)%";$summary+="Ping: $($best.PingAvgMs) ms";$summary+="TCP: $($best.TcpHost):$($best.TcpPort) ($($best.TcpConnectMs) ms)";$summary+="Profile: $($best.FileName)";$summary+="Path: $($best.FullPath)"}else{$summary+='No candidate passed both ICMP and TCP tests.'}
$summary+='';$summary+='BEST CHICAGO';$summary+='============';if($bestChicago){$summary+="Hostname: $($bestChicago.Hostname)";$summary+="Load: $($bestChicago.LoadPercent)%";$summary+="Ping: $($bestChicago.PingAvgMs) ms";$summary+="TCP: $($bestChicago.TcpHost):$($bestChicago.TcpPort) ($($bestChicago.TcpConnectMs) ms)";$summary+="Profile: $($bestChicago.FileName)";$summary+="Path: $($bestChicago.FullPath)"}else{$summary+='No Chicago candidate passed both tests.'}
$summary+='';$summary+='BEST FARGO';$summary+='==========' ;if($bestFargo){$summary+="Hostname: $($bestFargo.Hostname)";$summary+="Load: $($bestFargo.LoadPercent)%";$summary+="Ping: $($bestFargo.PingAvgMs) ms";$summary+="TCP: $($bestFargo.TcpHost):$($bestFargo.TcpPort) ($($bestFargo.TcpConnectMs) ms)";$summary+="Profile: $($bestFargo.FileName)";$summary+="Path: $($bestFargo.FullPath)"}else{$summary+='No Fargo candidate passed both tests.'}
$summary+='';$summary+='IMPORTANT';$summary+='=========';$summary+='ICMP ping measures network latency only.';$summary+='TCP port reachability confirms the remote TCP port accepts a connection, but does not prove OpenVPN TLS/authentication will succeed.';$summary+='Test the finalists in pfSense.';$summary+='';$summary+='Generated files:';$summary+=$allCsv;$summary+=$chicagoCsv;$summary+=$fargoCsv;$summary+=$topCsv;$summary+=$readyCsv;$summary+=$missingCsv;$summary+=$pathsTxt;$summary+=$summaryTxt
$summary | Set-Content -LiteralPath $summaryTxt -Encoding UTF8

Write-Banner "TOP $TopN TCP SERVERS"
$rankedFinal | Select-Object -First $TopN Rank,City,Hostname,ServerIP,LoadPercent,PingAvgMs,TcpReachable,TcpConnectMs,TcpPort,ProfileType,FileName | Format-Table -AutoSize
Write-Host ''
Write-Host '============================================================' -ForegroundColor Green
Write-Host 'TCP SCAN COMPLETE' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Green
Write-Host "Results: $OutputFolder" -ForegroundColor Yellow
if($best){Write-Host '';Write-Host 'BEST TCP CANDIDATE:' -ForegroundColor Cyan;Write-Host "  Host    : $($best.Hostname)";Write-Host "  City    : $($best.City)";Write-Host "  Load    : $($best.LoadPercent)%";Write-Host "  Ping    : $($best.PingAvgMs) ms";Write-Host "  TCP     : $($best.TcpHost):$($best.TcpPort) ($($best.TcpConnectMs) ms)";Write-Host "  Profile : $($best.FileName)";Write-Host "  Path    : $($best.FullPath)"}
Write-Host ''
Write-Host 'If the API is unavailable on this PC, put a valid TCP server JSON export at:' -ForegroundColor Yellow
Write-Host "  $ServerDataFile" -ForegroundColor White
Write-Host ''
