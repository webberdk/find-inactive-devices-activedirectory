<#
.SYNOPSIS
  AD Inactive Device Review v2.1.1 (READ-ONLY) - configuration via variables in script

.DESCRIPTION
  Inventory and assess inactive AD computer objects, with selectable mode:
    - Servers  = STRICT allow-list (WindowsServer, Linux, Unix, NonWindowsNonClient)
                NOTE: Clients and Unknown are excluded by default in Servers mode.
    - Clients  = clients only
    - All      = everything

  Enriches with:
    - Enabled/Disabled
    - Last logon (replicated via LastLogonDate OR optional true lastLogon across all DCs)
    - Password last set (pwdLastSet)
    - SPNs (count)
    - OU path
    - Group memberships (count + sample)
    - Optional DNS resolution and ping

  Outputs (per run folder with timestamp):
    - InactiveDevices_<timestamp>.csv
    - InactiveDevices_<timestamp>_FindingsSummary.txt
    - InactiveDevices_<timestamp>_RunTranscript.txt

.NOTES
  - Requires RSAT ActiveDirectory module
  - READ-ONLY (no Set-AD* calls)
  - $AllDCs is heavy in large environments
#>

# =========================
# CONFIG (edit these only)
# =========================
$ScriptVersion         = "2.1.1"

$Mode                  = "Clients"   # Servers | Clients | All
$InactiveDays           = 180
$DisableCandidateDays   = 180
$DeleteCandidateDays    = 365

$AllDCs                = $false      # $true = query lastLogon across all DCs (heavier)
$SearchBase            = ""          # e.g. "OU=Servers,DC=tdk,DC=dk" or "" for whole domain
$ResolveDns            = $false
$Ping                  = $false
$ResultPageSize        = 500         # AD query paging size (tune for large environments)
$StreamCsv             = $true       # Write CSV incrementally to reduce memory usage
$SortCsvByDaysInactive = $false      # Requires buffering results (ignored when StreamCsv=$true)

# If true: exclude objects where OperatingSystem is empty/unknown
$ExcludeUnknownOS      = $false

# If true: allow Unknown OS objects in Servers mode (default false = strict)
$IncludeUnknownInServers = $false

# Base output folder + per-run timestamp subfolder
$RunTimestamp          = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir                = "C:\Temp\AD_InactiveDevices\$RunTimestamp"
# =========================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Directory {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Get-OUPathFromDN {
  param([Parameter(Mandatory)][string]$DistinguishedName)
  return ($DistinguishedName -replace '^CN=[^,]+,', '')
}

function Safe-ResolveDns {
  param([string]$Name)
  try { Resolve-DnsName -Name $Name -ErrorAction Stop | Out-Null; return $true } catch { return $false }
}

function Safe-Ping {
  param([string]$Name)
  try { return Test-Connection -ComputerName $Name -Count 1 -Quiet -ErrorAction Stop } catch { return $false }
}

function Get-MaxLastLogonFromAllDCs {
  param(
    [Parameter(Mandatory)][string]$ComputerDN,
    [Parameter(Mandatory)][string[]]$DCs
  )

  $max = 0L
  foreach ($dc in $DCs) {
    try {
      $ll = (Get-ADComputer -Server $dc -Identity $ComputerDN -Properties lastLogon).lastLogon
      if ($ll -and [int64]$ll -gt $max) { $max = [int64]$ll }
    } catch {
      # ignore DC-specific read issues
    }
  }

  if ($max -gt 0) { return [DateTime]::FromFileTimeUtc($max).ToLocalTime() }
  return $null
}

function Get-DeviceClassV2 {
  <#
    Returns:
      Client
      WindowsServer
      Linux
      Unix
      NonWindowsNonClient
      Unknown
  #>
  param([string]$OperatingSystem)

  if ([string]::IsNullOrWhiteSpace($OperatingSystem)) { return "Unknown" }
  $os = $OperatingSystem.Trim()

  # Clients
  $clientPatterns = @(
    '^Windows 11', '^Windows 10', '^Windows 8\.1', '^Windows 8', '^Windows 7', '^Windows Vista', '^Windows XP',
    '^Mac OS X', '^macOS', '^OS X',
    'Android', 'iOS', 'iPadOS',
    '^Windows Phone'
  )
  foreach ($p in $clientPatterns) { if ($os -match $p) { return "Client" } }

  # Windows Server
  if ($os -match '^Windows Server') { return "WindowsServer" }

  # Linux
  $linuxPatterns = @(
    'Red Hat', '\bRHEL\b', 'CentOS', 'Rocky', 'AlmaLinux', 'Oracle Linux',
    'Ubuntu', 'Debian',
    'SUSE', '\bSLES\b', 'openSUSE',
    '\bLinux\b'
  )
  foreach ($p in $linuxPatterns) { if ($os -match $p) { return "Linux" } }

  # Unix/BSD
  $unixPatterns = @(
    '\bAIX\b', 'Solaris', '\bSunOS\b', 'HP-UX',
    'FreeBSD', 'NetBSD', 'OpenBSD'
  )
  foreach ($p in $unixPatterns) { if ($os -match $p) { return "Unix" } }

  # Other non-windows, non-client (appliances often show odd strings)
  if ($os -notmatch '^Windows') { return "NonWindowsNonClient" }

  return "Unknown"
}

function Get-ModeAllowedClasses {
  param(
    [Parameter(Mandatory)][string]$Mode,
    [Parameter(Mandatory)][bool]$IncludeUnknownInServers
  )
  switch ($Mode) {
    "Servers" {
      $allowed = @("WindowsServer","Linux","Unix","NonWindowsNonClient")
      if ($IncludeUnknownInServers) { $allowed += "Unknown" }
      return $allowed
    }
    "Clients" { return @("Client") }
    "All"     { return @("Client","WindowsServer","Linux","Unix","NonWindowsNonClient","Unknown") }
    default   { throw "Invalid Mode '$Mode'." }
  }
}

# -------------------------
# Validation of config
# -------------------------
$validModes = @("Servers","Clients","All")
if ($validModes -notcontains $Mode) { throw "Invalid `$Mode '$Mode'. Allowed: Servers, Clients, All." }

foreach ($d in @($InactiveDays,$DisableCandidateDays,$DeleteCandidateDays)) {
  if ($d -lt 0) { throw "Days values must be >= 0." }
}
if ($DisableCandidateDays -gt $DeleteCandidateDays) {
  Write-Warning "DisableCandidateDays ($DisableCandidateDays) is greater than DeleteCandidateDays ($DeleteCandidateDays). This may be unintended."
}

Import-Module ActiveDirectory

Ensure-Directory -Path $OutDir

# Keep stamp for filenames as well (same value as folder timestamp)
$stamp   = $RunTimestamp
$csvPath = Join-Path $OutDir "InactiveDevices_$stamp.csv"
$txtPath = Join-Path $OutDir "InactiveDevices_$stamp`_FindingsSummary.txt"
$logPath = Join-Path $OutDir "InactiveDevices_$stamp`_RunTranscript.txt"

Start-Transcript -Path $logPath | Out-Null

try {
  $domain = Get-ADDomain
  $dcs = (Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
  $cutInactive = (Get-Date).AddDays(-$InactiveDays)

  $allowedClasses = Get-ModeAllowedClasses -Mode $Mode -IncludeUnknownInServers:$IncludeUnknownInServers
  $allowedClassSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$allowedClasses)

  $searchParams = @{
    Filter     = '*'
    Properties = @(
      'OperatingSystem','OperatingSystemVersion',
      'Enabled','LastLogonDate','lastLogonTimestamp',
      'pwdLastSet','whenCreated','whenChanged',
      'servicePrincipalName','memberOf','DNSHostName','DistinguishedName'
    )
    ResultPageSize = $ResultPageSize
    ResultSetSize  = $null
  }
  if ($SearchBase -and $SearchBase.Trim()) { $searchParams['SearchBase'] = $SearchBase.Trim() }

  Write-Host "ScriptVersion: $ScriptVersion"
  Write-Host "Domain: $($domain.DNSRoot)"
  Write-Host "DCs: $($dcs -join ', ')"
  Write-Host "Mode: $Mode"
  Write-Host "Allowed DeviceClasses: $($allowedClasses -join ', ')"
  Write-Host "Inactive cutoff: $cutInactive (InactiveDays=$InactiveDays)"
  Write-Host "LastLogon mode: $(if ($AllDCs) {"All DCs (lastLogon)"} else {"Replicated (LastLogonDate)"} )"
  Write-Host "ExcludeUnknownOS: $ExcludeUnknownOS"
  Write-Host "IncludeUnknownInServers: $IncludeUnknownInServers"
  Write-Host "SearchBase: $(if ($SearchBase) {$SearchBase} else {"<DomainRoot>"} )"
  Write-Host "ResolveDns: $ResolveDns | Ping: $Ping"
  Write-Host "ResultPageSize: $ResultPageSize | StreamCsv: $StreamCsv | SortCsvByDaysInactive: $SortCsvByDaysInactive"
  Write-Host "OutDir: $OutDir"
  Write-Host ""

  $computers = Get-ADComputer @searchParams
  $results = New-Object System.Collections.Generic.List[object]

  if ($StreamCsv -and $SortCsvByDaysInactive) {
    Write-Warning "SortCsvByDaysInactive ignored because StreamCsv=$StreamCsv."
    $SortCsvByDaysInactive = $false
  }

  $csvWritten = $false
  $total = 0
  $enabledCount = 0
  $disabledCount = 0
  $deleteCand = 0
  $disableCand = 0
  $reviewOnly = 0
  $byClass = @{}
  $byOU = @{}
  $topSPN = New-Object System.Collections.Generic.List[object]

  $i = 0
  foreach ($c in $computers) {
    $i++
    if ($i % 500 -eq 0) { Write-Host "Processed $i / $($computers.Count)..." }

    $deviceClass = Get-DeviceClassV2 -OperatingSystem $c.OperatingSystem

    if ($ExcludeUnknownOS -and $deviceClass -eq "Unknown") { continue }

    # STRICT mode filtering: only include allowed classes for the selected mode
    if (-not $allowedClassSet.Contains($deviceClass)) { continue }

    # Determine last logon
    $lastLogon = $null
    if ($AllDCs) {
      $lastLogon = Get-MaxLastLogonFromAllDCs -ComputerDN $c.DistinguishedName -DCs $dcs
    } else {
      $lastLogon = $c.LastLogonDate
    }

    # If never logged on, use whenCreated as effective last seen
    $effectiveLastSeen = $lastLogon
    if (-not $effectiveLastSeen) { $effectiveLastSeen = $c.whenCreated }

    # Inactivity filter
    if ($effectiveLastSeen -ge $cutInactive) { continue }

    $ouPath = Get-OUPathFromDN -DistinguishedName $c.DistinguishedName

    $pwdLastSet = $null
    if ($c.pwdLastSet -and [int64]$c.pwdLastSet -gt 0) {
      $pwdLastSet = [DateTime]::FromFileTimeUtc([int64]$c.pwdLastSet).ToLocalTime()
    }

    $spnCount = 0
    if ($c.servicePrincipalName) { $spnCount = @($c.servicePrincipalName).Count }

    $groupCount = 0
    $groupSample = ""
    if ($c.memberOf) {
      $groupCount = @($c.memberOf).Count
      $groupSample = (@($c.memberOf) | Select-Object -First 5) -join ';'
    }

    $daysInactive = [math]::Floor((New-TimeSpan -Start $effectiveLastSeen -End (Get-Date)).TotalDays)

    # Lifecycle recommendation
    $step = "Review"
    $rationale = New-Object System.Collections.Generic.List[string]
    if ($deviceClass -eq "Unknown") { $rationale.Add("UnknownOSString") }

    if (-not $c.Enabled) {
      $step = "Review"
      $rationale.Add("AlreadyDisabled")
    } else {
      if ($daysInactive -ge $DeleteCandidateDays) {
        $step = "DeleteCandidate"
        $rationale.Add("EnabledAndInactive>=${DeleteCandidateDays}d")
      } elseif ($daysInactive -ge $DisableCandidateDays) {
        $step = "DisableCandidate"
        $rationale.Add("EnabledAndInactive>=${DisableCandidateDays}d")
      } else {
        $step = "Review"
        $rationale.Add("Inactive<DisableCandidateThreshold")
      }
    }

    if ($spnCount -gt 0) { $rationale.Add("HasSPNs($spnCount)") }
    if ($groupCount -gt 0) { $rationale.Add("HasGroupMemberships($groupCount)") }

    $dnsOK = $null
    $pingOK = $null
    if ($ResolveDns) { $dnsOK = Safe-ResolveDns -Name $c.Name }
    if ($Ping) { $pingOK = Safe-Ping -Name $c.Name }

    $row = [pscustomobject]@{
      ScriptVersion          = $ScriptVersion
      RunTimestamp           = $RunTimestamp

      ConfigMode             = $Mode
      AllowedClasses         = ($allowedClasses -join ',')

      Name                   = $c.Name
      DNSHostName            = $c.DNSHostName
      Enabled                = $c.Enabled

      OperatingSystem        = $c.OperatingSystem
      OperatingSystemVersion = $c.OperatingSystemVersion
      DeviceClass            = $deviceClass

      OUPath                 = $ouPath
      DistinguishedName      = $c.DistinguishedName

      LastLogonEffective     = $effectiveLastSeen
      LastLogonSource        = $(if ($AllDCs) {"lastLogon (max across DCs)"} else {"LastLogonDate (replicated)"} )
      DaysInactive           = $daysInactive

      PasswordLastSet        = $pwdLastSet
      WhenCreated            = $c.whenCreated
      WhenChanged            = $c.whenChanged

      SPNCount               = $spnCount
      GroupCount             = $groupCount
      GroupSample            = $groupSample

      DnsResolves            = $dnsOK
      PingResponds           = $pingOK

      SuggestedLifecycleStep = $step
      Rationale              = ($rationale -join ';')
    }

    $total++
    if ($row.Enabled) { $enabledCount++ } else { $disabledCount++ }
    if ($row.SuggestedLifecycleStep -eq "DeleteCandidate") { $deleteCand++ }
    elseif ($row.SuggestedLifecycleStep -eq "DisableCandidate") { $disableCand++ }
    else { $reviewOnly++ }

    if ($byClass.ContainsKey($row.DeviceClass)) { $byClass[$row.DeviceClass]++ } else { $byClass[$row.DeviceClass] = 1 }
    if ($byOU.ContainsKey($row.OUPath)) { $byOU[$row.OUPath]++ } else { $byOU[$row.OUPath] = 1 }

    if ($row.SPNCount -gt 0) {
      $topSPN.Add($row)
      if ($topSPN.Count -gt 40) {
        $topSPN = [System.Collections.Generic.List[object]]($topSPN | Sort-Object SPNCount -Descending | Select-Object -First 20)
      }
    }

    if ($StreamCsv) {
      if (-not $csvWritten) {
        $row | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $csvWritten = $true
      } else {
        $row | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Append
      }
    } else {
      $results.Add($row)
    }
  }

  if (-not $StreamCsv) {
    if ($SortCsvByDaysInactive) {
      $results |
        Sort-Object DaysInactive -Descending |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    } else {
      $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    }
    $total = $results.Count
    $enabledCount  = ($results | Where-Object Enabled).Count
    $disabledCount = $total - $enabledCount
    $deleteCand  = ($results | Where-Object SuggestedLifecycleStep -eq "DeleteCandidate").Count
    $disableCand = ($results | Where-Object SuggestedLifecycleStep -eq "DisableCandidate").Count
    $reviewOnly  = ($results | Where-Object SuggestedLifecycleStep -eq "Review").Count
    $byClass = $results | Group-Object DeviceClass | Sort-Object Count -Descending
    $topOU = $results | Group-Object OUPath | Sort-Object Count -Descending | Select-Object -First 10
    $topSPN = $results | Where-Object { $_.SPNCount -gt 0 } | Sort-Object SPNCount -Descending | Select-Object -First 20
  } else {
    if (-not $csvWritten) {
      "" | Out-File -FilePath $csvPath -Encoding UTF8
    }
    $byClass = $byClass.GetEnumerator() | Sort-Object Value -Descending
    $topOU = $byOU.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    $topSPN = $topSPN | Sort-Object SPNCount -Descending | Select-Object -First 20
  }

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("AD Inactive Device Review v$ScriptVersion - Summary")
  $lines.Add("Timestamp: $(Get-Date)")
  $lines.Add("RunTimestamp: $RunTimestamp")
  $lines.Add("Domain: $($domain.DNSRoot)")
  $lines.Add("SearchBase: $(if ($SearchBase) {$SearchBase} else {"<DomainRoot>"} )")
  $lines.Add("Mode: $Mode")
  $lines.Add("Allowed DeviceClasses: $($allowedClasses -join ', ')")
  $lines.Add("InactiveDays: $InactiveDays | DisableCandidateDays: $DisableCandidateDays | DeleteCandidateDays: $DeleteCandidateDays")
  $lines.Add("LastLogon mode: $(if ($AllDCs) {"All DCs (lastLogon)"} else {"Replicated (LastLogonDate)"} )")
  $lines.Add("ExcludeUnknownOS: $ExcludeUnknownOS")
  $lines.Add("IncludeUnknownInServers: $IncludeUnknownInServers")
  $lines.Add("ResolveDns: $ResolveDns | Ping: $Ping")
  $lines.Add("OutDir: $OutDir")
  $lines.Add("")
  $lines.Add("Counts")
  $lines.Add("  Total inactive objects: $total")
  $lines.Add("  Enabled: $enabledCount")
  $lines.Add("  Disabled: $disabledCount")
  $lines.Add("")
  $lines.Add("By DeviceClass")
  foreach ($g in $byClass) {
    $count = if ($g.PSObject.Properties['Count']) { $g.Count } elseif ($g.PSObject.Properties['Value']) { $g.Value } else { 0 }
    $name = if ($g.PSObject.Properties['Name']) { $g.Name } else { $g.Key }
    $lines.Add(("  {0} -> {1}" -f $name, $count))
  }
  $lines.Add("")
  $lines.Add("Lifecycle recommendation (read-only)")
  $lines.Add("  DeleteCandidate: $deleteCand")
  $lines.Add("  DisableCandidate: $disableCand")
  $lines.Add("  Review: $reviewOnly")
  $lines.Add("")
  $lines.Add("Top OUs by inactive object count (Top 10)")
  foreach ($g in $topOU) {
    $count = if ($g.PSObject.Properties['Count']) { $g.Count } elseif ($g.PSObject.Properties['Value']) { $g.Value } else { 0 }
    $name = if ($g.PSObject.Properties['Name']) { $g.Name } else { $g.Key }
    $lines.Add(("  {0}  ->  {1}" -f $count, $name))
  }
  $lines.Add("")
  $lines.Add("Top inactive objects with SPNs (Top 20) - decom/service dependency review required")
  foreach ($x in $topSPN) {
    $lines.Add(("  {0} | Class={1} | Enabled={2} | DaysInactive={3} | SPNCount={4} | Step={5}" -f $x.Name, $x.DeviceClass, $x.Enabled, $x.DaysInactive, $x.SPNCount, $x.SuggestedLifecycleStep))
  }
  $lines.Add("")
  $lines.Add("Outputs")
  $lines.Add("  CSV: $csvPath")
  $lines.Add("  Summary: $txtPath")
  $lines.Add("  Transcript: $logPath")
  $lines.Add("")
  $lines.Add("Notes")
  $lines.Add("  - STRICT mode filtering is enforced via allow-list by DeviceClass.")
  $lines.Add("  - In Servers mode, Client is NEVER included. Unknown is included only if IncludeUnknownInServers=$true.")
  $lines.Add("  - SuggestedLifecycleStep is guidance only; validate ownership/CMDB/service dependency before any action.")
  $lines.Add("  - Suggested decom lifecycle: CMDB status -> Monitoring removal -> AD disable -> SPN review -> Group cleanup -> AD delete (after retention).")

  $lines | Out-File -FilePath $txtPath -Encoding UTF8

  Write-Host ""
  Write-Host "Done."
  Write-Host "CSV: $csvPath"
  Write-Host "Summary: $txtPath"
  Write-Host "Transcript: $logPath"
}
finally {
  Stop-Transcript | Out-Null
}
