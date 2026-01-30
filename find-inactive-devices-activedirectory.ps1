<#
.SYNOPSIS
  AD Inactive Device Review v2.1 (READ-ONLY) - configuration via variables in script

.DESCRIPTION
  Inventory and assess inactive AD computer objects, with selectable mode:
    - Servers  = non-clients (Windows Server + Linux/Unix/non-client devices), excludes clients
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
$Mode                 = "Servers"   # Servers | Clients | All
$InactiveDays          = 180
$DisableCandidateDays  = 180
$DeleteCandidateDays   = 365

$AllDCs               = $false      # $true = query lastLogon across all DCs (heavier)
$SearchBase           = ""          # e.g. "OU=Servers,DC=tdk,DC=dk" or "" for whole domain
$ResolveDns           = $false
$Ping                 = $false
$ExcludeUnknownOS     = $true

# Base output folder + per-run timestamp subfolder
$RunTimestamp         = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir               = "C:\Temp\AD_InactiveDevices\$RunTimestamp"
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

    Notes:
      - Uses OperatingSystem string, which can be empty or inconsistent.
      - "Unknown" = empty or non-matching string.
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

  # Other non-windows, non-client
  if ($os -notmatch '^Windows') { return "NonWindowsNonClient" }

  return "Unknown"
}

# -------------------------
# Validation of config
# -------------------------
$validModes = @("Servers","Clients","All")
if ($validModes -notcontains $Mode) {
  throw "Invalid `$Mode '$Mode'. Allowed: Servers, Clients, All."
}
if ($InactiveDays -lt 0 -or $DisableCandidateDays -lt 0 -or $DeleteCandidateDays -lt 0) {
  throw "Days values must be >= 0."
}
if ($DisableCandidateDays -gt $DeleteCandidateDays) {
  Write-Warning "DisableCandidateDays ($DisableCandidateDays) is greater than DeleteCandidateDays ($DeleteCandidateDays). This may be unintended."
}

Import-Module ActiveDirectory

Ensure-Directory -Path $OutDir

# Keep stamp for filenames as well (same value as folder timestamp)
$stamp = $RunTimestamp

$csvPath  = Join-Path $OutDir "InactiveDevices_$stamp.csv"
$txtPath  = Join-Path $OutDir "InactiveDevices_$stamp`_FindingsSummary.txt"
$logPath  = Join-Path $OutDir "InactiveDevices_$stamp`_RunTranscript.txt"

Start-Transcript -Path $logPath | Out-Null

try {
  $domain = Get-ADDomain
  $dcs = (Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)

  $cutInactive = (Get-Date).AddDays(-$InactiveDays)

  $searchParams = @{
    Filter     = '*'
    Properties = @(
      'OperatingSystem','OperatingSystemVersion',
      'Enabled','LastLogonDate','lastLogonTimestamp',
      'pwdLastSet','whenCreated','whenChanged',
      'servicePrincipalName','memberOf','DNSHostName','DistinguishedName'
    )
  }
  if ($SearchBase -and $SearchBase.Trim()) {
    $searchParams['SearchBase'] = $SearchBase.Trim()
  }

  Write-Host "Domain: $($domain.DNSRoot)"
  Write-Host "DCs: $($dcs -join ', ')"
  Write-Host "Mode: $Mode"
  Write-Host "Inactive cutoff: $cutInactive (InactiveDays=$InactiveDays)"
  Write-Host "LastLogon mode: $(if ($AllDCs) {"All DCs (lastLogon)"} else {"Replicated (LastLogonDate)"} )"
  Write-Host "ExcludeUnknownOS: $ExcludeUnknownOS"
  Write-Host "SearchBase: $(if ($SearchBase) {$SearchBase} else {"<DomainRoot>"} )"
  Write-Host "ResolveDns: $ResolveDns | Ping: $Ping"
  Write-Host "OutDir: $OutDir"
  Write-Host ""

  $computers = Get-ADComputer @searchParams
  $results = New-Object System.Collections.Generic.List[object]

  $i = 0
  foreach ($c in $computers) {
    $i++
    if ($i % 500 -eq 0) { Write-Host "Processed $i / $($computers.Count)..." }

    $deviceClass = Get-DeviceClassV2 -OperatingSystem $c.OperatingSystem

    if ($ExcludeUnknownOS -and $deviceClass -eq "Unknown") { continue }

    # Mode filtering
    switch ($Mode) {
      "Servers" { if ($deviceClass -eq "Client") { continue } }
      "Clients" { if ($deviceClass -ne "Client") { continue } }
      "All"     { }
    }

    # Determine last logon
    $lastLogon = $null
    if ($AllDCs) {
      $lastLogon = Get-MaxLastLogonFromAllDCs -ComputerDN $c.DistinguishedName -DCs $dcs
    } else {
      $lastLogon = $c.LastLogonDate
    }

    $effectiveLastSeen = $lastLogon
    if (-not $effectiveLastSeen) { $effectiveLastSeen = $c.whenCreated }

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

    $results.Add([pscustomobject]@{
      Mode                   = $Mode
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
    })
  }

  $results |
    Sort-Object DaysInactive -Descending |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

  # Summary
  $total = $results.Count
  $enabledCount  = ($results | Where-Object Enabled).Count
  $disabledCount = $total - $enabledCount

  $deleteCand  = ($results | Where-Object SuggestedLifecycleStep -eq "DeleteCandidate").Count
  $disableCand = ($results | Where-Object SuggestedLifecycleStep -eq "DisableCandidate").Count
  $reviewOnly  = ($results | Where-Object SuggestedLifecycleStep -eq "Review").Count

  $byClass = $results | Group-Object DeviceClass | Sort-Object Count -Descending
  $topOU = $results | Group-Object OUPath | Sort-Object Count -Descending | Select-Object -First 10
  $topSPN = $results | Where-Object { $_.SPNCount -gt 0 } | Sort-Object SPNCount -Descending | Select-Object -First 20

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("AD Inactive Device Review v2.1 - Summary")
  $lines.Add("Timestamp: $(Get-Date)")
  $lines.Add("Domain: $($domain.DNSRoot)")
  $lines.Add("SearchBase: $(if ($SearchBase) {$SearchBase} else {"<DomainRoot>"} )")
  $lines.Add("Mode: $Mode")
  $lines.Add("InactiveDays: $InactiveDays | DisableCandidateDays: $DisableCandidateDays | DeleteCandidateDays: $DeleteCandidateDays")
  $lines.Add("LastLogon mode: $(if ($AllDCs) {"All DCs (lastLogon)"} else {"Replicated (LastLogonDate)"} )")
  $lines.Add("ExcludeUnknownOS: $ExcludeUnknownOS")
  $lines.Add("ResolveDns: $ResolveDns | Ping: $Ping")
  $lines.Add("OutDir: $OutDir")
  $lines.Add("")
  $lines.Add("Counts")
  $lines.Add("  Total inactive objects: $total")
  $lines.Add("  Enabled: $enabledCount")
  $lines.Add("  Disabled: $disabledCount")
  $lines.Add("")
  $lines.Add("By DeviceClass")
  foreach ($g in $byClass) { $lines.Add(("  {0} -> {1}" -f $g.Name, $g.Count)) }
  $lines.Add("")
  $lines.Add("Lifecycle recommendation (read-only)")
  $lines.Add("  DeleteCandidate: $deleteCand")
  $lines.Add("  DisableCandidate: $disableCand")
  $lines.Add("  Review: $reviewOnly")
  $lines.Add("")
  $lines.Add("Top OUs by inactive object count (Top 10)")
  foreach ($g in $topOU) { $lines.Add(("  {0}  ->  {1}" -f $g.Count, $g.Name)) }
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
  $lines.Add("  - SuggestedLifecycleStep is guidance only; validate ownership/CMDB/service dependency before any action.")
  $lines.Add("  - Suggested decom lifecycle: CMDB status -> Monitoring removal -> AD disable -> SPN review -> Group cleanup -> AD delete (after retention).")
  $lines.Add("  - If you see too many Unknown OS entries, keep ExcludeUnknownOS=$true or improve OS string hygiene in AD.")

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
