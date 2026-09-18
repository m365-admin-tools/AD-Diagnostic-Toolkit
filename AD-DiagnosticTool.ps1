<#
.SYNOPSIS
    M365admintools.com - Author Charles Arconi - created 8/5/2026
    AD Diagnostic Toolkit 1.0 - dcdiag / repadmin / nltest / native health checks with a
    checklist-driven GUI, a color-coded results grid and an HTML customer report.

.DESCRIPTION
    Companion tool to "AD Attribute Editor 5.0". Where the editor writes, this tool only
    reads: it wraps dcdiag.exe, repadmin.exe, nltest.exe and w32tm.exe, plus a handful of
    native PowerShell / System.DirectoryServices checks, behind one GUI so a tech can pick
    exactly what to run and against which domain controllers, then hand the customer a
    report at the end.

    Workflow:
      1. Connect to the current domain (or type a DC / domain name to bind elsewhere).
      2. Pick which domain controllers are in scope. Per-DC tests run once per checked DC;
         domain-wide tests (FSMO, replication summary, trusts, ...) run once regardless.
      3. Pick which tests to run from the categorized checklist (DCDiag, Replication,
         Netlogon, Directory Health), or use a preset: Quick Health Check, Select All,
         Select None.
      4. Run. Each result gets a Pass / Warn / Fail / Error status, a one-line summary, and
         full raw tool output in the detail pane below the grid.
      5. Export a CSV of the grid and/or a self-contained HTML report to hand to the
         customer or file with the ticket.

    Everything runs in the current user's security context on the machine the script is
    launched from (no embedded alternate-credential handling) -- run it from a domain
    controller or an admin workstation that already has line of sight and rights into the
    target environment, the same way you'd run dcdiag by hand.

    Status is a HEURISTIC based on tool exit codes and known output text patterns. It is a
    triage aid, not a verdict -- always read the raw output before acting on a Fail, and
    treat a Pass as "nothing obviously wrong found here", not "certified healthy". Every
    test here is read-only except "Recalculate Topology (KCC)" under Replication, which is
    unchecked by default and marked in red because it forces the KCC to recompute the
    replication topology.

.PARAMETER Server
    Optional domain controller or DNS domain name to bind to for the initial connect.
    Leave blank to use the current domain context of the machine running the script.

.EXAMPLE
    .\AD-DiagnosticTool.ps1

.EXAMPLE
    .\AD-DiagnosticTool.ps1 -Server dc01.contoso.com

.NOTES
    Requires Windows PowerShell 5.1 on Windows.
    Requires dcdiag.exe, repadmin.exe, nltest.exe and w32tm.exe on PATH -- present by
    default on any domain controller, or via the "RSAT: Active Directory Domain Services
    and Lightweight Directory Tools" Windows feature on an admin workstation.
    Read-only with one clearly marked exception (repadmin /kcc). Safe to run against
    production. Always review raw output before treating a Fail as confirmed.
#>

[CmdletBinding()]
param(
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.DirectoryServices
# Not Add-Type'd: on Windows PowerShell, referencing a
# [System.DirectoryServices.ActiveDirectory.X] type below resolves the
# assembly on its own the first time it's touched. Add-Type -AssemblyName
# for this one is unnecessary and fails outright on some hosts/editions
# (partial-name assembly resolution is pickier than type-literal resolution),
# so it is deliberately left out rather than wrapped in a swallowed try/catch.
try { Add-Type -AssemblyName Microsoft.VisualBasic } catch { }
[System.Windows.Forms.Application]::EnableVisualStyles()

# ===========================================================================
# State
# ===========================================================================

$script:Ctx = [pscustomobject]@{
    BindServer        = $null   # server or DNS domain name used for the current bind
    Domain            = $null   # System.DirectoryServices.ActiveDirectory.Domain
    Forest            = $null   # System.DirectoryServices.ActiveDirectory.Forest
    DomainControllers = @()     # { Name, IPAddress, SiteName, OSVersion, IsGC }
    Trusts            = @()
}

$script:Results          = New-Object System.Collections.Generic.List[object]
$script:CancelRequested  = $false
$script:SuppressChecks   = $false

# ===========================================================================
# Test catalog
#
# Id       : stable key, also stashed in the TreeNode.Tag for the checklist
# Category : groups tests under a TreeView parent node (DCDiag / Replication /
#            Netlogon / Directory Health)
# Label    : what the technician sees
# Tool     : dispatch key -> dcdiag | repadmin | nltest | native
# Scope    : PerDC (run once per checked domain controller) or DomainWide
#            (run once no matter how many DCs are checked)
# Default  : checked out of the box / included in the "Quick Health Check" preset
# TestArg  : dcdiag /test:<TestArg>
# Action   : dispatch key inside the repadmin / nltest / native runner
# Caution  : not read-only -- rendered in red, unchecked by default
# ===========================================================================

$script:TestCatalog = @(
    # --- DCDiag: default test set (what "dcdiag /s:<dc>" runs with no /test:) ---
    @{ Id='dd-connectivity'; Category='DCDiag'; Label='Connectivity';                       Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='Connectivity' }
    @{ Id='dd-advertising';  Category='DCDiag'; Label='Advertising';                        Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='Advertising' }
    @{ Id='dd-frsevent';     Category='DCDiag'; Label='FRS Event Log';                      Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='FrsEvent' }
    @{ Id='dd-dfsrevent';    Category='DCDiag'; Label='DFSR Event Log';                     Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='DFSREvent' }
    @{ Id='dd-sysvol';       Category='DCDiag'; Label='SYSVOL Check';                       Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='SysVolCheck' }
    @{ Id='dd-kccevent';     Category='DCDiag'; Label='KCC Event Log';                      Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='KccEvent' }
    @{ Id='dd-roleholders';  Category='DCDiag'; Label='Knows Of Role Holders';              Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='KnowsOfRoleHolders' }
    @{ Id='dd-machineacct';  Category='DCDiag'; Label='Machine Account';                    Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='MachineAccount' }
    @{ Id='dd-ncsecdesc';    Category='DCDiag'; Label='Naming Context Security Descriptor'; Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='NCSecDesc' }
    @{ Id='dd-netlogons';    Category='DCDiag'; Label='NetLogons';                          Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='NetLogons' }
    @{ Id='dd-objrepl';      Category='DCDiag'; Label='Objects Replicated';                 Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='ObjectsReplicated' }
    @{ Id='dd-replications'; Category='DCDiag'; Label='Replications';                       Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='Replications' }
    @{ Id='dd-ridmanager';   Category='DCDiag'; Label='RID Manager';                        Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='RidManager' }
    @{ Id='dd-services';     Category='DCDiag'; Label='Services';                           Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='Services' }
    @{ Id='dd-systemlog';    Category='DCDiag'; Label='System Log';                         Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='SystemLog' }
    @{ Id='dd-verifyref';    Category='DCDiag'; Label='Verify References';                  Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='VerifyReferences' }
    @{ Id='dd-dns';          Category='DCDiag'; Label='DNS Health';                         Tool='dcdiag'; Scope='PerDC'; Default=$true;  TestArg='DNS' }
    # --- DCDiag: non-default tests (dcdiag only runs these if you name them explicitly) ---
    @{ Id='dd-sdrefdom';     Category='DCDiag'; Label='Check SD Reference Domain';          Tool='dcdiag'; Scope='PerDC'; Default=$false; TestArg='CheckSDRefDom' }
    @{ Id='dd-crossref';     Category='DCDiag'; Label='Cross-Reference Validation';         Tool='dcdiag'; Scope='PerDC'; Default=$false; TestArg='CrossRefValidation' }
    @{ Id='dd-locator';      Category='DCDiag'; Label='Locator Check';                      Tool='dcdiag'; Scope='PerDC'; Default=$false; TestArg='LocatorCheck' }
    @{ Id='dd-intersite';    Category='DCDiag'; Label='Intersite';                          Tool='dcdiag'; Scope='PerDC'; Default=$false; TestArg='Intersite' }
    @{ Id='dd-topology';     Category='DCDiag'; Label='Topology';                           Tool='dcdiag'; Scope='PerDC'; Default=$false; TestArg='Topology' }
    @{ Id='dd-entref';       Category='DCDiag'; Label='Verify Enterprise References';       Tool='dcdiag'; Scope='PerDC'; Default=$false; TestArg='VerifyEnterpriseReferences' }

    # --- Replication (repadmin) ---
    @{ Id='ra-summary';     Category='Replication'; Label='Replication Summary (all DCs)'; Tool='repadmin'; Scope='DomainWide'; Default=$true;  Action='replsummary' }
    @{ Id='ra-showrepl';    Category='Replication'; Label='Show Replication Status';       Tool='repadmin'; Scope='PerDC';      Default=$true;  Action='showrepl' }
    @{ Id='ra-queue';       Category='Replication'; Label='Replication Queue';             Tool='repadmin'; Scope='PerDC';      Default=$false; Action='queue' }
    @{ Id='ra-bridgeheads'; Category='Replication'; Label='Bridgehead Servers';            Tool='repadmin'; Scope='DomainWide'; Default=$false; Action='bridgeheads' }
    @{ Id='ra-kcc';         Category='Replication'; Label='Recalculate Topology (KCC)';    Tool='repadmin'; Scope='PerDC';      Default=$false; Action='kcc'; Caution=$true }

    # --- Netlogon (nltest) ---
    @{ Id='nl-query';     Category='Netlogon'; Label='Netlogon Service Query'; Tool='nltest'; Scope='PerDC';      Default=$true;  Action='query' }
    @{ Id='nl-dsgetsite'; Category='Netlogon'; Label='DC Site Assignment';     Tool='nltest'; Scope='PerDC';      Default=$true;  Action='dsgetsite' }
    @{ Id='nl-dclist';    Category='Netlogon'; Label='DC List';               Tool='nltest'; Scope='DomainWide'; Default=$true;  Action='dclist' }
    @{ Id='nl-dsgetdc';   Category='Netlogon'; Label='Locate DC';             Tool='nltest'; Scope='DomainWide'; Default=$false; Action='dsgetdc' }
    @{ Id='nl-trusts';    Category='Netlogon'; Label='Domain Trusts';         Tool='nltest'; Scope='DomainWide'; Default=$true;  Action='domain_trusts' }

    # --- Directory Health (native PowerShell / System.DirectoryServices) ---
    @{ Id='nv-fsmo';        Category='Directory Health'; Label='FSMO Role Holders';           Tool='native'; Scope='DomainWide'; Default=$true;  Action='FSMO' }
    @{ Id='nv-dcinv';       Category='Directory Health'; Label='Domain Controller Inventory';  Tool='native'; Scope='DomainWide'; Default=$true;  Action='DCInventory' }
    @{ Id='nv-dnssrv';      Category='Directory Health'; Label='DNS SRV Records';              Tool='native'; Scope='DomainWide'; Default=$true;  Action='DnsSrv' }
    @{ Id='nv-sysvolshare'; Category='Directory Health'; Label='SYSVOL / NETLOGON Shares';     Tool='native'; Scope='PerDC';      Default=$true;  Action='SysvolShares' }
    @{ Id='nv-timesync';    Category='Directory Health'; Label='Time Sync (W32Time)';          Tool='native'; Scope='PerDC';      Default=$true;  Action='TimeSync' }
    @{ Id='nv-eventlogs';   Category='Directory Health'; Label='Event Log Scan (last 24h)';    Tool='native'; Scope='PerDC';      Default=$true;  Action='EventLogs' }
    @{ Id='nv-pwdpolicy';   Category='Directory Health'; Label='Password & Lockout Policy';    Tool='native'; Scope='DomainWide'; Default=$false; Action='PwdPolicy' }
    @{ Id='nv-tombstone';   Category='Directory Health'; Label='Tombstone Lifetime';           Tool='native'; Scope='DomainWide'; Default=$false; Action='Tombstone' }
    @{ Id='nv-recyclebin';  Category='Directory Health'; Label='AD Recycle Bin Status';        Tool='native'; Scope='DomainWide'; Default=$false; Action='RecycleBin' }
) | ForEach-Object {
    # Index access (not dot access): under Set-StrictMode -Version Latest,
    # reading a missing hashtable key by dot (e.g. $_.Action on a dcdiag entry
    # that only has TestArg) THROWS, whereas $_['Action'] safely returns $null.
    # Every catalog row is normalized here so downstream code always sees the
    # full property set regardless of which optional keys the source row set.
    [pscustomobject]@{
        Id       = $_['Id']
        Category = $_['Category']
        Label    = $_['Label']
        Tool     = $_['Tool']
        Scope    = $_['Scope']
        Default  = [bool]$_['Default']
        TestArg  = $_['TestArg']
        Action   = $_['Action']
        Caution  = [bool]$_['Caution']
    }
}

# ===========================================================================
# Directory discovery layer (System.DirectoryServices.ActiveDirectory -- no
# ActiveDirectory module / RSAT cmdlets required)
# ===========================================================================

function Connect-Environment {
    param([string]$TargetServer)

    $script:Ctx.BindServer = $TargetServer
    $domain = $null

    if ([string]::IsNullOrWhiteSpace($TargetServer)) {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    } else {
        $ts = $TargetServer.Trim()
        try {
            $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('DirectoryServer', $ts)
            $dcObj = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($ctx)
            $domain = $dcObj.Domain
        } catch {
            $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $ts)
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($ctx)
        }
    }

    $script:Ctx.Domain = $domain
    $script:Ctx.Forest = $domain.Forest

    $dcList = New-Object System.Collections.Generic.List[object]
    foreach ($d in $domain.DomainControllers) {
        $gc = $false
        try { $gc = $d.IsGlobalCatalog() } catch { }
        $dcList.Add([pscustomobject]@{
            Name      = $d.Name
            IPAddress = $d.IPAddress
            SiteName  = $d.SiteName
            OSVersion = $d.OSVersion
            IsGC      = $gc
        })
    }
    $script:Ctx.DomainControllers = @($dcList | Sort-Object Name)

    try { $script:Ctx.Trusts = @($domain.GetAllTrustRelationships()) }
    catch { $script:Ctx.Trusts = @() }
}

function Get-FirstProp {
    param($Entry, [string]$Name)
    try {
        if ($Entry.Properties.Contains($Name) -and $Entry.Properties[$Name].Count -gt 0) {
            return $Entry.Properties[$Name][0]
        }
    } catch { }
    return $null
}

# ===========================================================================
# Process / runspace helpers
# ===========================================================================

function Invoke-ExternalTool {
    <# Runs a console tool with output redirected to temp files (avoids stdout/stderr
       buffer deadlocks on chatty tools like dcdiag /v), bounded by a timeout, and
       cancellable via $script:CancelRequested. Pumps the WinForms message loop while
       waiting so the GUI does not appear to hang during a long dcdiag/repadmin call. #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSeconds = 120
    )

    if (-not (Get-Command $FilePath -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            ExitCode = -1; Output = ''; Cancelled = $false
            Error = "'$FilePath' was not found on PATH. Install the 'RSAT: Active Directory Domain Services and Lightweight Directory Tools' Windows feature, or run this from a domain controller."
        }
    }

    $stamp   = [guid]::NewGuid().ToString('N')
    $outFile = Join-Path $env:TEMP "addiag_$stamp.out.txt"
    $errFile = Join-Path $env:TEMP "addiag_$stamp.err.txt"
    $cancelled = $false
    $timedOut  = $false
    $exitCode  = -1

    try {
        $p = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -PassThru `
                -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $p.HasExited) {
            if ($sw.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $timedOut = $true; break }
            if ($script:CancelRequested) { $cancelled = $true; break }
            Start-Sleep -Milliseconds 150
            [System.Windows.Forms.Application]::DoEvents()
        }
        if ($timedOut -or $cancelled) {
            try { $p.Kill() } catch { }
            $p.WaitForExit(3000) | Out-Null
        }
        $exitCode = if ($timedOut -or $cancelled) { -1 } else { $p.ExitCode }
    } catch {
        return [pscustomobject]@{ ExitCode = -1; Output = ''; Error = $_.Exception.Message; Cancelled = $false }
    }

    $out = if (Test-Path -LiteralPath $outFile) { Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue } else { '' }
    $errText = if (Test-Path -LiteralPath $errFile) { Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue } else { '' }
    Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue

    if (-not $out) { $out = '' }
    if ($timedOut) { $errText = "TIMED OUT after $TimeoutSeconds second(s).`r`n$errText" }

    return [pscustomobject]@{ ExitCode = $exitCode; Output = $out; Error = $errText; Cancelled = $cancelled }
}

function Invoke-TimeBoxed {
    <# Runs a scriptblock in its own runspace with a hard timeout, for native checks
       (DNS resolution, UNC share tests, remote event log queries) that could otherwise
       hang indefinitely against an unreachable or firewalled target. #>
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [hashtable]$Params = @{},
        [int]$TimeoutSeconds = 15
    )
    $ps = [System.Management.Automation.PowerShell]::Create()
    try {
        $null = $ps.AddScript($ScriptBlock)
        foreach ($k in $Params.Keys) { $null = $ps.AddParameter($k, $Params[$k]) }
        $asyncResult = $ps.BeginInvoke()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $asyncResult.IsCompleted) {
            if ($sw.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                try { $ps.Stop() } catch { }
                throw "Timed out after $TimeoutSeconds second(s)."
            }
            if ($script:CancelRequested) {
                try { $ps.Stop() } catch { }
                throw 'Cancelled by user.'
            }
            Start-Sleep -Milliseconds 100
            [System.Windows.Forms.Application]::DoEvents()
        }
        $result = $ps.EndInvoke($asyncResult)
        if ($ps.HadErrors -and $ps.Streams.Error.Count -gt 0) {
            throw ($ps.Streams.Error[0].ToString())
        }
        return $result
    } finally {
        $ps.Dispose()
    }
}

# ===========================================================================
# Tool dispatchers -- each returns { Status, Summary, Raw, Command }
# Status is Pass / Warn / Fail / Info (cancelled) -- Error is reserved for the
# dispatcher wrapper (Invoke-DiagnosticTest) when an exception is thrown.
# ===========================================================================

function Get-DcDiagStatus {
    param([string]$Output, [int]$ExitCode)
    if ($Output -match '(?im)^\s*\.+\s*\S+\s+failed\s+test\s+\S+') { return 'Fail' }
    if ($ExitCode -ne 0) { return 'Warn' }
    if ($Output -match '(?im)\bwarning\b') { return 'Warn' }
    if ($Output -match '(?im)passed test') { return 'Pass' }
    return 'Info'
}

function Invoke-DcDiagTest {
    param($TestDef, [string]$TargetDC, $Options)

    $argList = @("/s:$TargetDC", "/test:$($TestDef.TestArg)")
    if ($TestDef.TestArg -eq 'DNS') { $argList += if ($Options.DeepDns) { '/DnsAll' } else { '/DnsBasic' } }
    if ($Options.Verbose) { $argList += '/v' }

    $cmd = "dcdiag $($argList -join ' ')"
    $res = Invoke-ExternalTool -FilePath 'dcdiag.exe' -ArgumentList $argList -TimeoutSeconds $Options.TimeoutSeconds

    if ($res.Cancelled) { return [pscustomobject]@{ Status='Info'; Summary='Cancelled by user.'; Raw=$res.Output; Command=$cmd } }
    if ($res.ExitCode -eq -1 -and $res.Error) { return [pscustomobject]@{ Status='Error'; Summary=$res.Error; Raw=$res.Output; Command=$cmd } }

    $status = Get-DcDiagStatus -Output $res.Output -ExitCode $res.ExitCode
    $matchLines = [regex]::Matches($res.Output, '(?m)^\s*\.+\s*\S+\s+(passed|failed)\s+test\s+\S+.*$') | ForEach-Object { $_.Value.Trim() }
    $summary = if ($matchLines) { $matchLines -join '; ' } else { (($res.Output -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1) }
    if (-not $summary) { $summary = '(no output)' }

    return [pscustomobject]@{ Status=$status; Summary=$summary; Raw=$res.Output; Command=$cmd }
}

function Get-RepadminStatus {
    param([string]$Output, [string]$Action)
    if ($Output -match '(?im)failed to |access is denied|unable to |could not |last error:\s*(?!0\b)\d+') { return 'Fail' }
    if ($Action -eq 'replsummary' -and ($Output -match '(?im)\bfail\b|largest delta.*?[1-9]\d{2,}\s*d')) { return 'Fail' }
    if ($Output -match '(?im)\bwarn') { return 'Warn' }
    return 'Pass'
}

function Invoke-RepadminTest {
    param($TestDef, [string]$TargetDC, $Options)

    $argList = switch ($TestDef.Action) {
        'replsummary' { @('/replsummary') }
        'showrepl'    { @($TargetDC, '/showrepl', '/verbose', '/all') }
        'queue'       { @('/queue', $TargetDC) }
        'kcc'         { @('/kcc', $TargetDC) }
        'bridgeheads' { @('/bridgeheads') }
        default       { throw "Unknown repadmin action '$($TestDef.Action)'." }
    }

    $cmd = "repadmin $($argList -join ' ')"
    $res = Invoke-ExternalTool -FilePath 'repadmin.exe' -ArgumentList $argList -TimeoutSeconds $Options.TimeoutSeconds

    if ($res.Cancelled) { return [pscustomobject]@{ Status='Info'; Summary='Cancelled by user.'; Raw=$res.Output; Command=$cmd } }
    if ($res.ExitCode -eq -1 -and $res.Error) { return [pscustomobject]@{ Status='Error'; Summary=$res.Error; Raw=$res.Output; Command=$cmd } }

    $status = Get-RepadminStatus -Output $res.Output -Action $TestDef.Action
    $lines = $res.Output -split "`r?`n" | Where-Object { $_.Trim() }
    $summary = if ($lines) { ($lines | Select-Object -First 3) -join ' | ' } else { '(no output)' }

    return [pscustomobject]@{ Status=$status; Summary=$summary; Raw=$res.Output; Command=$cmd }
}

function Invoke-NltestTest {
    param($TestDef, [string]$TargetDC, $Options)

    $domainName = $script:Ctx.Domain.Name
    $argList = switch ($TestDef.Action) {
        'query'         { @("/server:$TargetDC", '/query') }
        'dsgetsite'     { @("/server:$TargetDC", '/dsgetsite') }
        'dclist'        { @("/dclist:$domainName") }
        'dsgetdc'       { @("/dsgetdc:$domainName") }
        'domain_trusts' { @('/domain_trusts') }
        default         { throw "Unknown nltest action '$($TestDef.Action)'." }
    }

    $cmd = "nltest $($argList -join ' ')"
    $res = Invoke-ExternalTool -FilePath 'nltest.exe' -ArgumentList $argList -TimeoutSeconds $Options.TimeoutSeconds

    if ($res.Cancelled) { return [pscustomobject]@{ Status='Info'; Summary='Cancelled by user.'; Raw=$res.Output; Command=$cmd } }
    if ($res.ExitCode -eq -1 -and $res.Error) { return [pscustomobject]@{ Status='Error'; Summary=$res.Error; Raw=$res.Output; Command=$cmd } }

    $status = if ($res.Output -match '(?im)the command completed successfully') { 'Pass' }
              elseif ($res.ExitCode -ne 0) { 'Fail' }
              else { 'Warn' }
    $lines = $res.Output -split "`r?`n" | Where-Object { $_.Trim() }
    $summary = if ($lines) { ($lines | Select-Object -First 2) -join ' | ' } else { '(no output)' }

    return [pscustomobject]@{ Status=$status; Summary=$summary; Raw=$res.Output; Command=$cmd }
}

# --- Native checks ---

function Test-Native-FSMO {
    $cmd = '(native) FSMO role holder inventory + reachability check'
    try {
        $forest = $script:Ctx.Forest
        $domain = $script:Ctx.Domain
        $roles = [ordered]@{
            'Schema Master'         = $forest.SchemaRoleOwner.Name
            'Domain Naming Master'  = $forest.NamingRoleOwner.Name
            'PDC Emulator'          = $domain.PdcRoleOwner.Name
            'RID Master'            = $domain.RidRoleOwner.Name
            'Infrastructure Master' = $domain.InfrastructureRoleOwner.Name
        }
        $lines = New-Object System.Collections.Generic.List[string]
        $unreachable = New-Object System.Collections.Generic.List[string]
        foreach ($k in $roles.Keys) {
            $holder = $roles[$k]
            $ok = $false
            try { $ok = Test-Connection -ComputerName $holder -Count 1 -Quiet -ErrorAction SilentlyContinue } catch { }
            if (-not $ok) { $unreachable.Add($k) }
            $lines.Add(('{0,-24}: {1}  [{2}]' -f $k, $holder, $(if ($ok) { 'reachable' } else { 'UNREACHABLE' })))
        }
        $status = if ($unreachable.Count -gt 0) { 'Fail' } else { 'Pass' }
        $summary = if ($unreachable.Count -gt 0) { "Unreachable role holder(s): $($unreachable -join ', ')" } else { 'All 5 FSMO roles reachable.' }
        return [pscustomobject]@{ Status=$status; Summary=$summary; Raw=($lines -join "`r`n"); Command=$cmd }
    } catch {
        return [pscustomobject]@{ Status='Error'; Summary=$_.Exception.Message; Raw=$_.Exception.ToString(); Command=$cmd }
    }
}

function Test-Native-DCInventory {
    $cmd = '(native) domain controller inventory via System.DirectoryServices.ActiveDirectory'
    try {
        $dcs = $script:Ctx.DomainControllers
        if (-not $dcs -or $dcs.Count -eq 0) {
            return [pscustomobject]@{ Status='Fail'; Summary='No domain controllers were enumerated.'; Raw=''; Command=$cmd }
        }
        $lines = foreach ($d in $dcs) { '{0,-24} {1,-16} {2,-24} {3}{4}' -f $d.Name, $d.IPAddress, $d.SiteName, $d.OSVersion, $(if ($d.IsGC) { '  [GC]' } else { '' }) }
        $raw = ('{0,-24} {1,-16} {2,-24} {3}' -f 'Name', 'IPAddress', 'Site', 'OS') + "`r`n" + ($lines -join "`r`n")
        return [pscustomobject]@{ Status='Pass'; Summary="$($dcs.Count) domain controller(s) enumerated."; Raw=$raw; Command=$cmd }
    } catch {
        return [pscustomobject]@{ Status='Error'; Summary=$_.Exception.Message; Raw=$_.Exception.ToString(); Command=$cmd }
    }
}

function Test-Native-DnsSrv {
    $cmd = '(native) Resolve-DnsName SRV records for _ldap._tcp.dc._msdcs.<domain>'
    $domainName = $script:Ctx.Domain.Name
    $name = "_ldap._tcp.dc._msdcs.$domainName"
    try {
        $all = @(Invoke-TimeBoxed -TimeoutSeconds 15 -ScriptBlock {
            param($n) Resolve-DnsName -Name $n -Type SRV -ErrorAction Stop
        } -Params @{ n = $name })

        # Resolve-DnsName returns the SRV answers PLUS the additional-section
        # A/AAAA glue records for those targets. Glue records have no NameTarget,
        # so they must be filtered out before that property is read, and they
        # must not be counted as SRV records.
        $srv  = @($all | Where-Object { $_.Type -eq 'SRV' })
        $glue = @($all | Where-Object { $_.Type -ne 'SRV' })

        $count   = $srv.Count
        $dcCount = @($script:Ctx.DomainControllers).Count

        $lines = @($srv | Sort-Object NameTarget | ForEach-Object {
            "$($_.NameTarget)  (priority $($_.Priority), weight $($_.Weight), port $($_.Port))"
        })
        if ($glue.Count) {
            $lines += ''
            $lines += "Additional records returned by the resolver ($($glue.Count)):"
            $lines += @($glue | ForEach-Object {
                $addr = if ($_.PSObject.Properties['IP4Address']) { $_.IP4Address }
                        elseif ($_.PSObject.Properties['IP6Address']) { $_.IP6Address }
                        else { '' }
                "  $($_.Name)  $($_.Type)  $addr"
            })
        }

        $status = if ($count -eq 0) { 'Fail' } elseif ($count -lt $dcCount) { 'Warn' } else { 'Pass' }
        $summary = "$count SRV record(s) found for $name (expected >= $dcCount DC(s))."
        return [pscustomobject]@{ Status=$status; Summary=$summary; Raw=($lines -join "`r`n"); Command=$cmd }
    } catch {
        return [pscustomobject]@{ Status='Fail'; Summary="DNS resolution failed: $($_.Exception.Message)"; Raw=$_.Exception.ToString(); Command=$cmd }
    }
}

function Test-Native-SysvolShares {
    param([string]$TargetDC)
    $sysvolPath = "\\$TargetDC\SYSVOL"
    $netlogonPath = "\\$TargetDC\NETLOGON"
    $cmd = "(native) Test-Path $sysvolPath and $netlogonPath"
    try {
        $sysvolOk = Invoke-TimeBoxed -TimeoutSeconds 15 -ScriptBlock { param($p) Test-Path -LiteralPath $p } -Params @{ p = $sysvolPath }
        $netlogonOk = Invoke-TimeBoxed -TimeoutSeconds 15 -ScriptBlock { param($p) Test-Path -LiteralPath $p } -Params @{ p = $netlogonPath }
        $raw = "SYSVOL   ($sysvolPath)   : $(if ($sysvolOk) { 'reachable' } else { 'NOT reachable' })`r`nNETLOGON ($netlogonPath) : $(if ($netlogonOk) { 'reachable' } else { 'NOT reachable' })"
        $status = if ($sysvolOk -and $netlogonOk) { 'Pass' } else { 'Fail' }
        $summary = if ($status -eq 'Pass') { 'SYSVOL and NETLOGON shares are both reachable.' } else { 'One or both of SYSVOL / NETLOGON is not reachable.' }
        return [pscustomobject]@{ Status=$status; Summary=$summary; Raw=$raw; Command=$cmd }
    } catch {
        return [pscustomobject]@{ Status='Error'; Summary=$_.Exception.Message; Raw=$_.Exception.ToString(); Command=$cmd }
    }
}

function Test-Native-TimeSync {
    param([string]$TargetDC, $Options)
    $argList = @('/query', '/status', "/computer:$TargetDC")
    $cmd = "w32tm $($argList -join ' ')"
    $timeout = [Math]::Min([int]$Options.TimeoutSeconds, 30)
    $res = Invoke-ExternalTool -FilePath 'w32tm.exe' -ArgumentList $argList -TimeoutSeconds $timeout

    if ($res.Cancelled) { return [pscustomobject]@{ Status='Info'; Summary='Cancelled by user.'; Raw=$res.Output; Command=$cmd } }
    if ($res.ExitCode -eq -1 -and $res.Error) { return [pscustomobject]@{ Status='Error'; Summary=$res.Error; Raw=$res.Output; Command=$cmd } }

    $out = $res.Output
    if ($res.ExitCode -ne 0 -or -not $out.Trim()) {
        return [pscustomobject]@{ Status='Fail'; Summary='w32tm could not query time status on this DC (RPC/firewall or W32Time service down?).'; Raw=$out; Command=$cmd }
    }

    $src = 'unknown'; $stratum = -1
    if ($out -match '(?im)Source:\s*(.+)') { $src = $Matches[1].Trim() }
    if ($out -match '(?im)Stratum:\s*(\d+)') { $stratum = [int]$Matches[1] }

    $status = 'Pass'; $summary = "Time source '$src', stratum $stratum."
    if ($src -match '(?i)Free-running|Local CMOS') { $status = 'Warn'; $summary = "Time source is '$src' -- not synced to a real source." }
    elseif ($stratum -ge 10 -or $stratum -eq -1) { $status = 'Warn' }

    return [pscustomobject]@{ Status=$status; Summary=$summary; Raw=$out; Command=$cmd }
}

function Test-Native-EventLogs {
    param([string]$TargetDC, $Options)
    $cmd = "(native) Get-WinEvent -ComputerName $TargetDC -LogName 'Directory Service','DNS Server','DFS Replication','System' (last 24h, Critical/Error/Warning)"
    try {
        $events = @(Invoke-TimeBoxed -TimeoutSeconds 25 -ScriptBlock {
            param($cn)
            $logs = 'Directory Service', 'DNS Server', 'DFS Replication', 'System'
            $found = @()
            foreach ($log in $logs) {
                try {
                    $found += Get-WinEvent -ComputerName $cn -FilterHashtable @{ LogName = $log; Level = 1,2,3; StartTime = (Get-Date).AddHours(-24) } -MaxEvents 25 -ErrorAction Stop
                } catch {
                    if ($_.Exception.Message -notmatch 'No events were found') { throw }
                }
            }
            return $found
        } -Params @{ cn = $TargetDC })

        if ($events.Count -eq 0) {
            return [pscustomobject]@{ Status='Pass'; Summary='No Critical/Error/Warning events in the last 24 hours.'; Raw='(none)'; Command=$cmd }
        }
        $crit = @($events | Where-Object { $_.Level -le 2 })
        $lines = $events | Sort-Object TimeCreated -Descending | ForEach-Object {
            $firstMsgLine = (($_.Message -split "`r?`n") | Select-Object -First 1)
            "$($_.TimeCreated)  [$($_.LogName)/$($_.LevelDisplayName)]  Id=$($_.Id)  $($_.ProviderName)  $firstMsgLine"
        }
        $status = if ($crit.Count -gt 0) { 'Fail' } else { 'Warn' }
        $summary = "$($events.Count) event(s) in last 24h ($($crit.Count) Critical/Error)."
        return [pscustomobject]@{ Status=$status; Summary=$summary; Raw=($lines -join "`r`n"); Command=$cmd }
    } catch {
        return [pscustomobject]@{ Status='Error'; Summary=$_.Exception.Message; Raw=$_.Exception.ToString(); Command=$cmd }
    }
}

function Test-Native-PwdPolicy {
    <# Uses a DirectorySearcher rather than DirectoryEntry.Properties to read
       maxPwdAge: it is an Integer8 (64-bit) LDAP attribute, and DirectoryEntry
       hands those back as a COM IADsLargeInteger wrapper (HighPart/LowPart),
       not a plain integer -- casting that straight to [int64] misbehaves.
       DirectorySearcher results marshal Integer8 values as a real Int64. #>
    $cmd = '(native) domain password/lockout policy via LDAP domain object attributes'
    $searcher = $null
    try {
        $rootEntry = $script:Ctx.Domain.GetDirectoryEntry()
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($rootEntry)
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
        $searcher.Filter = '(objectClass=*)'
        foreach ($p in 'minPwdLength','pwdHistoryLength','maxPwdAge','lockoutThreshold','pwdProperties') {
            $null = $searcher.PropertiesToLoad.Add($p)
        }
        $sr = $searcher.FindOne()
        if (-not $sr) { throw 'Domain policy attributes could not be read (empty search result).' }

        $minLen  = [int]$sr.Properties['minpwdlength'][0]
        $histLen = [int]$sr.Properties['pwdhistorylength'][0]
        $maxAgeTicks = [int64]$sr.Properties['maxpwdage'][0]
        $lockoutThreshold = [int]$sr.Properties['lockoutthreshold'][0]
        $pwdProps = [int]$sr.Properties['pwdproperties'][0]
        $complexity = (($pwdProps -band 1) -ne 0)
        $maxAgeDays = if ($maxAgeTicks -eq 0) { 0 } else { [Math]::Round((-$maxAgeTicks) / 864000000000, 1) }

        $lines = @(
            "Minimum password length   : $minLen"
            "Password history          : $histLen remembered"
            "Maximum password age      : $(if ($maxAgeDays -eq 0) { 'Never expires' } else { "$maxAgeDays days" })"
            "Complexity requirements   : $(if ($complexity) { 'Enabled' } else { 'DISABLED' })"
            "Account lockout threshold : $(if ($lockoutThreshold -eq 0) { 'Disabled (no lockout)' } else { "$lockoutThreshold attempts" })"
        )
        $warn = New-Object System.Collections.Generic.List[string]
        if (-not $complexity) { $warn.Add('complexity disabled') }
        if ($lockoutThreshold -eq 0) { $warn.Add('no account lockout') }
        if ($maxAgeDays -eq 0) { $warn.Add('passwords never expire') }

        $status = if ($warn.Count -gt 0) { 'Warn' } else { 'Pass' }
        $summary = if ($warn.Count -gt 0) { "Baseline policy concerns: $($warn -join ', '). Check for Fine-Grained Password Policies (PSOs) that may override this." } else { 'Baseline domain password policy looks reasonable.' }
        return [pscustomobject]@{ Status=$status; Summary=$summary; Raw=($lines -join "`r`n"); Command=$cmd }
    } catch {
        return [pscustomobject]@{ Status='Error'; Summary=$_.Exception.Message; Raw=$_.Exception.ToString(); Command=$cmd }
    } finally {
        if ($searcher) { $searcher.Dispose() }
    }
}

function Test-Native-Tombstone {
    $cmd = '(native) tombstoneLifetime on CN=Directory Service,CN=Windows NT,CN=Services,<Configuration NC>'
    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        $configNC = Get-FirstProp $rootDse 'configurationNamingContext'
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$configNC")
        $val = Get-FirstProp $entry 'tombstoneLifetime'
        $days = if ($null -ne $val) { [int]$val } else { 60 }
        $raw = "tombstoneLifetime attribute : $(if ($null -ne $val) { $val } else { '(not set -- AD default of 60 days applies)' })`r`nEffective tombstone lifetime : $days day(s)"
        $status = if ($days -lt 60) { 'Warn' } else { 'Pass' }
        return [pscustomobject]@{ Status=$status; Summary="Effective tombstone lifetime: $days day(s)."; Raw=$raw; Command=$cmd }
    } catch {
        return [pscustomobject]@{ Status='Error'; Summary=$_.Exception.Message; Raw=$_.Exception.ToString(); Command=$cmd }
    }
}

function Test-Native-RecycleBin {
    $cmd = '(native) msDS-EnabledFeature on CN=Partitions vs the Recycle Bin optional feature'
    try {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
        $configNC = Get-FirstProp $rootDse 'configurationNamingContext'
        $partitions = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Partitions,$configNC")
        $enabled = @()
        if ($partitions.Properties.Contains('msDS-EnabledFeature')) { $enabled = @($partitions.Properties['msDS-EnabledFeature']) }
        $isEnabled = $enabled | Where-Object { $_ -match '(?i)CN=Recycle Bin Feature' }
        $status = if ($isEnabled) { 'Pass' } else { 'Warn' }
        $summary = if ($isEnabled) { 'AD Recycle Bin is enabled.' } else { 'AD Recycle Bin is NOT enabled -- accidental object deletions cannot be easily restored.' }
        $raw = if ($enabled.Count -gt 0) { "Enabled optional features:`r`n" + ($enabled -join "`r`n") } else { '(no optional features enabled)' }
        return [pscustomobject]@{ Status=$status; Summary=$summary; Raw=$raw; Command=$cmd }
    } catch {
        return [pscustomobject]@{ Status='Error'; Summary=$_.Exception.Message; Raw=$_.Exception.ToString(); Command=$cmd }
    }
}

function Invoke-NativeTest {
    param($TestDef, [string]$TargetDC, $Options)
    switch ($TestDef.Action) {
        'FSMO'         { return Test-Native-FSMO }
        'DCInventory'  { return Test-Native-DCInventory }
        'DnsSrv'       { return Test-Native-DnsSrv }
        'SysvolShares' { return Test-Native-SysvolShares -TargetDC $TargetDC }
        'TimeSync'     { return Test-Native-TimeSync -TargetDC $TargetDC -Options $Options }
        'EventLogs'    { return Test-Native-EventLogs -TargetDC $TargetDC -Options $Options }
        'PwdPolicy'    { return Test-Native-PwdPolicy }
        'Tombstone'    { return Test-Native-Tombstone }
        'RecycleBin'   { return Test-Native-RecycleBin }
        default        { throw "Unknown native action '$($TestDef.Action)'." }
    }
}

function Invoke-DiagnosticTest {
    param($TestDef, [string]$TargetDC, $Options)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'Error'; $summary = ''; $raw = ''; $cmdText = ''
    try {
        $r = switch ($TestDef.Tool) {
            'dcdiag'   { Invoke-DcDiagTest   -TestDef $TestDef -TargetDC $TargetDC -Options $Options }
            'repadmin' { Invoke-RepadminTest -TestDef $TestDef -TargetDC $TargetDC -Options $Options }
            'nltest'   { Invoke-NltestTest   -TestDef $TestDef -TargetDC $TargetDC -Options $Options }
            'native'   { Invoke-NativeTest   -TestDef $TestDef -TargetDC $TargetDC -Options $Options }
            default    { throw "Unknown tool '$($TestDef.Tool)'." }
        }
        $status = $r.Status; $summary = $r.Summary; $raw = $r.Raw; $cmdText = $r.Command
    } catch {
        if ($_.Exception.Message -eq 'Cancelled by user.') { $status = 'Info'; $summary = 'Cancelled by user.' }
        else { $status = 'Error'; $summary = $_.Exception.Message }
        $raw = $_.Exception.ToString()
    }
    $sw.Stop()
    return [pscustomobject]@{
        Category = $TestDef.Category
        Test     = $TestDef.Label
        Target   = $(if ($TargetDC) { $TargetDC } else { '(domain)' })
        Status   = $status
        Summary  = $summary
        Duration = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        Raw      = $raw
        Command  = $cmdText
    }
}

function Write-ErrorLog {
    <#
        Appends a full error record to the log file so anything shown in a dialog
        is also captured on disk with its type, message, source position and
        stack trace. Falls back to the temp folder if the log field is blank.
        Never throws.
    #>
    param(
        [Parameter(Mandatory)][string]$Context,
        $ErrorRecord,
        [string]$Message
    )

    $path = ''
    try { $path = $txtLog.Text.Trim() } catch { }
    if (-not $path) { $path = Join-Path ([System.IO.Path]::GetTempPath()) 'ADDiagnosticTool.log' }

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine("**ERROR--$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $null = $sb.AppendLine("Context=$Context")
    if ($Message) { $null = $sb.AppendLine("Message=$Message") }
    if ($ErrorRecord) {
        $ex = $ErrorRecord.Exception
        if ($ex) {
            $null = $sb.AppendLine("Type=$($ex.GetType().FullName)")
            if (-not $Message) { $null = $sb.AppendLine("Message=$($ex.Message)") }
            if ($ex.InnerException) {
                $null = $sb.AppendLine("Inner=$($ex.InnerException.GetType().FullName): $($ex.InnerException.Message)")
            }
        }
        if ($ErrorRecord.InvocationInfo -and $ErrorRecord.InvocationInfo.PositionMessage) {
            $null = $sb.AppendLine("Position=$($ErrorRecord.InvocationInfo.PositionMessage)")
        }
        if ($ErrorRecord.ScriptStackTrace) {
            $null = $sb.AppendLine("StackTrace=$($ErrorRecord.ScriptStackTrace)")
        }
    }
    $null = $sb.AppendLine("RunAs=$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")

    try { Add-Content -LiteralPath $path -Value $sb.ToString() -Encoding UTF8 }
    catch { Write-Warning "Error-log write failed: $($_.Exception.Message)" }
}

function Write-DiagLog {
    param([string]$Path, $Result)
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine("**RESULT--$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $null = $sb.AppendLine("Category=$($Result.Category)")
    $null = $sb.AppendLine("Test=$($Result.Test)")
    $null = $sb.AppendLine("Target=$($Result.Target)")
    $null = $sb.AppendLine("Status=$($Result.Status)")
    $null = $sb.AppendLine("Summary=$($Result.Summary)")
    $null = $sb.AppendLine("Command=$($Result.Command)")
    try { Add-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8 } catch { }
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;')
}

function Export-HtmlReport {
    param([string]$Path)

    $domainName = if ($script:Ctx.Domain) { $script:Ctx.Domain.Name } else { 'Unknown' }
    $forestName = if ($script:Ctx.Forest) { $script:Ctx.Forest.Name } else { 'Unknown' }
    $generated  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $total = $script:Results.Count
    $pass  = @($script:Results | Where-Object { $_.Status -eq 'Pass' }).Count
    $warn  = @($script:Results | Where-Object { $_.Status -eq 'Warn' }).Count
    $fail  = @($script:Results | Where-Object { $_.Status -eq 'Fail' }).Count
    $err   = @($script:Results | Where-Object { $_.Status -eq 'Error' }).Count

    $css = @'
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:0;background:#f4f5f7;color:#222}
header{background:#0a2f5c;color:#fff;padding:20px 30px}
header h1{margin:0;font-size:22px}
header p{margin:4px 0 0;font-size:13px;color:#cfe0f5}
.wrap{padding:20px 30px}
.summary{display:flex;gap:14px;margin-bottom:24px;flex-wrap:wrap}
.card{background:#fff;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,.15);padding:14px 20px;min-width:110px;text-align:center}
.card .n{font-size:26px;font-weight:700}
.card .l{font-size:12px;color:#666;text-transform:uppercase}
.c-pass{color:#0a8a3f}.c-warn{color:#c07a00}.c-fail{color:#c0392b}.c-err{color:#c0392b}
h2{border-bottom:2px solid #0a2f5c;padding-bottom:4px;margin-top:32px;font-size:18px;color:#0a2f5c}
table{width:100%;border-collapse:collapse;background:#fff;margin-top:8px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e2e2e2;font-size:13px;vertical-align:top}
th{background:#eef2f7;font-size:12px;text-transform:uppercase;color:#444}
.badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:600;color:#fff;white-space:nowrap}
.b-pass{background:#0a8a3f}.b-warn{background:#c07a00}.b-fail{background:#c0392b}.b-err{background:#c0392b}.b-info{background:#777}
details summary{cursor:pointer;color:#0a2f5c;font-size:12px;margin-top:4px}
pre{white-space:pre-wrap;word-break:break-word;background:#f8f9fb;border:1px solid #e2e2e2;padding:8px;margin:6px 0 0;font-size:12px;max-height:320px;overflow:auto}
footer{padding:20px 30px;color:#888;font-size:12px}
'@

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8">')
    $null = $sb.AppendLine("<title>AD Diagnostic Report - $(ConvertTo-HtmlSafe $domainName)</title>")
    $null = $sb.AppendLine("<style>$css</style></head><body>")
    $null = $sb.AppendLine('<header><h1>Active Directory Diagnostic Report</h1>')
    $null = $sb.AppendLine("<p>Domain: $(ConvertTo-HtmlSafe $domainName) &nbsp;|&nbsp; Forest: $(ConvertTo-HtmlSafe $forestName) &nbsp;|&nbsp; Generated: $generated</p></header>")
    $null = $sb.AppendLine('<div class="wrap">')
    $null = $sb.AppendLine('<div class="summary">')
    $null = $sb.AppendLine("<div class='card'><div class='n'>$total</div><div class='l'>Total</div></div>")
    $null = $sb.AppendLine("<div class='card'><div class='n c-pass'>$pass</div><div class='l'>Pass</div></div>")
    $null = $sb.AppendLine("<div class='card'><div class='n c-warn'>$warn</div><div class='l'>Warn</div></div>")
    $null = $sb.AppendLine("<div class='card'><div class='n c-fail'>$fail</div><div class='l'>Fail</div></div>")
    $null = $sb.AppendLine("<div class='card'><div class='n c-err'>$err</div><div class='l'>Error</div></div>")
    $null = $sb.AppendLine('</div>')

    foreach ($cat in ($script:Results | Group-Object Category)) {
        $null = $sb.AppendLine("<h2>$(ConvertTo-HtmlSafe $cat.Name)</h2>")
        $null = $sb.AppendLine('<table><tr><th>Test</th><th>Target</th><th>Status</th><th>Summary</th><th>Duration</th></tr>')
        foreach ($r in $cat.Group) {
            $badgeClass = switch ($r.Status) { 'Pass' {'b-pass'} 'Warn' {'b-warn'} 'Fail' {'b-fail'} 'Error' {'b-err'} default {'b-info'} }
            $null = $sb.AppendLine('<tr>')
            $null = $sb.AppendLine("<td>$(ConvertTo-HtmlSafe $r.Test)</td>")
            $null = $sb.AppendLine("<td>$(ConvertTo-HtmlSafe $r.Target)</td>")
            $null = $sb.AppendLine("<td><span class='badge $badgeClass'>$($r.Status)</span></td>")
            $rawBlock = "$(ConvertTo-HtmlSafe $r.Command)`r`n`r`n$(ConvertTo-HtmlSafe $r.Raw)"
            $null = $sb.AppendLine("<td>$(ConvertTo-HtmlSafe $r.Summary)<details><summary>Command / raw output</summary><pre>$rawBlock</pre></details></td>")
            $null = $sb.AppendLine("<td>$($r.Duration)s</td>")
            $null = $sb.AppendLine('</tr>')
        }
        $null = $sb.AppendLine('</table>')
    }

    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine('<footer>Generated by AD Diagnostic Toolkit &mdash; m365admintools.com &mdash; Status is a heuristic based on tool exit codes and known output patterns. Always corroborate with the raw output before taking action.</footer>')
    $null = $sb.AppendLine('</body></html>')

    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8
}

# ===========================================================================
# UI
# ===========================================================================

$form               = New-Object System.Windows.Forms.Form
$form.Text          = 'AD Diagnostic Toolkit 1.0.2  (build 2026-08-06)'
$form.StartPosition = 'CenterScreen'
$form.Font          = New-Object System.Drawing.Font('Segoe UI', 9)
$form.MinimumSize   = New-Object System.Drawing.Size(620, 340)
$form.FormBorderStyle = 'Sizable'
$form.MaximizeBox   = $true
$form.KeyPreview    = $true
$form.AutoScaleMode = 'None'

$fTitle = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
$fBold  = New-Object System.Drawing.Font('Segoe UI', 9,  [System.Drawing.FontStyle]::Bold)
$fSmall = New-Object System.Drawing.Font('Segoe UI', 8)
$fMono  = New-Object System.Drawing.Font('Consolas', 9)
$cBlue   = [System.Drawing.Color]::FromArgb(0,0,190)
$cRed    = [System.Drawing.Color]::FromArgb(190,0,0)
$cGreen  = [System.Drawing.Color]::FromArgb(0,120,0)
$cOrange = [System.Drawing.Color]::FromArgb(190,120,0)
$cGray   = [System.Drawing.Color]::FromArgb(110,110,110)

function New-Lbl {
    param($Text,$X,$Y,$W=120,$H=18,$Font=$null,$Color=$null)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.Location = New-Object System.Drawing.Point($X,$Y)
    $l.Size = New-Object System.Drawing.Size($W,$H)
    if ($Font)  { $l.Font = $Font }
    if ($Color) { $l.ForeColor = $Color }
    return $l
}

$tbl = New-Object System.Windows.Forms.TableLayoutPanel
$tbl.Dock = 'Fill'
$tbl.ColumnCount = 1
$tbl.RowCount = 2
$null = $tbl.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$null = $tbl.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$null = $tbl.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 118)))
$form.Controls.Add($tbl)

$pnlMain = New-Object System.Windows.Forms.Panel
$pnlMain.Dock = 'Fill'
$pnlMain.AutoScroll = $true
$tbl.Controls.Add($pnlMain, 0, 0)

$pnlBottom = New-Object System.Windows.Forms.Panel
$pnlBottom.Dock = 'Fill'
$tbl.Controls.Add($pnlBottom, 0, 1)

# --- Header ---

$pnlMain.Controls.Add((New-Lbl 'Active Directory Diagnostic Toolkit' 12 1 500 26 $fTitle))
$lnkSite = New-Object System.Windows.Forms.LinkLabel
$lnkSite.Text             = 'Charles Arconi  |  m365admintools.com'
$lnkSite.Location         = New-Object System.Drawing.Point(12,25)
$lnkSite.Size             = New-Object System.Drawing.Size(378,16)
$lnkSite.Font             = $fSmall
$lnkSite.ForeColor        = $cGray
$lnkSite.LinkColor        = $cBlue
$lnkSite.ActiveLinkColor  = $cBlue
$lnkSite.VisitedLinkColor = $cBlue
$lnkSite.LinkBehavior     = [System.Windows.Forms.LinkBehavior]::HoverUnderline
$lnkSite.AutoSize         = $false

$siteLinkText = 'm365admintools.com'
$lnkSite.LinkArea = New-Object System.Windows.Forms.LinkArea(
    $lnkSite.Text.IndexOf($siteLinkText), $siteLinkText.Length)

$lnkSite.Add_LinkClicked({
    try {
        $lnkSite.LinkVisited = $true
        Start-Process 'https://m365admintools.com'
    } catch {
        Write-ErrorLog -Context 'Open m365admintools.com link' -ErrorRecord $_
        Set-Status "Could not open browser: $($_.Exception.Message)"
    }
})
$pnlMain.Controls.Add($lnkSite)

# --- 1. Target ---
$grpTarget = New-Object System.Windows.Forms.GroupBox
$grpTarget.Text = ' 1. Target '
$grpTarget.ForeColor = $cBlue
$grpTarget.Location = New-Object System.Drawing.Point(12,52)
$grpTarget.Size = New-Object System.Drawing.Size(936,80)
$pnlMain.Controls.Add($grpTarget)

$grpTarget.Controls.Add((New-Lbl 'Domain' 12 25 54))
$txtDomain = New-Object System.Windows.Forms.TextBox
$txtDomain.Location = New-Object System.Drawing.Point(66,22)
$txtDomain.Size = New-Object System.Drawing.Size(240,22)
$txtDomain.ReadOnly = $true
$txtDomain.ForeColor = $cBlue
$grpTarget.Controls.Add($txtDomain)

$grpTarget.Controls.Add((New-Lbl 'Bind target' 320 25 68))
$txtBindTarget = New-Object System.Windows.Forms.TextBox
$txtBindTarget.Location = New-Object System.Drawing.Point(392,22)
$txtBindTarget.Size = New-Object System.Drawing.Size(258,22)
$txtBindTarget.ReadOnly = $true
$grpTarget.Controls.Add($txtBindTarget)

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = 'Connect / Change...'
$btnConnect.Location = New-Object System.Drawing.Point(662,21)
$btnConnect.Size = New-Object System.Drawing.Size(140,24)
$grpTarget.Controls.Add($btnConnect)

$lblConnInfo = New-Lbl '' 12 55 900 16 $fSmall $cGray
$grpTarget.Controls.Add($lblConnInfo)

# --- 2. Domain Controllers ---
$grpDCs = New-Object System.Windows.Forms.GroupBox
$grpDCs.Text = ' 2. Domain Controllers in Scope '
$grpDCs.ForeColor = $cBlue
$grpDCs.Location = New-Object System.Drawing.Point(12,140)
$grpDCs.Size = New-Object System.Drawing.Size(936,140)
$pnlMain.Controls.Add($grpDCs)

$clbTargets = New-Object System.Windows.Forms.CheckedListBox
$clbTargets.Location = New-Object System.Drawing.Point(10,20)
$clbTargets.Size = New-Object System.Drawing.Size(700,108)
$clbTargets.CheckOnClick = $true
$clbTargets.IntegralHeight = $false
$grpDCs.Controls.Add($clbTargets)

$btnDcAll = New-Object System.Windows.Forms.Button
$btnDcAll.Text = 'All'
$btnDcAll.Location = New-Object System.Drawing.Point(720,20)
$btnDcAll.Size = New-Object System.Drawing.Size(80,24)
$grpDCs.Controls.Add($btnDcAll)

$btnDcNone = New-Object System.Windows.Forms.Button
$btnDcNone.Text = 'None'
$btnDcNone.Location = New-Object System.Drawing.Point(720,50)
$btnDcNone.Size = New-Object System.Drawing.Size(80,24)
$grpDCs.Controls.Add($btnDcNone)

$lblDcCount = New-Lbl '' 720 82 200 16 $fSmall $cGray
$grpDCs.Controls.Add($lblDcCount)

$grpDCs.Controls.Add((New-Lbl 'Per-DC tests (DCDiag, ShowRepl, Netlogon checks, ...) run once for each checked DC. Domain-wide tests (FSMO, Replication Summary, Trusts, ...) run once regardless of how many are checked.' 10 112 916 24 $fSmall $cGray))

# --- 3. Diagnostic Tests ---
$grpTests = New-Object System.Windows.Forms.GroupBox
$grpTests.Text = ' 3. Diagnostic Tests '
$grpTests.ForeColor = $cBlue
$grpTests.Location = New-Object System.Drawing.Point(12,288)
$grpTests.Size = New-Object System.Drawing.Size(936,300)
$pnlMain.Controls.Add($grpTests)

$treeTests = New-Object System.Windows.Forms.TreeView
$treeTests.Location = New-Object System.Drawing.Point(10,20)
$treeTests.Size = New-Object System.Drawing.Size(578,232)
$treeTests.CheckBoxes = $true
$grpTests.Controls.Add($treeTests)

$grpTests.Controls.Add((New-Lbl "'Recalculate Topology (KCC)' (in red) forces the KCC to recompute replication topology -- not purely read-only. Left unchecked by default." 10 258 578 34 $fSmall $cRed))

$btnPresetQuick = New-Object System.Windows.Forms.Button
$btnPresetQuick.Text = 'Quick Health Check'
$btnPresetQuick.Location = New-Object System.Drawing.Point(602,20)
$btnPresetQuick.Size = New-Object System.Drawing.Size(324,26)
$grpTests.Controls.Add($btnPresetQuick)

$btnPresetFull = New-Object System.Windows.Forms.Button
$btnPresetFull.Text = 'Select All'
$btnPresetFull.Location = New-Object System.Drawing.Point(602,50)
$btnPresetFull.Size = New-Object System.Drawing.Size(158,26)
$grpTests.Controls.Add($btnPresetFull)

$btnPresetNone = New-Object System.Windows.Forms.Button
$btnPresetNone.Text = 'Select None'
$btnPresetNone.Location = New-Object System.Drawing.Point(768,50)
$btnPresetNone.Size = New-Object System.Drawing.Size(158,26)
$grpTests.Controls.Add($btnPresetNone)

$grpRunOpts = New-Object System.Windows.Forms.GroupBox
$grpRunOpts.Text = ' Run options '
$grpRunOpts.Location = New-Object System.Drawing.Point(602,88)
$grpRunOpts.Size = New-Object System.Drawing.Size(324,164)
$grpTests.Controls.Add($grpRunOpts)

$chkVerbose = New-Object System.Windows.Forms.CheckBox
$chkVerbose.Text = 'Verbose DCDiag output (/v)'
$chkVerbose.Location = New-Object System.Drawing.Point(12,24)
$chkVerbose.Size = New-Object System.Drawing.Size(280,22)
$grpRunOpts.Controls.Add($chkVerbose)

$chkDeepDns = New-Object System.Windows.Forms.CheckBox
$chkDeepDns.Text = 'Deep DNS analysis (/DnsAll, slow)'
$chkDeepDns.Location = New-Object System.Drawing.Point(12,50)
$chkDeepDns.Size = New-Object System.Drawing.Size(280,22)
$grpRunOpts.Controls.Add($chkDeepDns)

$grpRunOpts.Controls.Add((New-Lbl 'Per-test timeout (seconds)' 12 82 200 18))
$numTimeout = New-Object System.Windows.Forms.NumericUpDown
$numTimeout.Location = New-Object System.Drawing.Point(12,102)
$numTimeout.Size = New-Object System.Drawing.Size(80,22)
$numTimeout.Minimum = 15
$numTimeout.Maximum = 600
$numTimeout.Increment = 15
$numTimeout.Value = 120
$grpRunOpts.Controls.Add($numTimeout)

$grpRunOpts.Controls.Add((New-Lbl 'Status is a heuristic (exit code + text patterns). Always review the raw output for the real story.' 12 130 300 30 $fSmall $cGray))

# --- 4. Results ---
$grpResults = New-Object System.Windows.Forms.GroupBox
$grpResults.Text = ' 4. Results '
$grpResults.ForeColor = $cBlue
$grpResults.Location = New-Object System.Drawing.Point(12,596)
$grpResults.Size = New-Object System.Drawing.Size(936,220)
$pnlMain.Controls.Add($grpResults)

$lvResults = New-Object System.Windows.Forms.ListView
$lvResults.Location = New-Object System.Drawing.Point(10,20)
$lvResults.Size = New-Object System.Drawing.Size(916,164)
$lvResults.View = 'Details'
$lvResults.FullRowSelect = $true
$lvResults.GridLines = $true
$null = $lvResults.Columns.Add('Category', 110)
$null = $lvResults.Columns.Add('Test',     190)
$null = $lvResults.Columns.Add('Target',   120)
$null = $lvResults.Columns.Add('Status',    70)
$null = $lvResults.Columns.Add('Summary',  350)
$null = $lvResults.Columns.Add('Sec',       60)
$grpResults.Controls.Add($lvResults)

$lblSummary = New-Lbl '' 10 190 916 20 $fBold
$grpResults.Controls.Add($lblSummary)

# --- 5. Details ---
$grpDetail = New-Object System.Windows.Forms.GroupBox
$grpDetail.Text = ' 5. Details (select a result row above) '
$grpDetail.ForeColor = $cBlue
$grpDetail.Location = New-Object System.Drawing.Point(12,824)
$grpDetail.Size = New-Object System.Drawing.Size(936,160)
$pnlMain.Controls.Add($grpDetail)

$txtDetail = New-Object System.Windows.Forms.TextBox
$txtDetail.Location = New-Object System.Drawing.Point(10,20)
$txtDetail.Size = New-Object System.Drawing.Size(916,130)
$txtDetail.Multiline = $true
$txtDetail.ReadOnly = $true
$txtDetail.ScrollBars = 'Vertical'
$txtDetail.Font = $fMono
$grpDetail.Controls.Add($txtDetail)

# --- Action bar contents ---
$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(12,4)
$progress.Size = New-Object System.Drawing.Size(936,12)
$progress.Anchor = 'Top,Left,Right'
$pnlBottom.Controls.Add($progress)

$pnlBottom.Controls.Add((New-Lbl 'Log' 12 24 26 16 $fSmall))
$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Location = New-Object System.Drawing.Point(42,21)
$txtLog.Size = New-Object System.Drawing.Size(380,22)
$txtLog.Anchor = 'Top,Left'
$txtLog.Text = Join-Path $env:USERPROFILE 'Documents\ADDiagnosticTool.log'
$pnlBottom.Controls.Add($txtLog)

$btnOpenLog = New-Object System.Windows.Forms.Button
$btnOpenLog.Text = 'Open'
$btnOpenLog.Location = New-Object System.Drawing.Point(428,20)
$btnOpenLog.Size = New-Object System.Drawing.Size(58,24)
$btnOpenLog.Anchor = 'Top,Left'
$pnlBottom.Controls.Add($btnOpenLog)

$lblStatus = New-Lbl 'Ready' 12 48 700 16 $fSmall
$lblStatus.Anchor = 'Top,Left,Right'
$pnlBottom.Controls.Add($lblStatus)

$flowBtn = New-Object System.Windows.Forms.FlowLayoutPanel
$flowBtn.Dock = 'Bottom'
$flowBtn.Height = 56
$flowBtn.FlowDirection = 'RightToLeft'
$flowBtn.WrapContents = $true
$flowBtn.Padding = New-Object System.Windows.Forms.Padding(8,6,10,6)
$pnlBottom.Controls.Add($flowBtn)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = 'Close'
$btnClose.Size = New-Object System.Drawing.Size(86,28)
$flowBtn.Controls.Add($btnClose)

$btnExportHtml = New-Object System.Windows.Forms.Button
$btnExportHtml.Text = 'Export HTML Report  (F8)'
$btnExportHtml.Size = New-Object System.Drawing.Size(168,28)
$flowBtn.Controls.Add($btnExportHtml)

$btnExportCsv = New-Object System.Windows.Forms.Button
$btnExportCsv.Text = 'Export CSV  (F7)'
$btnExportCsv.Size = New-Object System.Drawing.Size(120,28)
$flowBtn.Controls.Add($btnExportCsv)

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = 'Cancel  (F6)'
$btnCancel.Size = New-Object System.Drawing.Size(104,28)
$btnCancel.ForeColor = $cRed
$btnCancel.Enabled = $false
$flowBtn.Controls.Add($btnCancel)

$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = 'RUN DIAGNOSTICS  (F5)'
$btnRun.Size = New-Object System.Drawing.Size(168,28)
$btnRun.Font = $fBold
$btnRun.ForeColor = $cBlue
$flowBtn.Controls.Add($btnRun)

# --- Size the window to fit the screen it opens on ---
$designW = 1000
$designH = 820
try {
    $wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $w = [Math]::Min($designW, [Math]::Max(620, $wa.Width  - 40))
    $h = [Math]::Min($designH, [Math]::Max(340, $wa.Height - 40))
} catch {
    $w = $designW; $h = $designH
}
$form.Size = New-Object System.Drawing.Size($w, $h)

$form.Add_Shown({
    try {
        $sc = [System.Windows.Forms.Screen]::FromControl($form).WorkingArea
        $nw = [Math]::Min($form.Width,  [Math]::Max(620, $sc.Width  - 40))
        $nh = [Math]::Min($form.Height, [Math]::Max(340, $sc.Height - 40))
        if ($nw -ne $form.Width -or $nh -ne $form.Height) { $form.Size = New-Object System.Drawing.Size($nw, $nh) }
        if ($form.Left -lt $sc.Left) { $form.Left = $sc.Left + 10 }
        if ($form.Top  -lt $sc.Top)  { $form.Top  = $sc.Top  + 10 }
    } catch { }
})

# ===========================================================================
# UI helpers
# ===========================================================================

function Set-Status {
    param([string]$Text)
    $lblStatus.Text = $Text
    [System.Windows.Forms.Application]::DoEvents()
}

function Build-TestTree {
    $treeTests.BeginUpdate()
    $treeTests.Nodes.Clear()
    foreach ($cat in ($script:TestCatalog | Group-Object Category)) {
        $catNode = New-Object System.Windows.Forms.TreeNode($cat.Name)
        $catNode.Tag = $null
        foreach ($t in $cat.Group) {
            $leaf = New-Object System.Windows.Forms.TreeNode($t.Label)
            $leaf.Tag = $t.Id
            $leaf.Checked = [bool]$t.Default
            if ($t.Caution) { $leaf.ForeColor = $cRed }
            $null = $catNode.Nodes.Add($leaf)
        }
        $catNode.Checked = (@($catNode.Nodes | Where-Object { -not $_.Checked })).Count -eq 0
        $null = $treeTests.Nodes.Add($catNode)
        $catNode.Expand()
    }
    $treeTests.EndUpdate()
}

$treeTests.Add_AfterCheck({
    param($sender,$e)
    if ($script:SuppressChecks) { return }
    $script:SuppressChecks = $true
    try {
        if ($e.Node.Nodes.Count -gt 0) {
            foreach ($child in $e.Node.Nodes) { $child.Checked = $e.Node.Checked }
        } else {
            $parent = $e.Node.Parent
            if ($parent) { $parent.Checked = (@($parent.Nodes | Where-Object { -not $_.Checked })).Count -eq 0 }
        }
    } finally { $script:SuppressChecks = $false }
})

function Set-TestChecks {
    param([scriptblock]$Predicate)
    $script:SuppressChecks = $true
    try {
        foreach ($catNode in $treeTests.Nodes) {
            foreach ($leaf in $catNode.Nodes) {
                $t = $script:TestCatalog | Where-Object { $_.Id -eq [string]$leaf.Tag } | Select-Object -First 1
                $leaf.Checked = [bool](& $Predicate $t)
            }
            $catNode.Checked = (@($catNode.Nodes | Where-Object { -not $_.Checked })).Count -eq 0
        }
    } finally { $script:SuppressChecks = $false }
}

function Get-SelectedTestDefs {
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($catNode in $treeTests.Nodes) {
        foreach ($leaf in $catNode.Nodes) {
            if ($leaf.Checked) { $ids.Add([string]$leaf.Tag) }
        }
    }
    return @($script:TestCatalog | Where-Object { $ids -contains $_.Id })
}

function Get-SelectedTargets {
    return @($clbTargets.CheckedItems | ForEach-Object { [string]$_ })
}

function Add-ResultRow {
    param($r)
    $it = New-Object System.Windows.Forms.ListViewItem($r.Category)
    $null = $it.SubItems.Add($r.Test)
    $null = $it.SubItems.Add($r.Target)
    $null = $it.SubItems.Add($r.Status)
    $null = $it.SubItems.Add($r.Summary)
    $null = $it.SubItems.Add([string]$r.Duration)
    $it.Tag = $r
    switch ($r.Status) {
        'Fail'  { $it.ForeColor = $cRed }
        'Error' { $it.ForeColor = $cRed; $it.Font = $fBold }
        'Warn'  { $it.ForeColor = $cOrange }
        'Pass'  { $it.ForeColor = $cGreen }
        default { $it.ForeColor = $cGray }
    }
    $null = $lvResults.Items.Add($it)
    $it.EnsureVisible()
}

function Initialize-Session {
    param([string]$TargetServer)
    try {
        Set-Status 'Connecting to Active Directory ...'
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        Connect-Environment -TargetServer $TargetServer
        $txtDomain.Text = $script:Ctx.Domain.Name
        $txtBindTarget.Text = if ($TargetServer) { $TargetServer } else { '(current domain context)' }
        $clbTargets.Items.Clear()
        foreach ($dc in $script:Ctx.DomainControllers) { $null = $clbTargets.Items.Add($dc.Name, $true) }
        $lblDcCount.Text = "$($script:Ctx.DomainControllers.Count) DC(s)"
        $lblConnInfo.Text = "Forest: $($script:Ctx.Forest.Name)   |   Domain: $($script:Ctx.Domain.Name)   |   Trusts: $($script:Ctx.Trusts.Count)"
        Set-Status "Connected. $($script:Ctx.DomainControllers.Count) domain controller(s) found."
    } catch {
        Set-Status "Connect failed: $($_.Exception.Message)"
        Write-ErrorLog -Context 'Initialize-Session (connect)' -ErrorRecord $_
        [System.Windows.Forms.MessageBox]::Show("Could not connect to Active Directory.`r`n`r`n$($_.Exception.Message)",'Not connected','OK','Warning') | Out-Null
    } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

# ===========================================================================
# Events
# ===========================================================================

$btnDcAll.Add_Click({ for ($i=0; $i -lt $clbTargets.Items.Count; $i++) { $clbTargets.SetItemChecked($i,$true) } })
$btnDcNone.Add_Click({ for ($i=0; $i -lt $clbTargets.Items.Count; $i++) { $clbTargets.SetItemChecked($i,$false) } })

$btnPresetQuick.Add_Click({ Set-TestChecks -Predicate { param($t) [bool]$t.Default } })
$btnPresetFull.Add_Click({ Set-TestChecks -Predicate { $true } })
$btnPresetNone.Add_Click({ Set-TestChecks -Predicate { $false } })

$btnConnect.Add_Click({
    $s = [Microsoft.VisualBasic.Interaction]::InputBox('Domain controller name or DNS domain name to bind to (blank = current domain context):','Connect', [string]$script:Ctx.BindServer)
    Initialize-Session -TargetServer $s.Trim()
})

$btnOpenLog.Add_Click({
    $p = $txtLog.Text
    if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType File -Path $p -Force | Out-Null }
    Start-Process notepad.exe -ArgumentList $p
})

$btnClose.Add_Click({ $form.Close() })

$lvResults.Add_SelectedIndexChanged({
    if ($lvResults.SelectedItems.Count -eq 0) { return }
    $r = $lvResults.SelectedItems[0].Tag
    if ($r) {
        $txtDetail.Text = "Command : $($r.Command)`r`nTarget  : $($r.Target)`r`nStatus  : $($r.Status)`r`nSummary : $($r.Summary)`r`nDuration: $($r.Duration)s`r`n`r`n--- Raw output ---`r`n$($r.Raw)"
    }
})

$btnExportCsv.Add_Click({
    if ($script:Results.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Run diagnostics first.','Export','OK','Information') | Out-Null
        return
    }
    $d = New-Object System.Windows.Forms.SaveFileDialog
    $d.Filter = 'CSV (*.csv)|*.csv'
    $d.FileName = "ADDiag-$($script:Ctx.Domain.Name)-$(Get-Date -Format yyyyMMdd-HHmmss).csv"
    if ($d.ShowDialog() -eq 'OK') {
        try {
            $script:Results | Select-Object Category,Test,Target,Status,Summary,Duration,Command,Raw |
                Export-Csv -LiteralPath $d.FileName -NoTypeInformation -Encoding UTF8
            Set-Status "Exported $($script:Results.Count) row(s) to CSV."
        } catch {
            Write-ErrorLog -Context 'Export CSV' -ErrorRecord $_
            Set-Status "CSV export failed: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Export failed','OK','Error') | Out-Null
        }
    }
})

$btnExportHtml.Add_Click({
    if ($script:Results.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Run diagnostics first.','Export','OK','Information') | Out-Null
        return
    }
    $d = New-Object System.Windows.Forms.SaveFileDialog
    $d.Filter = 'HTML report (*.html)|*.html'
    $d.FileName = "ADDiag-$($script:Ctx.Domain.Name)-$(Get-Date -Format yyyyMMdd-HHmmss).html"
    if ($d.ShowDialog() -eq 'OK') {
        try {
            Export-HtmlReport -Path $d.FileName
            Set-Status "HTML report written to $($d.FileName)."
            [System.Windows.Forms.MessageBox]::Show("Report saved.`r`n`r`n$($d.FileName)",'Export complete','OK','Information') | Out-Null
        } catch {
            Write-ErrorLog -Context 'Export HTML report' -ErrorRecord $_
            Set-Status "HTML export failed: $($_.Exception.Message)"
            $m = $_.Exception.Message + "`r`n`r`n" + $_.InvocationInfo.PositionMessage
            [System.Windows.Forms.MessageBox]::Show($m,'Export failed','OK','Error') | Out-Null
        }
    }
})

$btnCancel.Add_Click({ $script:CancelRequested = $true; Set-Status 'Cancelling ...' })

$btnRun.Add_Click({
  try {
    if (-not $script:Ctx.Domain) {
        [System.Windows.Forms.MessageBox]::Show('Not connected to Active Directory yet.','Run','OK','Warning') | Out-Null
        return
    }
    # @() is required here. A function returning a one-element array has that
    # array unrolled on return, so with a single test selected or a single DC
    # checked the variable would be a scalar and .Count would throw under
    # Set-StrictMode -Version Latest.
    $tests = @(Get-SelectedTestDefs)
    if ($tests.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Select at least one test.','Run','OK','Warning') | Out-Null
        return
    }
    $targets = @(Get-SelectedTargets)
    $needsDC = @($tests | Where-Object { $_.Scope -eq 'PerDC' })
    if ($targets.Count -eq 0 -and $needsDC.Count -gt 0) {
        [System.Windows.Forms.MessageBox]::Show('Select at least one target domain controller -- one or more checked tests are per-DC.','Run','OK','Warning') | Out-Null
        return
    }

    $options = [pscustomobject]@{
        Verbose        = [bool]$chkVerbose.Checked
        DeepDns        = [bool]$chkDeepDns.Checked
        TimeoutSeconds = [int]$numTimeout.Value
    }
    $logPath = $txtLog.Text.Trim()

    $work = New-Object System.Collections.Generic.List[object]
    foreach ($t in $tests) {
        if ($t.Scope -eq 'PerDC') {
            foreach ($dc in $targets) { $work.Add([pscustomobject]@{ TestDef=$t; TargetDC=$dc }) }
        } else {
            $work.Add([pscustomobject]@{ TestDef=$t; TargetDC=$null })
        }
    }

    $script:CancelRequested = $false
    $script:Results = New-Object System.Collections.Generic.List[object]
    $lvResults.Items.Clear()
    $txtDetail.Clear()
    $progress.Minimum = 0; $progress.Maximum = [Math]::Max($work.Count,1); $progress.Value = 0
    $btnRun.Enabled = $false; $btnCancel.Enabled = $true
    $sumPass=0; $sumWarn=0; $sumFail=0; $sumErr=0

    try {
        foreach ($w in $work) {
            if ($script:CancelRequested) { Set-Status 'Cancelled.'; break }
            $progress.Value = [Math]::Min($progress.Value+1, $progress.Maximum)
            $tgtTxt = if ($w.TargetDC) { " on $($w.TargetDC)" } else { '' }
            Set-Status "[$($progress.Value)/$($progress.Maximum)] $($w.TestDef.Category) - $($w.TestDef.Label)$tgtTxt ..."

            $r = Invoke-DiagnosticTest -TestDef $w.TestDef -TargetDC $w.TargetDC -Options $options
            $script:Results.Add($r)
            Add-ResultRow $r
            switch ($r.Status) {
                'Pass'  { $sumPass++ }
                'Warn'  { $sumWarn++ }
                'Fail'  { $sumFail++ }
                'Error' { $sumErr++ }
            }
            if ($logPath) { Write-DiagLog -Path $logPath -Result $r }
        }
    } finally {
        $btnRun.Enabled = $true; $btnCancel.Enabled = $false; $progress.Value = 0
    }

    $lblSummary.Text = "Completed: $($script:Results.Count) test(s) run.  Pass=$sumPass  Warn=$sumWarn  Fail=$sumFail  Error=$sumErr"
    $lblSummary.ForeColor = if ($sumFail -gt 0 -or $sumErr -gt 0) { $cRed } elseif ($sumWarn -gt 0) { $cOrange } else { $cGreen }
    Set-Status 'Diagnostic run complete.'
  }
  catch {
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    $btnRun.Enabled = $true; $btnCancel.Enabled = $false; $progress.Value = 0
    Write-ErrorLog -Context 'Run handler (unhandled)' -ErrorRecord $_
    $m = $_.Exception.GetType().FullName + ': ' + $_.Exception.Message + `
         "`r`n`r`n" + $_.InvocationInfo.PositionMessage + "`r`n`r`n" + $_.ScriptStackTrace
    [System.Windows.Forms.MessageBox]::Show($m,'Run failed (diagnostic)','OK','Error') | Out-Null
  }
})

$form.Add_KeyDown({
    switch ($_.KeyCode) {
        'F5'     { if ($btnRun.Enabled)        { $btnRun.PerformClick() };        $_.Handled = $true }
        'F6'     { if ($btnCancel.Enabled)     { $btnCancel.PerformClick() };     $_.Handled = $true }
        'F7'     { if ($btnExportCsv.Enabled)  { $btnExportCsv.PerformClick() };  $_.Handled = $true }
        'F8'     { if ($btnExportHtml.Enabled) { $btnExportHtml.PerformClick() }; $_.Handled = $true }
        'Escape' { $form.Close(); $_.Handled = $true }
    }
})

# ===========================================================================
# Go
# ===========================================================================

$script:Ctx.BindServer = $Server
$form.Add_Shown({
    $form.Activate()
    try {
        Build-TestTree
        Initialize-Session -TargetServer $Server
    } catch {
        Write-ErrorLog -Context 'Startup (Build-TestTree / Initialize-Session)' -ErrorRecord $_
        $m = $_.Exception.GetType().FullName + ': ' + $_.Exception.Message + `
             "`r`n`r`n" + $_.InvocationInfo.PositionMessage + "`r`n`r`n" + $_.ScriptStackTrace
        [System.Windows.Forms.MessageBox]::Show($m,'Startup failed (diagnostic)','OK','Error') | Out-Null
    }
})
[void]$form.ShowDialog()
$form.Dispose()
