[CmdletBinding()]
param(
    [string]$OutputDir = 'C:\Users\Public\soc_advanced_report',
    [int]$SecurityHours = 24,
    [int]$NewUsersDays = 7,
    [int]$RecentFileDays = 3,
    [int]$MaxEventsPerQuery = 500,
    [int]$MaxItemsPerSection = 1000,
    [int]$EventMessageLength = 500,
    [switch]$SkipDeepFileScan,
    [switch]$NoSummaryReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptStart = Get-Date
$sectionErrors = New-Object System.Collections.Generic.List[object]

function Add-SectionError {
    param(
        [Parameter(Mandatory)] [string]$Section,
        [Parameter(Mandatory)] [System.Exception]$Exception
    )

    $sectionErrors.Add([pscustomobject]@{
        Section = $Section
        Error = $Exception.Message
        Type = $Exception.GetType().FullName
        TimeUtc = (Get-Date).ToUniversalTime().ToString('o')
    })
}

function Invoke-Section {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock,
        [object]$DefaultValue = $null
    )

    try {
        & $ScriptBlock
    }
    catch {
        Add-SectionError -Section $Name -Exception $_.Exception
        $DefaultValue
    }
}

function Get-EventData {
    param(
        [Parameter(Mandatory)] [hashtable]$Filter,
        [int]$MaxEvents = 300,
        [int]$MaxMessageLength = 500
    )

    $events = $null
    try {
        $events = Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxEvents -ErrorAction Stop
    }
    catch {
        if (
            $_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or
            $_.Exception.Message -like 'No events were found*'
        ) {
            return @()
        }

        throw
    }

    $events |
        ForEach-Object {
            $msg = $_.Message
            if ($msg) {
                $msg = $msg -replace "`r`n", "`n"
            }

            if ($msg -and $msg.Length -gt $MaxMessageLength) {
                $msg = $msg.Substring(0, $MaxMessageLength) + '...'
            }

            [pscustomobject]@{
                TimeCreated = if ($_.TimeCreated) { $_.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
                Id = $_.Id
                RecordId = $_.RecordId
                Provider = $_.ProviderName
                Level = $_.LevelDisplayName
                Message = $msg
            }
        }
}

function Convert-ToJsonFriendlyObject {
    param([object]$InputObject)

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [DateTime]) {
        return $InputObject.ToUniversalTime().ToString('o')
    }

    if ($InputObject -is [DateTimeOffset]) {
        return $InputObject.ToUniversalTime().ToString('o')
    }

    if ($InputObject -is [Enum]) {
        return [string]$InputObject
    }

    if (
        $InputObject -is [string] -or
        $InputObject.GetType().IsPrimitive -or
        $InputObject -is [decimal] -or
        $InputObject -is [guid]
    ) {
        return $InputObject
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $dictOut = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            $dictOut[$key] = Convert-ToJsonFriendlyObject -InputObject $InputObject[$key]
        }
        return $dictOut
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $listOut = New-Object System.Collections.Generic.List[object]
        foreach ($item in $InputObject) {
            $listOut.Add((Convert-ToJsonFriendlyObject -InputObject $item))
        }
        return ,$listOut.ToArray()
    }

    $props = @($InputObject.PSObject.Properties)
    if ($props.Count -eq 0) {
        return $InputObject
    }

    $objOut = [ordered]@{}
    foreach ($prop in $props) {
        if ($prop.MemberType -notin @('NoteProperty', 'Property', 'ScriptProperty')) { continue }
        $objOut[$prop.Name] = Convert-ToJsonFriendlyObject -InputObject $prop.Value
    }

    return $objOut
}

function Write-HumanSummary {
    param(
        [Parameter(Mandatory)] [object]$Report,
        [Parameter(Mandatory)] [string]$Path
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $meta = $Report.Metadata
    $summary = $Report.Summary

    $lines.Add('# SOC/DFIR Triage Summary')
    $lines.Add('')
    $lines.Add(('Host: {0}' -f $meta.Hostname))
    $lines.Add(('Generated (UTC): {0}' -f $meta.GeneratedAtUtc))
    $lines.Add(('Duration (seconds): {0}' -f $meta.DurationSeconds))
    $lines.Add('')

    $lines.Add('## Counters')
    $lines.Add(('- Failed logons: {0}' -f $summary.FailedLogons))
    $lines.Add(('- New users: {0}' -f $summary.NewUsers))
    $lines.Add(('- Startup registry entries: {0}' -f $summary.StartupRegistryEntries))
    $lines.Add(('- Suspicious services: {0}' -f $summary.SuspiciousServices))
    $lines.Add(('- External established connections: {0}' -f $summary.ExternalEstablishedConnections))
    $lines.Add(('- Recent suspicious files: {0}' -f $summary.RecentSuspiciousFiles))
    $lines.Add(('- IOC name matches: {0}' -f $summary.IOCNameMatches))
    $lines.Add(('- IOC content matches: {0}' -f $summary.IOCContentMatches))
    $lines.Add(('- Section errors: {0}' -f $summary.SectionErrors))
    $lines.Add('')

    $lines.Add('## Top External Connections')
    $connections = @($Report.Network.PossibleReverseShell | Select-Object -First 20)
    if ($connections.Count -eq 0) {
        $lines.Add('- None')
    }
    else {
        foreach ($conn in $connections) {
            $lines.Add(('- {0}:{1} -> {2}:{3} | PID {4} | {5}' -f $conn.LocalAddress, $conn.LocalPort, $conn.RemoteAddress, $conn.RemotePort, $conn.OwningProcessId, $conn.ProcessName))
        }
    }
    $lines.Add('')

    $lines.Add('## Top Suspicious Services')
    $services = @($Report.Persistence.SuspiciousServices | Select-Object -First 20)
    if ($services.Count -eq 0) {
        $lines.Add('- None')
    }
    else {
        foreach ($svc in $services) {
            $lines.Add(('- {0} ({1}) | {2}' -f $svc.Name, $svc.State, $svc.PathName))
        }
    }
    $lines.Add('')

    $lines.Add('## Top IOC Content Matches')
    $iocHits = @($Report.AdvancedIOC.ScriptContentMatches | Select-Object -First 20)
    if ($iocHits.Count -eq 0) {
        $lines.Add('- None')
    }
    else {
        foreach ($hit in $iocHits) {
            $lines.Add(('- {0}:{1} | {2}' -f $hit.FullName, $hit.LineNumber, $hit.Pattern))
        }
    }
    $lines.Add('')

    $lines.Add('## Section Errors')
    $errors = @($Report.SectionErrors)
    if ($errors.Count -eq 0) {
        $lines.Add('- None')
    }
    else {
        foreach ($err in $errors) {
            $lines.Add(('- {0}: {1}' -f $err.Section, $err.Error))
        }
    }

    Set-Content -Path $Path -Value ($lines -join "`r`n") -Encoding UTF8
}

function Test-IsExternalAddress {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }

    $normalized = $Address.Trim().ToLowerInvariant()

    if ($normalized -in @('0.0.0.0', '::', '::1')) { return $false }
    if ($normalized -like '127.*') { return $false }
    if ($normalized -like '169.254.*') { return $false }
    if ($normalized -like '10.*') { return $false }
    if ($normalized -like '192.168.*') { return $false }
    if ($normalized -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $false }
    if ($normalized -match '^fe80:') { return $false }
    if ($normalized -match '^fc[0-9a-f]{2}:') { return $false }
    if ($normalized -match '^fd[0-9a-f]{2}:') { return $false }

    if ($normalized.StartsWith('::ffff:')) {
        $mapped = $normalized.Substring(7)
        return (Test-IsExternalAddress -Address $mapped)
    }

    return $true
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$reportFile = Join-Path $OutputDir ("soc_advanced_report_{0}.json" -f $timestamp)
$summaryFile = Join-Path $OutputDir ("soc_advanced_report_{0}_summary.md" -f $timestamp)

$isAdmin = Invoke-Section -Name 'AdminCheck' -DefaultValue $false -ScriptBlock {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

$processMap = Invoke-Section -Name 'ProcessInventory' -DefaultValue @{} -ScriptBlock {
    $map = @{}
    Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | ForEach-Object {
        $map[$_.ProcessId] = [pscustomobject]@{
            ProcessName = $_.Name
            ExecutablePath = $_.ExecutablePath
            CommandLine = $_.CommandLine
        }
    }
    $map
}

$report = [ordered]@{}
$report.Metadata = [ordered]@{
    Hostname = $env:COMPUTERNAME
    GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    ScriptVersion = '2.0'
    IsElevated = $isAdmin
    Parameters = [ordered]@{
        OutputDir = $OutputDir
        SecurityHours = $SecurityHours
        NewUsersDays = $NewUsersDays
        RecentFileDays = $RecentFileDays
        MaxEventsPerQuery = $MaxEventsPerQuery
        MaxItemsPerSection = $MaxItemsPerSection
        EventMessageLength = $EventMessageLength
        SkipDeepFileScan = [bool]$SkipDeepFileScan
        NoSummaryReport = [bool]$NoSummaryReport
    }
}

$report.SystemInfo = Invoke-Section -Name 'SystemInfo' -DefaultValue @{} -ScriptBlock {
    Get-ComputerInfo |
        Select-Object CsName, OsName, WindowsProductName, WindowsVersion, OsArchitecture, OsBuildNumber, CsDomain
}

$report.LoggedUsers = Invoke-Section -Name 'LoggedUsers' -DefaultValue @() -ScriptBlock {
    $output = (& cmd /c 'query user' 2>$null)
    if (-not $output) {
        @()
    }
    else {
        $output | Select-Object -Skip 1 | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
}

$report.LocalAdmins = Invoke-Section -Name 'LocalAdmins' -DefaultValue @() -ScriptBlock {
    $administratorsSid = 'S-1-5-32-544'
    $adminGroup = Get-LocalGroup -SID $administratorsSid -ErrorAction Stop
    Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop |
        Select-Object Name, ObjectClass, PrincipalSource
}

$now = Get-Date
$report.SecurityEvents = [ordered]@{}

$report.SecurityEvents.FailedLogons = Invoke-Section -Name 'SecurityEvents.FailedLogons' -DefaultValue @() -ScriptBlock {
    Get-EventData -Filter @{ LogName = 'Security'; Id = 4625; StartTime = $now.AddHours(-$SecurityHours) } -MaxEvents $MaxEventsPerQuery -MaxMessageLength $EventMessageLength
}

$report.SecurityEvents.NewUsers = Invoke-Section -Name 'SecurityEvents.NewUsers' -DefaultValue @() -ScriptBlock {
    Get-EventData -Filter @{ LogName = 'Security'; Id = 4720; StartTime = $now.AddDays(-$NewUsersDays) } -MaxEvents $MaxEventsPerQuery -MaxMessageLength $EventMessageLength
}

$report.SecurityEvents.PrivilegedOps = Invoke-Section -Name 'SecurityEvents.PrivilegedOps' -DefaultValue @() -ScriptBlock {
    Get-EventData -Filter @{ LogName = 'Security'; Id = 4673; StartTime = $now.AddHours(-$SecurityHours) } -MaxEvents $MaxEventsPerQuery -MaxMessageLength $EventMessageLength
}

$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

$report.Persistence = [ordered]@{}

$report.Persistence.StartupRegistry = Invoke-Section -Name 'Persistence.StartupRegistry' -DefaultValue @() -ScriptBlock {
    $excludeProps = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
    $items = New-Object System.Collections.Generic.List[object]

    foreach ($key in $runKeys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }

        $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        foreach ($property in $props.PSObject.Properties) {
            if ($property.MemberType -ne 'NoteProperty') { continue }
            if ($excludeProps -contains $property.Name) { continue }

            $items.Add([pscustomobject]@{
                Location = $key
                Name = $property.Name
                Value = [string]$property.Value
            })
        }
    }

    $items
}

$report.Persistence.Services = Invoke-Section -Name 'Persistence.Services' -DefaultValue @() -ScriptBlock {
    Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
        Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId
}

$report.Persistence.SuspiciousServices = Invoke-Section -Name 'Persistence.SuspiciousServices' -DefaultValue @() -ScriptBlock {
    Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
        Where-Object {
            $path = [string]$_.PathName
            if ([string]::IsNullOrWhiteSpace($path)) { return $false }

            $normalized = $path.ToLowerInvariant()
            ($normalized -match '\\users\\') -or
            ($normalized -match '\\programdata\\') -or
            ($normalized -match '\\temp\\') -or
            ($normalized -match '\\public\\')
        } |
        Select-Object Name, DisplayName, State, StartMode, PathName
}

$report.Persistence.ScheduledTasks = Invoke-Section -Name 'Persistence.ScheduledTasks' -DefaultValue @() -ScriptBlock {
    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $task = $_

        $actionTexts = New-Object System.Collections.Generic.List[string]
        foreach ($action in @($task.Actions)) {
            if ($null -eq $action) { continue }

            if ($action.PSObject.Properties.Match('Execute').Count -gt 0) {
                $actionTexts.Add(('{0} {1}' -f [string]$action.Execute, [string]$action.Arguments).Trim())
                continue
            }

            if ($action.PSObject.Properties.Match('ClassId').Count -gt 0) {
                $actionTexts.Add(('ComHandler {0}' -f [string]$action.ClassId).Trim())
                continue
            }

            $actionTexts.Add([string]$action)
        }

        $triggerTexts = New-Object System.Collections.Generic.List[string]
        foreach ($trigger in @($task.Triggers)) {
            if ($null -eq $trigger) { continue }
            $triggerTexts.Add([string]$trigger)
        }

        $principal = $task.Principal

        [pscustomobject]@{
            TaskName = $task.TaskName
            TaskPath = $task.TaskPath
            State = [string]$task.State
            Author = [string]$task.Author
            UserId = if ($principal) { [string]$principal.UserId } else { $null }
            RunLevel = if ($principal) { [string]$principal.RunLevel } else { $null }
            Actions = $actionTexts -join ' | '
            Triggers = $triggerTexts -join ' | '
        }
    }
}

$report.Persistence.WmiSubscription = [ordered]@{}

$report.Persistence.WmiSubscription.EventFilters = Invoke-Section -Name 'Persistence.WmiSubscription.EventFilters' -DefaultValue @() -ScriptBlock {
    Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop |
        Select-Object Name, Query, QueryLanguage, EventNamespace
}

$report.Persistence.WmiSubscription.CommandLineConsumers = Invoke-Section -Name 'Persistence.WmiSubscription.CommandLineConsumers' -DefaultValue @() -ScriptBlock {
    Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' -ErrorAction Stop |
        Select-Object Name, CommandLineTemplate, RunInteractively
}

$report.Persistence.WmiSubscription.ActiveScriptConsumers = Invoke-Section -Name 'Persistence.WmiSubscription.ActiveScriptConsumers' -DefaultValue @() -ScriptBlock {
    Get-CimInstance -Namespace 'root\subscription' -ClassName 'ActiveScriptEventConsumer' -ErrorAction Stop |
        Select-Object Name, ScriptingEngine, ScriptText
}

$report.Persistence.WmiSubscription.FilterBindings = Invoke-Section -Name 'Persistence.WmiSubscription.FilterBindings' -DefaultValue @() -ScriptBlock {
    Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop |
        Select-Object Filter, Consumer
}

$connections = Invoke-Section -Name 'Network.AllConnections' -DefaultValue @() -ScriptBlock {
    Get-NetTCPConnection -ErrorAction Stop
}

$report.Network = [ordered]@{}

$report.Network.Connections = $connections | ForEach-Object {
    $proc = $null
    if ($processMap.ContainsKey($_.OwningProcess)) {
        $proc = $processMap[$_.OwningProcess]
    }

    [pscustomobject]@{
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort = $_.RemotePort
        State = [string]$_.State
        OwningProcessId = $_.OwningProcess
        ProcessName = if ($proc) { $proc.ProcessName } else { $null }
        ProcessPath = if ($proc) { $proc.ExecutablePath } else { $null }
        CommandLine = if ($proc) { $proc.CommandLine } else { $null }
    }
}

$report.Network.ListeningPorts = $report.Network.Connections |
    Where-Object { $_.State -eq 'Listen' } |
    Select-Object LocalAddress, LocalPort, OwningProcessId, ProcessName, ProcessPath

$lolbinProcessNames = @(
    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
    'rundll32.exe', 'regsvr32.exe', 'wmic.exe', 'certutil.exe', 'bitsadmin.exe',
    'python.exe', 'node.exe', 'java.exe', 'nc.exe', 'ncat.exe'
)

$report.Network.PossibleReverseShell = $report.Network.Connections |
    Where-Object {
        $_.State -eq 'Established' -and
        (Test-IsExternalAddress -Address $_.RemoteAddress)
    } |
    ForEach-Object {
        $name = [string]$_.ProcessName
        $nameLower = $name.ToLowerInvariant()
        $isLolbin = $lolbinProcessNames -contains $nameLower

        [pscustomobject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            OwningProcessId = $_.OwningProcessId
            ProcessName = $_.ProcessName
            ProcessPath = $_.ProcessPath
            CommandLine = $_.CommandLine
            IsLOLBinOrScriptHost = $isLolbin
            Reason = if ($isLolbin) { 'External established connection from LOLBin/script host process' } else { 'External established connection' }
        }
    }

$report.FileFindings = [ordered]@{}

$fileCutoff = $now.AddDays(-$RecentFileDays)
$suspiciousExtensions = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.scr')

$recentScanRoots = @(
    'C:\Users\Public',
    'C:\Windows\Temp',
    "$env:TEMP"
)

if (-not $SkipDeepFileScan) {
    $recentScanRoots += @(
        'C:\Users\*\Downloads',
        'C:\Users\*\AppData\Local\Temp',
        'C:\Users\*\AppData\Roaming'
    )
}

$report.FileFindings.RecentSuspiciousFiles = Invoke-Section -Name 'FileFindings.RecentSuspiciousFiles' -DefaultValue @() -ScriptBlock {
    $hits = New-Object System.Collections.Generic.List[object]

    foreach ($root in $recentScanRoots) {
        $files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            if ($file.LastWriteTime -lt $fileCutoff) { continue }
            if ($suspiciousExtensions -notcontains $file.Extension.ToLowerInvariant()) { continue }

            $hits.Add([pscustomobject]@{
                FullName = $file.FullName
                Extension = $file.Extension
                Length = $file.Length
                LastWriteTime = $file.LastWriteTime
            })
        }
    }

    $hits |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First $MaxItemsPerSection
}

$tempPaths = @("$env:TEMP", 'C:\Windows\Temp')
$report.FileFindings.TempDlls = Invoke-Section -Name 'FileFindings.TempDlls' -DefaultValue @() -ScriptBlock {
    $dlls = New-Object System.Collections.Generic.List[object]

    foreach ($path in $tempPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }

        Get-ChildItem -Path $path -Recurse -File -Filter '*.dll' -ErrorAction SilentlyContinue |
            ForEach-Object {
                $dlls.Add([pscustomobject]@{
                    FullName = $_.FullName
                    Length = $_.Length
                    LastWriteTime = $_.LastWriteTime
                })
            }
    }

    $dlls |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First $MaxItemsPerSection
}

$report.CredentialDumping = [ordered]@{}

$report.CredentialDumping.Security4656Lsass = Invoke-Section -Name 'CredentialDumping.Security4656Lsass' -DefaultValue @() -ScriptBlock {
    Get-EventData -Filter @{ LogName = 'Security'; Id = 4656; StartTime = $now.AddHours(-$SecurityHours) } -MaxEvents $MaxEventsPerQuery -MaxMessageLength $EventMessageLength |
        Where-Object { $_.Message -match '(?i)lsass\.exe' }
}

$report.CredentialDumping.SysmonProcessAccessLsass = Invoke-Section -Name 'CredentialDumping.SysmonProcessAccessLsass' -DefaultValue @() -ScriptBlock {
    if (-not (Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)) {
        return @()
    }

    Get-EventData -Filter @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 10; StartTime = $now.AddHours(-$SecurityHours) } -MaxEvents $MaxEventsPerQuery -MaxMessageLength $EventMessageLength |
        Where-Object { $_.Message -match '(?i)lsass\.exe' }
}

$report.AdvancedIOC = [ordered]@{}

$iocTargets = @(
    [pscustomobject]@{ Path = 'C:\Windows\System32'; Recurse = $false },
    [pscustomobject]@{ Path = "$env:TEMP"; Recurse = $true },
    [pscustomobject]@{ Path = 'C:\Users\Public'; Recurse = $true }
)

$fileNamePatterns = @(
    'beacon(?:64)?\.exe$',
    'empire(?:-server)?\.exe$',
    'meterpreter',
    'shell(?:code)?',
    'mimikatz',
    'rubeus',
    'nanodump',
    'procdump'
)

$contentPatterns = @(
    '(?i)invoke-mimikatz',
    '(?i)invoke-reflectivepeinjection',
    '(?i)powershell.+-enc',
    '(?i)frombase64string\(',
    '(?i)downloadstring\(',
    '(?i)iex\s*\('
)

$scriptExtensions = @('.ps1', '.psm1', '.cmd', '.bat', '.vbs', '.js', '.hta')

$report.AdvancedIOC.NameMatches = Invoke-Section -Name 'AdvancedIOC.NameMatches' -DefaultValue @() -ScriptBlock {
    $hits = New-Object System.Collections.Generic.List[object]

    foreach ($target in $iocTargets) {
        if (-not (Test-Path -LiteralPath $target.Path)) { continue }

        $files = Get-ChildItem -Path $target.Path -File -Recurse:$target.Recurse -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            foreach ($pattern in $fileNamePatterns) {
                if ($file.Name -match $pattern) {
                    $hits.Add([pscustomobject]@{
                        MatchType = 'FileNamePattern'
                        Pattern = $pattern
                        FullName = $file.FullName
                        Name = $file.Name
                        LastWriteTime = $file.LastWriteTime
                    })
                    break
                }
            }
        }
    }

    $hits |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First $MaxItemsPerSection
}

$report.AdvancedIOC.ScriptContentMatches = Invoke-Section -Name 'AdvancedIOC.ScriptContentMatches' -DefaultValue @() -ScriptBlock {
    $hits = New-Object System.Collections.Generic.List[object]

    foreach ($target in $iocTargets) {
        if (-not (Test-Path -LiteralPath $target.Path)) { continue }

        $candidateFiles = Get-ChildItem -Path $target.Path -File -Recurse:$target.Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $scriptExtensions -contains $_.Extension.ToLowerInvariant() -and $_.Length -le 1MB
            }

        foreach ($file in $candidateFiles) {
            $matches = Select-String -Path $file.FullName -Pattern $contentPatterns -AllMatches -ErrorAction SilentlyContinue
            foreach ($match in $matches) {
                $line = $match.Line
                if ($line -and $line.Length -gt 300) {
                    $line = $line.Substring(0, 300) + '...'
                }

                $hits.Add([pscustomobject]@{
                    MatchType = 'ScriptContentPattern'
                    Pattern = $match.Pattern
                    FullName = $file.FullName
                    LineNumber = $match.LineNumber
                    Line = $line
                    LastWriteTime = $file.LastWriteTime
                })
            }
        }
    }

    $hits |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First $MaxItemsPerSection
}

$report.Summary = [ordered]@{
    FailedLogons = @($report.SecurityEvents.FailedLogons).Count
    NewUsers = @($report.SecurityEvents.NewUsers).Count
    StartupRegistryEntries = @($report.Persistence.StartupRegistry).Count
    SuspiciousServices = @($report.Persistence.SuspiciousServices).Count
    ExternalEstablishedConnections = @($report.Network.PossibleReverseShell).Count
    RecentSuspiciousFiles = @($report.FileFindings.RecentSuspiciousFiles).Count
    IOCNameMatches = @($report.AdvancedIOC.NameMatches).Count
    IOCContentMatches = @($report.AdvancedIOC.ScriptContentMatches).Count
    SectionErrors = $sectionErrors.Count
}

$report.SectionErrors = $sectionErrors
$report.Metadata.DurationSeconds = [math]::Round(((Get-Date) - $scriptStart).TotalSeconds, 2)

$jsonReadyReport = Convert-ToJsonFriendlyObject -InputObject $report
$json = $jsonReadyReport | ConvertTo-Json -Depth 20
$json = $json -replace '\\u003c', '<' -replace '\\u003e', '>' -replace '\\u0026', '&'
Set-Content -Path $reportFile -Value $json -Encoding UTF8

$summaryWritten = $false
if (-not $NoSummaryReport) {
    Write-HumanSummary -Report $jsonReadyReport -Path $summaryFile
    $summaryWritten = $true
}

Write-Host ''
Write-Host 'Advanced SOC/DFIR triage completed.'
Write-Host ('JSON report saved to: {0}' -f $reportFile)
if ($summaryWritten) {
    Write-Host ('Summary report saved to: {0}' -f $summaryFile)
}

if ($sectionErrors.Count -gt 0) {
    Write-Warning ('Some sections failed. See SectionErrors in JSON report. Count: {0}' -f $sectionErrors.Count)
}

