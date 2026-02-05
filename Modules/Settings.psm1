#Requires -Version 5.1
<#
.SYNOPSIS
    Application settings management module for ADapp.
.DESCRIPTION
    Provides functions to load, save, and edit application settings. Handles
    merging of shared settings from network paths, local overrides from
    %ProgramData%\ADapp\config\settings.local.json, and environment variable
    overrides (ADAPP_*). Also provides a multi-tab WinForms settings dialog.
.NOTES
    Module: Settings
    Author: ADapp Team
#>

#region Functions

function Load-Settings {
    <#
    .SYNOPSIS
        Loads merged application settings and applies defaults.
    .DESCRIPTION
        Loads config/settings.json, merges optional shared settings from
        ProgramData\ADapp\Data (or PreferredSharedPath), merges the local
        override at %ProgramData%\ADapp\config\settings.local.json, then
        applies environment variable overrides (ADAPP_*). If settings.json
        is missing, writes defaults first.
    .PARAMETER ScriptPath
        Application root path used to locate the config folder.
    .OUTPUTS
        PSCustomObject
        The merged settings object.
    .EXAMPLE
        $settings = Load-Settings -ScriptPath $PSScriptRoot
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    $configDir = Join-Path -Path $ScriptPath -ChildPath "config"
    $settingsPath = Join-Path -Path $configDir -ChildPath "settings.json"

    if (-not (Test-Path $settingsPath)) {
        $defaultSettings = @{ 
            Application = @{
                Title = "AD Search Tool"
                Version = "1.0.15"
                MainFormSize = @{ Width = 1200; Height = 800 }
                MinFormSize = @{ Width = 800; Height = 600 }
            }
            UI = @{
                SearchButtonBackColor = "#4a6fba"
                SearchButtonForeColor = "#ffffff"
                Theme = @{
                    Mode = "System"
                    PrimaryColor = "#4a6fba"
                    SecondaryColor = "#f0f0f0"
                    BackgroundColor = "#ffffff"
                    TextColor = "#333333"
                }
                ThemeDark = @{
                    PrimaryColor = "#3a3a3a"
                    SecondaryColor = "#4a4a4a"
                    BackgroundColor = "#323232"
                    TextColor = "#f0f0f0"
                }
            }
            Search = @{
                MaxSearchHistory = 20
                ExactMatchDefault = $false
                IncludeDisabledDefault = $false
            }
            AD = @{
                ADSyncDC = ""
                ADSyncScriptPath = ""
                PreferredDomainControllers = @()
                UserBaseOU = @()
                ComputerBaseOU = @()
                GroupBaseOU = @()
                ServerBaseOU = @()
            }
            Connections = @{
                VNCPath        = "C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe"
                RDPTimeout     = 30
                VNCTimeout     = 30
                # Optional VNC password used when launching the viewer. Stored in plain text
                # in %ProgramData%\ADapp\config\settings.local.json; do not store in shared settings.
                VNCPassword    = ""
                # When $true, VNC connections are opened with the -viewonly flag.
                VNCViewOnly    = $true
            }
            Logging = @{
                LogPath = "$env:ProgramData\ADapp\Logs"
                EnableTranscript = $true
                MaxLogFileSizeMB = 10
                MaxLogFiles = 5
            }
            Data = @{
                PreferredSharedPath = ""
            }
            PDQ = @{ 
                ReportFolder = ""
                ReportFilePattern = "Logged in User.csv"
                Enabled = $true 
            }
            QUser = @{
                Enabled = $true
                CacheAgeMinutes = 5
                TimeoutSeconds = 10
                MaxComputersPerQuery = 50
                EnableHistoricalTracking = $true
                HistoricalDaysToKeep = 30
                # PowerShell remoting (WinRM) fallback for quser. Disabled by default to avoid hangs in locked-down networks.
                UseInvokeCommandFallback = $false
            }
            Shortcuts = @{
                FocusSearch = "Ctrl+F"
                NewSearch = "Ctrl+N"
                ClearFilters = "Esc"
                ConnectRDP = "Ctrl+Alt+R"
                ConnectVNC = "Ctrl+Alt+V"
                ConnectPing = "Ctrl+Alt+P"
            }
            Printers = @{
                PrintServer = ""
            }
            Monitor = @{
                StartWithWindows = $false
                StartMinimized = $false
                CloseToTray = $false
                # When $true, the Locked Monitor UI will start with the "Show tracked" filter enabled.
                ShowTrackedByDefault = $true
            }
        }
        $localSharedDir = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
        # Resolve active shared path: prefer PreferredSharedPath from local shared file if present, else local
        $sharedSettingsPath = Join-Path -Path $localSharedDir -ChildPath "settings.json"
        $activeDir = $localSharedDir
        try {
            if (Test-Path $sharedSettingsPath) {
                $bootstrap = Get-Content -Path $sharedSettingsPath -Raw | ConvertFrom-Json
                if ($bootstrap -and $bootstrap.Data -and $bootstrap.Data.PreferredSharedPath) {
                    $pref = [Environment]::ExpandEnvironmentVariables([string]$bootstrap.Data.PreferredSharedPath)
                    if (-not [string]::IsNullOrWhiteSpace($pref) -and (Test-Path $pref)) {
                        $activeDir = $pref
                        $sharedSettingsPath = Join-Path -Path $activeDir -ChildPath "settings.json"
                    }
                }
            }
        } catch {}
        try {
            if (Test-Path $sharedSettingsPath) {
                $loadedShared = Get-Content -Path $sharedSettingsPath -Raw | ConvertFrom-Json
                if ($loadedShared -and $loadedShared.Connections) {
                    # Never trust secrets from shared settings
                    $hadSecret = $false
                    try {
                        if (-not [string]::IsNullOrWhiteSpace([string]$loadedShared.Connections.VNCPassword)) { $hadSecret = $true }
                    } catch {}
                    $loadedShared.Connections.VNCPassword = ""
                    if ($hadSecret) {
                        try {
                            $sanitized = Get-SanitizedSettingsForShared -Settings $loadedShared
                            $sanitized | ConvertTo-Json -Depth 7 | Out-File -FilePath $sharedSettingsPath -Encoding UTF8
                        } catch {}
                    }
                }
                if ($loadedShared) {
                    foreach ($p in $loadedShared.PSObject.Properties) {
                        try { $defaultSettings | Add-Member -MemberType NoteProperty -Name $p.Name -Value $p.Value -Force } catch {}
                    }
                    return $defaultSettings
                }
            }
        } catch {}

        # Seed local settings from defaults (app-dir config is read-only; shared gets updated on save/sync)
        try {
            if (-not (Test-Path $localSharedDir)) { New-Item -ItemType Directory -Path $localSharedDir -Force | Out-Null }
            $sanitized = Get-SanitizedSettingsForShared -Settings $defaultSettings
            $sanitized | ConvertTo-Json -Depth 7 | Out-File -FilePath (Join-Path -Path $localSharedDir -ChildPath "settings.json") -Encoding UTF8
        } catch {}
        return $defaultSettings
    }
    else {
        try {
            $loaded = Get-Content -Path $settingsPath -Raw | ConvertFrom-Json

            # Resolve active shared path first; load shared settings when available (shared-first)
            $localSharedDir = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
            $preferred = try { if ($loaded.Data -and $loaded.Data.PreferredSharedPath) { [Environment]::ExpandEnvironmentVariables([string]$loaded.Data.PreferredSharedPath) } else { "" } } catch { "" }
            $activeDir = if (-not [string]::IsNullOrWhiteSpace($preferred) -and (Test-Path $preferred)) { $preferred } else { $localSharedDir }
            $sharedSettingsPath = Join-Path -Path $activeDir -ChildPath "settings.json"
            if (Test-Path $sharedSettingsPath) {
                try {
                    $shared = Get-Content -Path $sharedSettingsPath -Raw | ConvertFrom-Json
                    if ($shared) {
                        if ($shared.Connections) {
                            try { $shared.Connections.VNCPassword = "" } catch {}
                            try {
                                $sanitized = Get-SanitizedSettingsForShared -Settings $shared
                                $sanitized | ConvertTo-Json -Depth 7 | Out-File -FilePath $sharedSettingsPath -Encoding UTF8
                            } catch {}
                        }
                        foreach ($p in $shared.PSObject.Properties) {
                            try { $loaded | Add-Member -MemberType NoteProperty -Name $p.Name -Value $p.Value -Force } catch {}
                        }
                    }
                } catch {}
            }

            # Ensure all required sections exist (merge known keys; preserve unknown keys)
            if (-not $loaded.Application) {
                $loaded | Add-Member -MemberType NoteProperty -Name Application -Value (@{ Title = "AD Search Tool"; Version = "1.0.15"; MainFormSize = @{ Width = 1200; Height = 800 }; MinFormSize = @{ Width = 800; Height = 600 } }) -Force
            }

            # Normalize application window sizes (guard against tiny or invalid values)
            try {
                if (-not (Get-Member -InputObject $loaded.Application -Name MainFormSize -ErrorAction SilentlyContinue)) {
                    $loaded.Application | Add-Member -MemberType NoteProperty -Name MainFormSize -Value (@{ Width = 1200; Height = 800 }) -Force
                }
                if (-not (Get-Member -InputObject $loaded.Application -Name MinFormSize -ErrorAction SilentlyContinue)) {
                    $loaded.Application | Add-Member -MemberType NoteProperty -Name MinFormSize -Value (@{ Width = 800; Height = 600 }) -Force
                }

                $minWidth = 800
                $minHeight = 600
                try {
                    if ($loaded.Application.MinFormSize.Width -gt 0) { $minWidth = [int]$loaded.Application.MinFormSize.Width }
                } catch {}
                try {
                    if ($loaded.Application.MinFormSize.Height -gt 0) { $minHeight = [int]$loaded.Application.MinFormSize.Height }
                } catch {}

                $mainWidth = 1200
                $mainHeight = 800
                try {
                    if ($loaded.Application.MainFormSize.Width -gt 0) { $mainWidth = [int]$loaded.Application.MainFormSize.Width }
                } catch {}
                try {
                    if ($loaded.Application.MainFormSize.Height -gt 0) { $mainHeight = [int]$loaded.Application.MainFormSize.Height }
                } catch {}

                if ($mainWidth -lt $minWidth) { $mainWidth = $minWidth }
                if ($mainHeight -lt $minHeight) { $mainHeight = $minHeight }

                try { $loaded.Application.MinFormSize.Width = $minWidth } catch {}
                try { $loaded.Application.MinFormSize.Height = $minHeight } catch {}
                try { $loaded.Application.MainFormSize.Width = $mainWidth } catch {}
                try { $loaded.Application.MainFormSize.Height = $mainHeight } catch {}
            } catch {}
            
            if (-not $loaded.Connections) {
                $loaded | Add-Member -MemberType NoteProperty -Name Connections -Value (@{
                        VNCPath           = "C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe"
                        RDPTimeout        = 30
                        VNCTimeout        = 30
                        VNCPassword       = ""
                        VNCViewOnly       = $true
                    }) -Force
            } else {
                # Validate and fix known keys; preserve unknown keys
                $conn = $loaded.Connections
                $rdpTimeout = if ($conn.RDPTimeout -lt 5) { 30 } else { $conn.RDPTimeout }
                $vncTimeout = if ($conn.VNCTimeout -lt 5) { 30 } else { $conn.VNCTimeout }
                $vncPath = if ([string]::IsNullOrEmpty($conn.VNCPath)) { "C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe" } else { $conn.VNCPath }
                $vncPassword = if ($null -ne $conn.VNCPassword) { [string]$conn.VNCPassword } else { "" }
                $vncViewOnly = if ($null -ne $conn.VNCViewOnly) { [bool]$conn.VNCViewOnly } else { $true }
                $knownConn = @{
                    VNCPath           = $vncPath
                    RDPTimeout        = $rdpTimeout
                    VNCTimeout        = $vncTimeout
                    VNCPassword       = $vncPassword
                    VNCViewOnly       = $vncViewOnly
                }
                $newConn = @{}
                foreach ($k in $knownConn.Keys) { $newConn[$k] = $knownConn[$k] }
                if ($conn -is [hashtable]) {
                    foreach ($k in $conn.Keys) { if ($k -notin $knownConn.Keys) { $newConn[$k] = $conn[$k] } }
                } else {
                    foreach ($p in $conn.PSObject.Properties) { if ($p.Name -notin $knownConn.Keys) { $newConn[$p.Name] = $p.Value } }
                }
                $loaded.Connections = $newConn
            }
            
            if (-not $loaded.AD) {
                $loaded | Add-Member -MemberType NoteProperty -Name AD -Value (@{ 
                    ADSyncDC = ""; 
                    ADSyncScriptPath = "";
                    PreferredDomainControllers = @();
                    UserBaseOU = @();
                    ComputerBaseOU = @();
                    GroupBaseOU = @();
                    ServerBaseOU = @()
                }) -Force
            } else {
                # Validate and fix AD values (leave empty if not set; user configures via settings)
                if (-not (Get-Member -InputObject $loaded.AD -Name ADSyncDC -ErrorAction SilentlyContinue)) {
                    $loaded.AD | Add-Member -MemberType NoteProperty -Name ADSyncDC -Value "" -Force
                }
                if (-not (Get-Member -InputObject $loaded.AD -Name ADSyncScriptPath -ErrorAction SilentlyContinue)) {
                    $loaded.AD | Add-Member -MemberType NoteProperty -Name ADSyncScriptPath -Value "" -Force
                }
                if (-not (Get-Member -InputObject $loaded.AD -Name PreferredDomainControllers -ErrorAction SilentlyContinue)) {
                    $loaded.AD | Add-Member -MemberType NoteProperty -Name PreferredDomainControllers -Value @() -Force
                }
                
                # Ensure base OU properties exist
                if (-not (Get-Member -InputObject $loaded.AD -Name UserBaseOU -ErrorAction SilentlyContinue)) {
                    $loaded.AD | Add-Member -MemberType NoteProperty -Name UserBaseOU -Value @() -Force
                }
                
                if (-not (Get-Member -InputObject $loaded.AD -Name ComputerBaseOU -ErrorAction SilentlyContinue)) {
                    $loaded.AD | Add-Member -MemberType NoteProperty -Name ComputerBaseOU -Value @() -Force
                }
                
                if (-not (Get-Member -InputObject $loaded.AD -Name GroupBaseOU -ErrorAction SilentlyContinue)) {
                    $loaded.AD | Add-Member -MemberType NoteProperty -Name GroupBaseOU -Value @() -Force
                }

                if (-not (Get-Member -InputObject $loaded.AD -Name ServerBaseOU -ErrorAction SilentlyContinue)) {
                    $loaded.AD | Add-Member -MemberType NoteProperty -Name ServerBaseOU -Value @() -Force
                }

                # Normalize base OU and PreferredDomainControllers values to arrays
                foreach ($ouKey in @('PreferredDomainControllers','UserBaseOU','ComputerBaseOU','GroupBaseOU','ServerBaseOU')) {
                    if ($loaded.AD.PSObject.Properties[$ouKey]) {
                        $current = $loaded.AD.$ouKey
                        if ($null -eq $current) {
                            $loaded.AD.$ouKey = @()
                        } elseif ($current -is [string]) {
                            $trimmed = $current.Trim()
                            $loaded.AD.$ouKey = if ([string]::IsNullOrWhiteSpace($trimmed)) { @() } else { @($trimmed) }
                        } elseif ($current -isnot [System.Collections.IEnumerable] -or $current -is [string]) {
                            $loaded.AD.$ouKey = @()
                        } else {
                            $loaded.AD.$ouKey = @($current) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ }
                        }
                    }
                }
            }
            
            if (-not $loaded.Search) {
                $loaded | Add-Member -MemberType NoteProperty -Name Search -Value (@{ MaxSearchHistory = 20; ExactMatchDefault = $false; IncludeDisabledDefault = $false; AdvancedSearchDefault = $false }) -Force
            } else {
                # Validate and fix known keys; preserve unknown keys
                $search = $loaded.Search
                $maxHistory = if ($search.MaxSearchHistory -lt 5) { 20 } elseif ($search.MaxSearchHistory -gt 100) { 100 } else { $search.MaxSearchHistory }
                $exactMatch = if ($null -eq $search.ExactMatchDefault) { $false } else { $search.ExactMatchDefault }
                $includeDisabled = if ($null -eq $search.IncludeDisabledDefault) { $false } else { $search.IncludeDisabledDefault }
                $advancedDefault = if ($null -eq $search.AdvancedSearchDefault) { $false } else { $search.AdvancedSearchDefault }
                $knownSearch = @{
                    MaxSearchHistory = $maxHistory
                    ExactMatchDefault = $exactMatch
                    IncludeDisabledDefault = $includeDisabled
                    AdvancedSearchDefault = $advancedDefault
                }
                $newSearch = @{}
                foreach ($k in $knownSearch.Keys) { $newSearch[$k] = $knownSearch[$k] }
                if ($search -is [hashtable]) {
                    foreach ($k in $search.Keys) { if ($k -notin $knownSearch.Keys) { $newSearch[$k] = $search[$k] } }
                } else {
                    foreach ($p in $search.PSObject.Properties) { if ($p.Name -notin $knownSearch.Keys) { $newSearch[$p.Name] = $p.Value } }
                }
                $loaded.Search = $newSearch
            }
            
            if (-not $loaded.Logging) {
                $loaded | Add-Member -MemberType NoteProperty -Name Logging -Value (@{ LogPath = "$env:ProgramData\ADapp\Logs"; EnableTranscript = $true; MaxLogFileSizeMB = 10; MaxLogFiles = 5 }) -Force
            } else {
                # Validate and fix known keys; preserve unknown keys
                $log = $loaded.Logging
                $logPath = if ([string]::IsNullOrEmpty($log.LogPath)) { "$env:ProgramData\ADapp\Logs" } else { $log.LogPath }
                $maxLogSize = if ($log.MaxLogFileSizeMB -lt 1) { 10 } else { $log.MaxLogFileSizeMB }
                $maxLogFiles = if ($log.MaxLogFiles -lt 1) { 5 } else { $log.MaxLogFiles }
                $enableTranscript = if ($null -eq $log.EnableTranscript) { $true } else { $log.EnableTranscript }
                $knownLog = @{
                    LogPath = [Environment]::ExpandEnvironmentVariables($logPath)
                    EnableTranscript = $enableTranscript
                    MaxLogFileSizeMB = $maxLogSize
                    MaxLogFiles = $maxLogFiles
                    EnableConsoleLogging = if ($null -ne $log.EnableConsoleLogging) { $log.EnableConsoleLogging } else { $true }
                    EnableFileLogging = if ($null -ne $log.EnableFileLogging) { $log.EnableFileLogging } else { $true }
                }
                $newLog = @{}
                foreach ($k in $knownLog.Keys) { $newLog[$k] = $knownLog[$k] }
                if ($log -is [hashtable]) {
                    foreach ($k in $log.Keys) { if ($k -notin $knownLog.Keys) { $newLog[$k] = $log[$k] } }
                } else {
                    foreach ($p in $log.PSObject.Properties) { if ($p.Name -notin $knownLog.Keys) { $newLog[$p.Name] = $p.Value } }
                }
                $loaded.Logging = $newLog
            }

            # UI settings (theme and appearance)
            try {
                if (-not $loaded.UI) {
                    $loaded | Add-Member -MemberType NoteProperty -Name UI -Value (@{
                        SearchButtonBackColor = "#4a6fba"
                        SearchButtonForeColor = "#ffffff"
                        Theme = @{
                            Mode = "System"
                            PrimaryColor = "#4a6fba"
                            SecondaryColor = "#f0f0f0"
                            BackgroundColor = "#ffffff"
                            TextColor = "#333333"
                        }
                        ThemeDark = @{
                            PrimaryColor = "#3a3a3a"
                            SecondaryColor = "#4a4a4a"
                            BackgroundColor = "#323232"
                            TextColor = "#f0f0f0"
                        }
                    }) -Force
                } else {
                    # Ensure Theme exists
                    if (-not $loaded.UI.Theme) {
                        $loaded.UI | Add-Member -MemberType NoteProperty -Name Theme -Value (@{
                            Mode = "System"
                            PrimaryColor = "#4a6fba"
                            SecondaryColor = "#f0f0f0"
                            BackgroundColor = "#ffffff"
                            TextColor = "#333333"
                        }) -Force
                    } else {
                        # Backfill Mode if missing/empty
                        if ([string]::IsNullOrWhiteSpace([string]$loaded.UI.Theme.Mode)) {
                            try { $loaded.UI.Theme | Add-Member -MemberType NoteProperty -Name Mode -Value "System" -Force } catch { $loaded.UI.Theme.Mode = "System" }
                        }
                        # Backfill light palette if any fields missing
                        if (-not $loaded.UI.Theme.PrimaryColor) { $loaded.UI.Theme.PrimaryColor = "#4a6fba" }
                        if (-not $loaded.UI.Theme.SecondaryColor) { $loaded.UI.Theme.SecondaryColor = "#f0f0f0" }
                        if (-not $loaded.UI.Theme.BackgroundColor) { $loaded.UI.Theme.BackgroundColor = "#ffffff" }
                        if (-not $loaded.UI.Theme.TextColor) { $loaded.UI.Theme.TextColor = "#333333" }
                    }

                    # Ensure ThemeDark exists (optional)
                    if (-not $loaded.UI.ThemeDark) {
                        $loaded.UI | Add-Member -MemberType NoteProperty -Name ThemeDark -Value (@{
                            PrimaryColor = "#3a3a3a"
                            SecondaryColor = "#4a4a4a"
                            BackgroundColor = "#323232"
                            TextColor = "#f0f0f0"
                        }) -Force
                    } else {
                        if (-not $loaded.UI.ThemeDark.PrimaryColor) { $loaded.UI.ThemeDark.PrimaryColor = "#3a3a3a" }
                        if (-not $loaded.UI.ThemeDark.SecondaryColor) { $loaded.UI.ThemeDark.SecondaryColor = "#4a4a4a" }
                        if (-not $loaded.UI.ThemeDark.BackgroundColor) { $loaded.UI.ThemeDark.BackgroundColor = "#323232" }
                        if (-not $loaded.UI.ThemeDark.TextColor) { $loaded.UI.ThemeDark.TextColor = "#f0f0f0" }
                    }
                }
            } catch {}

            # Data settings (preserve unknown keys)
            if (-not $loaded.Data) {
                $loaded | Add-Member -MemberType NoteProperty -Name Data -Value (@{ PreferredSharedPath = "" }) -Force
            } else {
                $data = $loaded.Data
                $pref = if ($null -eq $data.PreferredSharedPath) { "" } else { [string]$data.PreferredSharedPath }
                $expanded = if ([string]::IsNullOrWhiteSpace($pref)) { "" } else { [Environment]::ExpandEnvironmentVariables($pref) }
                $knownData = @{ PreferredSharedPath = $expanded }
                $newData = @{}
                foreach ($k in $knownData.Keys) { $newData[$k] = $knownData[$k] }
                if ($data -is [hashtable]) {
                    foreach ($k in $data.Keys) { if ($k -notin $knownData.Keys) { $newData[$k] = $data[$k] } }
                } else {
                    foreach ($p in $data.PSObject.Properties) { if ($p.Name -notin $knownData.Keys) { $newData[$p.Name] = $p.Value } }
                }
                $loaded.Data = $newData
            }
            
            if (-not $loaded.PDQ) {
                $loaded | Add-Member -MemberType NoteProperty -Name PDQ -Value (@{ ReportFolder = ""; ReportFilePattern = "Logged in User.csv"; Enabled = $true }) -Force
            }
            # PDQ Inventory CLI settings (backwards compatible; may be missing in older settings)
            try {
                $cliDefaults = @{
                    Enabled = $false
                    ExecutablePath = "C:\Program Files (x86)\Admin Arsenal\PDQ Inventory\PDQInventory.exe"
                    CacheTimeoutMinutes = 15
                    AutoQueryOnSelection = $true
                    AutoQueryOnSearch = $false
                    AutoQueryMaxResults = 5
                }
                if ($loaded.PDQ) {
                    if (-not $loaded.PDQ.InventoryCLI) {
                        # Add as hashtable so it stays consistent with other normalized sections
                        $loaded.PDQ | Add-Member -MemberType NoteProperty -Name InventoryCLI -Value (@{} + $cliDefaults) -Force
                    } elseif ($loaded.PDQ.InventoryCLI -is [hashtable]) {
                        foreach ($k in $cliDefaults.Keys) {
                            if (-not $loaded.PDQ.InventoryCLI.ContainsKey($k)) { $loaded.PDQ.InventoryCLI[$k] = $cliDefaults[$k] }
                        }
                    } else {
                        foreach ($k in $cliDefaults.Keys) {
                            if (-not ($loaded.PDQ.InventoryCLI.PSObject.Properties.Name -contains $k)) {
                                $loaded.PDQ.InventoryCLI | Add-Member -MemberType NoteProperty -Name $k -Value $cliDefaults[$k] -Force
                            }
                        }
                    }
                }
            } catch {}
            
            if (-not $loaded.QUser) {
                $loaded | Add-Member -MemberType NoteProperty -Name QUser -Value (@{ Enabled = $true; CacheAgeMinutes = 5; TimeoutSeconds = 10; MaxComputersPerQuery = 50; EnableHistoricalTracking = $true; HistoricalDaysToKeep = 30; UseInvokeCommandFallback = $false }) -Force
            } else {
                # Validate and fix known keys; preserve unknown keys
                $quser = $loaded.QUser
                $cacheAge = if ($quser.CacheAgeMinutes -lt 1) { 5 } elseif ($quser.CacheAgeMinutes -gt 60) { 60 } else { $quser.CacheAgeMinutes }
                $timeout = if ($quser.TimeoutSeconds -lt 5) { 10 } elseif ($quser.TimeoutSeconds -gt 60) { 60 } else { $quser.TimeoutSeconds }
                $maxComputers = if ($quser.MaxComputersPerQuery -lt 10) { 50 } elseif ($quser.MaxComputersPerQuery -gt 200) { 200 } else { $quser.MaxComputersPerQuery }
                $enabled = if ($null -eq $quser.Enabled) { $true } else { $quser.Enabled }
                $enableHistorical = if ($null -eq $quser.EnableHistoricalTracking) { $true } else { $quser.EnableHistoricalTracking }
                $daysToKeep = if ($quser.HistoricalDaysToKeep -lt 7) { 30 } elseif ($quser.HistoricalDaysToKeep -gt 365) { 365 } else { $quser.HistoricalDaysToKeep }
                $useInvokeFallback = if ($null -eq $quser.UseInvokeCommandFallback) { $false } else { [bool]$quser.UseInvokeCommandFallback }
                $knownQUser = @{
                    Enabled = $enabled
                    CacheAgeMinutes = $cacheAge
                    TimeoutSeconds = $timeout
                    MaxComputersPerQuery = $maxComputers
                    EnableHistoricalTracking = $enableHistorical
                    HistoricalDaysToKeep = if ($quser.HistoricalDaysToKeep) { $daysToKeep } else { 30 }
                    UseInvokeCommandFallback = $useInvokeFallback
                }
                $newQUser = @{}
                foreach ($k in $knownQUser.Keys) { $newQUser[$k] = $knownQUser[$k] }
                if ($quser -is [hashtable]) {
                    foreach ($k in $quser.Keys) { if ($k -notin $knownQUser.Keys) { $newQUser[$k] = $quser[$k] } }
                } else {
                    foreach ($p in $quser.PSObject.Properties) { if ($p.Name -notin $knownQUser.Keys) { $newQUser[$p.Name] = $p.Value } }
                }
                $loaded.QUser = $newQUser
            }
            
            # Printers settings (preserve unknown keys)
            if (-not $loaded.Printers) {
                $loaded | Add-Member -MemberType NoteProperty -Name Printers -Value (@{ PrintServer = "" }) -Force
            } else {
                $printers = $loaded.Printers
                $printServer = if ($null -eq $printers.PrintServer) { "" } else { [string]$printers.PrintServer }
                $knownPrinters = @{ PrintServer = $printServer }
                $newPrinters = @{}
                foreach ($k in $knownPrinters.Keys) { $newPrinters[$k] = $knownPrinters[$k] }
                if ($printers -is [hashtable]) {
                    foreach ($k in $printers.Keys) { if ($k -notin $knownPrinters.Keys) { $newPrinters[$k] = $printers[$k] } }
                } else {
                    foreach ($p in $printers.PSObject.Properties) { if ($p.Name -notin $knownPrinters.Keys) { $newPrinters[$p.Name] = $p.Value } }
                }
                $loaded.Printers = $newPrinters
            }

            # Monitor settings (preserve unknown keys)
            if (-not $loaded.Monitor) {
                $loaded | Add-Member -MemberType NoteProperty -Name Monitor -Value (@{
                    StartWithWindows       = $false
                    StartMinimized         = $false
                    CloseToTray            = $false
                    ShowTrackedByDefault   = $true
                }) -Force
            } else {
                $mon = $loaded.Monitor
                $knownMonitor = @{
                    StartWithWindows = if ($null -eq $mon.StartWithWindows) { $false } else { [bool]$mon.StartWithWindows }
                    StartMinimized = if ($null -eq $mon.StartMinimized) { $false } else { [bool]$mon.StartMinimized }
                    CloseToTray = if ($null -eq $mon.CloseToTray) { $false } else { [bool]$mon.CloseToTray }
                    ShowTrackedByDefault = if ($null -eq $mon.ShowTrackedByDefault) { $true } else { [bool]$mon.ShowTrackedByDefault }
                }
                $newMonitor = @{}
                foreach ($k in $knownMonitor.Keys) { $newMonitor[$k] = $knownMonitor[$k] }
                if ($mon -is [hashtable]) {
                    foreach ($k in $mon.Keys) { if ($k -notin $knownMonitor.Keys) { $newMonitor[$k] = $mon[$k] } }
                } else {
                    foreach ($p in $mon.PSObject.Properties) { if ($p.Name -notin $knownMonitor.Keys) { $newMonitor[$p.Name] = $p.Value } }
                }
                $loaded.Monitor = $newMonitor
            }

            # Shortcuts settings (preserve unknown keys)
            $defaultShortcuts = @{ 
                FocusSearch = "Ctrl+F"; 
                NewSearch = "Ctrl+N"; 
                ClearFilters = "Esc"; 
                ConnectRDP = "Ctrl+Alt+R"; 
                ConnectVNC = "Ctrl+Alt+V";
                ConnectPing = "Ctrl+Alt+P"
            }
            if (-not $loaded.Shortcuts) {
                $loaded | Add-Member -MemberType NoteProperty -Name Shortcuts -Value $defaultShortcuts -Force
            } else {
                $short = $loaded.Shortcuts
                $knownShort = @{
                    FocusSearch = if ($short.FocusSearch) { [string]$short.FocusSearch } else { $defaultShortcuts.FocusSearch }
                    NewSearch   = if ($short.NewSearch)   { [string]$short.NewSearch }   else { $defaultShortcuts.NewSearch }
                    ClearFilters= if ($short.ClearFilters){ [string]$short.ClearFilters }else { $defaultShortcuts.ClearFilters }
                    ConnectRDP  = if ($short.ConnectRDP)  { [string]$short.ConnectRDP }  else { $defaultShortcuts.ConnectRDP }
                    ConnectVNC  = if ($short.ConnectVNC)  { [string]$short.ConnectVNC }  else { $defaultShortcuts.ConnectVNC }
                    ConnectPing = if ($short.ConnectPing) { [string]$short.ConnectPing } else { $defaultShortcuts.ConnectPing }
                }
                $newShort = @{}
                foreach ($k in $knownShort.Keys) { $newShort[$k] = $knownShort[$k] }
                if ($short -is [hashtable]) {
                    foreach ($k in $short.Keys) { if ($k -notin $knownShort.Keys) { $newShort[$k] = $short[$k] } }
                } else {
                    foreach ($p in $short.PSObject.Properties) { if ($p.Name -notin $knownShort.Keys) { $newShort[$p.Name] = $p.Value } }
                }
                $loaded.Shortcuts = $newShort
            }
            
            # Merge settings.local.json if present (machine-specific secrets/overrides, not committed to git)
            try {
                $localConfigDir = Join-Path -Path $env:ProgramData -ChildPath "ADapp\config"
                $localOverridePath = Join-Path -Path $localConfigDir -ChildPath "settings.local.json"
                # One-time migration if local override exists in app config dir
                $legacyOverridePath = Join-Path -Path $configDir -ChildPath "settings.local.json"
                try {
                    if (-not (Test-Path $localConfigDir)) { New-Item -ItemType Directory -Path $localConfigDir -Force | Out-Null }
                } catch {}
                if (-not (Test-Path $localOverridePath) -and (Test-Path $legacyOverridePath)) {
                    try {
                        Copy-Item -Path $legacyOverridePath -Destination $localOverridePath -Force
                        Remove-Item -Path $legacyOverridePath -Force -ErrorAction SilentlyContinue
                    } catch {}
                }
                if (Test-Path $localOverridePath) {
                    $localOverride = Get-Content -Path $localOverridePath -Raw | ConvertFrom-Json
                    if ($localOverride) {
                        foreach ($p in $localOverride.PSObject.Properties) {
                            if ($p.Value -is [PSCustomObject]) {
                                # Merge nested objects
                                if (-not $loaded.PSObject.Properties[$p.Name]) {
                                    $loaded | Add-Member -MemberType NoteProperty -Name $p.Name -Value $p.Value -Force
                                } else {
                                    foreach ($np in $p.Value.PSObject.Properties) {
                                        try { $loaded.($p.Name) | Add-Member -MemberType NoteProperty -Name $np.Name -Value $np.Value -Force } catch {}
                                    }
                                }
                            } else {
                                try { $loaded | Add-Member -MemberType NoteProperty -Name $p.Name -Value $p.Value -Force } catch {}
                            }
                        }
                    }
                }
            } catch {}

            # Apply environment variable overrides (format: ADAPP_SECTION_KEY, e.g., ADAPP_CONNECTIONS_VNCPASSWORD)
            try {
                $envVNCPassword = $env:ADAPP_CONNECTIONS_VNCPASSWORD
                if (-not [string]::IsNullOrEmpty($envVNCPassword)) {
                    if (-not $loaded.Connections) { $loaded | Add-Member -MemberType NoteProperty -Name Connections -Value @{} -Force }
                    if ($loaded.Connections -is [hashtable]) {
                        $loaded.Connections['VNCPassword'] = $envVNCPassword
                    } else {
                        $loaded.Connections | Add-Member -MemberType NoteProperty -Name VNCPassword -Value $envVNCPassword -Force
                    }
                }
            } catch {}

            # Backfill PDQ Inventory CLI defaults again after merging shared settings (shared file may replace the PDQ object)
            try {
                $cliDefaults = @{
                    Enabled = $false
                    ExecutablePath = "C:\Program Files (x86)\Admin Arsenal\PDQ Inventory\PDQInventory.exe"
                    CacheTimeoutMinutes = 15
                    AutoQueryOnSelection = $true
                    AutoQueryOnSearch = $false
                    AutoQueryMaxResults = 5
                }
                if ($loaded.PDQ) {
                    if (-not $loaded.PDQ.InventoryCLI) {
                        $loaded.PDQ | Add-Member -MemberType NoteProperty -Name InventoryCLI -Value (@{} + $cliDefaults) -Force
                    } elseif ($loaded.PDQ.InventoryCLI -is [hashtable]) {
                        foreach ($k in $cliDefaults.Keys) {
                            if (-not $loaded.PDQ.InventoryCLI.ContainsKey($k)) { $loaded.PDQ.InventoryCLI[$k] = $cliDefaults[$k] }
                        }
                    } else {
                        foreach ($k in $cliDefaults.Keys) {
                            if (-not ($loaded.PDQ.InventoryCLI.PSObject.Properties.Name -contains $k)) {
                                $loaded.PDQ.InventoryCLI | Add-Member -MemberType NoteProperty -Name $k -Value $cliDefaults[$k] -Force
                            }
                        }
                    }
                }
            } catch {}

            # Backfill UI Theme defaults again after merging shared settings (deep properties may have been replaced)
            try {
                if (-not $loaded.UI) {
                    $loaded | Add-Member -MemberType NoteProperty -Name UI -Value (@{}) -Force
                }
                if (-not $loaded.UI.Theme) {
                    $loaded.UI | Add-Member -MemberType NoteProperty -Name Theme -Value (@{}) -Force
                }
                if ([string]::IsNullOrWhiteSpace([string]$loaded.UI.Theme.Mode)) {
                    try { $loaded.UI.Theme | Add-Member -MemberType NoteProperty -Name Mode -Value "System" -Force } catch { $loaded.UI.Theme.Mode = "System" }
                }
                if (-not $loaded.UI.Theme.PrimaryColor) { $loaded.UI.Theme.PrimaryColor = "#4a6fba" }
                if (-not $loaded.UI.Theme.SecondaryColor) { $loaded.UI.Theme.SecondaryColor = "#f0f0f0" }
                if (-not $loaded.UI.Theme.BackgroundColor) { $loaded.UI.Theme.BackgroundColor = "#ffffff" }
                if (-not $loaded.UI.Theme.TextColor) { $loaded.UI.Theme.TextColor = "#333333" }

                if (-not $loaded.UI.ThemeDark) {
                    $loaded.UI | Add-Member -MemberType NoteProperty -Name ThemeDark -Value (@{}) -Force
                }
                if (-not $loaded.UI.ThemeDark.PrimaryColor) { $loaded.UI.ThemeDark.PrimaryColor = "#3a3a3a" }
                if (-not $loaded.UI.ThemeDark.SecondaryColor) { $loaded.UI.ThemeDark.SecondaryColor = "#4a4a4a" }
                if (-not $loaded.UI.ThemeDark.BackgroundColor) { $loaded.UI.ThemeDark.BackgroundColor = "#323232" }
                if (-not $loaded.UI.ThemeDark.TextColor) { $loaded.UI.ThemeDark.TextColor = "#f0f0f0" }
            } catch {}

            return $loaded
        }
        catch {
            Write-Warning "Error loading settings: $_"
            return @{ 
                Application = @{ Title = "AD Search Tool"; Version = "1.0.15" }
                Connections = @{ VNCPath = "C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe"; RDPTimeout = 30; VNCTimeout = 30; VNCPassword = ""; VNCViewOnly = $true }
                AD = @{ ADSyncDC = ""; ADSyncScriptPath = ""; PreferredDomainControllers = @() }
                Search = @{ MaxSearchHistory = 20; ExactMatchDefault = $false; IncludeDisabledDefault = $false }
                Logging = @{ LogPath = "$env:ProgramData\ADapp\Logs"; EnableTranscript = $true; MaxLogFileSizeMB = 10; MaxLogFiles = 5 }
                PDQ = @{ ReportFolder = ""; ReportFilePattern = "Logged in User.csv"; Enabled = $true }
                QUser = @{ Enabled = $true; CacheAgeMinutes = 5; TimeoutSeconds = 10; MaxComputersPerQuery = 50; EnableHistoricalTracking = $true; HistoricalDaysToKeep = 30 }
                Printers = @{ PrintServer = "" }
            }
        }
    }
}

function Get-SanitizedSettingsForShared {
    <#
    .SYNOPSIS
        Returns a sanitized copy of settings safe to store in shared locations.
    .DESCRIPTION
        Clones the provided settings via JSON round-trip and strips secrets
        (such as VNCPassword) so the shared settings.json cannot persist
        sensitive values.
    .PARAMETER Settings
        The settings object to sanitize.
    .OUTPUTS
        PSCustomObject
        A sanitized clone of the settings.
    .EXAMPLE
        $safe = Get-SanitizedSettingsForShared -Settings $Settings
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Settings
    )
    try {
        # Deep clone to avoid mutating caller
        $clone = $Settings | ConvertTo-Json -Depth 7 | ConvertFrom-Json
        if ($clone -and $clone.Connections) {
            $clone.Connections.VNCPassword = ""
        }
        return $clone
    } catch {
        return $Settings
    }
}

function Save-Settings {
    <#
    .SYNOPSIS
        Persists settings to shared and local configuration files.
    .DESCRIPTION
        Writes sanitized settings to the active shared settings.json, then
        persists secrets into %ProgramData%\ADapp\config\settings.local.json.
        The app-dir config/settings.json is treated as read-only defaults and
        is not updated. Also triggers shared data sync when available.
    .PARAMETER Settings
        The settings object to save.
    .PARAMETER ScriptPath
        Application root path used to locate the config folder.
    .OUTPUTS
        None
    .EXAMPLE
        Save-Settings -Settings $Settings -ScriptPath $PSScriptRoot
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Settings,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )
    $localSharedDir = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
    try { if (-not (Test-Path $localSharedDir)) { New-Item -ItemType Directory -Path $localSharedDir -Force | Out-Null } } catch {}

    $localSettingsPath = Join-Path -Path $localSharedDir -ChildPath "settings.json"
    $sanitized = Get-SanitizedSettingsForShared -Settings $Settings
    $json = $sanitized | ConvertTo-Json -Depth 7

    # Always write to local first (source for this machine; sync pushes when shared is available)
    try { $json | Out-File -FilePath $localSettingsPath -Encoding UTF8 } catch {}

    # When preferred shared path is available, push to shared if local is newer or shared does not exist
    $preferred = try { if ($Settings.Data -and $Settings.Data.PreferredSharedPath) { [Environment]::ExpandEnvironmentVariables([string]$Settings.Data.PreferredSharedPath) } else { "" } } catch { "" }
    $preferredAvailable = $false
    if (-not [string]::IsNullOrWhiteSpace($preferred)) {
        try {
            if (-not (Test-Path $preferred)) { New-Item -ItemType Directory -Path $preferred -Force | Out-Null }
        } catch {}
        $preferredAvailable = Test-Path $preferred
    }
    if ($preferredAvailable) {
        $sharedSettingsPath = Join-Path -Path $preferred -ChildPath "settings.json"
        $pushToShared = $false
        try {
            if (-not (Test-Path $sharedSettingsPath)) {
                $pushToShared = $true
            } else {
                $localWt = (Get-Item -Path $localSettingsPath -ErrorAction SilentlyContinue).LastWriteTime
                $sharedWt = (Get-Item -Path $sharedSettingsPath -ErrorAction SilentlyContinue).LastWriteTime
                if ($localWt -gt $sharedWt) { $pushToShared = $true }
            }
            if ($pushToShared) {
                $json | Out-File -FilePath $sharedSettingsPath -Encoding UTF8
            }
        } catch {}
    }

    # Persist secrets to settings.local.json (local overrides only)
    try {
        $localConfigDir = Join-Path -Path $env:ProgramData -ChildPath "ADapp\config"
        try { if (-not (Test-Path $localConfigDir)) { New-Item -ItemType Directory -Path $localConfigDir -Force | Out-Null } } catch {}
        $localOverridePath = Join-Path -Path $localConfigDir -ChildPath "settings.local.json"
        $vncPassword = ""
        try { $vncPassword = [string]$Settings.Connections.VNCPassword } catch {}

        $localOverride = $null
        if (Test-Path $localOverridePath) {
            try { $localOverride = Get-Content -Path $localOverridePath -Raw | ConvertFrom-Json } catch { $localOverride = $null }
        }
        if (-not $localOverride) { $localOverride = [PSCustomObject]@{} }

        $existingVncPassword = ""
        try { $existingVncPassword = [string]$localOverride.Connections.VNCPassword } catch { $existingVncPassword = "" }
        if ([string]::IsNullOrEmpty($vncPassword) -and -not [string]::IsNullOrEmpty($existingVncPassword)) {
            $vncPassword = $existingVncPassword
        }

        if (-not [string]::IsNullOrEmpty($vncPassword)) {
            if (-not $localOverride.Connections) {
                try { $localOverride | Add-Member -MemberType NoteProperty -Name Connections -Value @{} -Force } catch {}
            }
            try { $localOverride.Connections | Add-Member -MemberType NoteProperty -Name VNCPassword -Value $vncPassword -Force } catch { $localOverride.Connections.VNCPassword = $vncPassword }
            $localOverride | ConvertTo-Json -Depth 7 | Out-File -FilePath $localOverridePath -Encoding UTF8
        }
    } catch {}

    # Best-effort trigger shared data sync
    try { if (Get-Command Sync-SharedData -ErrorAction SilentlyContinue) { Sync-SharedData -Trigger "SettingsSaved" } } catch {}
}

function Ensure-LockedMonitorScheduledTask {
    <#
    .SYNOPSIS
        Ensures the Locked Monitor scheduled task is created or removed.
    .DESCRIPTION
        Creates or removes a per-user scheduled task that starts Locked
        Monitor at Windows logon based on the Enabled parameter.
    .PARAMETER Enabled
        Whether the scheduled task should be enabled.
    .PARAMETER AppRoot
        The root directory of the application (where LockedMonitor.exe or
        LockedMonitor.ps1 is located).
    .OUTPUTS
        System.Boolean
        $true if the task was managed successfully; $false otherwise.
    .EXAMPLE
        Ensure-LockedMonitorScheduledTask -Enabled $true -AppRoot $PSScriptRoot
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [bool]$Enabled,

        [Parameter(Mandatory = $true)]
        [string]$AppRoot
    )

    $taskName = "ADapp_LockedMonitor"
    # Use root folder (no custom TaskPath) - simpler and more reliable

    try {
        if ($Enabled) {
            # Determine executable path
            $exePath = Join-Path $AppRoot "LockedMonitor.exe"
            $scriptPath = Join-Path $AppRoot "LockedMonitor.ps1"
            
            $action = $null
            if (Test-Path $exePath) {
                # Use the exe launcher
                $action = New-ScheduledTaskAction -Execute $exePath
            } elseif (Test-Path $scriptPath) {
                # Fall back to PowerShell script
                $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NoLogo -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$scriptPath`""
            } else {
                Write-Warning "LockedMonitor.exe and LockedMonitor.ps1 not found at $AppRoot. Cannot create scheduled task."
                return $false
            }

            # Create trigger for logon
            # Note: -AtLogOn triggers on initial login only
            # Unlock support would require -OnSessionStateChange which may not be available
            # in all PowerShell versions, so we'll use -AtLogOn which is widely supported
            $trigger = New-ScheduledTaskTrigger -AtLogOn

            # Create principal for current user
            $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

            # Register the task in root folder (no custom path)
            # When TaskPath is not specified, task is created in root folder
            $registerParams = @{
                TaskName = $taskName
                Action = $action
                Trigger = $trigger
                Principal = $principal
                Description = "Starts Locked Monitor at Windows logon"
                Force = $true
            }
            Register-ScheduledTask @registerParams | Out-Null
            return $true
        } else {
            # Remove the task if it exists - try both root and custom path for compatibility
            try {
                $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if ($existingTask) {
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false | Out-Null
                    return $true
                }
            } catch {
                # Try with custom path in case it was created there
                try {
                    $existingTask = Get-ScheduledTask -TaskName "LockedMonitor" -TaskPath "\ADapp\" -ErrorAction SilentlyContinue
                    if ($existingTask) {
                        Unregister-ScheduledTask -TaskName "LockedMonitor" -TaskPath "\ADapp\" -Confirm:$false | Out-Null
                    }
                } catch {
                    # Task might not exist, which is fine
                }
            }
            return $true
        }
    } catch {
        Write-Warning "Error managing Locked Monitor scheduled task: $_"
        Write-Warning "Full error: $($_.Exception.Message)"
        return $false
    }
}

function Show-SettingsDialog {
    <#
    .SYNOPSIS
        Shows the settings UI dialog and saves changes.
    .DESCRIPTION
        Builds a multi-tab Windows Forms dialog for editing settings, persists
        changes to settings.json and settings.local.json, and updates the
        Locked Monitor scheduled task if needed.
    .PARAMETER Settings
        The settings object to edit in memory.
    .PARAMETER settingsPath
        Path to config/settings.json used to resolve the application root.
    .OUTPUTS
        None
    .EXAMPLE
        Show-SettingsDialog -Settings $Settings -settingsPath "$PSScriptRoot\config\settings.json"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Settings,

        [Parameter(Mandatory = $true)]
        [string]$settingsPath
    )

    try {
        # Ensure PDQ.InventoryCLI exists with all properties before building UI
        if ($Settings.PDQ -and -not $Settings.PDQ.InventoryCLI) {
            $Settings.PDQ | Add-Member -MemberType NoteProperty -Name InventoryCLI -Value (@{
                Enabled = $false
                ExecutablePath = ""
                CacheTimeoutMinutes = 15
                AutoQueryOnSelection = $true
                AutoQueryOnSearch = $false
                AutoQueryMaxResults = 5
            }) -Force
        }
        
        # Create main form
        $settingsForm = New-Object System.Windows.Forms.Form
        $settingsForm.Text = "Settings"
        $settingsForm.Size = New-Object System.Drawing.Size(600, 500)
        $settingsForm.StartPosition = "CenterParent"
        $settingsForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        $settingsForm.MaximizeBox = $false
        $settingsForm.MinimizeBox = $false

        # Create tab control
        $tabControl = New-Object System.Windows.Forms.TabControl
        $tabControl.Location = New-Object System.Drawing.Point(10, 10)
        $tabControl.Size = New-Object System.Drawing.Size(565, 400)
        $settingsForm.Controls.Add($tabControl)

        # === GENERAL TAB ===
        $generalTab = New-Object System.Windows.Forms.TabPage
        $generalTab.Text = "General"
        $tabControl.TabPages.Add($generalTab)

        $y = 20

        # Application Title
        $lblTitle = New-Object System.Windows.Forms.Label
        $lblTitle.Text = "Application Title:"
        $lblTitle.Location = New-Object System.Drawing.Point(10, $y)
        $lblTitle.AutoSize = $true
        $generalTab.Controls.Add($lblTitle)
        
        $txtTitle = New-Object System.Windows.Forms.TextBox
        $txtTitle.Name = "Title"
        $txtTitle.Location = New-Object System.Drawing.Point(150, $y)
        $txtTitle.Size = New-Object System.Drawing.Size(350, 20)
        $txtTitle.Text = if ($Settings.Application.Title) { $Settings.Application.Title } else { "AD Search Tool" }
        $generalTab.Controls.Add($txtTitle)
        $y += 35

        # Max Search History
        $lblHistory = New-Object System.Windows.Forms.Label
        $lblHistory.Text = "Max Search History:"
        $lblHistory.Location = New-Object System.Drawing.Point(10, $y)
        $lblHistory.AutoSize = $true
        $generalTab.Controls.Add($lblHistory)
        
        $numHistory = New-Object System.Windows.Forms.NumericUpDown
        $numHistory.Name = "MaxSearchHistory"
        $numHistory.Location = New-Object System.Drawing.Point(150, $y)
        $numHistory.Size = New-Object System.Drawing.Size(100, 20)
        $numHistory.Minimum = 5
        $numHistory.Maximum = 100
        $validValue = [Math]::Max(5, [Math]::Min(100, $Settings.Search.MaxSearchHistory))
        $numHistory.Value = $validValue
        # Update the settings object with the corrected value so it's consistent
        $Settings.Search.MaxSearchHistory = $validValue
        $generalTab.Controls.Add($numHistory)
        $y += 35

        # Search Defaults
        $chkExact = New-Object System.Windows.Forms.CheckBox
        $chkExact.Name = "ExactMatchDefault"
        $chkExact.Text = "Exact match by default"
        $chkExact.Location = New-Object System.Drawing.Point(10, $y)
        $chkExact.AutoSize = $true
        $chkExact.Checked = if ($null -ne $Settings.Search.ExactMatchDefault) { $Settings.Search.ExactMatchDefault } else { $false }
        $generalTab.Controls.Add($chkExact)
        $y += 30

        $chkDisabled = New-Object System.Windows.Forms.CheckBox
        $chkDisabled.Name = "IncludeDisabledDefault"
        $chkDisabled.Text = "Include disabled accounts by default"
        $chkDisabled.Location = New-Object System.Drawing.Point(10, $y)
        $chkDisabled.AutoSize = $true
        $chkDisabled.Checked = if ($null -ne $Settings.Search.IncludeDisabledDefault) { $Settings.Search.IncludeDisabledDefault } else { $false }
        $generalTab.Controls.Add($chkDisabled)
        $y += 30

        $chkAdvancedDefault = New-Object System.Windows.Forms.CheckBox
        $chkAdvancedDefault.Name = "AdvancedSearchDefault"
        $chkAdvancedDefault.Text = "Show advanced search options by default"
        $chkAdvancedDefault.Location = New-Object System.Drawing.Point(10, $y)
        $chkAdvancedDefault.AutoSize = $true
        $chkAdvancedDefault.Checked = if ($null -ne $Settings.Search.AdvancedSearchDefault) { $Settings.Search.AdvancedSearchDefault } else { $false }
        $generalTab.Controls.Add($chkAdvancedDefault)
        $y += 40

        # Data Folder section
        $lblDataFolder = New-Object System.Windows.Forms.Label
        $lblDataFolder.Text = "Application Data:"
        $lblDataFolder.Location = New-Object System.Drawing.Point(10, $y)
        $lblDataFolder.AutoSize = $true
        $lblDataFolder.Font = New-Object System.Drawing.Font("Segoe UI", 9.0, [System.Drawing.FontStyle]::Bold)
        $generalTab.Controls.Add($lblDataFolder)
        $y += 25

        # Open Data Folder button
        $btnOpenDataFolder = New-Object System.Windows.Forms.Button
        $btnOpenDataFolder.Text = "Open Data Folder"
        $btnOpenDataFolder.Location = New-Object System.Drawing.Point(10, $y)
        $btnOpenDataFolder.Size = New-Object System.Drawing.Size(120, 25)
        $btnOpenDataFolder.Add_Click({
            try {
                $dataPath = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
                if (Test-Path $dataPath) {
                    Start-Process "explorer.exe" -ArgumentList $dataPath
                } else {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Data folder not found at: $dataPath",
                        "Folder Not Found",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Error opening data folder: $_",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
        })
        $generalTab.Controls.Add($btnOpenDataFolder)

        # Data folder path label
        $lblDataPath = New-Object System.Windows.Forms.Label
        $dataPath = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
        $lblDataPath.Text = "Path: $dataPath"
        $lblDataPath.Location = New-Object System.Drawing.Point(140, ($y + 4))
        $lblDataPath.Size = New-Object System.Drawing.Size(350, 20)
        $lblDataPath.ForeColor = [System.Drawing.Color]::Gray
        $generalTab.Controls.Add($lblDataPath)

        $y += 30

        # Preferred shared data folder label
        $lblPreferredShared = New-Object System.Windows.Forms.Label
        $lblPreferredShared.Text = "Shared data folder:"
        $lblPreferredShared.Location = New-Object System.Drawing.Point(10, $y)
        $lblPreferredShared.AutoSize = $true
        $generalTab.Controls.Add($lblPreferredShared)

        # Preferred shared data folder textbox
        $txtPreferredShared = New-Object System.Windows.Forms.TextBox
        $txtPreferredShared.Name = "PreferredSharedPath"
        $txtPreferredShared.Location = New-Object System.Drawing.Point(150, $y)
        $txtPreferredShared.Size = New-Object System.Drawing.Size(350, 20)
        $txtPreferredShared.Text = if ($Settings.Data -and $Settings.Data.PreferredSharedPath) { $Settings.Data.PreferredSharedPath } else { "" }
        $generalTab.Controls.Add($txtPreferredShared)

        # Browse button for shared data folder
        $btnBrowseShared = New-Object System.Windows.Forms.Button
        $btnBrowseShared.Text = "..."
        $btnBrowseShared.Location = New-Object System.Drawing.Point(510, ($y - 2))
        $btnBrowseShared.Size = New-Object System.Drawing.Size(30, 24)
        $btnBrowseShared.Add_Click({
            $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
            $fbd.Description = "Select Shared Data Folder"
            if ($fbd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $txtPreferredShared.Text = $fbd.SelectedPath
            }
        })
        $generalTab.Controls.Add($btnBrowseShared)

        $y += 35

        # Open Active Data Folder button
        $btnOpenActiveData = New-Object System.Windows.Forms.Button
        $btnOpenActiveData.Text = "Open Active Data Folder"
        $btnOpenActiveData.Location = New-Object System.Drawing.Point(10, $y)
        $btnOpenActiveData.Size = New-Object System.Drawing.Size(170, 25)
        $btnOpenActiveData.Add_Click({
            try {
                if (Get-Command Open-ActiveSharedFolder -ErrorAction SilentlyContinue) {
                    Open-ActiveSharedFolder
                } else {
                    $localPath = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
                    Start-Process "explorer.exe" -ArgumentList $localPath
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Error opening active data folder: $_",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
        })
        $generalTab.Controls.Add($btnOpenActiveData)

        # Open Local Data Folder button
        $btnOpenLocalData = New-Object System.Windows.Forms.Button
        $btnOpenLocalData.Text = "Open Local Data Folder"
        $btnOpenLocalData.Location = New-Object System.Drawing.Point(190, $y)
        $btnOpenLocalData.Size = New-Object System.Drawing.Size(160, 25)
        $btnOpenLocalData.Add_Click({
            try {
                $localPath = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
                if (Test-Path $localPath) {
                    Start-Process "explorer.exe" -ArgumentList $localPath
                } else {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Local data folder not found at: $localPath",
                        "Folder Not Found",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Error opening local data folder: $_",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
        })
        $generalTab.Controls.Add($btnOpenLocalData)

        # Sync Now button
        $btnSyncNow = New-Object System.Windows.Forms.Button
        $btnSyncNow.Text = "Sync Now"
        $btnSyncNow.Location = New-Object System.Drawing.Point(360, $y)
        $btnSyncNow.Size = New-Object System.Drawing.Size(90, 25)
        $btnSyncNow.Add_Click({
            try {
                if (Get-Command Sync-SharedData -ErrorAction SilentlyContinue) {
                    Sync-SharedData -Trigger "Manual"
                    [System.Windows.Forms.MessageBox]::Show(
                        "Sync completed.",
                        "Data Sync",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    )
                } else {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Sync is unavailable (module not loaded).",
                        "Data Sync",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    )
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Error during sync: $_",
                    "Data Sync",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
        })
        $generalTab.Controls.Add($btnSyncNow)

        # === APPEARANCE TAB ===
        $appearanceTab = New-Object System.Windows.Forms.TabPage
        $appearanceTab.Text = "Appearance"
        $tabControl.TabPages.Add($appearanceTab)

        $ya = 20

        $lblThemeMode = New-Object System.Windows.Forms.Label
        $lblThemeMode.Text = "Theme mode:"
        $lblThemeMode.Location = New-Object System.Drawing.Point(10, $ya)
        $lblThemeMode.AutoSize = $true
        $appearanceTab.Controls.Add($lblThemeMode)

        $cmbThemeMode = New-Object System.Windows.Forms.ComboBox
        $cmbThemeMode.Name = "ThemeMode"
        $cmbThemeMode.Location = New-Object System.Drawing.Point(150, ($ya - 2))
        $cmbThemeMode.Size = New-Object System.Drawing.Size(220, 21)
        $cmbThemeMode.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        [void]$cmbThemeMode.Items.AddRange(@("System (follow OS)", "Light", "Dark"))
        try {
            $mode = try { if ($Settings.UI -and $Settings.UI.Theme -and $Settings.UI.Theme.Mode) { [string]$Settings.UI.Theme.Mode } else { "System" } } catch { "System" }
            switch ($mode) {
                "Light"  { $cmbThemeMode.SelectedIndex = 1 }
                "Dark"   { $cmbThemeMode.SelectedIndex = 2 }
                default   { $cmbThemeMode.SelectedIndex = 0 }
            }
        } catch { $cmbThemeMode.SelectedIndex = 0 }
        $appearanceTab.Controls.Add($cmbThemeMode)

        # === CONNECTIONS TAB ===
        $connectionsTab = New-Object System.Windows.Forms.TabPage
        $connectionsTab.Text = "Connections"
        $tabControl.TabPages.Add($connectionsTab)

        $y = 20

        # VNC Path
        $lblVNC = New-Object System.Windows.Forms.Label
        $lblVNC.Text = "VNC Viewer Path:"
        $lblVNC.Location = New-Object System.Drawing.Point(10, $y)
        $lblVNC.AutoSize = $true
        $connectionsTab.Controls.Add($lblVNC)
        
        $txtVNC = New-Object System.Windows.Forms.TextBox
        $txtVNC.Name = "VNCPath"
        $txtVNC.Location = New-Object System.Drawing.Point(10, ($y + 20))
        $txtVNC.Size = New-Object System.Drawing.Size(450, 20)
        $txtVNC.Text = if ($Settings.Connections.VNCPath) { $Settings.Connections.VNCPath } else { "C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe" }
        $connectionsTab.Controls.Add($txtVNC)
        
        $btnBrowseVNC = New-Object System.Windows.Forms.Button
        $btnBrowseVNC.Text = "Browse..."
        $btnBrowseVNC.Location = New-Object System.Drawing.Point(470, ($y + 18))
        $btnBrowseVNC.Size = New-Object System.Drawing.Size(75, 25)
        $btnBrowseVNC.Add_Click({
            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $openFileDialog.Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*"
            $openFileDialog.Title = "Select VNC Viewer"
            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $txtVNC.Text = $openFileDialog.FileName
            }
        })
        $connectionsTab.Controls.Add($btnBrowseVNC)
        $y += 50

        # VNC Password (optional)
        $lblVNCPassword = New-Object System.Windows.Forms.Label
        $lblVNCPassword.Text = "VNC Password (optional):"
        $lblVNCPassword.Location = New-Object System.Drawing.Point(10, $y)
        $lblVNCPassword.AutoSize = $true
        $connectionsTab.Controls.Add($lblVNCPassword)

        $txtVNCPassword = New-Object System.Windows.Forms.TextBox
        $txtVNCPassword.Name = "VNCPassword"
        $txtVNCPassword.Location = New-Object System.Drawing.Point(10, ($y + 20))
        $txtVNCPassword.Size = New-Object System.Drawing.Size(200, 20)
        $txtVNCPassword.UseSystemPasswordChar = $true
        $txtVNCPassword.Text = if ($Settings.Connections.VNCPassword) { [string]$Settings.Connections.VNCPassword } else { "" }
        $connectionsTab.Controls.Add($txtVNCPassword)

        # View-only toggle
        $chkVNCViewOnly = New-Object System.Windows.Forms.CheckBox
        $chkVNCViewOnly.Name = "VNCViewOnly"
        $chkVNCViewOnly.Text = "Open VNC connections in view-only mode"
        $chkVNCViewOnly.Location = New-Object System.Drawing.Point(230, ($y + 18))
        $chkVNCViewOnly.AutoSize = $true
        $chkVNCViewOnly.Checked = if ($null -ne $Settings.Connections.VNCViewOnly) { [bool]$Settings.Connections.VNCViewOnly } else { $true }
        $connectionsTab.Controls.Add($chkVNCViewOnly)

        $y += 70

        # Connection Timeouts
        $lblTimeouts = New-Object System.Windows.Forms.Label
        $lblTimeouts.Text = "Connection Timeouts (seconds):"
        $lblTimeouts.Location = New-Object System.Drawing.Point(10, $y)
        $lblTimeouts.AutoSize = $true
        $lblTimeouts.Font = New-Object System.Drawing.Font("Segoe UI", 9.0, [System.Drawing.FontStyle]::Bold)
        $connectionsTab.Controls.Add($lblTimeouts)
        $y += 30

        # RDP Timeout
        $lblRDP = New-Object System.Windows.Forms.Label
        $lblRDP.Text = "RDP Timeout:"
        $lblRDP.Location = New-Object System.Drawing.Point(20, $y)
        $lblRDP.AutoSize = $true
        $connectionsTab.Controls.Add($lblRDP)
        
        $numRDP = New-Object System.Windows.Forms.NumericUpDown
        $numRDP.Name = "RDPTimeout"
        $numRDP.Location = New-Object System.Drawing.Point(150, $y)
        $numRDP.Size = New-Object System.Drawing.Size(80, 20)
        $numRDP.Minimum = 5
        $numRDP.Maximum = 300
        $validRDPTimeout = [Math]::Max(5, [Math]::Min(300, $Settings.Connections.RDPTimeout))
        $numRDP.Value = $validRDPTimeout
        $Settings.Connections.RDPTimeout = $validRDPTimeout
        $connectionsTab.Controls.Add($numRDP)
        $y += 30

        # VNC Timeout
        $lblVNCTimeout = New-Object System.Windows.Forms.Label
        $lblVNCTimeout.Text = "VNC Timeout:"
        $lblVNCTimeout.Location = New-Object System.Drawing.Point(20, $y)
        $lblVNCTimeout.AutoSize = $true
        $connectionsTab.Controls.Add($lblVNCTimeout)
        
        $numVNC = New-Object System.Windows.Forms.NumericUpDown
        $numVNC.Name = "VNCTimeout"
        $numVNC.Location = New-Object System.Drawing.Point(150, $y)
        $numVNC.Size = New-Object System.Drawing.Size(80, 20)
        $numVNC.Minimum = 5
        $numVNC.Maximum = 300
        $validVNCTimeout = [Math]::Max(5, [Math]::Min(300, $Settings.Connections.VNCTimeout))
        $numVNC.Value = $validVNCTimeout
        $Settings.Connections.VNCTimeout = $validVNCTimeout
        $connectionsTab.Controls.Add($numVNC)

        # === MONITOR TAB ===
        $monitorTab = New-Object System.Windows.Forms.TabPage
        $monitorTab.Text = "Monitor"
        $tabControl.TabPages.Add($monitorTab)

        $y = 20

        # Start with Windows
        $chkStartWithWindows = New-Object System.Windows.Forms.CheckBox
        $chkStartWithWindows.Name = "MonitorStartWithWindows"
        $chkStartWithWindows.Text = "Start Locked Monitor at Windows logon"
        $chkStartWithWindows.Location = New-Object System.Drawing.Point(10, $y)
        $chkStartWithWindows.AutoSize = $true
        $chkStartWithWindows.Checked = if ($null -ne $Settings.Monitor -and $null -ne $Settings.Monitor.StartWithWindows) { $Settings.Monitor.StartWithWindows } else { $false }
        $monitorTab.Controls.Add($chkStartWithWindows)
        $y += 35

        # Start minimized
        $chkStartMinimized = New-Object System.Windows.Forms.CheckBox
        $chkStartMinimized.Name = "MonitorStartMinimized"
        $chkStartMinimized.Text = "Start minimized to tray"
        $chkStartMinimized.Location = New-Object System.Drawing.Point(10, $y)
        $chkStartMinimized.AutoSize = $true
        $chkStartMinimized.Checked = if ($null -ne $Settings.Monitor -and $null -ne $Settings.Monitor.StartMinimized) { $Settings.Monitor.StartMinimized } else { $false }
        $monitorTab.Controls.Add($chkStartMinimized)
        $y += 35

        # Close to tray
        $chkCloseToTray = New-Object System.Windows.Forms.CheckBox
        $chkCloseToTray.Name = "MonitorCloseToTray"
        $chkCloseToTray.Text = "Close button minimizes to tray"
        $chkCloseToTray.Location = New-Object System.Drawing.Point(10, $y)
        $chkCloseToTray.AutoSize = $true
        $chkCloseToTray.Checked = if ($null -ne $Settings.Monitor -and $null -ne $Settings.Monitor.CloseToTray) { $Settings.Monitor.CloseToTray } else { $false }
        $monitorTab.Controls.Add($chkCloseToTray)
        $y += 40

        # Show tracked by default
        $chkShowTrackedByDefault = New-Object System.Windows.Forms.CheckBox
        $chkShowTrackedByDefault.Name = "MonitorShowTrackedByDefault"
        $chkShowTrackedByDefault.Text = "Start with 'Show tracked' enabled"
        $chkShowTrackedByDefault.Location = New-Object System.Drawing.Point(10, $y)
        $chkShowTrackedByDefault.AutoSize = $true
        $chkShowTrackedByDefault.Checked = if ($null -ne $Settings.Monitor -and $null -ne $Settings.Monitor.ShowTrackedByDefault) { $Settings.Monitor.ShowTrackedByDefault } else { $true }
        $monitorTab.Controls.Add($chkShowTrackedByDefault)
        $y += 40

        # Help text
        $lblMonitorHelp = New-Object System.Windows.Forms.Label
        $lblMonitorHelp.Text = "Note: When 'Close to tray' is enabled, clicking the X button will minimize the monitor to the system tray instead of closing it. Use the tray icon context menu to exit."
        $lblMonitorHelp.Location = New-Object System.Drawing.Point(10, $y)
        $lblMonitorHelp.Size = New-Object System.Drawing.Size(520, 50)
        $lblMonitorHelp.ForeColor = [System.Drawing.Color]::Gray
        $lblMonitorHelp.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 8)
        $monitorTab.Controls.Add($lblMonitorHelp)

        # === SHORTCUTS TAB ===
        $shortcutsTab = New-Object System.Windows.Forms.TabPage
        $shortcutsTab.Text = "Shortcuts"
        $tabControl.TabPages.Add($shortcutsTab)

        $y = 20
        
        # Helper: normalize key event to string (local copy for dialog)
        function Normalize-ShortcutFromKeyEvent {
            param($e)
            $parts = @()
            if ($e.Control) { $parts += 'Ctrl' }
            if ($e.Alt) { $parts += 'Alt' }
            if ($e.Shift) { $parts += 'Shift' }
            $keyCode = [string]$e.KeyCode
            $map = @{ Escape='Esc'; Return='Enter'; Capital='CapsLock'; Prior='PageUp'; Next='PageDown' }
            $special = @('ShiftKey','ControlKey','Menu')
            if ($special -contains $keyCode) { return '' }
            if ($map.ContainsKey($keyCode)) { $key = $map[$keyCode] }
            elseif ($keyCode -match '^F\d{1,2}$') { $key = $keyCode }
            elseif ($keyCode -in @('Left','Right','Up','Down','Home','End','Insert','Delete','Back','Tab','Space')) {
                switch ($keyCode) { Back { $key = 'Backspace' } Tab { $key = 'Tab' } Space { $key = 'Space' } default { $key = $keyCode } }
            } else { $key = $keyCode }
            if (-not $key) { return '' }
            $parts += $key
            return ($parts -join '+')
        }

        $shortcutDefs = [ordered]@{
            FocusSearch = 'Focus search'
            NewSearch   = 'New search'
            ClearFilters= 'Clear filters'
            ConnectRDP  = 'Remote Desktop'
            ConnectVNC  = 'VNC Connection'
            ConnectPing  = 'Ping Computer'
        }

        $shortcutBoxes = @{}
        foreach ($kv in $shortcutDefs.GetEnumerator()) {
            $label = New-Object System.Windows.Forms.Label
            $label.Text = $kv.Value + ":"
            $label.Location = New-Object System.Drawing.Point(10, $y)
            $label.AutoSize = $true
            $shortcutsTab.Controls.Add($label)

            $tb = New-Object System.Windows.Forms.TextBox
            $tb.Name = "Shortcut_" + $kv.Key
            $tb.Location = New-Object System.Drawing.Point(150, ($y - 2))
            $tb.Size = New-Object System.Drawing.Size(200, 20)
            $tb.ReadOnly = $true
            $existing = try { if ($Settings.Shortcuts) { $Settings.Shortcuts.$($kv.Key) } else { $null } } catch { $null }
            if ([string]::IsNullOrWhiteSpace($existing)) {
                $defaults = @{ FocusSearch='Ctrl+F'; NewSearch='Ctrl+N'; ClearFilters='Esc'; ConnectRDP='Ctrl+Alt+R'; ConnectVNC='Ctrl+Alt+V'; ConnectPing='Ctrl+Alt+P' }
                $tb.Text = $defaults[$kv.Key]
            } else { $tb.Text = [string]$existing }
            $tb.Add_KeyDown({ param($s,$e)
                $combo = Normalize-ShortcutFromKeyEvent -e $e
                if (-not [string]::IsNullOrWhiteSpace($combo)) { $s.Text = $combo }
                $e.SuppressKeyPress = $true
            })
            $shortcutsTab.Controls.Add($tb)
            $shortcutBoxes[$kv.Key] = $tb
            $y += 35
        }

        # Reset to defaults button
        $btnResetShortcuts = New-Object System.Windows.Forms.Button
        $btnResetShortcuts.Text = "Reset to defaults"
        $btnResetShortcuts.Location = New-Object System.Drawing.Point(10, $y)
        $btnResetShortcuts.Size = New-Object System.Drawing.Size(130, 25)
        $btnResetShortcuts.Add_Click({
            $defaults = @{ FocusSearch='Ctrl+F'; NewSearch='Ctrl+N'; ClearFilters='Esc'; ConnectRDP='Ctrl+Alt+R'; ConnectVNC='Ctrl+Alt+V'; ConnectPing='Ctrl+Alt+P' }
            foreach ($k in $shortcutBoxes.Keys) { $shortcutBoxes[$k].Text = $defaults[$k] }
        })
        $shortcutsTab.Controls.Add($btnResetShortcuts)

        # === ACTIVE DIRECTORY TAB ===
        $adTab = New-Object System.Windows.Forms.TabPage
        $adTab.Text = "Active Directory"
        $adTab.AutoScroll = $true
        $tabControl.TabPages.Add($adTab)

        $y = 20

        # AD Sync DC
        $lblADDC = New-Object System.Windows.Forms.Label
        $lblADDC.Text = "AD Sync Domain Controller:"
        $lblADDC.Location = New-Object System.Drawing.Point(10, $y)
        $lblADDC.AutoSize = $true
        $adTab.Controls.Add($lblADDC)
        
        $txtADDC = New-Object System.Windows.Forms.TextBox
        $txtADDC.Name = "ADSyncDC"
        $txtADDC.Location = New-Object System.Drawing.Point(10, ($y + 20))
        $txtADDC.Size = New-Object System.Drawing.Size(300, 20)
        $txtADDC.Text = if ($Settings.AD.ADSyncDC) { $Settings.AD.ADSyncDC } else { "" }
        $adTab.Controls.Add($txtADDC)
        $y += 60

        # AD Sync Script Path
        $lblADScript = New-Object System.Windows.Forms.Label
        $lblADScript.Text = "AD Sync Script Path:"
        $lblADScript.Location = New-Object System.Drawing.Point(10, $y)
        $lblADScript.AutoSize = $true
        $adTab.Controls.Add($lblADScript)
        
        $txtADScript = New-Object System.Windows.Forms.TextBox
        $txtADScript.Name = "ADSyncScriptPath"
        $txtADScript.Location = New-Object System.Drawing.Point(10, ($y + 20))
        $txtADScript.Size = New-Object System.Drawing.Size(450, 20)
        $txtADScript.Text = if ($Settings.AD.ADSyncScriptPath) { $Settings.AD.ADSyncScriptPath } else { "" }
        $adTab.Controls.Add($txtADScript)
        
        $btnBrowseScript = New-Object System.Windows.Forms.Button
        $btnBrowseScript.Text = "Browse..."
        $btnBrowseScript.Location = New-Object System.Drawing.Point(470, ($y + 18))
        $btnBrowseScript.Size = New-Object System.Drawing.Size(75, 25)
        $btnBrowseScript.Add_Click({
            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $openFileDialog.Filter = "PowerShell scripts (*.ps1)|*.ps1|All files (*.*)|*.*"
            $openFileDialog.Title = "Select AD Sync Script"
            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $txtADScript.Text = $openFileDialog.FileName
            }
        })
        $adTab.Controls.Add($btnBrowseScript)
        $y += 60

        # Print Server
        $lblPrintServer = New-Object System.Windows.Forms.Label
        $lblPrintServer.Text = "Print Server:"
        $lblPrintServer.Location = New-Object System.Drawing.Point(10, $y)
        $lblPrintServer.AutoSize = $true
        $adTab.Controls.Add($lblPrintServer)
        
        $txtPrintServer = New-Object System.Windows.Forms.TextBox
        $txtPrintServer.Name = "PrintServer"
        $txtPrintServer.Location = New-Object System.Drawing.Point(10, ($y + 20))
        $txtPrintServer.Size = New-Object System.Drawing.Size(300, 20)
        $txtPrintServer.Text = if ($Settings.Printers -and $Settings.Printers.PrintServer) { $Settings.Printers.PrintServer } else { "" }
        $adTab.Controls.Add($txtPrintServer)
        $y += 60

        # Base OU Settings
        $lblBaseOUs = New-Object System.Windows.Forms.Label
        $lblBaseOUs.Text = "Base Organizational Units:"
        $lblBaseOUs.Location = New-Object System.Drawing.Point(10, $y)
        $lblBaseOUs.AutoSize = $true
        $lblBaseOUs.Font = New-Object System.Drawing.Font("Segoe UI", 9.0, [System.Drawing.FontStyle]::Bold)
        $adTab.Controls.Add($lblBaseOUs)
        $y += 25

        # User Base OUs
        $lblUserBaseOU = New-Object System.Windows.Forms.Label
        $lblUserBaseOU.Text = "User Base OUs (one per line):"
        $lblUserBaseOU.Location = New-Object System.Drawing.Point(10, $y)
        $lblUserBaseOU.AutoSize = $true
        $adTab.Controls.Add($lblUserBaseOU)
        
        $txtUserBaseOU = New-Object System.Windows.Forms.TextBox
        $txtUserBaseOU.Name = "UserBaseOU"
        $txtUserBaseOU.Location = New-Object System.Drawing.Point(10, ($y + 20))
        $txtUserBaseOU.Size = New-Object System.Drawing.Size(500, 60)
        $txtUserBaseOU.Multiline = $true
        $txtUserBaseOU.ScrollBars = "Vertical"
        $txtUserBaseOU.Text = if ($Settings.AD.UserBaseOU -and $Settings.AD.UserBaseOU.Count -gt 0) { ($Settings.AD.UserBaseOU -join "`r`n") } else { "" }
        $adTab.Controls.Add($txtUserBaseOU)
        $y += 90

        # Computer Base OUs
        $lblComputerBaseOU = New-Object System.Windows.Forms.Label
        $lblComputerBaseOU.Text = "Computer Base OUs (one per line):"
        $lblComputerBaseOU.Location = New-Object System.Drawing.Point(10, $y)
        $lblComputerBaseOU.AutoSize = $true
        $adTab.Controls.Add($lblComputerBaseOU)
        
        $txtComputerBaseOU = New-Object System.Windows.Forms.TextBox
        $txtComputerBaseOU.Name = "ComputerBaseOU"
        $txtComputerBaseOU.Location = New-Object System.Drawing.Point(10, ($y + 20))
        $txtComputerBaseOU.Size = New-Object System.Drawing.Size(500, 60)
        $txtComputerBaseOU.Multiline = $true
        $txtComputerBaseOU.ScrollBars = "Vertical"
        $txtComputerBaseOU.Text = if ($Settings.AD.ComputerBaseOU -and $Settings.AD.ComputerBaseOU.Count -gt 0) { ($Settings.AD.ComputerBaseOU -join "`r`n") } else { "" }
        $adTab.Controls.Add($txtComputerBaseOU)
        $y += 90

        # Group Base OUs
        $lblGroupBaseOU = New-Object System.Windows.Forms.Label
        $lblGroupBaseOU.Text = "Group Base OUs (one per line):"
        $lblGroupBaseOU.Location = New-Object System.Drawing.Point(10, $y)
        $lblGroupBaseOU.AutoSize = $true
        $adTab.Controls.Add($lblGroupBaseOU)
        
        $txtGroupBaseOU = New-Object System.Windows.Forms.TextBox
        $txtGroupBaseOU.Name = "GroupBaseOU"
        $txtGroupBaseOU.Location = New-Object System.Drawing.Point(10, ($y + 20))
        $txtGroupBaseOU.Size = New-Object System.Drawing.Size(500, 60)
        $txtGroupBaseOU.Multiline = $true
        $txtGroupBaseOU.ScrollBars = "Vertical"
        $txtGroupBaseOU.Text = if ($Settings.AD.GroupBaseOU -and $Settings.AD.GroupBaseOU.Count -gt 0) { ($Settings.AD.GroupBaseOU -join "`r`n") } else { "" }
        $adTab.Controls.Add($txtGroupBaseOU)
        $y += 90

        # Server Base OUs
        $lblServerBaseOU = New-Object System.Windows.Forms.Label
        $lblServerBaseOU.Text = "Server Base OUs (one per line):"
        $lblServerBaseOU.Location = New-Object System.Drawing.Point(10, $y)
        $lblServerBaseOU.AutoSize = $true
        $adTab.Controls.Add($lblServerBaseOU)
        
        $txtServerBaseOU = New-Object System.Windows.Forms.TextBox
        $txtServerBaseOU.Name = "ServerBaseOU"
        $txtServerBaseOU.Location = New-Object System.Drawing.Point(10, ($y + 20))
        $txtServerBaseOU.Size = New-Object System.Drawing.Size(500, 60)
        $txtServerBaseOU.Multiline = $true
        $txtServerBaseOU.ScrollBars = "Vertical"
        $txtServerBaseOU.Text = if ($Settings.AD.ServerBaseOU -and $Settings.AD.ServerBaseOU.Count -gt 0) { ($Settings.AD.ServerBaseOU -join "`r`n") } else { "" }
        $adTab.Controls.Add($txtServerBaseOU)

        # === LOGGING TAB ===
        $loggingTab = New-Object System.Windows.Forms.TabPage
        $loggingTab.Text = "Logging"
        $tabControl.TabPages.Add($loggingTab)

        $y = 20

        # Log Path
        $lblLogPath = New-Object System.Windows.Forms.Label
        $lblLogPath.Text = "Log Path:"
        $lblLogPath.Location = New-Object System.Drawing.Point(10, $y)
        $lblLogPath.AutoSize = $true
        $loggingTab.Controls.Add($lblLogPath)
        
        $txtLogPath = New-Object System.Windows.Forms.TextBox
        $txtLogPath.Name = "LogPath"
        $txtLogPath.Location = New-Object System.Drawing.Point(10, ($y + 20))
        $txtLogPath.Size = New-Object System.Drawing.Size(450, 20)
        $txtLogPath.Text = if ($Settings.Logging.LogPath) { $Settings.Logging.LogPath } else { "$env:ProgramData\ADapp\Logs" }
        $loggingTab.Controls.Add($txtLogPath)
        
        $btnBrowseLog = New-Object System.Windows.Forms.Button
        $btnBrowseLog.Text = "Browse..."
        $btnBrowseLog.Location = New-Object System.Drawing.Point(470, ($y + 18))
        $btnBrowseLog.Size = New-Object System.Drawing.Size(75, 25)
        $btnBrowseLog.Add_Click({
            $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
            $folderDialog.Description = "Select Log Folder"
            if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $txtLogPath.Text = $folderDialog.SelectedPath
            }
        })
        $loggingTab.Controls.Add($btnBrowseLog)
        $y += 70

        # Enable Transcript
        $chkTranscript = New-Object System.Windows.Forms.CheckBox
        $chkTranscript.Name = "EnableTranscript"
        $chkTranscript.Text = "Enable transcript logging"
        $chkTranscript.Location = New-Object System.Drawing.Point(10, $y)
        $chkTranscript.AutoSize = $true
        $chkTranscript.Checked = if ($null -ne $Settings.Logging.EnableTranscript) { $Settings.Logging.EnableTranscript } else { $true }
        $loggingTab.Controls.Add($chkTranscript)
        $y += 35

        # Max Log File Size
        $lblLogSize = New-Object System.Windows.Forms.Label
        $lblLogSize.Text = "Max Log File Size (MB):"
        $lblLogSize.Location = New-Object System.Drawing.Point(10, $y)
        $lblLogSize.AutoSize = $true
        $loggingTab.Controls.Add($lblLogSize)
        
        $numLogSize = New-Object System.Windows.Forms.NumericUpDown
        $numLogSize.Name = "MaxLogFileSizeMB"
        $numLogSize.Location = New-Object System.Drawing.Point(150, $y)
        $numLogSize.Size = New-Object System.Drawing.Size(80, 20)
        $numLogSize.Minimum = 1
        $numLogSize.Maximum = 1000
        $validLogSize = [Math]::Max(1, [Math]::Min(1000, $Settings.Logging.MaxLogFileSizeMB))
        $numLogSize.Value = $validLogSize
        $Settings.Logging.MaxLogFileSizeMB = $validLogSize
        $loggingTab.Controls.Add($numLogSize)
        $y += 35

        # Max Log Files
        $lblLogFiles = New-Object System.Windows.Forms.Label
        $lblLogFiles.Text = "Max Log Files:"
        $lblLogFiles.Location = New-Object System.Drawing.Point(10, $y)
        $lblLogFiles.AutoSize = $true
        $loggingTab.Controls.Add($lblLogFiles)
        
        $numLogFiles = New-Object System.Windows.Forms.NumericUpDown
        $numLogFiles.Name = "MaxLogFiles"
        $numLogFiles.Location = New-Object System.Drawing.Point(150, $y)
        $numLogFiles.Size = New-Object System.Drawing.Size(80, 20)
        $numLogFiles.Minimum = 1
        $numLogFiles.Maximum = 100
        $validLogFiles = [Math]::Max(1, [Math]::Min(100, $Settings.Logging.MaxLogFiles))
        $numLogFiles.Value = $validLogFiles
        $Settings.Logging.MaxLogFiles = $validLogFiles
        $loggingTab.Controls.Add($numLogFiles)
        $y += 35

        # Log Auto-Refresh Settings
        if (-not $Settings.Logging.PSObject.Properties['EnableLogAutoRefresh']) {
            $Settings.Logging | Add-Member -MemberType NoteProperty -Name EnableLogAutoRefresh -Value $true -Force
        }
        if (-not $Settings.Logging.PSObject.Properties['LogAutoRefreshInterval']) {
            $Settings.Logging | Add-Member -MemberType NoteProperty -Name LogAutoRefreshInterval -Value 5 -Force
        }
        if (-not $Settings.Logging.PSObject.Properties['LogViewTailLimit']) {
            $Settings.Logging | Add-Member -MemberType NoteProperty -Name LogViewTailLimit -Value 100 -Force
        }

        $chkLogAutoRefresh = New-Object System.Windows.Forms.CheckBox
        $chkLogAutoRefresh.Name = "EnableLogAutoRefresh"
        $chkLogAutoRefresh.Text = "Enable log auto-refresh"
        $chkLogAutoRefresh.Location = New-Object System.Drawing.Point(10, $y)
        $chkLogAutoRefresh.AutoSize = $true
        $chkLogAutoRefresh.Checked = $Settings.Logging.EnableLogAutoRefresh
        $loggingTab.Controls.Add($chkLogAutoRefresh)
        $y += 30

        $lblRefreshInterval = New-Object System.Windows.Forms.Label
        $lblRefreshInterval.Text = "Refresh Interval (sec):"
        $lblRefreshInterval.Location = New-Object System.Drawing.Point(10, $y)
        $lblRefreshInterval.AutoSize = $true
        $loggingTab.Controls.Add($lblRefreshInterval)

        $numRefreshInterval = New-Object System.Windows.Forms.NumericUpDown
        $numRefreshInterval.Name = "LogAutoRefreshInterval"
        $numRefreshInterval.Location = New-Object System.Drawing.Point(150, $y)
        $numRefreshInterval.Size = New-Object System.Drawing.Size(80, 20)
        $numRefreshInterval.Minimum = 1
        $numRefreshInterval.Maximum = 60
        $validInterval = [Math]::Max(1, [Math]::Min(60, $Settings.Logging.LogAutoRefreshInterval))
        $numRefreshInterval.Value = $validInterval
        $Settings.Logging.LogAutoRefreshInterval = $validInterval
        $loggingTab.Controls.Add($numRefreshInterval)
        $y += 35

        # Log Tail Limit
        $lblTailLimit = New-Object System.Windows.Forms.Label
        $lblTailLimit.Text = "Log View Tail Limit (lines):"
        $lblTailLimit.Location = New-Object System.Drawing.Point(10, $y)
        $lblTailLimit.AutoSize = $true
        $loggingTab.Controls.Add($lblTailLimit)

        $numTailLimit = New-Object System.Windows.Forms.NumericUpDown
        $numTailLimit.Name = "LogViewTailLimit"
        $numTailLimit.Location = New-Object System.Drawing.Point(150, $y)
        $numTailLimit.Size = New-Object System.Drawing.Size(80, 20)
        $numTailLimit.Minimum = 10
        $numTailLimit.Maximum = 1000
        $validTailLimit = if ($Settings.Logging.LogViewTailLimit) { [Math]::Max(10, [Math]::Min(1000, $Settings.Logging.LogViewTailLimit)) } else { 100 }
        $numTailLimit.Value = $validTailLimit
        $Settings.Logging.LogViewTailLimit = $validTailLimit
        $loggingTab.Controls.Add($numTailLimit)
        $y += 50

        # Open Logs Folder button
        $btnOpenLogsFolder = New-Object System.Windows.Forms.Button
        $btnOpenLogsFolder.Text = "Open Logs Folder"
        $btnOpenLogsFolder.Location = New-Object System.Drawing.Point(10, $y)
        $btnOpenLogsFolder.Size = New-Object System.Drawing.Size(120, 25)
        $btnOpenLogsFolder.Add_Click({
            try {
                $logsPath = if ($Settings.Logging.LogPath) { $Settings.Logging.LogPath } else { "$env:ProgramData\ADapp\Logs" }
                $expandedPath = [Environment]::ExpandEnvironmentVariables($logsPath)
                if (Test-Path $expandedPath) {
                    Start-Process "explorer.exe" -ArgumentList $expandedPath
                } else {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Logs folder not found at: $expandedPath",
                        "Folder Not Found",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    )
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Error opening logs folder: $_",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
        })
        $loggingTab.Controls.Add($btnOpenLogsFolder)

        # === PDQ TAB ===
        $pdqTab = New-Object System.Windows.Forms.TabPage
        $pdqTab.Text = "PDQ"
        $pdqTab.AutoScroll = $true
        $tabControl.TabPages.Add($pdqTab)

        $y = 20

        # PDQ Inventory Report Section Header
        $lblPDQHeader = New-Object System.Windows.Forms.Label
        $lblPDQHeader.Text = "PDQ Inventory Report Import"
        $lblPDQHeader.Location = New-Object System.Drawing.Point(10, $y)
        $lblPDQHeader.AutoSize = $true
        $lblPDQHeader.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
        $pdqTab.Controls.Add($lblPDQHeader)
        $y += 25

        # PDQ Enabled
        $chkPDQEnabled = New-Object System.Windows.Forms.CheckBox
        $chkPDQEnabled.Name = "PDQEnabled"
        $chkPDQEnabled.Text = "Enable PDQ Inventory report integration"
        $chkPDQEnabled.Location = New-Object System.Drawing.Point(10, $y)
        $chkPDQEnabled.Size = New-Object System.Drawing.Size(300, 20)
        $chkPDQEnabled.Checked = if ($null -eq $Settings.PDQ.Enabled) { $true } else { $Settings.PDQ.Enabled }
        $pdqTab.Controls.Add($chkPDQEnabled)
        $y += 30

        # PDQ Report Folder
        $lblPDQFolder = New-Object System.Windows.Forms.Label
        $lblPDQFolder.Text = "Report Folder:"
        $lblPDQFolder.Location = New-Object System.Drawing.Point(10, $y)
        $lblPDQFolder.AutoSize = $true
        $pdqTab.Controls.Add($lblPDQFolder)

        $txtPDQFolder = New-Object System.Windows.Forms.TextBox
        $txtPDQFolder.Name = "PDQReportFolder"
        $txtPDQFolder.Location = New-Object System.Drawing.Point(110, $y)
        $txtPDQFolder.Size = New-Object System.Drawing.Size(350, 20)
        $txtPDQFolder.Text = if ($Settings.PDQ.ReportFolder) { $Settings.PDQ.ReportFolder } else { "" }
        $pdqTab.Controls.Add($txtPDQFolder)

        $btnPDQBrowse = New-Object System.Windows.Forms.Button
        $btnPDQBrowse.Text = "..."
        $btnPDQBrowse.Location = New-Object System.Drawing.Point(470, ($y - 2))
        $btnPDQBrowse.Size = New-Object System.Drawing.Size(30, 24)
        $btnPDQBrowse.Add_Click({
            $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
            $fbd.Description = "Select PDQ Auto Report output folder"
            if ($fbd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $txtPDQFolder.Text = $fbd.SelectedPath
            }
        })
        $pdqTab.Controls.Add($btnPDQBrowse)
        $y += 30

        # PDQ File Pattern
        $lblPDQPattern = New-Object System.Windows.Forms.Label
        $lblPDQPattern.Text = "File Pattern:"
        $lblPDQPattern.Location = New-Object System.Drawing.Point(10, $y)
        $lblPDQPattern.AutoSize = $true
        $pdqTab.Controls.Add($lblPDQPattern)

        $txtPDQPattern = New-Object System.Windows.Forms.TextBox
        $txtPDQPattern.Name = "PDQReportFilePattern"
        $txtPDQPattern.Location = New-Object System.Drawing.Point(110, $y)
        $txtPDQPattern.Size = New-Object System.Drawing.Size(350, 20)
        $txtPDQPattern.Text = if ($Settings.PDQ.ReportFilePattern) { $Settings.PDQ.ReportFilePattern } else { "Logged in User.csv" }
        $pdqTab.Controls.Add($txtPDQPattern)
        $y += 40

        # PDQ Deploy Section
        $lblPDQDeployHeader = New-Object System.Windows.Forms.Label
        $lblPDQDeployHeader.Text = "PDQ Deploy Integration"
        $lblPDQDeployHeader.Location = New-Object System.Drawing.Point(10, $y)
        $lblPDQDeployHeader.AutoSize = $true
        $lblPDQDeployHeader.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
        $pdqTab.Controls.Add($lblPDQDeployHeader)
        $y += 25

        # PDQ Deploy Enabled
        $chkPDQDeployEnabled = New-Object System.Windows.Forms.CheckBox
        $chkPDQDeployEnabled.Name = "PDQDeployEnabled"
        $chkPDQDeployEnabled.Text = "Enable PDQ Deploy integration"
        $chkPDQDeployEnabled.Location = New-Object System.Drawing.Point(10, $y)
        $chkPDQDeployEnabled.Size = New-Object System.Drawing.Size(250, 20)
        $chkPDQDeployEnabled.Checked = if ($Settings.PDQ.Deploy -and ($null -ne $Settings.PDQ.Deploy.Enabled)) { $Settings.PDQ.Deploy.Enabled } else { $true }
        $pdqTab.Controls.Add($chkPDQDeployEnabled)
        $y += 30

        # PDQ Deploy Executable Path
        $lblPDQDeployPath = New-Object System.Windows.Forms.Label
        $lblPDQDeployPath.Text = "Executable:"
        $lblPDQDeployPath.Location = New-Object System.Drawing.Point(10, $y)
        $lblPDQDeployPath.AutoSize = $true
        $pdqTab.Controls.Add($lblPDQDeployPath)

        $txtPDQDeployPath = New-Object System.Windows.Forms.TextBox
        $txtPDQDeployPath.Name = "PDQDeployExecutablePath"
        $txtPDQDeployPath.Location = New-Object System.Drawing.Point(110, $y)
        $txtPDQDeployPath.Size = New-Object System.Drawing.Size(350, 20)
        $txtPDQDeployPath.Text = if ($Settings.PDQ.Deploy -and $Settings.PDQ.Deploy.ExecutablePath) { $Settings.PDQ.Deploy.ExecutablePath } else { "C:\\Program Files (x86)\\Admin Arsenal\\PDQ Deploy\\PDQDeploy.exe" }
        $pdqTab.Controls.Add($txtPDQDeployPath)

        $btnPDQDeployBrowse = New-Object System.Windows.Forms.Button
        $btnPDQDeployBrowse.Text = "..."
        $btnPDQDeployBrowse.Location = New-Object System.Drawing.Point(470, ($y - 2))
        $btnPDQDeployBrowse.Size = New-Object System.Drawing.Size(30, 24)
        $btnPDQDeployBrowse.Add_Click({
            $ofd = New-Object System.Windows.Forms.OpenFileDialog
            $ofd.Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*"
            $ofd.Title = "Select PDQDeploy.exe"
            if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $txtPDQDeployPath.Text = $ofd.FileName
            }
        })
        $pdqTab.Controls.Add($btnPDQDeployBrowse)
        $y += 30

        # PDQ Deploy Packages (picker UI)
        $script:PDQDeploySelectedPackages = @()
        try {
            if ($Settings.PDQ.Deploy -and $Settings.PDQ.Deploy.Packages) {
                $script:PDQDeploySelectedPackages = @($Settings.PDQ.Deploy.Packages)
            } else {
                $script:PDQDeploySelectedPackages = @()
            }
        } catch {
            $script:PDQDeploySelectedPackages = @()
        }

        $lblPDQPackages = New-Object System.Windows.Forms.Label
        $lblPDQPackages.Text = "Packages:"
        $lblPDQPackages.Location = New-Object System.Drawing.Point(10, $y)
        $lblPDQPackages.AutoSize = $true
        $pdqTab.Controls.Add($lblPDQPackages)

        $btnSelectPDQPackages = New-Object System.Windows.Forms.Button
        $btnSelectPDQPackages.Name = "PDQDeployPackagesSelectButton"
        $btnSelectPDQPackages.Text = "Select Packages..."
        $btnSelectPDQPackages.Location = New-Object System.Drawing.Point(110, ($y - 2))
        $btnSelectPDQPackages.Size = New-Object System.Drawing.Size(130, 24)
        $pdqTab.Controls.Add($btnSelectPDQPackages)

        $btnRefreshPDQPackages = New-Object System.Windows.Forms.Button
        $btnRefreshPDQPackages.Name = "PDQDeployPackagesRefreshButton"
        $btnRefreshPDQPackages.Text = "Refresh"
        $btnRefreshPDQPackages.Location = New-Object System.Drawing.Point(245, ($y - 2))
        $btnRefreshPDQPackages.Size = New-Object System.Drawing.Size(80, 24)
        $pdqTab.Controls.Add($btnRefreshPDQPackages)

        $y += 28

        $txtPDQPackagesSummary = New-Object System.Windows.Forms.TextBox
        $txtPDQPackagesSummary.Name = "PDQDeployPackagesSummary"
        $txtPDQPackagesSummary.Location = New-Object System.Drawing.Point(10, $y)
        $txtPDQPackagesSummary.Size = New-Object System.Drawing.Size(490, 60)
        $txtPDQPackagesSummary.Multiline = $true
        $txtPDQPackagesSummary.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
        $txtPDQPackagesSummary.ReadOnly = $true
        $txtPDQPackagesSummary.BackColor = [System.Drawing.SystemColors]::Window
        $pdqTab.Controls.Add($txtPDQPackagesSummary)

        $lblPDQPackagesHint = New-Object System.Windows.Forms.Label
        $lblPDQPackagesHint.Text = "Tip: These are the packages shown in the app's PDQ Deploy menu/actions."
        $lblPDQPackagesHint.Location = New-Object System.Drawing.Point(10, ($y + 62))
        $lblPDQPackagesHint.Size = New-Object System.Drawing.Size(520, 16)
        $lblPDQPackagesHint.ForeColor = [System.Drawing.Color]::Gray
        $lblPDQPackagesHint.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 8)
        $pdqTab.Controls.Add($lblPDQPackagesHint)

        $updatePDQPackagesSummary = {
            try {
                $pkgs = @($script:PDQDeploySelectedPackages | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                $txtPDQPackagesSummary.Text = ($pkgs -join "`r`n")
            } catch {
                $txtPDQPackagesSummary.Text = ""
            }
        }

        & $updatePDQPackagesSummary

        $btnSelectPDQPackages.Add_Click({
            try {
                $initial = @($script:PDQDeploySelectedPackages)
                $picked = $null
                try {
                    $picked = Show-PDQDeployPackagePickerDialog -SelectedPackages $initial -ParentForm $settingsForm
                } catch {
                    $picked = $null
                }
                # Dialog returns $null on Cancel; returns string[] (possibly empty) on OK.
                if ($null -ne $picked) {
                    $script:PDQDeploySelectedPackages = @($picked)
                    & $updatePDQPackagesSummary
                }
            } catch {}
        })

        $btnRefreshPDQPackages.Add_Click({
            try {
                try { Get-PDQDeployPackagesCached -ForceRefresh | Out-Null } catch {}
                # Re-open picker quickly after refresh if user wants, but keep this as a lightweight action.
                [System.Windows.Forms.MessageBox]::Show(
                    "PDQ package cache refreshed.",
                    "PDQ Deploy",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                ) | Out-Null
            } catch {}
        })

        $y += 85

        # PDQ Inventory CLI Section
        $lblPDQInventoryCLIHeader = New-Object System.Windows.Forms.Label
        $lblPDQInventoryCLIHeader.Text = "PDQ Inventory CLI Integration"
        $lblPDQInventoryCLIHeader.Location = New-Object System.Drawing.Point(10, $y)
        $lblPDQInventoryCLIHeader.AutoSize = $true
        $lblPDQInventoryCLIHeader.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
        $pdqTab.Controls.Add($lblPDQInventoryCLIHeader)
        $y += 25

        # PDQ Inventory CLI Enabled
        $chkPDQInventoryCLIEnabled = New-Object System.Windows.Forms.CheckBox
        $chkPDQInventoryCLIEnabled.Name = "PDQInventoryCLIEnabled"
        $chkPDQInventoryCLIEnabled.Text = "Enable PDQ Inventory CLI integration"
        $chkPDQInventoryCLIEnabled.Location = New-Object System.Drawing.Point(10, $y)
        $chkPDQInventoryCLIEnabled.Size = New-Object System.Drawing.Size(250, 20)
        $chkPDQInventoryCLIEnabled.Checked = if ($Settings.PDQ.InventoryCLI -and ($null -ne $Settings.PDQ.InventoryCLI.Enabled)) { $Settings.PDQ.InventoryCLI.Enabled } else { $true }
        $pdqTab.Controls.Add($chkPDQInventoryCLIEnabled)
        $y += 30

        # PDQ Inventory CLI Executable Path
        $lblPDQInventoryCLIPath = New-Object System.Windows.Forms.Label
        $lblPDQInventoryCLIPath.Text = "Executable:"
        $lblPDQInventoryCLIPath.Location = New-Object System.Drawing.Point(10, $y)
        $lblPDQInventoryCLIPath.AutoSize = $true
        $pdqTab.Controls.Add($lblPDQInventoryCLIPath)

        $txtPDQInventoryCLIPath = New-Object System.Windows.Forms.TextBox
        $txtPDQInventoryCLIPath.Name = "PDQInventoryCLIExecutablePath"
        $txtPDQInventoryCLIPath.Location = New-Object System.Drawing.Point(110, $y)
        $txtPDQInventoryCLIPath.Size = New-Object System.Drawing.Size(350, 20)
        $txtPDQInventoryCLIPath.Text = if ($Settings.PDQ.InventoryCLI -and $Settings.PDQ.InventoryCLI.ExecutablePath) { $Settings.PDQ.InventoryCLI.ExecutablePath } else { "C:\\Program Files (x86)\\Admin Arsenal\\PDQ Inventory\\PDQInventory.exe" }
        $pdqTab.Controls.Add($txtPDQInventoryCLIPath)

        $btnPDQInventoryCLIBrowse = New-Object System.Windows.Forms.Button
        $btnPDQInventoryCLIBrowse.Text = "..."
        $btnPDQInventoryCLIBrowse.Location = New-Object System.Drawing.Point(470, ($y - 2))
        $btnPDQInventoryCLIBrowse.Size = New-Object System.Drawing.Size(30, 24)
        $btnPDQInventoryCLIBrowse.Add_Click({
            $ofd = New-Object System.Windows.Forms.OpenFileDialog
            $ofd.Filter = "Executable Files (*.exe)|*.exe|All Files (*.*)|*.*"
            $ofd.Title = "Select PDQInventory.exe"
            if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $txtPDQInventoryCLIPath.Text = $ofd.FileName
            }
        })
        $pdqTab.Controls.Add($btnPDQInventoryCLIBrowse)
        $y += 30

        # Cache Timeout
        $lblCacheTimeout = New-Object System.Windows.Forms.Label
        $lblCacheTimeout.Text = "Cache Timeout (minutes):"
        $lblCacheTimeout.Location = New-Object System.Drawing.Point(10, $y)
        $lblCacheTimeout.AutoSize = $true
        $pdqTab.Controls.Add($lblCacheTimeout)

        $numCacheTimeout = New-Object System.Windows.Forms.NumericUpDown
        $numCacheTimeout.Name = "PDQInventoryCLICacheTimeoutMinutes"
        $numCacheTimeout.Location = New-Object System.Drawing.Point(180, $y)
        $numCacheTimeout.Size = New-Object System.Drawing.Size(60, 20)
        $numCacheTimeout.Minimum = 5
        $numCacheTimeout.Maximum = 120
        $numCacheTimeout.Value = if ($Settings.PDQ.InventoryCLI -and $Settings.PDQ.InventoryCLI.CacheTimeoutMinutes) { $Settings.PDQ.InventoryCLI.CacheTimeoutMinutes } else { 15 }
        $pdqTab.Controls.Add($numCacheTimeout)
        $y += 40
        $y += 35
        
        # Auto-query on selection
        $chkAutoQueryOnSelection = New-Object System.Windows.Forms.CheckBox
        $chkAutoQueryOnSelection.Name = "PDQInventoryCLIAutoQueryOnSelection"
        $chkAutoQueryOnSelection.Text = "Auto-query when computer is selected"
        $chkAutoQueryOnSelection.Location = New-Object System.Drawing.Point(10, $y)
        $chkAutoQueryOnSelection.Size = New-Object System.Drawing.Size(280, 20)
        $chkAutoQueryOnSelection.Checked = if ($null -eq $Settings.PDQ.InventoryCLI.AutoQueryOnSelection) { $true } else { $Settings.PDQ.InventoryCLI.AutoQueryOnSelection }
        $pdqTab.Controls.Add($chkAutoQueryOnSelection)
        $y += 30
        
        # Auto-query on search
        $chkAutoQueryOnSearch = New-Object System.Windows.Forms.CheckBox
        $chkAutoQueryOnSearch.Name = "PDQInventoryCLIAutoQueryOnSearch"
        $chkAutoQueryOnSearch.Text = "Auto-query when search completes (first max results)"
        $chkAutoQueryOnSearch.Location = New-Object System.Drawing.Point(10, $y)
        $chkAutoQueryOnSearch.Size = New-Object System.Drawing.Size(380, 20)
        $chkAutoQueryOnSearch.Checked = if ($null -eq $Settings.PDQ.InventoryCLI.AutoQueryOnSearch) { $false } else { $Settings.PDQ.InventoryCLI.AutoQueryOnSearch }
        $pdqTab.Controls.Add($chkAutoQueryOnSearch)
        $y += 30
        
        # Max results for auto-query on search
        $lblAutoQueryMax = New-Object System.Windows.Forms.Label
        $lblAutoQueryMax.Text = "Max results for auto-query:"
        $lblAutoQueryMax.Location = New-Object System.Drawing.Point(30, $y)
        $lblAutoQueryMax.AutoSize = $true
        $pdqTab.Controls.Add($lblAutoQueryMax)
        
        $numAutoQueryMax = New-Object System.Windows.Forms.NumericUpDown
        $numAutoQueryMax.Name = "PDQInventoryCLIAutoQueryMaxResults"
        $numAutoQueryMax.Location = New-Object System.Drawing.Point(200, $y)
        $numAutoQueryMax.Size = New-Object System.Drawing.Size(60, 20)
        $numAutoQueryMax.Minimum = 1
        $numAutoQueryMax.Maximum = 50
        $numAutoQueryMax.Value = if ($Settings.PDQ.InventoryCLI -and $Settings.PDQ.InventoryCLI.AutoQueryMaxResults) { $Settings.PDQ.InventoryCLI.AutoQueryMaxResults } else { 5 }
        $pdqTab.Controls.Add($numAutoQueryMax)

        # === DATA SOURCES TAB ===
        $dataSourcesTab = New-Object System.Windows.Forms.TabPage
        $dataSourcesTab.Text = "Data Sources"
        $tabControl.TabPages.Add($dataSourcesTab)

        $y = 20

        # QUser Section Header
        $lblQUserHeader = New-Object System.Windows.Forms.Label
        $lblQUserHeader.Text = "Live Sessions (QUser) Settings"
        $lblQUserHeader.Location = New-Object System.Drawing.Point(10, $y)
        $lblQUserHeader.AutoSize = $true
        $lblQUserHeader.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
        $dataSourcesTab.Controls.Add($lblQUserHeader)
        $y += 25

        # QUser Enabled
        $chkQUserEnabled = New-Object System.Windows.Forms.CheckBox
        $chkQUserEnabled.Name = "QUserEnabled"
        $chkQUserEnabled.Text = "Enable live session queries (QUser)"
        $chkQUserEnabled.Location = New-Object System.Drawing.Point(10, $y)
        $chkQUserEnabled.Size = New-Object System.Drawing.Size(250, 20)
        $chkQUserEnabled.Checked = if ($null -eq $Settings.QUser.Enabled) { $true } else { $Settings.QUser.Enabled }
        $dataSourcesTab.Controls.Add($chkQUserEnabled)
        $y += 30

        # Cache Age
        $lblCacheAge = New-Object System.Windows.Forms.Label
        $lblCacheAge.Text = "Cache Age (minutes):"
        $lblCacheAge.Location = New-Object System.Drawing.Point(10, $y)
        $lblCacheAge.AutoSize = $true
        $dataSourcesTab.Controls.Add($lblCacheAge)

        $numCacheAge = New-Object System.Windows.Forms.NumericUpDown
        $numCacheAge.Name = "QUserCacheAgeMinutes"
        $numCacheAge.Location = New-Object System.Drawing.Point(150, $y)
        $numCacheAge.Size = New-Object System.Drawing.Size(60, 20)
        $numCacheAge.Minimum = 1
        $numCacheAge.Maximum = 60
        $numCacheAge.Value = if ($Settings.QUser.CacheAgeMinutes) { $Settings.QUser.CacheAgeMinutes } else { 5 }
        $dataSourcesTab.Controls.Add($numCacheAge)
        
        # Timeout
        $lblTimeout = New-Object System.Windows.Forms.Label
        $lblTimeout.Text = "Timeout (seconds):"
        $lblTimeout.Location = New-Object System.Drawing.Point(250, $y)
        $lblTimeout.AutoSize = $true
        $dataSourcesTab.Controls.Add($lblTimeout)

        $numTimeout = New-Object System.Windows.Forms.NumericUpDown
        $numTimeout.Name = "QUserTimeoutSeconds"
        $numTimeout.Location = New-Object System.Drawing.Point(360, $y)
        $numTimeout.Size = New-Object System.Drawing.Size(60, 20)
        $numTimeout.Minimum = 5
        $numTimeout.Maximum = 60
        $numTimeout.Value = if ($Settings.QUser.TimeoutSeconds) { $Settings.QUser.TimeoutSeconds } else { 10 }
        $dataSourcesTab.Controls.Add($numTimeout)
        $y += 30

        # Historical Tracking
        $chkHistoricalTracking = New-Object System.Windows.Forms.CheckBox
        $chkHistoricalTracking.Name = "QUserEnableHistoricalTracking"
        $chkHistoricalTracking.Text = "Enable historical session tracking (like PDQ data)"
        $chkHistoricalTracking.Location = New-Object System.Drawing.Point(10, $y)
        $chkHistoricalTracking.Size = New-Object System.Drawing.Size(350, 20)
        $chkHistoricalTracking.Checked = if ($null -eq $Settings.QUser.EnableHistoricalTracking) { $true } else { $Settings.QUser.EnableHistoricalTracking }
        $dataSourcesTab.Controls.Add($chkHistoricalTracking)
        $y += 25

        # Days to keep
        $lblDaysToKeep = New-Object System.Windows.Forms.Label
        $lblDaysToKeep.Text = "Days to keep history:"
        $lblDaysToKeep.Location = New-Object System.Drawing.Point(10, $y)
        $lblDaysToKeep.AutoSize = $true
        $dataSourcesTab.Controls.Add($lblDaysToKeep)

        $numDaysToKeep = New-Object System.Windows.Forms.NumericUpDown
        $numDaysToKeep.Name = "QUserHistoricalDaysToKeep"
        $numDaysToKeep.Location = New-Object System.Drawing.Point(150, $y)
        $numDaysToKeep.Size = New-Object System.Drawing.Size(60, 20)
        $numDaysToKeep.Minimum = 7
        $numDaysToKeep.Maximum = 365
        $numDaysToKeep.Value = if ($Settings.QUser.HistoricalDaysToKeep) { $Settings.QUser.HistoricalDaysToKeep } else { 30 }
        $dataSourcesTab.Controls.Add($numDaysToKeep)
        $y += 35

        # Help text
        $lblHelp = New-Object System.Windows.Forms.Label
        $lblHelp.Text = "Note: QUser queries run on-demand when viewing computers. Historical tracking builds a record of where users have been logged in over time."
        $lblHelp.Location = New-Object System.Drawing.Point(10, $y)
        $lblHelp.Size = New-Object System.Drawing.Size(520, 40)
        $lblHelp.ForeColor = [System.Drawing.Color]::Gray
        $lblHelp.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 8)
        $dataSourcesTab.Controls.Add($lblHelp)

        # === BUTTONS ===
        $okBtn = New-Object System.Windows.Forms.Button
        $okBtn.Text = "Save"
        $okBtn.Location = New-Object System.Drawing.Point(420, 430)
        $okBtn.Size = New-Object System.Drawing.Size(75, 25)
        $okBtn.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $settingsForm.Controls.Add($okBtn)
        
        $cancelBtn = New-Object System.Windows.Forms.Button
        $cancelBtn.Text = "Cancel"
        $cancelBtn.Location = New-Object System.Drawing.Point(505, 430)
        $cancelBtn.Size = New-Object System.Drawing.Size(75, 25)
        $cancelBtn.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $settingsForm.Controls.Add($cancelBtn)
        
        $settingsForm.AcceptButton = $okBtn
        $settingsForm.CancelButton = $cancelBtn

        # Recursively searches a control tree for a control with the given Name
        function Find-ControlByName {
            param($Container, $Name)
            foreach ($control in $Container.Controls) {
                if ($control.Name -eq $Name) {
                    return $control
                }
                if ($control.Controls.Count -gt 0) {
                    $found = Find-ControlByName -Container $control -Name $Name
                    if ($found) { return $found }
                }
            }
            return $null
        }

        # Allow Enter to insert new lines in multiline OU fields
        foreach ($name in @("UserBaseOU", "ComputerBaseOU", "GroupBaseOU", "ServerBaseOU")) {
            $tb = Find-ControlByName -Container $settingsForm -Name $name
            if ($tb) {
                $tb.AcceptsReturn = $true
                $tb.AcceptsTab = $true
                $tb.Add_Enter({ $settingsForm.AcceptButton = $null })
                $tb.Add_Leave({ $settingsForm.AcceptButton = $okBtn })
            }
        }

        # Show dialog and process results
        # Capture original values used for change detection
        $originalPreferred = if ($Settings.Data) { $Settings.Data.PreferredSharedPath } else { "" }

        if ($settingsForm.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            # Update settings object - save all values (validation happens on load)
            $Settings.Application.Title = (Find-ControlByName -Container $settingsForm -Name "Title").Text
            
            $maxHistoryControl = Find-ControlByName -Container $settingsForm -Name "MaxSearchHistory"
            if ($maxHistoryControl) {
            # Ensure Search is a hashtable so we can safely add/update keys
            if (-not $Settings.Search) {
                $Settings | Add-Member -MemberType NoteProperty -Name Search -Value (@{}) -Force
            }
            if ($Settings.Search -isnot [hashtable]) {
                $normalizedSearch = @{}
                try {
                    foreach ($prop in $Settings.Search.PSObject.Properties) {
                        $normalizedSearch[$prop.Name] = $prop.Value
                    }
                } catch {}
                $Settings.Search = $normalizedSearch
            }

            $Settings.Search['MaxSearchHistory'] = [int]$maxHistoryControl.Value
            }
            $Settings.Search['ExactMatchDefault'] = (Find-ControlByName -Container $settingsForm -Name "ExactMatchDefault").Checked
            $Settings.Search['IncludeDisabledDefault'] = (Find-ControlByName -Container $settingsForm -Name "IncludeDisabledDefault").Checked
            $Settings.Search['AdvancedSearchDefault'] = (Find-ControlByName -Container $settingsForm -Name "AdvancedSearchDefault").Checked

            # Ensure Connections exists and is a hashtable so we can safely add new keys
            if (-not $Settings.Connections) {
                $Settings | Add-Member -MemberType NoteProperty -Name Connections -Value (@{}) -Force
            }
            if ($Settings.Connections -isnot [hashtable]) {
                $normalizedConnections = @{}
                try {
                    foreach ($prop in $Settings.Connections.PSObject.Properties) {
                        $normalizedConnections[$prop.Name] = $prop.Value
                    }
                } catch {}
                $Settings.Connections = $normalizedConnections
            }

            $Settings.Connections.VNCPath = (Find-ControlByName -Container $settingsForm -Name "VNCPath").Text
            $Settings.Connections.RDPTimeout = [int](Find-ControlByName -Container $settingsForm -Name "RDPTimeout").Value
            $Settings.Connections.VNCTimeout = [int](Find-ControlByName -Container $settingsForm -Name "VNCTimeout").Value
            # Optional VNC password and view-only toggle
            $vncPasswordControl = Find-ControlByName -Container $settingsForm -Name "VNCPassword"
            if ($vncPasswordControl) { $Settings.Connections.VNCPassword = [string]$vncPasswordControl.Text }
            $vncViewOnlyControl = Find-ControlByName -Container $settingsForm -Name "VNCViewOnly"
            if ($vncViewOnlyControl) { $Settings.Connections.VNCViewOnly = [bool]$vncViewOnlyControl.Checked }
            $Settings.AD.ADSyncDC = (Find-ControlByName -Container $settingsForm -Name "ADSyncDC").Text
            $Settings.AD.ADSyncScriptPath = (Find-ControlByName -Container $settingsForm -Name "ADSyncScriptPath").Text
            
            $convertOuList = {
                param([string]$text)
                if ([string]::IsNullOrWhiteSpace($text)) { return @() }
                return @(
                    $text -split '\r?\n' |
                        ForEach-Object { $_.Trim() } |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                )
            }
            
            # Ensure base OU properties exist before setting them
            if (-not (Get-Member -InputObject $Settings.AD -Name UserBaseOU -ErrorAction SilentlyContinue)) {
                $Settings.AD | Add-Member -MemberType NoteProperty -Name UserBaseOU -Value @() -Force
            }
            if (-not (Get-Member -InputObject $Settings.AD -Name ComputerBaseOU -ErrorAction SilentlyContinue)) {
                $Settings.AD | Add-Member -MemberType NoteProperty -Name ComputerBaseOU -Value @() -Force
            }
            if (-not (Get-Member -InputObject $Settings.AD -Name GroupBaseOU -ErrorAction SilentlyContinue)) {
                $Settings.AD | Add-Member -MemberType NoteProperty -Name GroupBaseOU -Value @() -Force
            }
            if (-not (Get-Member -InputObject $Settings.AD -Name ServerBaseOU -ErrorAction SilentlyContinue)) {
                $Settings.AD | Add-Member -MemberType NoteProperty -Name ServerBaseOU -Value @() -Force
            }
            
            $userBaseOUControl = Find-ControlByName -Container $settingsForm -Name "UserBaseOU"
            if ($userBaseOUControl) { $Settings.AD.UserBaseOU = & $convertOuList $userBaseOUControl.Text }
            $computerBaseOUControl = Find-ControlByName -Container $settingsForm -Name "ComputerBaseOU"
            if ($computerBaseOUControl) { $Settings.AD.ComputerBaseOU = & $convertOuList $computerBaseOUControl.Text }
            $groupBaseOUControl = Find-ControlByName -Container $settingsForm -Name "GroupBaseOU"
            if ($groupBaseOUControl) { $Settings.AD.GroupBaseOU = & $convertOuList $groupBaseOUControl.Text }
            $serverBaseOUControl = Find-ControlByName -Container $settingsForm -Name "ServerBaseOU"
            if ($serverBaseOUControl) { $Settings.AD.ServerBaseOU = & $convertOuList $serverBaseOUControl.Text }
            
            # Printers settings
            if (-not $Settings.Printers) { $Settings | Add-Member -MemberType NoteProperty -Name Printers -Value (@{ PrintServer = "" }) -Force }
            $printServerControl = Find-ControlByName -Container $settingsForm -Name "PrintServer"
            if ($printServerControl) { $Settings.Printers.PrintServer = $printServerControl.Text }
            
            $Settings.Logging.LogPath = (Find-ControlByName -Container $settingsForm -Name "LogPath").Text
            $Settings.Logging.EnableTranscript = (Find-ControlByName -Container $settingsForm -Name "EnableTranscript").Checked
            $Settings.Logging.MaxLogFileSizeMB = [int](Find-ControlByName -Container $settingsForm -Name "MaxLogFileSizeMB").Value
            $Settings.Logging.MaxLogFiles = [int](Find-ControlByName -Container $settingsForm -Name "MaxLogFiles").Value
            $Settings.Logging.EnableLogAutoRefresh = (Find-ControlByName -Container $settingsForm -Name "EnableLogAutoRefresh").Checked
            $Settings.Logging.LogAutoRefreshInterval = [int](Find-ControlByName -Container $settingsForm -Name "LogAutoRefreshInterval").Value
            $Settings.Logging.LogViewTailLimit = [int](Find-ControlByName -Container $settingsForm -Name "LogViewTailLimit").Value

            # UI Appearance
            try {
                if (-not $Settings.UI) { $Settings | Add-Member -MemberType NoteProperty -Name UI -Value (@{}) -Force }
                if (-not $Settings.UI.Theme) { $Settings.UI | Add-Member -MemberType NoteProperty -Name Theme -Value (@{}) -Force }
                $themeModeControl = Find-ControlByName -Container $settingsForm -Name "ThemeMode"
                if ($themeModeControl) {
                    $sel = [int]$themeModeControl.SelectedIndex
                    $mode = switch ($sel) { 0 { "System" } 1 { "Light" } 2 { "Dark" } default { "System" } }
                    $Settings.UI.Theme.Mode = $mode
                }
            } catch {}

            # Data settings
            if (-not $Settings.Data) { $Settings | Add-Member -MemberType NoteProperty -Name Data -Value (@{ PreferredSharedPath = "" }) -Force }
            $prefControl = Find-ControlByName -Container $settingsForm -Name "PreferredSharedPath"
            if ($prefControl) { $Settings.Data.PreferredSharedPath = $prefControl.Text }

            # Data Sources settings
            $Settings.PDQ.Enabled = (Find-ControlByName -Container $settingsForm -Name "PDQEnabled").Checked
            $Settings.PDQ.ReportFolder = (Find-ControlByName -Container $settingsForm -Name "PDQReportFolder").Text
            $Settings.PDQ.ReportFilePattern = (Find-ControlByName -Container $settingsForm -Name "PDQReportFilePattern").Text

            # PDQ Deploy settings
            if (-not $Settings.PDQ.Deploy) { $Settings.PDQ | Add-Member -MemberType NoteProperty -Name Deploy -Value (@{}) -Force }
            $Settings.PDQ.Deploy.Enabled = (Find-ControlByName -Container $settingsForm -Name "PDQDeployEnabled").Checked
            $Settings.PDQ.Deploy.ExecutablePath = (Find-ControlByName -Container $settingsForm -Name "PDQDeployExecutablePath").Text
            $Settings.PDQ.Deploy.Packages = @($script:PDQDeploySelectedPackages | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
            
            # PDQ Inventory CLI settings
            if (-not $Settings.PDQ.InventoryCLI) { 
                $Settings.PDQ | Add-Member -MemberType NoteProperty -Name InventoryCLI -Value ([PSCustomObject]@{
                    Enabled = $false
                    ExecutablePath = ""
                    CacheTimeoutMinutes = 15
                    AutoQueryOnSelection = $false
                    AutoQueryOnSearch = $false
                    AutoQueryMaxResults = 5
                }) -Force 
            } else {
                # Ensure new properties exist (InventoryCLI may be PSCustomObject or hashtable depending on how settings were loaded)
                if ($Settings.PDQ.InventoryCLI -is [hashtable]) {
                    if (-not $Settings.PDQ.InventoryCLI.ContainsKey('AutoQueryOnSelection')) { $Settings.PDQ.InventoryCLI['AutoQueryOnSelection'] = $false }
                    if (-not $Settings.PDQ.InventoryCLI.ContainsKey('AutoQueryOnSearch')) { $Settings.PDQ.InventoryCLI['AutoQueryOnSearch'] = $false }
                    if (-not $Settings.PDQ.InventoryCLI.ContainsKey('AutoQueryMaxResults')) { $Settings.PDQ.InventoryCLI['AutoQueryMaxResults'] = 5 }
                } else {
                    if (-not ($Settings.PDQ.InventoryCLI.PSObject.Properties.Name -contains 'AutoQueryOnSelection')) {
                        $Settings.PDQ.InventoryCLI | Add-Member -MemberType NoteProperty -Name AutoQueryOnSelection -Value $false -Force
                    }
                    if (-not ($Settings.PDQ.InventoryCLI.PSObject.Properties.Name -contains 'AutoQueryOnSearch')) {
                        $Settings.PDQ.InventoryCLI | Add-Member -MemberType NoteProperty -Name AutoQueryOnSearch -Value $false -Force
                    }
                    if (-not ($Settings.PDQ.InventoryCLI.PSObject.Properties.Name -contains 'AutoQueryMaxResults')) {
                        $Settings.PDQ.InventoryCLI | Add-Member -MemberType NoteProperty -Name AutoQueryMaxResults -Value 5 -Force
                    }
                }
            }
            $invCliEnabled = (Find-ControlByName -Container $settingsForm -Name "PDQInventoryCLIEnabled").Checked
            $invCliPath = (Find-ControlByName -Container $settingsForm -Name "PDQInventoryCLIExecutablePath").Text
            $invCliCache = [int](Find-ControlByName -Container $settingsForm -Name "PDQInventoryCLICacheTimeoutMinutes").Value
            $invCliAutoSel = (Find-ControlByName -Container $settingsForm -Name "PDQInventoryCLIAutoQueryOnSelection").Checked
            $invCliAutoSearch = (Find-ControlByName -Container $settingsForm -Name "PDQInventoryCLIAutoQueryOnSearch").Checked
            $invCliMax = [int](Find-ControlByName -Container $settingsForm -Name "PDQInventoryCLIAutoQueryMaxResults").Value
            if ($Settings.PDQ.InventoryCLI -is [hashtable]) {
                $Settings.PDQ.InventoryCLI['Enabled'] = [bool]$invCliEnabled
                $Settings.PDQ.InventoryCLI['ExecutablePath'] = [string]$invCliPath
                $Settings.PDQ.InventoryCLI['CacheTimeoutMinutes'] = [int]$invCliCache
                $Settings.PDQ.InventoryCLI['AutoQueryOnSelection'] = [bool]$invCliAutoSel
                $Settings.PDQ.InventoryCLI['AutoQueryOnSearch'] = [bool]$invCliAutoSearch
                $Settings.PDQ.InventoryCLI['AutoQueryMaxResults'] = [int]$invCliMax
            } else {
                $Settings.PDQ.InventoryCLI.Enabled = [bool]$invCliEnabled
                $Settings.PDQ.InventoryCLI.ExecutablePath = [string]$invCliPath
                $Settings.PDQ.InventoryCLI.CacheTimeoutMinutes = [int]$invCliCache
                $Settings.PDQ.InventoryCLI.AutoQueryOnSelection = [bool]$invCliAutoSel
                $Settings.PDQ.InventoryCLI.AutoQueryOnSearch = [bool]$invCliAutoSearch
                $Settings.PDQ.InventoryCLI.AutoQueryMaxResults = [int]$invCliMax
            }
            
            $Settings.QUser.Enabled = (Find-ControlByName -Container $settingsForm -Name "QUserEnabled").Checked
            $Settings.QUser.CacheAgeMinutes = [int](Find-ControlByName -Container $settingsForm -Name "QUserCacheAgeMinutes").Value
            $Settings.QUser.TimeoutSeconds = [int](Find-ControlByName -Container $settingsForm -Name "QUserTimeoutSeconds").Value
            $Settings.QUser.EnableHistoricalTracking = (Find-ControlByName -Container $settingsForm -Name "QUserEnableHistoricalTracking").Checked
            $Settings.QUser.HistoricalDaysToKeep = [int](Find-ControlByName -Container $settingsForm -Name "QUserHistoricalDaysToKeep").Value

            # Monitor settings
            if (-not $Settings.Monitor) { $Settings | Add-Member -MemberType NoteProperty -Name Monitor -Value (@{ StartWithWindows = $false; StartMinimized = $false; CloseToTray = $false; ShowTrackedByDefault = $true }) -Force }
            $Settings.Monitor.StartWithWindows = (Find-ControlByName -Container $settingsForm -Name "MonitorStartWithWindows").Checked
            $Settings.Monitor.StartMinimized = (Find-ControlByName -Container $settingsForm -Name "MonitorStartMinimized").Checked
            $Settings.Monitor.CloseToTray = (Find-ControlByName -Container $settingsForm -Name "MonitorCloseToTray").Checked
            $showTrackedDefaultChecked = (Find-ControlByName -Container $settingsForm -Name "MonitorShowTrackedByDefault").Checked
            # Ensure the new setting exists before we set it (handles older settings objects already in memory).
            if ($Settings.Monitor -is [hashtable]) {
                if (-not $Settings.Monitor.ContainsKey('ShowTrackedByDefault')) { $Settings.Monitor['ShowTrackedByDefault'] = $true }
                $Settings.Monitor['ShowTrackedByDefault'] = [bool]$showTrackedDefaultChecked
            } else {
                if ($null -eq $Settings.Monitor.PSObject.Properties['ShowTrackedByDefault']) {
                    $Settings.Monitor | Add-Member -MemberType NoteProperty -Name ShowTrackedByDefault -Value $true -Force
                }
                $Settings.Monitor.ShowTrackedByDefault = [bool]$showTrackedDefaultChecked
            }

            # Shortcuts settings
            if (-not $Settings.Shortcuts) {
                $Settings | Add-Member -MemberType NoteProperty -Name Shortcuts -Value (@{}) -Force
            }
            # Coerce Shortcuts to a hashtable if it came from JSON as PSCustomObject
            if ($Settings.Shortcuts -isnot [hashtable]) {
                $convertedShortcuts = @{}
                try {
                    foreach ($prop in $Settings.Shortcuts.PSObject.Properties) {
                        $convertedShortcuts[$prop.Name] = [string]$prop.Value
                    }
                } catch {}
                $Settings.Shortcuts = $convertedShortcuts
            }
            foreach ($key in @('FocusSearch','NewSearch','ClearFilters','ConnectRDP','ConnectVNC','ConnectPing')) {
                $tb = Find-ControlByName -Container $settingsForm -Name ("Shortcut_" + $key)
                if ($tb -and -not [string]::IsNullOrWhiteSpace($tb.Text)) { $Settings.Shortcuts[$key] = $tb.Text }
            }

            # Save settings (settingsPath points at config\settings.json; use repo root)
            $scriptPath = Split-Path (Split-Path $settingsPath -Parent) -Parent
            Save-Settings -Settings $Settings -ScriptPath $scriptPath

            # Update scheduled task for Locked Monitor
            try {
                $taskResult = Ensure-LockedMonitorScheduledTask -Enabled $Settings.Monitor.StartWithWindows -AppRoot $scriptPath
                if (-not $taskResult) {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Failed to update the scheduled task for Locked Monitor. Check that you have permission to create scheduled tasks.",
                        "Scheduled Task",
                        [System.Windows.Forms.MessageBoxButtons]::OK,
                        [System.Windows.Forms.MessageBoxIcon]::Warning
                    ) | Out-Null
                }
            } catch {
                Write-Warning "Failed to update Locked Monitor scheduled task: $_"
                [System.Windows.Forms.MessageBox]::Show(
                    "Error updating scheduled task: $_",
                    "Scheduled Task Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                ) | Out-Null
            }

            # If preferred shared path changed, prompt to merge now
            $newPreferred = if ($Settings.Data) { $Settings.Data.PreferredSharedPath } else { "" }
            if (([string]::IsNullOrWhiteSpace($originalPreferred) -and -not [string]::IsNullOrWhiteSpace($newPreferred)) -or
                ([string]::IsNullOrWhiteSpace($newPreferred) -and -not [string]::IsNullOrWhiteSpace($originalPreferred)) -or
                ($originalPreferred -ne $newPreferred)) {
                $mergeResult = [System.Windows.Forms.MessageBox]::Show(
                    "The preferred shared data folder changed. Do you want to merge data now?",
                    "Merge Data",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                if ($mergeResult -eq [System.Windows.Forms.DialogResult]::Yes) {
                    try {
                        if (Get-Command Sync-SharedData -ErrorAction SilentlyContinue) {
                            Sync-SharedData -Trigger "SettingsChanged"
                        } else {
                            [System.Windows.Forms.MessageBox]::Show(
                                "Sync is unavailable (module not loaded). Data will merge automatically when available.",
                                "Data Sync",
                                [System.Windows.Forms.MessageBoxButtons]::OK,
                                [System.Windows.Forms.MessageBoxIcon]::Information
                            )
                        }
                    } catch {
                        [System.Windows.Forms.MessageBox]::Show(
                            "Error during merge: $_",
                            "Data Sync",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Error
                        )
                    }
                }
            }
            [System.Windows.Forms.MessageBox]::Show("Settings saved successfully.","Settings",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information)
        }
    }
    catch {
        Write-Warning "Error in Settings dialog: $_"
        [System.Windows.Forms.MessageBox]::Show("Error editing settings: $_","Error",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

#endregion Functions

# ── Module Exports ────────────────────────────────────────────────────────────
Export-ModuleMember -Function Load-Settings, Save-Settings, Show-SettingsDialog
