#Requires -Version 5.1

<#
.SYNOPSIS
    Shared data resolution and merge utilities for ADapp.
.DESCRIPTION
    The DataSync module provides functions for resolving shared-versus-local
    data paths, reading and writing JSON/JSONL files safely, and merging
    favorites, search history, and lockout event data between local and
    preferred (network) storage locations.
.NOTES
    Module : DataSync
    Author : ADapp Team
#>

#region Functions

function Write-DebugLog {
    <#
    .SYNOPSIS
        Forwards a message to the application logger when available.
    .DESCRIPTION
        Attempts to call the global Write-Log function so that callers inside
        this module can emit diagnostic messages without taking a hard
        dependency on the logging infrastructure.
    .PARAMETER Message
        The text to log.
    .PARAMETER Level
        The severity level passed to Write-Log (e.g. Info, Warning, Error).
    .OUTPUTS
        None
    .EXAMPLE
        Write-DebugLog -Message "Something happened" -Level "Warning"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$Level = "Info"
    )
    try {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message $Message -Level $Level
        }
    }
    catch {}
}

function Test-DirectoryWritable {
    <#
    .SYNOPSIS
        Checks whether a directory path is writable by the current user.
    .DESCRIPTION
        Creates the directory if it does not exist, writes a temporary file,
        then removes it. Returns $true when the full round-trip succeeds.
    .PARAMETER Path
        The directory path to test for write access.
    .OUTPUTS
        [bool] $true if the directory is writable; $false otherwise.
    .EXAMPLE
        Test-DirectoryWritable -Path "\\server\share\Data"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
        $testFile = Join-Path -Path $Path -ChildPath ".writetest.tmp"
        "" | Set-Content -Path $testFile -Force -ErrorAction Stop
        Remove-Item -Path $testFile -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        Write-DebugLog -Message "Test-DirectoryWritable failed for '$Path': $_" -Level "Warning"
        return $false
    }
}

function Resolve-SharedDataPaths {
    <#
    .SYNOPSIS
        Determines the local, preferred, and active data/monitor paths.
    .DESCRIPTION
        Reads the PreferredSharedPath from the supplied Settings object,
        expands environment variables, tests writability, and returns a
        PSCustomObject that describes every path the application may use.
    .PARAMETER Settings
        The application settings object that may contain a
        Data.PreferredSharedPath property.
    .OUTPUTS
        [PSCustomObject] with LocalDataPath, PreferredDataPath, ActiveDataPath
        and related properties.
    .EXAMPLE
        $ctx = Resolve-SharedDataPaths -Settings $global:Settings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        $Settings
    )
    $localDataPath    = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
    $localMonitorPath = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Monitor"
    $preferredBase    = ""
    try {
        if ($Settings -and $Settings.Data -and $Settings.Data.PreferredSharedPath) {
            $preferredBase = [Environment]::ExpandEnvironmentVariables([string]$Settings.Data.PreferredSharedPath)
        }
    }
    catch {}

    # Pre-compute preferred sub-paths so the writability test targets the
    # actual Data subfolder rather than the (possibly read-only) share root.
    $preferredDataPath    = ""
    $preferredMonitorPath = ""
    $preferredAvailable   = $false

    if (-not [string]::IsNullOrWhiteSpace($preferredBase)) {
        $preferredDataPath    = Join-Path -Path $preferredBase -ChildPath "Data"
        $preferredMonitorPath = Join-Path -Path $preferredBase -ChildPath "Monitor"

        # Writability is checked against Data because that is where shared
        # favourites and search history are persisted.
        $preferredAvailable = Test-DirectoryWritable -Path $preferredDataPath

        # Best-effort creation of Monitor folder; failure here should not
        # force the entire sync to fall back to local data.
        if ($preferredAvailable -and -not [string]::IsNullOrWhiteSpace($preferredMonitorPath)) {
            try {
                if (-not (Test-Path $preferredMonitorPath)) {
                    New-Item -ItemType Directory -Path $preferredMonitorPath -Force | Out-Null
                }
            }
            catch {
                Write-DebugLog -Message "Resolve-SharedDataPaths: preferred monitor folder not writable/creatable at '$preferredMonitorPath': $_" -Level "Warning"
            }
        }
    }

    $activeDataPath    = if ($preferredAvailable) { $preferredDataPath } else { $localDataPath }
    $activeMonitorPath = if ($preferredAvailable) { $preferredMonitorPath } else { $localMonitorPath }

    return [PSCustomObject]@{
        LocalDataPath       = $localDataPath
        LocalMonitorPath    = $localMonitorPath
        PreferredBase       = $preferredBase
        PreferredDataPath   = $preferredDataPath
        PreferredMonitorPath = $preferredMonitorPath
        PreferredAvailable  = $preferredAvailable
        ActiveDataPath      = $activeDataPath
        ActiveMonitorPath   = $activeMonitorPath
        ActiveIsPreferred   = $preferredAvailable
        PreferredConfigured = -not [string]::IsNullOrWhiteSpace($preferredBase)
        # Legacy properties kept for backward compatibility
        LocalPath           = $localDataPath
        PreferredPath       = $preferredBase
        ActivePath          = $activeDataPath
    }
}

function Read-JsonArraySafe {
    <#
    .SYNOPSIS
        Reads a JSON file and returns its content as an array.
    .DESCRIPTION
        Safely loads a JSON file, handling missing files, null content, and
        parse errors. Always returns an array (empty on failure).
    .PARAMETER Path
        Full path to the JSON file.
    .OUTPUTS
        [array] The deserialised objects, or an empty array on failure.
    .EXAMPLE
        $items = Read-JsonArraySafe -Path "C:\ProgramData\ADapp\Data\favorites.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    if (-not (Test-Path $Path)) { return @() }
    try {
        $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $obj) { return @() }
        if ($obj -is [Array]) { return $obj }
        return @($obj)
    }
    catch {
        Write-DebugLog -Message "Read-JsonArraySafe parse error for '$Path': $_" -Level "Warning"
        return @()
    }
}

function Write-JsonArraySafe {
    <#
    .SYNOPSIS
        Serialises an array to a JSON file, creating parent directories as needed.
    .DESCRIPTION
        Converts the supplied array to JSON (depth 7) and writes it to the
        specified path. An empty array is written as "[]". Throws on failure
        so callers can decide how to handle write errors.
    .PARAMETER Path
        Full path to the target JSON file.
    .PARAMETER Array
        The collection of objects to serialise.
    .OUTPUTS
        None
    .EXAMPLE
        Write-JsonArraySafe -Path "C:\ProgramData\ADapp\Data\favorites.json" -Array $favorites
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $Array
    )
    try {
        $dir = Split-Path -Path $Path -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $arr  = @($Array)
        $json = if ($arr.Count -eq 0) { "[]" } else { $arr | ConvertTo-Json -Depth 7 }
        Set-Content -Path $Path -Value $json -Encoding UTF8 -Force -ErrorAction Stop
    }
    catch {
        Write-DebugLog -Message "Write-JsonArraySafe failed for '$Path': $_" -Level "Warning"
        throw
    }
}

function Read-JsonLFileSafe {
    <#
    .SYNOPSIS
        Reads a JSONL (or legacy JSON-array) file and returns its entries as an array.
    .DESCRIPTION
        Detects whether the file uses newline-delimited JSON or the legacy
        array format and parses accordingly. Returns an empty array when the
        file is missing or unparseable.
    .PARAMETER Path
        Full path to the JSONL file.
    .OUTPUTS
        [array] Parsed event objects, or an empty array on failure.
    .EXAMPLE
        $events = Read-JsonLFileSafe -Path "C:\ProgramData\ADapp\Monitor\lockout-events.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    if (-not (Test-Path $Path)) { return @() }
    try {
        $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $trim = $raw.TrimStart()
        if ($trim.StartsWith('[')) {
            # Legacy array JSON format
            try { return @(($raw | ConvertFrom-Json)) }
            catch { return @() }
        }
        # Newline-delimited JSON (JSONL) format
        $events = @()
        foreach ($line in (Get-Content -Path $Path)) {
            $l = [string]$line
            if ([string]::IsNullOrWhiteSpace($l)) { continue }
            try {
                $obj = $l | ConvertFrom-Json
                if ($null -ne $obj) { $events += $obj }
            }
            catch {}
        }
        return $events
    }
    catch {
        Write-DebugLog -Message "Read-JsonLFileSafe parse error for '$Path': $_" -Level "Warning"
        return @()
    }
}

function Write-JsonLFileSafe {
    <#
    .SYNOPSIS
        Serialises an array of events to a JSONL file.
    .DESCRIPTION
        Each event object is written as a single compressed JSON line.
        Parent directories are created when missing. Throws on failure.
    .PARAMETER Path
        Full path to the target JSONL file.
    .PARAMETER Events
        The collection of event objects to serialise.
    .OUTPUTS
        None
    .EXAMPLE
        Write-JsonLFileSafe -Path "C:\ProgramData\ADapp\Monitor\lockout-events.json" -Events $merged
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $Events
    )
    try {
        $dir = Split-Path -Path $Path -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $evtArray = @($Events)
        $lines = @()
        foreach ($e in $evtArray) {
            $lines += ($e | ConvertTo-Json -Compress -Depth 5)
        }
        Set-Content -Path $Path -Value $lines -Encoding UTF8 -Force -ErrorAction Stop
    }
    catch {
        Write-DebugLog -Message "Write-JsonLFileSafe failed for '$Path': $_" -Level "Warning"
        throw
    }
}

function Get-FavoriteSignature {
    <#
    .SYNOPSIS
        Computes a deduplication key for a favourite item.
    .DESCRIPTION
        Concatenates SearchTerm, SearchType, and the JSON representation of
        AdvancedSearch (if any) to produce a unique string signature used
        during merge operations.
    .PARAMETER Item
        The favourite object to fingerprint.
    .OUTPUTS
        [string] A pipe-delimited signature string.
    .EXAMPLE
        $sig = Get-FavoriteSignature -Item $favorite
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Item
    )
    $adv = if ($Item.AdvancedSearch) { ($Item.AdvancedSearch | ConvertTo-Json -Depth 7) } else { "" }
    return ($Item.SearchTerm + "|" + $Item.SearchType + "|" + $adv)
}

function Merge-FavoritesFiles {
    <#
    .SYNOPSIS
        Merges favourite entries from local, preferred, and active files.
    .DESCRIPTION
        Reads favourites from the active, local, and preferred JSON files,
        deduplicates by signature (active entries take priority), trims to
        MaxFavorites, and writes the merged result back to all three locations.
    .PARAMETER LocalFile
        Path to the local favourites JSON file.
    .PARAMETER PreferredFile
        Path to the preferred (shared) favourites JSON file.
    .PARAMETER ActiveFile
        Optional path to the currently active favourites file.
    .OUTPUTS
        None
    .EXAMPLE
        Merge-FavoritesFiles -LocalFile $localFav -PreferredFile $sharedFav -ActiveFile $activeFav
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LocalFile,

        [Parameter(Mandatory = $true)]
        [string]$PreferredFile,

        [string]$ActiveFile = ""
    )
    $local  = Read-JsonArraySafe -Path $LocalFile
    $shared = Read-JsonArraySafe -Path $PreferredFile

    # The active file holds the most recent runtime data and must be read
    # separately so its entries take highest priority during deduplication.
    $active = @()
    if ($ActiveFile -and (Test-Path $ActiveFile)) {
        $active = Read-JsonArraySafe -Path $ActiveFile
    }

    $bySig = @{}
    # Process active first so its entries win on duplicate signatures.
    foreach ($it in @($active) + @($local) + @($shared)) {
        if ($null -eq $it) { continue }
        $sig = Get-FavoriteSignature -Item $it
        if (-not $bySig.ContainsKey($sig)) {
            $bySig[$sig] = $it
        }
    }

    $merged = @()
    foreach ($kv in $bySig.GetEnumerator()) { $merged += $kv.Value }

    # Trim deterministically so results are stable across runs.
    $maxFav = if ($global:AppConfig -and $global:AppConfig.MaxFavorites) { [int]$global:AppConfig.MaxFavorites } else { 50 }
    $merged = $merged | Sort-Object -Property @{Expression="Name"; Ascending=$true}, @{Expression="SearchType"; Ascending=$true}, @{Expression="SearchTerm"; Ascending=$true} | Select-Object -First $maxFav

    Write-JsonArraySafe -Path $LocalFile -Array $merged
    Write-JsonArraySafe -Path $PreferredFile -Array $merged

    # Keep the active file in sync with the merged result.
    if ($ActiveFile) {
        Write-JsonArraySafe -Path $ActiveFile -Array $merged
    }
}

function Merge-SearchHistoryFiles {
    <#
    .SYNOPSIS
        Merges search-history entries from local, preferred, and active files.
    .DESCRIPTION
        Reads history from the active, local, and preferred JSON files,
        deduplicates by SearchTerm+SearchType (active entries take priority),
        trims to MaxSearchHistory, and writes the result back to all locations.
    .PARAMETER LocalFile
        Path to the local search-history JSON file.
    .PARAMETER PreferredFile
        Path to the preferred (shared) search-history JSON file.
    .PARAMETER ActiveFile
        Optional path to the currently active search-history file.
    .OUTPUTS
        None
    .EXAMPLE
        Merge-SearchHistoryFiles -LocalFile $localHist -PreferredFile $sharedHist -ActiveFile $activeHist
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LocalFile,

        [Parameter(Mandatory = $true)]
        [string]$PreferredFile,

        [string]$ActiveFile = ""
    )
    $local  = Read-JsonArraySafe -Path $LocalFile
    $shared = Read-JsonArraySafe -Path $PreferredFile

    # The active file holds the most recent runtime data and must be read
    # separately so its entries take highest priority during deduplication.
    $active = @()
    if ($ActiveFile -and (Test-Path $ActiveFile)) {
        $active = Read-JsonArraySafe -Path $ActiveFile
    }

    $seen   = New-Object 'System.Collections.Generic.HashSet[string]'
    $merged = @()
    # Process active first so its entries win on duplicate keys.
    foreach ($it in @($active) + @($local) + @($shared)) {
        if ($null -eq $it) { continue }
        $key = ($it.SearchTerm + "|" + $it.SearchType)
        if ($seen.Add($key)) { $merged += $it }
    }

    $max    = if ($global:AppConfig -and $global:AppConfig.MaxSearchHistory) { [int]$global:AppConfig.MaxSearchHistory } else { 30 }
    $merged = $merged | Select-Object -First $max

    Write-JsonArraySafe -Path $LocalFile -Array $merged
    Write-JsonArraySafe -Path $PreferredFile -Array $merged

    # Keep the active file in sync with the merged result.
    if ($ActiveFile) {
        Write-JsonArraySafe -Path $ActiveFile -Array $merged
    }
}

function Normalize-Username {
    <#
    .SYNOPSIS
        Normalises a username for consistent comparison.
    .DESCRIPTION
        Strips an optional DOMAIN\ prefix or @domain suffix, trims whitespace,
        and returns the result in lower-case so that lockout-event deduplication
        is case-insensitive.
    .PARAMETER u
        The raw username string to normalise.
    .OUTPUTS
        [string] The normalised, lower-case username.
    .EXAMPLE
        Normalize-Username -u "DOMAIN\jsmith"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$u
    )
    if ([string]::IsNullOrWhiteSpace($u)) { return '' }
    $n = $u.Trim()
    # Strip DOMAIN\ prefix
    if ($n -match '^[^\\]+\\(.+)$') { $n = $Matches[1] }
    # Strip @domain suffix
    if ($n -match '^(.+)@[^@]+$') { $n = $Matches[1] }
    return $n.ToLowerInvariant()
}

function Merge-LockoutEventsFiles {
    <#
    .SYNOPSIS
        Merges lockout-event logs from local, preferred, and active files.
    .DESCRIPTION
        Reads JSONL lockout events from the active, local, and preferred files,
        deduplicates by normalised Username+Timestamp, sorts newest-first, and
        writes the merged result back to all three locations.
    .PARAMETER LocalFile
        Path to the local lockout-events JSONL file.
    .PARAMETER PreferredFile
        Path to the preferred (shared) lockout-events JSONL file.
    .PARAMETER ActiveFile
        Optional path to the currently active lockout-events file.
    .OUTPUTS
        None
    .EXAMPLE
        Merge-LockoutEventsFiles -LocalFile $localEvents -PreferredFile $sharedEvents -ActiveFile $activeEvents
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LocalFile,

        [Parameter(Mandatory = $true)]
        [string]$PreferredFile,

        [string]$ActiveFile = ""
    )
    $local  = Read-JsonLFileSafe -Path $LocalFile
    $shared = Read-JsonLFileSafe -Path $PreferredFile

    # The active file contains the most recent runtime data.
    $active = @()
    if ($ActiveFile -and (Test-Path $ActiveFile)) {
        $active = Read-JsonLFileSafe -Path $ActiveFile
    }

    $seen   = New-Object 'System.Collections.Generic.HashSet[string]'
    $merged = @()
    # Process active first so its entries win on duplicate keys.
    foreach ($e in @($active) + @($local) + @($shared)) {
        if ($null -eq $e) { continue }
        try {
            $username  = if ($e.Username) { [string]$e.Username } else { '' }
            $timestamp = if ($e.Timestamp) { [string]$e.Timestamp } else { '' }
            $normUser  = Normalize-Username $username
            $key       = ($normUser + "|" + $timestamp)
            if ($seen.Add($key)) { $merged += $e }
        }
        catch {
            # Skip malformed events that cannot produce a valid key.
            continue
        }
    }

    # Sort newest-first for consistent output across machines.
    try {
        $merged = $merged | Sort-Object -Property @{Expression={
            try {
                if ($_.Timestamp -is [long] -or $_.Timestamp -is [int] -or $_.Timestamp -is [double]) {
                    [long]$_.Timestamp
                }
                else {
                    [long]::MaxValue
                }
            }
            catch { [long]::MaxValue }
        }; Descending=$true}
    }
    catch {}

    Write-JsonLFileSafe -Path $LocalFile -Events $merged
    Write-JsonLFileSafe -Path $PreferredFile -Events $merged

    # Keep the active file in sync with the merged result.
    if ($ActiveFile) {
        Write-JsonLFileSafe -Path $ActiveFile -Events $merged
    }
}

function Sync-SharedData {
    <#
    .SYNOPSIS
        Orchestrates data synchronisation between local and preferred storage.
    .DESCRIPTION
        Resolves active paths, ensures required directories exist, syncs
        settings.json (copy-if-newer), and merges favourites, search history,
        and lockout events. When a preferred share is available it is treated
        as the single source of truth; otherwise the app falls back to local
        storage.
    .PARAMETER Trigger
        An optional label describing what initiated the sync (e.g.
        "FavoritesSaved") so the function can optimise the merge direction.
    .OUTPUTS
        None
    .EXAMPLE
        Sync-SharedData -Trigger "FavoritesSaved"
    #>
    [CmdletBinding()]
    param(
        [string]$Trigger = ""
    )
    try {
        $ctx = Resolve-SharedDataPaths -Settings $global:Settings

        # Ensure required directories exist before any read/write operations.
        if (-not (Test-Path $ctx.LocalDataPath)) { New-Item -ItemType Directory -Path $ctx.LocalDataPath -Force | Out-Null }
        if (-not (Test-Path $ctx.LocalMonitorPath)) { New-Item -ItemType Directory -Path $ctx.LocalMonitorPath -Force | Out-Null }
        if ($ctx.PreferredConfigured -and $ctx.PreferredDataPath -and -not (Test-Path $ctx.PreferredDataPath)) { New-Item -ItemType Directory -Path $ctx.PreferredDataPath -Force | Out-Null }
        if ($ctx.PreferredConfigured -and $ctx.PreferredMonitorPath -and -not (Test-Path $ctx.PreferredMonitorPath)) { New-Item -ItemType Directory -Path $ctx.PreferredMonitorPath -Force | Out-Null }

        $localFav     = Join-Path -Path $ctx.LocalDataPath -ChildPath "favorites.json"
        $localHist    = Join-Path -Path $ctx.LocalDataPath -ChildPath "search_history.json"
        $sharedDataBase = if ($ctx.PreferredDataPath) { $ctx.PreferredDataPath } else { $ctx.LocalDataPath }
        $sharedFav    = Join-Path -Path $sharedDataBase -ChildPath "favorites.json"
        $sharedHist   = Join-Path -Path $sharedDataBase -ChildPath "search_history.json"

        # Determine active file paths before merging.
        $activeDataBase = $ctx.ActiveDataPath
        if (-not (Test-Path $activeDataBase)) { New-Item -ItemType Directory -Path $activeDataBase -Force | Out-Null }
        $activeFav  = Join-Path -Path $activeDataBase -ChildPath "favorites.json"
        $activeHist = Join-Path -Path $activeDataBase -ChildPath "search_history.json"

        # ── Settings sync (copy-if-newer) ──────────────────────────────
        try {
            $localSettings  = Join-Path -Path $ctx.LocalDataPath -ChildPath "settings.json"
            $sharedSettings = Join-Path -Path $sharedDataBase -ChildPath "settings.json"

            function Sanitize-SharedSettingsFile {
                param([string]$Path)
                try {
                    if (-not (Test-Path $Path)) { return }
                    $settings = Get-Content -Path $Path -Raw | ConvertFrom-Json
                    if ($settings -and $settings.Connections) {
                        $settings.Connections.VNCPassword = ""
                        $settings | ConvertTo-Json -Depth 7 | Out-File -FilePath $Path -Encoding UTF8
                    }
                }
                catch {}
            }

            if ($sharedDataBase -ne $ctx.LocalDataPath) {
                $localExists  = Test-Path $localSettings
                $sharedExists = Test-Path $sharedSettings
                if ($localExists -and $sharedExists) {
                    $lwt = (Get-Item $localSettings).LastWriteTime
                    $swt = (Get-Item $sharedSettings).LastWriteTime
                    if ($lwt -gt $swt) {
                        Copy-Item -Path $localSettings -Destination $sharedSettings -Force -ErrorAction SilentlyContinue
                        Sanitize-SharedSettingsFile -Path $sharedSettings
                    }
                    elseif ($swt -gt $lwt) {
                        Copy-Item -Path $sharedSettings -Destination $localSettings -Force -ErrorAction SilentlyContinue
                    }
                }
                elseif ($localExists -and -not $sharedExists) {
                    Copy-Item -Path $localSettings -Destination $sharedSettings -Force -ErrorAction SilentlyContinue
                    Sanitize-SharedSettingsFile -Path $sharedSettings
                }
                elseif ($sharedExists -and -not $localExists) {
                    Copy-Item -Path $sharedSettings -Destination $localSettings -Force -ErrorAction SilentlyContinue
                }
            }
        }
        catch { Write-DebugLog -Message "Settings.json sync failed: $_" -Level "Warning" }

        # ── Lockout events ─────────────────────────────────────────────
        $localEvents      = Join-Path -Path $ctx.LocalMonitorPath -ChildPath "lockout-events.json"
        $sharedMonitorBase = if ($ctx.PreferredMonitorPath) { $ctx.PreferredMonitorPath } else { $ctx.LocalMonitorPath }
        $sharedEvents     = Join-Path -Path $sharedMonitorBase -ChildPath "lockout-events.json"
        $activeMonitorBase = $ctx.ActiveMonitorPath
        if (-not (Test-Path $activeMonitorBase)) { New-Item -ItemType Directory -Path $activeMonitorBase -Force | Out-Null }
        $activeEvents = Join-Path -Path $activeMonitorBase -ChildPath "lockout-events.json"

        if ($ctx.PreferredConfigured -and $ctx.PreferredAvailable -and $ctx.PreferredDataPath) {
            # Preferred share is available -- treat it as single source of truth.

            if ($Trigger -eq "FavoritesSaved") {
                # Favourites were just saved to the active file (which points to
                # preferred when available); propagate to shared and local cache.
                $activeFavData = Read-JsonArraySafe -Path $activeFav
                Write-JsonArraySafe -Path $sharedFav -Array $activeFavData
                Write-JsonArraySafe -Path $localFav -Array $activeFavData
            }
            else {
                # Normal sync: preferred share is source of truth, mirror to local.
                $sharedFavData = Read-JsonArraySafe -Path $sharedFav
                Write-JsonArraySafe -Path $activeFav -Array $sharedFavData
                Write-JsonArraySafe -Path $localFav -Array $sharedFavData
            }

            # Search history follows the same source-of-truth pattern.
            $sharedHistData = Read-JsonArraySafe -Path $sharedHist
            Write-JsonArraySafe -Path $activeHist -Array $sharedHistData
            Write-JsonArraySafe -Path $localHist -Array $sharedHistData

            # Lockout events use merge behaviour because the log is append-only.
            Merge-LockoutEventsFiles -LocalFile $localEvents -PreferredFile $sharedEvents -ActiveFile $activeEvents
        }
        else {
            # No preferred share available; fall back to local storage.
            if (-not (Test-Path $localFav)) { Write-JsonArraySafe -Path $localFav -Array @() }
            if (-not (Test-Path $localHist)) { Write-JsonArraySafe -Path $localHist -Array @() }
            # Mirror active data back to local when paths differ.
            if ($activeHist -ne $localHist -and (Test-Path $activeHist)) {
                $activeData = Read-JsonArraySafe -Path $activeHist
                Write-JsonArraySafe -Path $localHist -Array $activeData
            }
            if ($activeEvents -ne $localEvents -and (Test-Path $activeEvents)) {
                $activeEventsData = Read-JsonLFileSafe -Path $activeEvents
                Write-JsonLFileSafe -Path $localEvents -Events $activeEventsData
            }
        }

        if ($global:AppConfig) {
            $global:AppConfig.FavoritesFile     = $activeFav
            $global:AppConfig.SearchHistoryFile  = $activeHist
        }

        # Emit a diagnostic summary so the log shows which data source won.
        $dataSource = if ($ctx.PreferredAvailable -and $ctx.PreferredDataPath) {
            "Preferred share (single source of truth)"
        }
        else {
            "Local only (preferred unavailable)"
        }
        Write-DebugLog -Message "Sync-SharedData completed (Trigger='$Trigger', DataSource='$dataSource', ActiveData='$activeDataBase', ActiveMonitor='$activeMonitorBase', PreferredAvailable=$($ctx.PreferredAvailable))" -Level "Info"
    }
    catch {
        Write-DebugLog -Message "Sync-SharedData error: $_" -Level "Warning"
    }
}

function Open-ActiveSharedFolder {
    <#
    .SYNOPSIS
        Opens the active shared data folder in Windows Explorer.
    .DESCRIPTION
        Resolves the current active data path and launches explorer.exe
        pointing to it, allowing the user to inspect shared data files.
    .OUTPUTS
        None
    .EXAMPLE
        Open-ActiveSharedFolder
    #>
    [CmdletBinding()]
    param()
    try {
        $ctx = Resolve-SharedDataPaths -Settings $global:Settings
        if (Test-Path $ctx.ActivePath) {
            Start-Process "explorer.exe" -ArgumentList $ctx.ActivePath
        }
    }
    catch {}
}

function Open-LocalFallbackFolder {
    <#
    .SYNOPSIS
        Opens the local fallback data folder in Windows Explorer.
    .DESCRIPTION
        Launches explorer.exe pointing to the ProgramData\ADapp\Data directory
        so the user can inspect local-only data files.
    .OUTPUTS
        None
    .EXAMPLE
        Open-LocalFallbackFolder
    #>
    [CmdletBinding()]
    param()
    try {
        $local = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"
        if (Test-Path $local) { Start-Process "explorer.exe" -ArgumentList $local }
    }
    catch {}
}

#endregion Functions

# ── Module Exports ──────────────────────────────────────────────────────
Export-ModuleMember -Function Resolve-SharedDataPaths, Test-DirectoryWritable, Sync-SharedData, Open-ActiveSharedFolder, Open-LocalFallbackFolder
