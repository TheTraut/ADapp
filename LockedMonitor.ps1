# Locked Users Monitor (Standalone)

[CmdletBinding()]
param()

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:isRefreshing = $false
$script:lockedMonitorRows = @()
$script:lockedMonitorVisibleCount = 0
$script:lastStatusContext = $null
$script:searchTextBox = $null
$script:clearSearchButton = $null

# Resolve app root regardless of script location (root or tools)
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (Test-Path (Join-Path $scriptRoot 'Modules')) {
    $appRoot = $scriptRoot
} else {
    $appRoot = Split-Path -Parent $scriptRoot
}

$modulesPath = Join-Path $appRoot 'Modules'
# Prefer a dedicated icon; fall back to ADapp icon
$iconPath = Join-Path $appRoot 'assets\icons\LockedMonitor.ico'
if (-not (Test-Path $iconPath)) { $iconPath = Join-Path $appRoot 'assets\icons\adapp.ico' }

# Load settings
try {
    Import-Module (Join-Path $modulesPath 'Settings.psm1') -Force -DisableNameChecking -ErrorAction SilentlyContinue | Out-Null
    $Settings = Load-Settings -ScriptPath $appRoot
} catch {
    $Settings = @{ Monitor = @{ StartWithWindows = $false; StartMinimized = $false; CloseToTray = $false } }
}

# Load DataSync module for shared path resolution and sync
try {
    Import-Module (Join-Path $modulesPath 'DataSync.psm1') -Force -DisableNameChecking -ErrorAction SilentlyContinue | Out-Null
    $global:Settings = $Settings
} catch {
    # If DataSync fails, continue with local-only paths
}

# Ensure proper taskbar icon by setting AppUserModelID
try {
    if (-not ([type]::GetType('WinAPI.TaskbarHelper'))) {
        Add-Type -AssemblyName System.Runtime.InteropServices
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace WinAPI {
  public static class TaskbarHelper {
    [DllImport("shell32.dll", SetLastError = true)]
    public static extern void SetCurrentProcessExplicitAppUserModelID([MarshalAs(UnmanagedType.LPWStr)] string AppID);
  }
}
"@ -Language CSharp
    }
    [WinAPI.TaskbarHelper]::SetCurrentProcessExplicitAppUserModelID("LockedUsersMonitor")
} catch {}

# Single-instance check: use named mutex and bring existing window to front
try {
    if (-not ([type]::GetType('WinAPI.WindowNative'))) {
        Add-Type -AssemblyName System.Runtime.InteropServices
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace WinAPI {
  public static class WindowNative {
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")]
    public static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")]
    public static extern bool BringWindowToTop(IntPtr hWnd);
    public const int SW_RESTORE = 9;
    public const int SW_SHOW = 5;
    public const int SW_SHOWNA = 8;
  }
}
"@ -Language CSharp
    }
    
    $mutex = New-Object System.Threading.Mutex($false, "ADapp_LockedMonitor_SingleInstance")
    $mutexAcquired = $mutex.WaitOne(0, $false)
    if (-not $mutexAcquired) {
        # Another instance is running, find and bring it to front
        $windowTitle = "Locked Accounts Monitor"
        $hWnd = [WinAPI.WindowNative]::FindWindow($null, $windowTitle)
        if ($hWnd -ne [IntPtr]::Zero) {
            # Check if window is minimized or hidden
            $isMinimized = [WinAPI.WindowNative]::IsIconic($hWnd)
            $isVisible = [WinAPI.WindowNative]::IsWindowVisible($hWnd)
            
            if ($isMinimized) {
                # Restore from minimized state
                [WinAPI.WindowNative]::ShowWindow($hWnd, [WinAPI.WindowNative]::SW_RESTORE)
            } elseif (-not $isVisible) {
                # Show if hidden
                [WinAPI.WindowNative]::ShowWindow($hWnd, [WinAPI.WindowNative]::SW_SHOW)
            }
            
            # Bring to front and activate
            [WinAPI.WindowNative]::BringWindowToTop($hWnd)
            [WinAPI.WindowNative]::SetForegroundWindow($hWnd)
        }
        exit 0
    }
} catch {
    # If mutex fails, continue anyway
    $mutex = $null
}

# Data folder - use shared paths if available
try {
    if (Get-Command Resolve-SharedDataPaths -ErrorAction SilentlyContinue) {
        $pathCtx = Resolve-SharedDataPaths -Settings $Settings
        $monitorDataDir = $pathCtx.ActiveMonitorPath
    } else {
        $monitorDataDir = Join-Path $env:ProgramData 'ADapp\Monitor'
    }
} catch {
    $monitorDataDir = Join-Path $env:ProgramData 'ADapp\Monitor'
}
if (-not (Test-Path $monitorDataDir)) { New-Item -ItemType Directory -Path $monitorDataDir -Force | Out-Null }
$eventsPath = Join-Path $monitorDataDir 'lockout-events.json'
$statePath  = Join-Path $monitorDataDir 'state.json'

<#
.SYNOPSIS
Brief description of Write-UiStatus.
.DESCRIPTION
Extended description of Write-UiStatus.
.PARAMETER text
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Write-UiStatus -text <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Write-UiStatus([string]$text) { if ($null -ne $statusLabel) { $statusLabel.Text = $text } }

function Get-LockedMonitorSearchText {
    try {
        if ($null -eq $script:searchTextBox) { return '' }
        $t = [string]$script:searchTextBox.Text
        if ([string]::IsNullOrWhiteSpace($t)) { return '' }
        return $t.Trim()
    } catch { return '' }
}

function Test-LockedMonitorRowMatches {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Row,
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Needle
    )

    if ([string]::IsNullOrWhiteSpace($Needle)) { return $true }
    $n = $Needle.Trim().ToLowerInvariant()
    try {
        $hay = @(
            [string]$Row.Username,
            [string]$Row.FullName,
            [string]$Row.LastLockout,
            [string]$Row.LockedSince,
            [string]$Row.LockoutsRange,
            [string]$Row.LockoutsAllTime
        ) -join ' '
        return ($hay.ToLowerInvariant().Contains($n))
    } catch {
        return $false
    }
}

function Update-LockedMonitorStatusFromContext {
    if ($null -eq $script:lastStatusContext) { return }
    $ctx = $script:lastStatusContext

    $filter = Get-LockedMonitorSearchText
    $filterSuffix = ''
    if (-not [string]::IsNullOrWhiteSpace($filter)) {
        $filterSuffix = " | Filter: '$filter' (showing $($script:lockedMonitorVisibleCount))"
    }

    $lockoutsPart = ''
    try {
        $lockoutsPart = (" | Lockouts (range): {0} | Lockouts (all time): {1}" -f ([int]$ctx.LockoutsRangeCount), ([int]$ctx.LockoutsAllTimeCount))
    } catch { $lockoutsPart = '' }

    if ([int]$ctx.TrackedCount -gt 0) {
        Write-UiStatus ("Locked: {0} | Tracked: {1}{2} | Last refresh: {3} | Range: {4} - {5}{6}" -f $ctx.LockedCount, $ctx.TrackedCount, $lockoutsPart, $ctx.LastRefresh, $ctx.FromStr, $ctx.ToStr, $filterSuffix)
    } else {
        Write-UiStatus ("Locked: {0}{1} | Last refresh: {2} | Range: {3} - {4}{5}" -f $ctx.LockedCount, $lockoutsPart, $ctx.LastRefresh, $ctx.FromStr, $ctx.ToStr, $filterSuffix)
    }
}

function Render-LockedMonitorListViewRows {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Rows = @()
    )

    $filter = Get-LockedMonitorSearchText

    # Preserve selection by username
    $selected = @()
    try { $selected = @($listView.SelectedItems | ForEach-Object { [string]$_.Text }) } catch { $selected = @() }
    $selectedSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($s in $selected) { $null = $selectedSet.Add($s) }

    $listView.BeginUpdate()
    try {
        $listView.Items.Clear()
        foreach ($row in @($Rows)) {
            if (-not (Test-LockedMonitorRowMatches -Row $row -Needle $filter)) { continue }

            $item = New-Object System.Windows.Forms.ListViewItem([string]$row.Username)
            $null = $item.SubItems.Add([string]$row.FullName)
            $null = $item.SubItems.Add([string]$row.LastLockout)
            $null = $item.SubItems.Add([string]$row.LockedSince)
            $null = $item.SubItems.Add([string]$row.LockoutsRange)
            $null = $item.SubItems.Add([string]$row.LockoutsAllTime)
            try { if ($null -ne $row.ForeColor) { $item.ForeColor = $row.ForeColor } } catch {}
            $item.Tag = [string]$row.Tag
            $null = $listView.Items.Add($item)

            # Restore selection
            try {
                if ($selectedSet.Contains([string]$item.Text)) { $item.Selected = $true }
            } catch {}
        }
    } finally {
        $listView.EndUpdate()
    }

    $script:lockedMonitorVisibleCount = 0
    try { $script:lockedMonitorVisibleCount = [int]$listView.Items.Count } catch { $script:lockedMonitorVisibleCount = 0 }

    Update-LockedMonitorStatusFromContext
}

<#
.SYNOPSIS
Brief description of Load-ModuleSafe.
.DESCRIPTION
Extended description of Load-ModuleSafe.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Load-ModuleSafe
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Load-ModuleSafe {
    try { Import-Module ActiveDirectory -ErrorAction Stop } catch {
        [System.Windows.Forms.MessageBox]::Show("ActiveDirectory module not found: $_", "Locked Monitor", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        exit 1
    }
    try { Import-Module (Join-Path $modulesPath 'LockedAccounts.psm1') -Force -DisableNameChecking -ErrorAction Stop } catch {
        [System.Windows.Forms.MessageBox]::Show("LockedAccounts module not found: $_", "Locked Monitor", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        exit 1
    }
}

<#
.SYNOPSIS
Brief description of Load-Events.
.DESCRIPTION
Extended description of Load-Events.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Load-Events
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Load-Events {
    if (-not (Test-Path $eventsPath)) { return @() }
    try {
        $raw = Get-Content $eventsPath -Raw
    } catch { return @() }
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    $trim = $raw.TrimStart()
    if ($trim.StartsWith('[')) {
        # Legacy array JSON
        try { return @(( $raw | ConvertFrom-Json )) } catch { return @() }
    }
    # Newline-delimited JSON (JSONL)
    $events = @()
    try {
        foreach ($line in (Get-Content $eventsPath)) {
            $l = [string]$line
            if ([string]::IsNullOrWhiteSpace($l)) { continue }
            try { $obj = $l | ConvertFrom-Json; if ($null -ne $obj) { $events += $obj } } catch {}
        }
    } catch { return @() }
    return $events
}
<#
.SYNOPSIS
Brief description of Save-Events.
.DESCRIPTION
Extended description of Save-Events.
.PARAMETER events
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Save-Events -events <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Save-Events($events) {
    # Rewrite as JSONL for robustness and stability
    try {
        $lines = @()
        foreach ($e in @($events)) { $lines += ($e | ConvertTo-Json -Compress -Depth 5) }
        Set-Content -Path $eventsPath -Encoding UTF8 -Value $lines
        # Sync to shared drive if available
        try {
            if (Get-Command Sync-SharedData -ErrorAction SilentlyContinue) {
                Sync-SharedData
            }
        } catch {}
    } catch {}
}
<#
.SYNOPSIS
Brief description of Append-Event.
.DESCRIPTION
Extended description of Append-Event.
.PARAMETER event
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Append-Event -event <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Append-Event($event) {
    try {
        $line = ($event | ConvertTo-Json -Compress -Depth 5)
        Add-Content -Path $eventsPath -Value $line -Encoding UTF8
        # Sync to shared drive if available (async to avoid blocking)
        try {
            if (Get-Command Sync-SharedData -ErrorAction SilentlyContinue) {
                # Use Start-Job or just call directly - for simplicity, call directly but catch errors
                Sync-SharedData -ErrorAction SilentlyContinue
            }
        } catch {}
    } catch {}
}
<#
.SYNOPSIS
Brief description of Prune-EventFile.
.DESCRIPTION
Extended description of Prune-EventFile.
.PARAMETER retain
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Prune-EventFile -retain <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Prune-EventFile([TimeSpan]$retain) {
    try {
        $cutoff = (Get-Date).Add(-$retain)
        $events = Load-Events
        if ($events.Count -eq 0) { return }
        $kept = @()
        foreach ($e in $events) {
            try {
                $ts = Convert-EventTimestamp $e.Timestamp
                if ($null -ne $ts -and $ts -ge $cutoff) { $kept += $e }
            } catch {}
        }
        Save-Events -events $kept
    } catch {}
}
<#
.SYNOPSIS
Brief description of Prune-Events.
.DESCRIPTION
Extended description of Prune-Events.
.PARAMETER events
Description.
.PARAMETER retain
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Prune-Events -events <value> -retain <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Prune-Events([object[]]$events, [TimeSpan]$retain) {
    $cutoff = (Get-Date).Add(-$retain)
    @($events | Where-Object {
        try { $ts = Convert-EventTimestamp $_.Timestamp; ($null -ne $ts) -and ($ts -ge $cutoff) } catch { $false }
    })
}

<#
.SYNOPSIS
Brief description of Load-State.
.DESCRIPTION
Extended description of Load-State.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Load-State
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Load-State {
    $default = [pscustomobject]@{ LastLocked = @(); LastRefresh = $null; LockSessionStart = @{} }
    if (Test-Path $statePath) {
        try {
            $s = Get-Content $statePath -Raw | ConvertFrom-Json
            if ($null -eq $s) { return $default }
            if (-not ($s.PSObject.Properties.Name -contains 'LastLocked')) { $s | Add-Member -NotePropertyName LastLocked -NotePropertyValue @() }
            if (-not ($s.PSObject.Properties.Name -contains 'LastRefresh')) { $s | Add-Member -NotePropertyName LastRefresh -NotePropertyValue $null }
            if (-not ($s.PSObject.Properties.Name -contains 'LockSessionStart')) { $s | Add-Member -NotePropertyName LockSessionStart -NotePropertyValue @{} }
            return $s
        } catch { return $default }
    }
    else { return $default }
}
<#
.SYNOPSIS
Brief description of Save-State.
.DESCRIPTION
Extended description of Save-State.
.PARAMETER state
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Save-State -state <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Save-State($state) { try { $state | ConvertTo-Json -Depth 5 | Set-Content -Path $statePath -Encoding UTF8 } catch {} }

<#
.SYNOPSIS
Brief description of Get-SelectedRangeSpan.
.DESCRIPTION
Extended description of Get-SelectedRangeSpan.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Get-SelectedRangeSpan
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Get-SelectedRangeSpan {
    # Normalize selected value to a string
    $value = [string]$rangeCombo.SelectedItem

    switch ($value) {
        '1h'         { [TimeSpan]::FromHours(1) }
        '4h'         { [TimeSpan]::FromHours(4) }
        '12h'        { [TimeSpan]::FromHours(12) }
        '24h'        { [TimeSpan]::FromHours(24) }
        '24hr'       { [TimeSpan]::FromHours(24) }
        '24hrs'      { [TimeSpan]::FromHours(24) }
        '24 hours'   { [TimeSpan]::FromHours(24) }
        '7d'         { [TimeSpan]::FromDays(7) }
        '30d'        { [TimeSpan]::FromDays(30) }
        default      { [TimeSpan]::FromHours(24) } # Safe default if something unexpected is selected
    }
}
<#
.SYNOPSIS
Brief description of Get-IntervalMs.
.DESCRIPTION
Extended description of Get-IntervalMs.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Get-IntervalMs
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Get-IntervalMs { switch ($intervalCombo.SelectedItem) { '15s' { 15000 } '30s' { 30000 } '1m' { 60000 } '2m' { 120000 } '5m' { 300000 } default { 30000 } } }

<#
.SYNOPSIS
Brief description of Ensure-ControlsEnabled.
.DESCRIPTION
Extended description of Ensure-ControlsEnabled.
.PARAMETER enabled
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Ensure-ControlsEnabled -enabled <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Ensure-ControlsEnabled([bool]$enabled) {
    $refreshButton.Enabled = $enabled
    $autoRefreshCheck.Enabled = $enabled
    $intervalCombo.Enabled = $enabled -and $autoRefreshCheck.Checked
    $rangeCombo.Enabled = $enabled
    $fromPicker.Enabled = $enabled -and ($rangeCombo.SelectedItem -eq 'Custom')
    $toPicker.Enabled = $enabled -and ($rangeCombo.SelectedItem -eq 'Custom')
    $unlockButton.Enabled = $enabled -and ($listView.SelectedItems.Count -gt 0)
    $resetButton.Enabled = $enabled -and ($listView.SelectedItems.Count -gt 0)
    # Keep enabled even with no selection so we can show a friendly prompt on click.
    if ($null -ne $openInADappButton) { $openInADappButton.Enabled = $enabled }
    if ($null -ne $showTrackedCheck) { $showTrackedCheck.Enabled = $enabled }
    if ($null -ne $pruneButton) { $pruneButton.Enabled = $enabled }
}

<#
.SYNOPSIS
Brief description of Get-CurrentLockedUsers.
.DESCRIPTION
Extended description of Get-CurrentLockedUsers.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Get-CurrentLockedUsers
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Get-CurrentLockedUsers { $users = Get-LockedADAccounts; if ($null -eq $users) { @() } else { @($users) } }

<# 
.SYNOPSIS
Adds click-to-sort behavior to a ListView in the Locked Monitor window.

.DESCRIPTION
Wires ColumnClick to toggle ascending/descending sort per column using a custom
IComparer. Updates column headers with ^ / v indicators to show the current sort.
#>

# Add comparer type for Locked Monitor sorting if it does not already exist
if (-not ([System.Management.Automation.PSTypeName]"LockedMonitorListViewComparer").Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Windows.Forms;
using System.Collections;

public class LockedMonitorListViewComparer : IComparer
{
    private int col;
    private bool ascending;

    public LockedMonitorListViewComparer(int column, bool asc)
    {
        col = column;
        ascending = asc;
    }

    public int Compare(object x, object y)
    {
        ListViewItem itemX = (ListViewItem)x;
        ListViewItem itemY = (ListViewItem)y;

        string strX = itemX.SubItems[col].Text;
        string strY = itemY.SubItems[col].Text;

        // Try numeric comparison first
        double numX, numY;
        bool isNumX = double.TryParse(strX, out numX);
        bool isNumY = double.TryParse(strY, out numY);
        int result;

        if (isNumX && isNumY)
        {
            result = numX.CompareTo(numY);
        }
        else
        {
            // Then try DateTime comparison
            DateTime dtX, dtY;
            bool isDtX = DateTime.TryParse(strX, out dtX);
            bool isDtY = DateTime.TryParse(strY, out dtY);

            if (isDtX && isDtY)
            {
                result = dtX.CompareTo(dtY);
            }
            else
            {
                result = String.Compare(strX, strY, StringComparison.CurrentCultureIgnoreCase);
            }
        }

        return ascending ? result : -result;
    }
}
"@ -ReferencedAssemblies System.Windows.Forms
}

function Add-LockedListViewSorting {
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListView]$ListView
    )

    $ListView.Add_ColumnClick({
        param($sender, $e)

        $lv   = $sender
        $col  = $e.Column
        $tag  = $lv.Tag

        if (-not $tag) {
            $tag = @{
                SortOrder  = @{}
                LastColumn = $null
            }
            $lv.Tag = $tag
        }

        # Determine next sort state for this column:
        # 1st click: ascending (^), 2nd: descending (v), 3rd: unsorted (no comparer, no icon)
        $hasExisting = $tag.SortOrder.ContainsKey($col)
        $ascending = $true
        $state = 'Ascending'

        if (-not $hasExisting -or $tag.LastColumn -ne $col) {
            # New column or previously unsorted -> start with ascending
            $ascending = $true
            $state = 'Ascending'
            $tag.SortOrder.Clear()
            $tag.SortOrder[$col] = $true
            $tag.LastColumn = $col
        } elseif ($tag.SortOrder[$col]) {
            # Was ascending -> switch to descending
            $ascending = $false
            $state = 'Descending'
            $tag.SortOrder[$col] = $false
            $tag.LastColumn = $col
        } else {
            # Was descending -> switch to unsorted
            $state = 'None'
            $tag.SortOrder.Remove($col) | Out-Null
            $tag.LastColumn = $null
        }

        if ($state -eq 'None') {
            # Clear sorting
            $lv.ListViewItemSorter = $null
        } else {
            # Apply comparer
            $lv.ListViewItemSorter = [LockedMonitorListViewComparer]::new($col, $ascending)
        }

        # Update header text with ^ / v indicator or none
        for ($i = 0; $i -lt $lv.Columns.Count; $i++) {
            $columnHeader = $lv.Columns[$i]
            $text = $columnHeader.Text

            # Strip existing indicator
            $text = $text -replace ' [\^v]$', ''

            if ($state -ne 'None' -and $i -eq $col) {
                $indicator = if ($ascending) { '^' } else { 'v' }
                $text += " $indicator"
            }

            $columnHeader.Text = $text
        }
    })
}

<#
.SYNOPSIS
Brief description of Get-ADUsersBySam.
.DESCRIPTION
Fetch AD user objects by SamAccountName values with properties used by the monitor.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Get-ADUsersBySam -samAccountNames @('jdoe','asmith')
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Get-ADUsersBySam {
    param([string[]]$samAccountNames)
    $results = @()
    if ($null -eq $samAccountNames -or $samAccountNames.Count -eq 0) { return $results }
    foreach ($sam in $samAccountNames) {
        try {
            $u = Get-ADUser -Filter "SamAccountName -eq '$sam'" -Properties SamAccountName, GivenName, Surname, Title, Department, EmailAddress, telephoneNumber, CanonicalName, MemberOf, LastLogon, PasswordLastSet, whenChanged, lockoutTime, LastBadPasswordAttempt
            if ($null -ne $u) { $results += $u }
        } catch {}
    }
    return $results
}

<#
.SYNOPSIS
Brief description of Convert-EventTimestamp.
.DESCRIPTION
Extended description of Convert-EventTimestamp.
.PARAMETER ts
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Convert-EventTimestamp -ts <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Convert-EventTimestamp($ts) {
    if ($ts -is [datetime]) { return $ts }
    if ($ts -is [string]) {
        # Handle /Date(XXXXXXXXXXXX)/ or /Date(XXXXXXXXXXXX+HHMM)/ forms
        if ($ts -match 'Date\(([-]?[0-9]+)([+-]\d{4})?\)') {
            try {
                $ms = [long]$Matches[1]
                # Always interpret as Unix epoch milliseconds (UTC) and convert to local time
                return ([DateTimeOffset]::FromUnixTimeMilliseconds($ms)).LocalDateTime
            }
            catch { return $null }
        }
        try { return ([DateTimeOffset]::Parse($ts)).LocalDateTime } catch { try { return [datetime]::Parse($ts) } catch { return $null } }
    }
    if ($ts -is [int] -or $ts -is [long] -or $ts -is [double]) {
        try { return ([DateTimeOffset]::FromUnixTimeMilliseconds([long]$ts)).LocalDateTime } catch { return $null }
    }
    return $null
}

<#
.SYNOPSIS
Brief description of To-EpochMilliseconds.
.DESCRIPTION
Extended description of To-EpochMilliseconds.
.PARAMETER dt
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
To-EpochMilliseconds -dt <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function To-EpochMilliseconds([datetime]$dt) {
    try { return [long]([DateTimeOffset]$dt).ToUnixTimeMilliseconds() } catch {
        try { $utc = $dt.ToUniversalTime(); return [long](($utc - [datetime]'1970-01-01Z').TotalMilliseconds) } catch { return 0L }
    }
}

<#
.SYNOPSIS
Brief description of Normalize-Username.
.DESCRIPTION
Extended description of Normalize-Username.
.PARAMETER u
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Normalize-Username -u <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Normalize-Username([string]$u) {
    if ([string]::IsNullOrWhiteSpace($u)) { return '' }
    $n = $u.Trim()
    # Strip DOMAIN\ prefix
    if ($n -match '^[^\\]+\\(.+)$') { $n = $Matches[1] }
    # Strip @domain suffix
    if ($n -match '^(.+)@[^@]+$') { $n = $Matches[1] }
    return $n.ToLowerInvariant()
}

<#
.SYNOPSIS
Brief description of Compute-LockoutStats.
.DESCRIPTION
Extended description of Compute-LockoutStats.
.PARAMETER events
Description.
.PARAMETER from
Description.
.PARAMETER to
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Compute-LockoutStats -events <value> -from <value> -to <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Compute-LockoutStats([object[]]$events, [DateTime]$from, [DateTime]$to) {
    # Case-insensitive stats table (Count + Last)
    $stats = @{}
    foreach ($e in $events) {
        try {
            # Only count lockout events (future-proof if other event types are added later)
            try {
                if ($null -ne $e.PSObject.Properties['Type']) {
                    $t = [string]$e.Type
                    if (-not [string]::IsNullOrWhiteSpace($t) -and $t.ToLowerInvariant() -ne 'lockout') { continue }
                }
            } catch {}
            $ts = Convert-EventTimestamp $e.Timestamp
            if ($null -ne $ts -and $ts -ge $from -and $ts -le $to) {
                $u = Normalize-Username ([string]$e.Username)
                if ([string]::IsNullOrEmpty($u)) { continue }
                if (-not $stats.ContainsKey($u)) { $stats[$u] = [pscustomobject]@{ Count = 0; Last = $null } }
                $s = $stats[$u]
                $s.Count = [int]$s.Count + 1
                if ($null -eq $s.Last -or $ts -gt $s.Last) { $s.Last = $ts }
                $stats[$u] = $s
            }
        } catch {}
    }
    $stats
}

<#
.SYNOPSIS
Brief description of Compute-LatestLockouts.
.DESCRIPTION
Extended description of Compute-LatestLockouts.
.PARAMETER events
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Compute-LatestLockouts -events <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Compute-LatestLockouts([object[]]$events) {
    $latest = @{}
    foreach ($e in $events) {
        try {
            $ts = Convert-EventTimestamp $e.Timestamp
            $u = Normalize-Username ([string]$e.Username)
            if ($null -eq $ts -or [string]::IsNullOrEmpty($u)) { continue }
            if (-not $latest.ContainsKey($u) -or $ts -gt $latest[$u]) { $latest[$u] = $ts }
        } catch {}
    }
    $latest
}

<#
.SYNOPSIS
Brief description of Update-ListView.
.DESCRIPTION
Extended description of Update-ListView.
.PARAMETER currentUsers
Description.
.PARAMETER stats
Description.
.PARAMETER latestAllTime
Description.
.PARAMETER lockSessionStart
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Update-ListView -currentUsers <value> -stats <value> -latestAllTime <value> -lockSessionStart <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Update-ListView([object[]]$currentUsers, [hashtable]$statsRange, [hashtable]$statsAllTime, [hashtable]$latestAllTime, [hashtable]$lockSessionStart, [object[]]$trackedUsers = $null) {
    if ($null -eq $statsRange) { $statsRange = @{} }
    if ($null -eq $statsAllTime) { $statsAllTime = @{} }
    if ($null -eq $latestAllTime) { $latestAllTime = @{} }
    if ($null -eq $lockSessionStart) { $lockSessionStart = @{} }

    $rows = @()
    foreach ($u in $currentUsers) {
        $username = if ($null -ne $u.SamAccountName -and $u.SamAccountName -ne '') { [string]$u.SamAccountName } else { '<unknown>' }
        $normUser = Normalize-Username $username
        $given = if ($null -ne $u.GivenName) { [string]$u.GivenName } else { '' }
        $sur = if ($null -ne $u.Surname) { [string]$u.Surname } else { '' }
        $fullName = ("{0} {1}" -f $given, $sur).Trim()
        if ([string]::IsNullOrEmpty($fullName)) { $fullName = $username }
        # NOTE: This column is intentionally "Last Lockout" (from our event log), not AD's whenChanged.
        # AD's whenChanged can update for many reasons and caused confusing "missing rows" when changing ranges.
        $lastLockoutStr = '-'
        $lastLockoutDt = $null
        try {
            if ($statsRange.ContainsKey($normUser) -and $null -ne $statsRange[$normUser].Last) {
                $lastLockoutDt = [datetime]$statsRange[$normUser].Last
                $lastLockoutStr = $lastLockoutDt.ToString('g')
            } elseif ($latestAllTime.ContainsKey($normUser) -and $null -ne $latestAllTime[$normUser]) {
                $lastLockoutDt = [datetime]$latestAllTime[$normUser]
                $lastLockoutStr = $lastLockoutDt.ToString('g')
            }
        } catch { $lastLockoutStr = '-' }
        $lookupKey = $normUser
        $countRange = 0
        $countAllTime = 0
        $lockedSinceDt = $null
        if ($statsRange.ContainsKey($lookupKey)) {
            $entry = $statsRange[$lookupKey]
            $countRange = [int]$entry.Count
            # Count is range-based; do not set Locked Since from stats
        }
        if ($statsAllTime.ContainsKey($lookupKey)) {
            $entryA = $statsAllTime[$lookupKey]
            $countAllTime = [int]$entryA.Count
        }
        # Prefer persisted session start, then AD lockout time
        try {
            if ($lockSessionStart.ContainsKey($lookupKey)) {
                $lockedSinceDt = Convert-EventTimestamp $lockSessionStart[$lookupKey]
            }
        } catch {}
        try {
            if ($null -eq $lockedSinceDt -and $u.lockoutTime -and [long]$u.lockoutTime -gt 0) {
                $lockedSinceDt = [datetime]::FromFileTime([long]$u.lockoutTime)
            }
        } catch {}
        $lockedSinceStr = if ($null -ne $lockedSinceDt) { $lockedSinceDt.ToString('g') } else { '-' }

        $rows += [pscustomobject]@{
            Username    = [string]$username
            FullName    = [string]$fullName
            LastLockout = [string]$lastLockoutStr
            LastLockoutDt = $lastLockoutDt
            LockedSince = [string]$lockedSinceStr
            LockoutsRange   = [string]$countRange
            LockoutsAllTime = [string]$countAllTime
            ForeColor   = [System.Drawing.Color]::Red
            Tag         = [string]$username
        }
    }
    # Add tracked-only users (not currently locked)
    $trackedCount = 0
    if ($null -ne $trackedUsers -and $trackedUsers.Count -gt 0) {
        foreach ($u in $trackedUsers) {
            $username = if ($null -ne $u.SamAccountName -and $u.SamAccountName -ne '') { [string]$u.SamAccountName } else { '<unknown>' }
            $normUser = Normalize-Username $username
            $given = if ($null -ne $u.GivenName) { [string]$u.GivenName } else { '' }
            $sur = if ($null -ne $u.Surname) { [string]$u.Surname } else { '' }
            $fullName = ("{0} {1}" -f $given, $sur).Trim()
            if ([string]::IsNullOrEmpty($fullName)) { $fullName = $username }
            $lastLockoutStr = '-'
            $lastLockoutDt = $null
            try {
                if ($statsRange.ContainsKey($normUser) -and $null -ne $statsRange[$normUser].Last) {
                    $lastLockoutDt = [datetime]$statsRange[$normUser].Last
                    $lastLockoutStr = $lastLockoutDt.ToString('g')
                } elseif ($latestAllTime.ContainsKey($normUser) -and $null -ne $latestAllTime[$normUser]) {
                    $lastLockoutDt = [datetime]$latestAllTime[$normUser]
                    $lastLockoutStr = $lastLockoutDt.ToString('g')
                }
            } catch { $lastLockoutStr = '-' }
            $countRange = 0
            $countAllTime = 0
            if ($statsRange.ContainsKey($normUser)) { $entry = $statsRange[$normUser]; $countRange = [int]$entry.Count }
            if ($statsAllTime.ContainsKey($normUser)) { $entryA = $statsAllTime[$normUser]; $countAllTime = [int]$entryA.Count }
            $rows += [pscustomobject]@{
                Username    = [string]$username
                FullName    = [string]$fullName
                LastLockout = [string]$lastLockoutStr
                LastLockoutDt = $lastLockoutDt
                LockedSince = '-'
                LockoutsRange   = [string]$countRange
                LockoutsAllTime = [string]$countAllTime
                ForeColor   = [System.Drawing.Color]::Gray
                Tag         = [string]$username
            }
            $trackedCount++
        }
    }

    $script:lockedMonitorRows = @(
        $rows | Sort-Object -Property @(
            @{ Expression = { if ($null -ne $_.LastLockoutDt) { $_.LastLockoutDt } else { [datetime]::MinValue } }; Descending = $true },
            @{ Expression = { $_.Username }; Ascending = $true }
        )
    )
    Render-LockedMonitorListViewRows -Rows $script:lockedMonitorRows
}

<#
.SYNOPSIS
Brief description of Record-NewLockouts.
.DESCRIPTION
Extended description of Record-NewLockouts.
.PARAMETER prevLocked
Description.
.PARAMETER currLocked
Description.
.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Record-NewLockouts -prevLocked <value> -currLocked <value>
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Record-NewLockouts([string[]]$prevLocked, [string[]]$currLocked) {
    $prevSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($v in $prevLocked) { $null = $prevSet.Add([string]$v) }
    $newlyLocked = @($currLocked | Where-Object { -not $prevSet.Contains([string]$_) })
    if (-not $newlyLocked.Count) { return }
    $nowMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    foreach ($n in $newlyLocked) {
        $evt = [pscustomobject]@{
            Timestamp = $nowMs
            Username  = (Normalize-Username $n)
            Type      = 'lockout'
        }
        Append-Event -event $evt
    }
}

<#
.SYNOPSIS
Brief description of Do-Refresh.
.DESCRIPTION
Extended description of Do-Refresh.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Do-Refresh
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Do-Refresh {
    if ($script:isRefreshing) { return }; $script:isRefreshing = $true; Ensure-ControlsEnabled $false; Write-UiStatus 'Refreshing...'
    try {
        # Sync events from shared drive first to get latest data
        try {
            if (Get-Command Sync-SharedData -ErrorAction SilentlyContinue) {
                Sync-SharedData -ErrorAction SilentlyContinue
            }
        } catch {}
        $state = Load-State; $prevLockedRaw = @($state.LastLocked); $users = Get-CurrentLockedUsers; $currLockedRaw = @($users | ForEach-Object { $_.SamAccountName })
        $prevLocked = @($prevLockedRaw | ForEach-Object { Normalize-Username $_ })
        $currLocked = @($currLockedRaw | ForEach-Object { Normalize-Username $_ })

        # Build easy lookup for current users by normalized username
        $userByNorm = @{}
        foreach ($u in $users) { $userByNorm[(Normalize-Username $u.SamAccountName)] = $u }

        # Normalize LockSessionStart to a hashtable we can mutate
        $lockStartMap = @{}
        if ($null -ne $state.LockSessionStart) {
            try {
                if ($state.LockSessionStart -is [hashtable]) {
                    foreach ($k in $state.LockSessionStart.Keys) { $lockStartMap[$k] = $state.LockSessionStart[$k] }
                } else {
                    $state.LockSessionStart.PSObject.Properties | ForEach-Object { $lockStartMap[$_.Name] = $_.Value }
                }
            } catch {}
        }

        # Determine newly locked and unlocked sets
        $prevSet = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($v in $prevLocked) { $null = $prevSet.Add([string]$v) }
        $currSet = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($v in $currLocked) { $null = $currSet.Add([string]$v) }
        $newlyLocked = @($currLocked | Where-Object { -not $prevSet.Contains($_) })
        $now = Get-Date

        if (-not $state.LastRefresh) {
            # First run: seed starts from AD lockout time if possible, else now
            foreach ($n in $currLocked) {
                $adDt = $null
                if ($userByNorm.ContainsKey($n)) {
                    try { if ($userByNorm[$n].lockoutTime -and [long]$userByNorm[$n].lockoutTime -gt 0) { $adDt = [datetime]::FromFileTime([long]$userByNorm[$n].lockoutTime) } } catch {}
                }
                $startDt = if ($null -ne $adDt) { $adDt } else { $now }
                $lockStartMap[$n] = (To-EpochMilliseconds $startDt)
            }
            $state.LastLocked = $currLocked; $state.LockSessionStart = $lockStartMap; $state.LastRefresh = $now; Save-State -state $state
        } else {
            # Record new lockout events and start times
            if ($newlyLocked.Count -gt 0) {
                Record-NewLockouts -prevLocked $prevLocked -currLocked $currLocked
                foreach ($n in $newlyLocked) {
                    $adDt = $null
                    if ($userByNorm.ContainsKey($n)) {
                        try { if ($userByNorm[$n].lockoutTime -and [long]$userByNorm[$n].lockoutTime -gt 0) { $adDt = [datetime]::FromFileTime([long]$userByNorm[$n].lockoutTime) } } catch {}
                    }
                    $startDt = if ($null -ne $adDt) { $adDt } else { $now }
                    $lockStartMap[$n] = (To-EpochMilliseconds $startDt)
                }
            }
            # Remove entries for users no longer locked
            foreach ($p in $prevLocked) { if (-not $currSet.Contains($p)) { $null = $lockStartMap.Remove($p) } }
            $state.LastLocked = $currLocked; $state.LockSessionStart = $lockStartMap; $state.LastRefresh = $now; Save-State -state $state
        }
        if ($rangeCombo.SelectedItem -eq 'Custom') {
            $from = $fromPicker.Value; $to = $toPicker.Value
        } elseif ($rangeCombo.SelectedItem -eq 'All time') {
            $from = [DateTime]::MinValue; $to = Get-Date
        } else {
            $span = Get-SelectedRangeSpan
            if (-not $span) {
                # Fallback to 24h if we somehow couldn't resolve the span
                $span = [TimeSpan]::FromHours(24)
            }
            $to = Get-Date
            $from = $to.Add(-$span)
        }
        $events = Load-Events
        $statsRange = Compute-LockoutStats -events $events -from $from -to $to
        $statsAllTime = Compute-LockoutStats -events $events -from ([DateTime]::MinValue) -to ([DateTime]::MaxValue)
        $latest = Compute-LatestLockouts -events $events

        $totalLockoutsRange = 0
        $totalLockoutsAllTime = 0
        try {
            $sumR = (@($statsRange.Values) | Measure-Object -Property Count -Sum).Sum
            if ($null -ne $sumR) { $totalLockoutsRange = [int]$sumR }
        } catch { $totalLockoutsRange = 0 }
        try {
            $sumA = (@($statsAllTime.Values) | Measure-Object -Property Count -Sum).Sum
            if ($null -ne $sumA) { $totalLockoutsAllTime = [int]$sumA }
        } catch { $totalLockoutsAllTime = 0 }

        # Build tracked-only list if requested
        $trackedUsers = @()
        if ($null -ne $showTrackedCheck -and $showTrackedCheck.Checked) {
            $currSet = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($v in $currLocked) { $null = $currSet.Add([string]$v) }
            $candidates = @()
            foreach ($k in $statsRange.Keys) { if (-not $currSet.Contains([string]$k)) { $candidates += [string]$k } }
            if ($candidates.Count -gt 0) { $trackedUsers = Get-ADUsersBySam -samAccountNames $candidates }
        }

        Update-ListView -currentUsers $users -statsRange $statsRange -statsAllTime $statsAllTime -latestAllTime $latest -lockSessionStart $lockStartMap -trackedUsers $trackedUsers
        $lockedCount = @($users).Count; $trackedCount = @($trackedUsers).Count
        $fromStr = $from.ToString('g'); $toStr = $to.ToString('g')
        $script:lastStatusContext = [pscustomobject]@{
            LockedCount  = [int]$lockedCount
            TrackedCount = [int]$trackedCount
            LockoutsRangeCount   = [int]$totalLockoutsRange
            LockoutsAllTimeCount = [int]$totalLockoutsAllTime
            LastRefresh  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            FromStr      = [string]$fromStr
            ToStr        = [string]$toStr
        }
        Update-LockedMonitorStatusFromContext
    } catch { [System.Windows.Forms.MessageBox]::Show("Refresh failed: $_", "Locked Monitor", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null } finally { Ensure-ControlsEnabled $true; $script:isRefreshing = $false }
}

<#
.SYNOPSIS
Brief description of Unlock-Selected.
.DESCRIPTION
Extended description of Unlock-Selected.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Unlock-Selected
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Unlock-Selected {
    if ($listView.SelectedItems.Count -eq 0) { return }
    $ids = @($listView.SelectedItems | ForEach-Object { $_.Text })
    foreach ($id in $ids) { $r = Unlock-ADUserAccount -Identity $id | Select-Object -First 1; if (-not $r.Unlocked) { [System.Windows.Forms.MessageBox]::Show("Failed to unlock ${id}: $($r.Error)", "Unlock", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null } }
    Do-Refresh
}

<#
.SYNOPSIS
Brief description of Show-PasswordDialog.
.DESCRIPTION
Extended description of Show-PasswordDialog.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Show-PasswordDialog
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Show-PasswordDialog {
    $dlg = New-Object System.Windows.Forms.Form; $dlg.Text = 'Reset Password'; $dlg.Size = New-Object System.Drawing.Size(360, 200); $dlg.StartPosition = 'CenterParent'; $dlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog; $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false
    $lbl1 = New-Object System.Windows.Forms.Label; $lbl1.Text = 'New password:'; $lbl1.Location = '10,20'; $lbl1.AutoSize = $true
    $txt1 = New-Object System.Windows.Forms.TextBox; $txt1.Location = '140,18'; $txt1.Size = '190,20'; $txt1.UseSystemPasswordChar = $true
    $lbl2 = New-Object System.Windows.Forms.Label; $lbl2.Text = 'Confirm password:'; $lbl2.Location = '10,55'; $lbl2.AutoSize = $true
    $txt2 = New-Object System.Windows.Forms.TextBox; $txt2.Location = '140,53'; $txt2.Size = '190,20'; $txt2.UseSystemPasswordChar = $true
    $chk = New-Object System.Windows.Forms.CheckBox; $chk.Text = 'Require change at next logon'; $chk.Location = '10,85'; $chk.AutoSize = $true; $chk.Checked = $true
    $ok = New-Object System.Windows.Forms.Button; $ok.Text = 'OK'; $ok.Location = '175,120'; $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; $cancel.Location = '255,120'; $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dlg.Controls.AddRange(@($lbl1,$txt1,$lbl2,$txt2,$chk,$ok,$cancel)); $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
    $res = $dlg.ShowDialog(); if ($res -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    if ([string]::IsNullOrWhiteSpace($txt1.Text) -or $txt1.Text -ne $txt2.Text) { [System.Windows.Forms.MessageBox]::Show('Passwords do not match or are empty.','Reset Password',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null; return $null }
    @{ Password = $txt1.Text; RequireChange = $chk.Checked }
}

<#
.SYNOPSIS
Brief description of Reset-SelectedPassword.
.DESCRIPTION
Extended description of Reset-SelectedPassword.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Reset-SelectedPassword
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Reset-SelectedPassword {
    if ($listView.SelectedItems.Count -eq 0) { return }
    $username = $listView.SelectedItems[0].Text; $dlgRes = Show-PasswordDialog; if ($null -eq $dlgRes) { return }
    
    # Validate password complexity
    if (Get-Command Test-PasswordComplexity -ErrorAction SilentlyContinue) {
        $validation = Test-PasswordComplexity -Password $dlgRes.Password
        if (-not $validation.IsValid) {
            [System.Windows.Forms.MessageBox]::Show($validation.ErrorMessage, "Password Complexity Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            return
        }
    }
    
    $sec = ConvertTo-SecureString -String $dlgRes.Password -AsPlainText -Force
    $r = Reset-ADUserPassword -Identity $username -NewPassword $sec -PlainTextPassword $dlgRes.Password -RequireChangeAtNextLogon:([bool]$dlgRes.RequireChange)
    if (-not $r.Reset) { [System.Windows.Forms.MessageBox]::Show("Failed to reset password for ${username}: $($r.Error)", "Reset Password", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null } else { [System.Windows.Forms.MessageBox]::Show("Password reset successful for ${username}.", "Reset Password", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null }
}

<#
.SYNOPSIS
Brief description of Initialize-UI.
.DESCRIPTION
Extended description of Initialize-UI.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Initialize-UI
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Initialize-UI {
    $form = New-Object System.Windows.Forms.Form; $form.Text = 'Locked Accounts Monitor'; $form.Size = New-Object System.Drawing.Size(950, 650); $form.StartPosition = 'CenterScreen'; if (Test-Path $iconPath) { try { $form.Icon = New-Object System.Drawing.Icon($iconPath) } catch {} }
    $form.MinimumSize = New-Object System.Drawing.Size(950, 650)

    $form.KeyPreview = $true

    $top = New-Object System.Windows.Forms.Panel; $top.Dock = [System.Windows.Forms.DockStyle]::Top; $top.Height = 72; $form.Controls.Add($top)
    $refreshButton = New-Object System.Windows.Forms.Button; $refreshButton.Text = 'Refresh'; $refreshButton.Location = New-Object System.Drawing.Point(10, 9); $refreshButton.Size = New-Object System.Drawing.Size(75, 24); $top.Controls.Add($refreshButton)
    $autoRefreshCheck = New-Object System.Windows.Forms.CheckBox; $autoRefreshCheck.Text = 'Auto-refresh'; $autoRefreshCheck.Location = New-Object System.Drawing.Point(100, 12); $autoRefreshCheck.AutoSize = $true; $top.Controls.Add($autoRefreshCheck)
    $intervalCombo = New-Object System.Windows.Forms.ComboBox; $intervalCombo.DropDownStyle = 'DropDownList'; $intervalCombo.Items.AddRange(@('15s','30s','1m','2m','5m')); $intervalCombo.SelectedIndex = 1; $intervalCombo.Location = New-Object System.Drawing.Point(200, 10); $intervalCombo.Width = 70; $top.Controls.Add($intervalCombo)
    $rangeLabel = New-Object System.Windows.Forms.Label; $rangeLabel.Text = 'Range:'; $rangeLabel.AutoSize = $true; $rangeLabel.Location = New-Object System.Drawing.Point(290, 14); $top.Controls.Add($rangeLabel)
    $rangeCombo = New-Object System.Windows.Forms.ComboBox; $rangeCombo.DropDownStyle = 'DropDownList'; $rangeCombo.Items.AddRange(@('1h','4h','12h','24h','7d','30d','All time','Custom')); $rangeCombo.SelectedIndex = 4; $rangeCombo.Location = New-Object System.Drawing.Point(340, 10); $rangeCombo.Width = 100; $top.Controls.Add($rangeCombo)
    $fromPicker = New-Object System.Windows.Forms.DateTimePicker; $fromPicker.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom; $fromPicker.CustomFormat = 'yyyy-MM-dd HH:mm'; $fromPicker.Location = New-Object System.Drawing.Point(430, 10); $fromPicker.Width = 150; $fromPicker.Enabled = $false; $top.Controls.Add($fromPicker)
    $toPicker = New-Object System.Windows.Forms.DateTimePicker; $toPicker.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom; $toPicker.CustomFormat = 'yyyy-MM-dd HH:mm'; $toPicker.Location = New-Object System.Drawing.Point(590, 10); $toPicker.Width = 150; $toPicker.Enabled = $false; $top.Controls.Add($toPicker)
    $showTrackedCheck = New-Object System.Windows.Forms.CheckBox; $showTrackedCheck.Text = 'Show tracked'; $showTrackedCheck.Location = New-Object System.Drawing.Point(750, 12); $showTrackedCheck.AutoSize = $true
    # Default state comes from settings (Monitor.ShowTrackedByDefault). Default = $true.
    try {
        $defaultShowTracked = $true
        if ($null -ne $Settings -and $null -ne $Settings.Monitor -and $null -ne $Settings.Monitor.ShowTrackedByDefault) {
            $defaultShowTracked = [bool]$Settings.Monitor.ShowTrackedByDefault
        }
        $showTrackedCheck.Checked = $defaultShowTracked
    } catch {
        $showTrackedCheck.Checked = $true
    }
    $top.Controls.Add($showTrackedCheck)
    $pruneButton = New-Object System.Windows.Forms.Button; $pruneButton.Text = 'Prune...'; $pruneButton.Location = New-Object System.Drawing.Point(840, 9); $pruneButton.Size = New-Object System.Drawing.Size(70, 24); $top.Controls.Add($pruneButton)

    # Search row (filters the current list; does not trigger AD queries)
    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.Text = 'Search:'
    $searchLabel.AutoSize = $true
    $searchLabel.Location = New-Object System.Drawing.Point(10, 46)
    $top.Controls.Add($searchLabel)

    $script:searchTextBox = New-Object System.Windows.Forms.TextBox
    $script:searchTextBox.Location = New-Object System.Drawing.Point(65, 43)
    $script:searchTextBox.Size = New-Object System.Drawing.Size(780, 20)
    $script:searchTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $top.Controls.Add($script:searchTextBox)

    $script:clearSearchButton = New-Object System.Windows.Forms.Button
    $script:clearSearchButton.Text = 'X'
    $script:clearSearchButton.Size = New-Object System.Drawing.Size(28, 22)
    $script:clearSearchButton.Location = New-Object System.Drawing.Point(882, 41)
    $script:clearSearchButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $top.Controls.Add($script:clearSearchButton)

    $listView = New-Object System.Windows.Forms.ListView; $listView.Dock = [System.Windows.Forms.DockStyle]::Fill; $listView.View = [System.Windows.Forms.View]::Details; $listView.FullRowSelect = $true; $listView.GridLines = $true
    $listView.Columns.Add('Username', 140) | Out-Null
    $listView.Columns.Add('Full Name', 200) | Out-Null
    $listView.Columns.Add('Last Lockout', 140) | Out-Null
    $listView.Columns.Add('Locked Since', 140) | Out-Null
    $listView.Columns.Add('Lockouts (range)', 110) | Out-Null
    $listView.Columns.Add('Lockouts (all time)', 120) | Out-Null
    $form.Controls.Add($listView); $listView.BringToFront()
    Add-LockedListViewSorting -ListView $listView

    $bottom = New-Object System.Windows.Forms.Panel; $bottom.Dock = [System.Windows.Forms.DockStyle]::Bottom; $bottom.Height = 36; $form.Controls.Add($bottom)
    $unlockButton = New-Object System.Windows.Forms.Button; $unlockButton.Text = 'Unlock Selected'; $unlockButton.Location = New-Object System.Drawing.Point(10, 6); $unlockButton.Size = New-Object System.Drawing.Size(120, 24); $bottom.Controls.Add($unlockButton)
    $resetButton = New-Object System.Windows.Forms.Button; $resetButton.Text = 'Reset Password...'; $resetButton.Location = New-Object System.Drawing.Point(140, 6); $resetButton.Size = New-Object System.Drawing.Size(130, 24); $bottom.Controls.Add($resetButton)
    $openInADappButton = New-Object System.Windows.Forms.Button; $openInADappButton.Text = 'Open in ADapp'; $openInADappButton.Location = New-Object System.Drawing.Point(280, 6); $openInADappButton.Size = New-Object System.Drawing.Size(120, 24); $bottom.Controls.Add($openInADappButton)
    $statusLabel = New-Object System.Windows.Forms.Label; $statusLabel.Text = 'Ready'; $statusLabel.AutoSize = $true; $statusLabel.Location = New-Object System.Drawing.Point(420, 10); $bottom.Controls.Add($statusLabel)

    $timer = New-Object System.Windows.Forms.Timer; $timer.Interval = Get-IntervalMs
    $refreshButton.Add_Click({ Do-Refresh })
    $autoRefreshCheck.Add_CheckedChanged({ $intervalCombo.Enabled = $autoRefreshCheck.Checked; if ($autoRefreshCheck.Checked) { $timer.Interval = Get-IntervalMs; $timer.Start() } else { $timer.Stop() } })
    $intervalCombo.Add_SelectedIndexChanged({ $timer.Interval = Get-IntervalMs })
    $rangeCombo.Add_SelectedIndexChanged({ $custom = ($rangeCombo.SelectedItem -eq 'Custom'); $fromPicker.Enabled = $custom; $toPicker.Enabled = $custom; Do-Refresh })
    $showTrackedCheck.Add_CheckedChanged({ Do-Refresh })
    $pruneButton.Add_Click({ $ts = Show-PruneDialog; if ($null -ne $ts) { Prune-EventFile -retain $ts; Do-Refresh } })
    $listView.Add_SelectedIndexChanged({ Ensure-ControlsEnabled $true })
    $unlockButton.Add_Click({ Unlock-Selected })
    $resetButton.Add_Click({ Reset-SelectedPassword })
    $openInADappButton.Add_Click({
        try {
            if ($listView.SelectedItems.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("Select a user first.", "Locked Monitor", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                return
            }
            $username = [string]$listView.SelectedItems[0].Text
            if ([string]::IsNullOrWhiteSpace($username)) {
                [System.Windows.Forms.MessageBox]::Show("Select a user first.", "Locked Monitor", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                return
            }

            # Give immediate feedback to the user (ADapp can take a moment to appear)
            try { if ($statusLabel) { $statusLabel.Text = "Opening ADapp..." } } catch {}
            try {
                $t = New-Object System.Windows.Forms.Timer
                $t.Interval = 3000
                $t.Add_Tick({
                    try { $t.Stop(); $t.Dispose() } catch {}
                    try { if ($statusLabel) { Update-LockedMonitorStatusFromContext } } catch {}
                })
                $t.Start()
            } catch {}

            # Best-effort: drop an IPC command file so a running ADapp instance can pick it up immediately.
            # (This avoids named-pipe / elevation / session issues.)
            try {
                $spoolDir = Join-Path -Path $env:ProgramData -ChildPath 'ADapp\ipc\spool'
                if (-not (Test-Path $spoolDir)) { New-Item -ItemType Directory -Path $spoolDir -Force | Out-Null }
                $cmd = @{ action = 'openUser'; user = $username } | ConvertTo-Json -Compress
                $cmdPath = Join-Path -Path $spoolDir -ChildPath ("cmd_{0}.json" -f ([guid]::NewGuid().ToString('N')))
                Set-Content -Path $cmdPath -Value $cmd -Encoding UTF8 -Force
            } catch {}

            $adappPath = Join-Path $appRoot 'ADapp.ps1'
            if (-not (Test-Path $adappPath)) {
                [System.Windows.Forms.MessageBox]::Show("ADapp.ps1 not found at:`n$adappPath", "Locked Monitor", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
                return
            }

            Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-NoLogo','-ExecutionPolicy','Bypass','-STA','-WindowStyle','Hidden','-File',"`"$adappPath`"","-OpenUser",$username) -WindowStyle Hidden | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to open ADapp: $_", "Locked Monitor", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    })
    $timer.Add_Tick({ Do-Refresh })

    $script:searchTextBox.Add_TextChanged({
        # Re-filter locally (no refresh)
        Render-LockedMonitorListViewRows -Rows $script:lockedMonitorRows
    })
    $script:clearSearchButton.Add_Click({
        try { $script:searchTextBox.Text = '' } catch {}
        try { $script:searchTextBox.Focus() } catch {}
    })
    $form.Add_KeyDown({
        param($sender, $e)
        try {
            if ($e.Control -and $e.KeyCode -eq [System.Windows.Forms.Keys]::F) {
                $e.Handled = $true
                $e.SuppressKeyPress = $true
                $script:searchTextBox.Focus()
                $script:searchTextBox.SelectAll()
            } elseif ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
                if (-not [string]::IsNullOrWhiteSpace((Get-LockedMonitorSearchText))) {
                    $e.Handled = $true
                    $e.SuppressKeyPress = $true
                    $script:searchTextBox.Text = ''
                }
            }
        } catch {}
    })

    # Create tray icon
    $script:trayIcon = New-Object System.Windows.Forms.NotifyIcon
    $script:trayIcon.Text = "Locked Accounts Monitor"
    if (Test-Path $iconPath) {
        try {
            $script:trayIcon.Icon = New-Object System.Drawing.Icon($iconPath)
        } catch {}
    }
    # Initial visibility will be set based on start-minimized setting below

    # Create context menu for tray icon
    $trayMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $showMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $showMenuItem.Text = "Show"
    $showMenuItem.Add_Click({
        if ($form.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
            $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        }
        $form.Show()
        $form.Activate()
        $form.BringToFront()
        $script:trayIcon.Visible = $false
    })
    $trayMenu.Items.Add($showMenuItem) | Out-Null

    $exitMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $exitMenuItem.Text = "Exit"
    $exitMenuItem.Add_Click({
        $script:isExiting = $true
        $script:trayIcon.Visible = $false
        if ($null -ne $mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() }
        $form.Close()
    })
    $trayMenu.Items.Add($exitMenuItem) | Out-Null

    $script:trayIcon.ContextMenuStrip = $trayMenu
    $script:trayIcon.Add_DoubleClick({
        if ($form.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) {
            $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        }
        $form.Show()
        $form.Activate()
        $form.BringToFront()
        $script:trayIcon.Visible = $false
    })

    # Handle minimize-to-tray (close-to-tray FormClosing handler is added at script level)
    $closeToTray = if ($null -ne $Settings.Monitor -and $null -ne $Settings.Monitor.CloseToTray) { $Settings.Monitor.CloseToTray } else { $false }
    $script:isExiting = $false
    $form.Add_Resize({
        if ($form.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized -and $closeToTray) {
            $form.Hide()
            $script:trayIcon.Visible = $true
        }
    })

    # Handle start minimized
    $startMinimized = if ($null -ne $Settings.Monitor -and $null -ne $Settings.Monitor.StartMinimized) { $Settings.Monitor.StartMinimized } else { $false }
    if ($startMinimized) {
        if ($closeToTray) {
            # Start hidden to tray
            $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
            $form.Hide()
            $script:trayIcon.Visible = $true
        } else {
            # Start minimized to taskbar
            $form.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
            $script:trayIcon.Visible = $false
        }
    } else {
        # Not starting minimized, hide tray icon
        $script:trayIcon.Visible = $false
    }

    Set-Variable -Scope Script -Name form -Value $form
    Set-Variable -Scope Script -Name refreshButton -Value $refreshButton
    Set-Variable -Scope Script -Name autoRefreshCheck -Value $autoRefreshCheck
    Set-Variable -Scope Script -Name intervalCombo -Value $intervalCombo
    Set-Variable -Scope Script -Name rangeCombo -Value $rangeCombo
    Set-Variable -Scope Script -Name fromPicker -Value $fromPicker
    Set-Variable -Scope Script -Name toPicker -Value $toPicker
    Set-Variable -Scope Script -Name listView -Value $listView
    Set-Variable -Scope Script -Name unlockButton -Value $unlockButton
    Set-Variable -Scope Script -Name resetButton -Value $resetButton
    Set-Variable -Scope Script -Name openInADappButton -Value $openInADappButton
    Set-Variable -Scope Script -Name statusLabel -Value $statusLabel
    Set-Variable -Scope Script -Name timer -Value $timer
    Set-Variable -Scope Script -Name showTrackedCheck -Value $showTrackedCheck
    Set-Variable -Scope Script -Name pruneButton -Value $pruneButton
    Set-Variable -Scope Script -Name searchTextBox -Value $script:searchTextBox
    Set-Variable -Scope Script -Name clearSearchButton -Value $script:clearSearchButton
}

<#
.SYNOPSIS
Brief description of Show-PruneDialog.
.DESCRIPTION
Shows dialog to choose a retention window and returns a TimeSpan; null cancels.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Show-PruneDialog
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Show-PruneDialog {
    $dlg = New-Object System.Windows.Forms.Form; $dlg.Text = 'Prune Events'; $dlg.Size = New-Object System.Drawing.Size(300, 160); $dlg.StartPosition = 'CenterParent'; $dlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog; $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false
    $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = 'Retain last:'; $lbl.Location = '10,20'; $lbl.AutoSize = $true
    $num = New-Object System.Windows.Forms.NumericUpDown; $num.Location = '90,18'; $num.Width = 80; $num.Minimum = 1; $num.Maximum = 3650; $num.Value = 30
    $units = New-Object System.Windows.Forms.ComboBox; $units.DropDownStyle = 'DropDownList'; $units.Items.AddRange(@('days','hours','weeks')); $units.SelectedIndex = 0; $units.Location = '180,18'; $units.Width = 80
    $ok = New-Object System.Windows.Forms.Button; $ok.Text = 'OK'; $ok.Location = '110,70'; $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; $cancel.Location = '190,70'; $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dlg.Controls.AddRange(@($lbl,$num,$units,$ok,$cancel)); $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
    $res = $dlg.ShowDialog(); if ($res -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    $value = [int]$num.Value; $unit = [string]$units.SelectedItem
    switch ($unit) {
        'hours' { return [TimeSpan]::FromHours($value) }
        'weeks' { return [TimeSpan]::FromDays(7 * $value) }
        default { return [TimeSpan]::FromDays($value) }
    }
}

Load-ModuleSafe
Initialize-UI
$autoRefreshCheck.Checked = $true

# Handle form shown - hide tray icon if visible, trigger refresh
$form.Add_Shown({
    if ($form.Visible) {
        $script:trayIcon.Visible = $false
    }
    Do-Refresh
})

# Cleanup on form closed
$form.Add_FormClosed({
    if ($null -ne $script:trayIcon) {
        $script:trayIcon.Visible = $false
        $script:trayIcon.Dispose()
    }
    if ($null -ne $mutex) {
        $mutex.ReleaseMutex()
        $mutex.Dispose()
    }
})

# Use Application.Run instead of ShowDialog to support close-to-tray behavior
# ShowDialog is modal and doesn't work well with canceling FormClosing
$form.Add_FormClosing({
    param($sender, $e)
    $closeToTray = if ($null -ne $Settings.Monitor -and $null -ne $Settings.Monitor.CloseToTray) { $Settings.Monitor.CloseToTray } else { $false }
    if ($closeToTray -and -not $script:isExiting) {
        $e.Cancel = $true
        $form.Hide()
        $script:trayIcon.Visible = $true
    }
})

[System.Windows.Forms.Application]::Run($form)


