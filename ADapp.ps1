# ADapp.ps1 - Active Directory Management Tool
# Main application script that imports all modules and initializes the UI

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OpenUser
)

# Force use of TLS 1.2 for web requests
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Redirect unnecessary output to null
$ProgressPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

# Add Windows Forms assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# === ADapp single-instance + IPC (spool-folder based, for integration from LockedMonitor, etc.) ===
$script:ADappMutexName = 'ADapp_SingleInstance'
$script:ADappIpcDir = Join-Path -Path $env:ProgramData -ChildPath 'ADapp\ipc'
$script:ADappIpcSpoolDir = Join-Path -Path $script:ADappIpcDir -ChildPath 'spool'
$script:StartupOpenUser = $null

# WinAPI helpers for bringing the main window to the foreground
try {
    if (-not ([type]::GetType('WinAPI.WindowNative'))) {
        Add-Type -AssemblyName System.Runtime.InteropServices
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace WinAPI {
  public static class WindowNative {
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")]
    public static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")]
    public static extern bool IsIconic(IntPtr hWnd);
    public const int SW_RESTORE = 9;
    public const int SW_SHOW = 5;
  }
}
"@ -Language CSharp
    }
} catch {}

function Write-ADappSpoolCommand {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Command
    )
    $payload = ($Command | ConvertTo-Json -Compress)
    if (-not (Test-Path $script:ADappIpcSpoolDir)) { New-Item -ItemType Directory -Path $script:ADappIpcSpoolDir -Force | Out-Null }
    $file = Join-Path -Path $script:ADappIpcSpoolDir -ChildPath ("cmd_{0}.json" -f ([guid]::NewGuid().ToString('N')))
    Set-Content -Path $file -Value $payload -Encoding UTF8 -Force
    return $true
}

function Initialize-ADappIpcSpoolPermissions {
    try {
        if (-not (Test-Path $script:ADappIpcSpoolDir)) { New-Item -ItemType Directory -Path $script:ADappIpcSpoolDir -Force | Out-Null }
        # Best-effort: allow non-admin processes to drop command files.
        try {
            $acl = Get-Acl -Path $script:ADappIpcSpoolDir
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Users','Modify','ContainerInherit,ObjectInherit','None','Allow')
            $acl.SetAccessRule($rule)
            Set-Acl -Path $script:ADappIpcSpoolDir -AclObject $acl
        } catch {}
    } catch {}
}

function Write-ADappIpcTrace {
    param([string]$Message)
    try {
        $logDir = Join-Path -Path $env:ProgramData -ChildPath 'ADapp\Logs'
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Message
        Add-Content -Path (Join-Path $logDir 'ADapp_IpcTrace.log') -Value $line -Encoding UTF8
    } catch {}
}

# Acquire single-instance mutex early to avoid heavy startup work in secondary instances.
$script:ADappMutex = $null
$script:ADappMutexAcquired = $false
try {
    $script:ADappMutex = New-Object System.Threading.Mutex($false, $script:ADappMutexName)
    $script:ADappMutexAcquired = $script:ADappMutex.WaitOne(0, $false)
} catch {
    $script:ADappMutex = $null
    $script:ADappMutexAcquired = $true  # fail open so the app still works
}

if (-not $script:ADappMutexAcquired) {
    # Another ADapp instance is running. Route request to the primary instance and exit.
    try {
        if (-not [string]::IsNullOrWhiteSpace($OpenUser)) {
            [void](Write-ADappSpoolCommand -Command @{ action = 'openUser'; user = $OpenUser })
        } else {
            [void](Write-ADappSpoolCommand -Command @{ action = 'activate' })
        }
    } catch {}
    exit 0
}

if (-not [string]::IsNullOrWhiteSpace($OpenUser)) {
    $script:StartupOpenUser = $OpenUser
}

function Normalize-ADappUsername {
    param([string]$Username)
    if ([string]::IsNullOrWhiteSpace($Username)) { return '' }
    $n = $Username.Trim()
    if ($n -match '^[^\\]+\\(.+)$') { $n = $Matches[1] }
    if ($n -match '^(.+)@[^@]+$') { $n = $Matches[1] }
    return $n.Trim()
}

function Format-ADappOUPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }

    $value = $Path.Trim()
    # If this is a DN, strip the leaf CN/OU first (e.g., CN=Computer1,...)
    if ($value -match '^(CN|OU)=[^,]+,(.+)$') {
        $value = $Matches[2]
    }

    # Remove domain suffix from distinguishedName (",DC=corp,DC=example")
    $value = $value -replace '(,DC=[^,]+)+$',''

    # Remove domain prefix from canonicalName ("corp.example/OU/SubOU/Object")
    if ($value -match '^[^/]+/.+') {
        $value = $value.Substring($value.IndexOf('/') + 1)
    }

    # Remove the leaf object name from canonical OU paths ("OU/SubOU/Object")
    if ($value -match '^.+/.+') {
        $value = $value.Substring(0, $value.LastIndexOf('/'))
    }

    return $value
}

function Ensure-ADappWindowForeground {
    param([Parameter(Mandatory=$true)][System.Windows.Forms.Form]$Form)
    try {
        if ($null -eq $Form -or $Form.IsDisposed) { return }
        $h = $Form.Handle
        if ($h -eq [IntPtr]::Zero) { return }
        try {
            if ([WinAPI.WindowNative]::IsIconic($h)) { [void][WinAPI.WindowNative]::ShowWindow($h, [WinAPI.WindowNative]::SW_RESTORE) }
            else { [void][WinAPI.WindowNative]::ShowWindow($h, [WinAPI.WindowNative]::SW_SHOW) }
        } catch {}
        try { [void][WinAPI.WindowNative]::BringWindowToTop($h) } catch {}
        try { [void][WinAPI.WindowNative]::SetForegroundWindow($h) } catch {}
        try { $Form.Activate() } catch {}
    } catch {}
}

function Invoke-ADappOpenUser {
    param([Parameter(Mandatory=$true)][string]$Username)
    try {
        $u = Normalize-ADappUsername -Username $Username
        if ([string]::IsNullOrWhiteSpace($u)) { return }

        if ($mainForm) { Ensure-ADappWindowForeground -Form $mainForm }

        try { if ($statusLabel) { $statusLabel.Text = "External request: searching user $u..." } } catch {}

        # Ensure advanced search is enabled so Exact Match is honored
        try { if ($advancedSearchCheckBox) { $advancedSearchCheckBox.Checked = $true } } catch {}
        try { if ($exactMatchCheckBox) { $exactMatchCheckBox.Checked = $true } } catch {}

        # Force Users search
        try {
            if ($typeComboBox -and $typeComboBox.Items) {
                $idx = $typeComboBox.Items.IndexOf("Users")
                if ($idx -ge 0) { $typeComboBox.SelectedIndex = $idx } else { $typeComboBox.SelectedItem = "Users" }
            }
        } catch {}

        try { if ($searchTextBox) { $searchTextBox.Text = $u } } catch {}
        try {
            if ($searchButton) { $searchButton.PerformClick() }
        } catch {}
    } catch {}
}

function Process-ADappIpcQueue {
    try {
        # Spool channel: ProgramData command files (read+delete)
        try {
            if (Test-Path $script:ADappIpcSpoolDir) {
                $files = @()
                try { $files = @(Get-ChildItem -Path $script:ADappIpcSpoolDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTimeUtc) } catch { $files = @() }
                foreach ($f in $files) {
                    $raw = $null
                    try { $raw = Get-Content -Path $f.FullName -Raw -ErrorAction Stop } catch { $raw = $null }
                    try { Remove-Item -Path $f.FullName -Force -ErrorAction SilentlyContinue } catch {}
                    if ([string]::IsNullOrWhiteSpace($raw)) { continue }
                    $cmd2 = $null
                    try { $cmd2 = $raw | ConvertFrom-Json } catch { $cmd2 = $null }
                    if (-not $cmd2) { continue }
                    $action2 = $null
                    try { $action2 = [string]$cmd2.action } catch { $action2 = $null }
                    if ($action2 -eq 'openUser') {
                        $user2 = $null
                        try { $user2 = [string]$cmd2.user } catch { $user2 = $null }
                        if (-not [string]::IsNullOrWhiteSpace($user2)) {
                            Write-ADappIpcTrace -Message ("recv spool openUser {0}" -f $user2)
                            Invoke-ADappOpenUser -Username $user2
                        }
                    } elseif ($action2 -eq 'activate') {
                        Write-ADappIpcTrace -Message "recv spool activate"
                        try { if ($mainForm) { Ensure-ADappWindowForeground -Form $mainForm } } catch {}
                    }
                }
            }
        } catch {}
    } catch {}
}

#
# NOTE: Previous iterations experimented with a custom ListView to prevent blank-area clicks from clearing selection.
# That approach is no longer needed because keyboard shortcuts now use a cached selection object.
#

# Add code to ensure taskbar icon is shown properly when window is initially hidden
# Try to set AppUserModelID to ensure proper taskbar icon
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
    $appId = if ($env:AppId) { $env:AppId } else { "ADSearchTool" }
    [WinAPI.TaskbarHelper]::SetCurrentProcessExplicitAppUserModelID($appId)
} catch {
    Write-Warning "Unable to set AppUserModelID: $_"
}

# Import modules
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:ScriptPath = $ScriptPath
$ModulesPath = Join-Path -Path $ScriptPath -ChildPath "Modules"

# Load application settings
try { Import-Module "$ModulesPath\Settings.psm1" -Force -DisableNameChecking | Out-Null } catch { Write-Warning "Error loading Settings module: $_" }
$settingsPath = Join-Path -Path (Join-Path -Path $ScriptPath -ChildPath "config") -ChildPath "settings.json"
try {
    $Settings = Load-Settings -ScriptPath $ScriptPath
    $global:Settings = $Settings
} catch {
    Write-Warning "Error loading settings: $_"
}

# Load Logging module first
try {
    Import-Module "$ModulesPath\Logging.psm1" -Force -DisableNameChecking | Out-Null
    Write-Log -Message "Loaded module: Logging" -Level "Info"
}
catch {
    Write-Log -Message "ERROR: Failed to load Logging module. The application may not function correctly." -Level "Error"
}

# Setup transcript logging early to capture all console output (if enabled)
# This allows the log viewer to follow the CLI as closely as possible
try {
    if ($Settings.Logging.EnableTranscript) {
        $transcriptLogFile = Join-Path -Path $global:Settings.Logging.LogPath -ChildPath "ADapp_Console.log"
        try { Import-Module "$ModulesPath\Transcript.psm1" -Force -DisableNameChecking | Out-Null } catch { Write-Log -Message "Transcript module load failed: $_" -Level "Warning" }
        Start-FilteredTranscript -Path $transcriptLogFile -Append
        Write-Log -Message "Transcript logging started early. Log file: $transcriptLogFile" -Level "Info"
    }
} catch {
    Write-Log -Message "Failed to start early transcript logging: $_" -Level "Warning"
}

# Check if ActiveDirectory module is available and import it
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Log -Message "Active Directory module loaded successfully" -Level "Info"
} 
catch {
    Write-Log -Message "Error loading Active Directory module: $_" -Level "Warning"
    # Rely on stubs in Modules/ADSearch.psm1 if needed
}

# Import all remaining module files
Get-ChildItem -Path $ModulesPath -Filter *.psm1 | Where-Object { $_.Name -ne "Logging.psm1" } | ForEach-Object {
    try {
        Import-Module $_.FullName -Force -DisableNameChecking | Out-Null
        Write-Log -Message "Loaded module: $($_.BaseName)" -Level "Info"
    } catch {
        Write-Log -Message "Error loading module $($_.BaseName): $_" -Level "Error"
    }
}

# Fallback Search-ADObjectsAdvanced removed (implemented in Modules/ADSearch.psm1)

# Fallback loader for Search-ADObjectsAdvanced in case module import/export fails
if (-not (Get-Command Search-ADObjectsAdvanced -ErrorAction SilentlyContinue)) {
    try {
        # Dot-source ADSearch.psm1 so its functions are available in this session
        . (Join-Path -Path $ModulesPath -ChildPath 'ADSearch.psm1')
    } catch {
        try { Write-Log -Message "Error loading Search-ADObjectsAdvanced from ADSearch.psm1: $_" -Level "Error" } catch {}
    }
}

# Setup global variables
$LocalDataPath = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data"

# Resolve shared data context (preferred vs local)
$activeSharedPath = $LocalDataPath
$sharedCtx = $null
try {
    if (Get-Command Resolve-SharedDataPaths -ErrorAction SilentlyContinue) {
        $sharedCtx = Resolve-SharedDataPaths -Settings $Settings
        if ($sharedCtx -and $sharedCtx.ActivePath) { $activeSharedPath = $sharedCtx.ActivePath }
        # One-time warning if preferred is configured but not available
        if ($sharedCtx.PreferredConfigured -and -not $sharedCtx.PreferredAvailable) {
            try {
                [System.Windows.Forms.MessageBox]::Show(
                    "Preferred shared data folder is unavailable. The app will use the local data folder and continue.",
                    "Data Folder",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
            } catch {}
        }
    }
} catch {}

$global:AppConfig = [PSCustomObject]@{
    Title = $Settings.Application.Title
    Version = $Settings.Application.Version
    LogPath = $Settings.Logging.LogPath
    DataPath = $LocalDataPath
    FavoritesFile = Join-Path -Path $activeSharedPath -ChildPath "favorites.json"
    SearchHistoryFile = Join-Path -Path $activeSharedPath -ChildPath "search_history.json"
    MaxSearchHistory = $Settings.Search.MaxSearchHistory
    MaxFavorites = 50
    SearchResults = New-Object System.Collections.ArrayList
    SearchHistory = New-Object System.Collections.ArrayList
    ActiveSearchFilters = @{
        Location = ""
        Status = ""
        DateRange = @{
            Enabled = $false
            StartDate = $null
            EndDate = $null
        }
    }
}

# Create required directories
if (-not (Test-Path -Path $global:AppConfig.LogPath)) {
    New-Item -Path $global:AppConfig.LogPath -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path -Path $global:AppConfig.DataPath)) {
    New-Item -Path $global:AppConfig.DataPath -ItemType Directory -Force | Out-Null
}

# === Keyboard shortcut helpers ===
function Convert-KeyEventToShortcutString {
    param($KeyEvent)
    try {
        $parts = @()
        if ($KeyEvent.Control) { $parts += 'Ctrl' }
        if ($KeyEvent.Alt) { $parts += 'Alt' }
        if ($KeyEvent.Shift) { $parts += 'Shift' }

        $keyCode = [string]$KeyEvent.KeyCode
        $map = @{ Escape='Esc'; Return='Enter'; Capital='CapsLock'; Prior='PageUp'; Next='PageDown' }
        $special = @('ShiftKey','ControlKey','Menu')

        if ($special -contains $keyCode) { return '' }

        if ($map.ContainsKey($keyCode)) { $key = $map[$keyCode] }
        elseif ($keyCode -match '^F\d{1,2}$') { $key = $keyCode }
        elseif ($keyCode -in @('Left','Right','Up','Down','Home','End','Insert','Delete','Back','Tab','Space')) { 
            $key = switch ($keyCode) { Back {'Backspace'} Tab {'Tab'} Space {'Space'} default { $keyCode } }
        }
        else { $key = $keyCode }

        if (-not $key) { return '' }
        $parts += $key
        return ($parts -join '+')
    } catch { return '' }
}

function Parse-ShortcutStringToKeys {
    param([string]$Shortcut)
    if ([string]::IsNullOrWhiteSpace($Shortcut)) { return [System.Windows.Forms.Keys]::None }
    $value = [System.Windows.Forms.Keys]::None
    foreach ($part in $Shortcut.Split('+')) {
        $p = $part.Trim()
        switch -Regex ($p) {
            '^Ctrl$'   { $value = $value -bor [System.Windows.Forms.Keys]::Control }
            '^Alt$'    { $value = $value -bor [System.Windows.Forms.Keys]::Alt }
            '^Shift$'  { $value = $value -bor [System.Windows.Forms.Keys]::Shift }
            '^Esc(ape)?$' { $value = $value -bor [System.Windows.Forms.Keys]::Escape }
            '^Enter$'  { $value = $value -bor [System.Windows.Forms.Keys]::Enter }
            '^Back(space)?$' { $value = $value -bor [System.Windows.Forms.Keys]::Back }
            '^Space$'  { $value = $value -bor [System.Windows.Forms.Keys]::Space }
            '^Tab$'    { $value = $value -bor [System.Windows.Forms.Keys]::Tab }
            '^Up$'     { $value = $value -bor [System.Windows.Forms.Keys]::Up }
            '^Down$'   { $value = $value -bor [System.Windows.Forms.Keys]::Down }
            '^Left$'   { $value = $value -bor [System.Windows.Forms.Keys]::Left }
            '^Right$'  { $value = $value -bor [System.Windows.Forms.Keys]::Right }
            '^PageUp$' { $value = $value -bor [System.Windows.Forms.Keys]::PageUp }
            '^PageDown$' { $value = $value -bor [System.Windows.Forms.Keys]::PageDown }
            '^F(\d{1,2})$' { $n = [int]$Matches[1]; $value = $value -bor ([System.Windows.Forms.Keys]::Parse([System.Windows.Forms.Keys], "F$n")) }
            '^[A-Z0-9]$' { $value = $value -bor ([System.Windows.Forms.Keys]::Parse([System.Windows.Forms.Keys], $p)) }
            default { }
        }
    }
    return $value
}

function Invoke-NewSearch {
    try {
        $searchTextBox.Text = ""
        try { $searchTextBox.Focus(); $searchTextBox.SelectAll() } catch {}
        try { if ($typeComboBox) { $typeComboBox.SelectedIndex = 0 } } catch {}
        try { $script:CurrentSelection = $null } catch {}
        try { Clear-SelectionHighlight } catch {}
        try { if ($resultsListView) { $resultsListView.Items.Clear() } } catch {}
        try { if ($fieldListView) { $fieldListView.Items.Clear() } } catch {}
        try { if ($groupsListView) { $groupsListView.Items.Clear() } } catch {}
        try { if ($locationListView) { $locationListView.Items.Clear() } } catch {}
        try { if ($statusLabel) { $statusLabel.Text = "Ready for new search" } } catch {}
        # Reset advanced search fields (but keep advanced search checkbox state)
        Clear-SearchFilters
    } catch {}
}

function Set-CurrentSelectionFromListViewItem {
    param([System.Windows.Forms.ListViewItem]$Item)
    if (-not $Item) { return }
    try {
        $typeText = ""
        $nameText = ""
        $tagObj = $null
        try { $typeText = [string]$Item.SubItems[0].Text } catch {}
        try { $nameText = [string]$Item.SubItems[1].Text } catch {}
        try { $tagObj = $Item.Tag } catch {}

        $script:CurrentSelection = [PSCustomObject]@{
            Type = $typeText
            Name = $nameText
            Tag  = $tagObj
        }
        try { Update-SelectionHighlight -Type $typeText -Name $nameText } catch {}
    } catch {}
}

function Get-CurrentSelection {
    # Only updates when there is an actual selection in the UI.
    try {
        if ($resultsListView -and $resultsListView.SelectedItems.Count -gt 0) {
            Set-CurrentSelectionFromListViewItem -Item $resultsListView.SelectedItems[0]
        }
    } catch {}
    return $script:CurrentSelection
}

function Show-SelectFromListDialog {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string]$Prompt,
        [Parameter(Mandatory=$true)][string[]]$Items,
        [System.Windows.Forms.Form]$ParentForm = $null
    )

    try {
        if (-not $Items -or $Items.Count -eq 0) { return $null }

        $form = New-Object System.Windows.Forms.Form
        $form.Text = $Title
        $form.Size = New-Object System.Drawing.Size(520, 420)
        $form.StartPosition = if ($ParentForm) { "CenterParent" } else { "CenterScreen" }
        $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
        $form.MaximizeBox = $true
        $form.MinimizeBox = $false
        $form.MinimumSize = New-Object System.Drawing.Size(420, 320)

        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = $Prompt
        $lbl.Location = New-Object System.Drawing.Point(10, 10)
        $lbl.Size = New-Object System.Drawing.Size(480, 40)
        $lbl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $form.Controls.Add($lbl)

        $list = New-Object System.Windows.Forms.ListBox
        $list.Location = New-Object System.Drawing.Point(10, 55)
        $list.Size = New-Object System.Drawing.Size(480, 260)
        $list.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        foreach ($it in @($Items)) { [void]$list.Items.Add([string]$it) }
        if ($list.Items.Count -gt 0) { $list.SelectedIndex = 0 }
        $form.Controls.Add($list)

        $btnOk = New-Object System.Windows.Forms.Button
        $btnOk.Text = "OK"
        $btnOk.Size = New-Object System.Drawing.Size(90, 28)
        $btnOk.Location = New-Object System.Drawing.Point(310, 330)
        $btnOk.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
        $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Controls.Add($btnOk)

        $btnCancel = New-Object System.Windows.Forms.Button
        $btnCancel.Text = "Cancel"
        $btnCancel.Size = New-Object System.Drawing.Size(90, 28)
        $btnCancel.Location = New-Object System.Drawing.Point(400, 330)
        $btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
        $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Controls.Add($btnCancel)

        $form.AcceptButton = $btnOk
        $form.CancelButton = $btnCancel

        $list.Add_DoubleClick({
            try { $form.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.Close() } catch {}
        })

        $dr = if ($ParentForm) { $form.ShowDialog($ParentForm) } else { $form.ShowDialog() }
        if ($dr -ne [System.Windows.Forms.DialogResult]::OK) { return $null }

        $sel = $null
        try { $sel = $list.SelectedItem } catch { $sel = $null }
        if ($null -eq $sel) { return $null }
        return [string]$sel
    } catch {
        return $null
    } finally {
        try { if ($form) { $form.Dispose() } } catch {}
    }
}

function Resolve-PDQTargetComputerNameFromSelection {
    param(
        [string]$Title = "PDQ",
        [System.Windows.Forms.Form]$ParentForm = $null
    )

    $sel = $null
    try { $sel = Get-CurrentSelection } catch { $sel = $null }

    if (-not $sel -or [string]::IsNullOrWhiteSpace($sel.Name)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please select a computer or user from the results list.",
            $Title,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return $null
    }

    if ($sel.Type -eq "Computer") {
        return $sel.Name
    }

    if ($sel.Type -eq "User") {
        $username = [string]$sel.Name
        $computers = @()

        try {
            if (Get-Command Get-CombinedUserLocationData -ErrorAction SilentlyContinue) {
                $loc = Get-CombinedUserLocationData -Username $username
                if ($loc) {
                    $computers = @($loc | ForEach-Object { $_.Computer })
                }
            } elseif (Get-Command Get-PDQComputersForUser -ErrorAction SilentlyContinue) {
                $computers = @(Get-PDQComputersForUser -Username $username)
            }
        } catch {
            $computers = @()
        }

        $computers = @($computers | ForEach-Object { 
            if ([string]::IsNullOrWhiteSpace($_)) { $null } else { ([string]$_).Trim() } 
        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

        if (-not $computers -or $computers.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                "No computers were found for user '$username'.",
                $Title,
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return $null
        }

        if ($computers.Count -eq 1) { return $computers[0] }

        $picked = Show-SelectFromListDialog `
            -Title "$Title - Select Computer" `
            -Prompt "Multiple computers were found for user '$username'. Select a target computer:" `
            -Items $computers `
            -ParentForm $ParentForm

        return $picked
    }

    [System.Windows.Forms.MessageBox]::Show(
        "Please select a computer or user from the results list.",
        $Title,
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
    return $null
}

function Update-PDQMenuStateFromCurrentSelection {
    try {
        $sel = $null
        try { $sel = Get-CurrentSelection } catch { $sel = $null }
        $isTargetSelected = ($sel -and (($sel.Type -eq "Computer") -or ($sel.Type -eq "User")) -and -not [string]::IsNullOrWhiteSpace($sel.Name))

        # PDQ Deploy package items
        try {
            if ($script:pdqDeployMenuItems) {
                $deployAvailable = $false
                try { $deployAvailable = [bool](Test-PDQDeployAvailable) } catch { $deployAvailable = $false }
                foreach ($item in $script:pdqDeployMenuItems) {
                    try { $item.Enabled = ($isTargetSelected -and $deployAvailable) } catch {}
                }
            }
        } catch {}

        # PDQ Inventory menu items
        try {
            $inventoryAvailable = $false
            try { $inventoryAvailable = [bool](Test-PDQInventoryCLIAvailable) } catch { $inventoryAvailable = $false }
            if ($script:pdqInventoryRefreshMenuItem) {
                try { $script:pdqInventoryRefreshMenuItem.Enabled = ($isTargetSelected -and $inventoryAvailable) } catch {}
            }
            if ($script:pdqInventoryDetailsMenuItem) {
                try { $script:pdqInventoryDetailsMenuItem.Enabled = ($isTargetSelected -and $inventoryAvailable) } catch {}
            }
        } catch {}
    } catch {}
}

function Get-ResultsListViewItemForCurrentSelection {
    # Returns the actual ListViewItem for the cached selection (even if the UI selection was cleared).
    $sel = $null
    try { $sel = Get-CurrentSelection } catch { $sel = $null }
    if (-not $resultsListView -or -not $sel -or [string]::IsNullOrWhiteSpace($sel.Name)) { return $null }

    try {
        if ($resultsListView.SelectedItems.Count -gt 0) { return $resultsListView.SelectedItems[0] }
    } catch {}

    try {
        foreach ($it in $resultsListView.Items) {
            try {
                if ($it -and $it.SubItems.Count -ge 2) {
                    $t = ""
                    $n = ""
                    try { $t = [string]$it.SubItems[0].Text } catch {}
                    try { $n = [string]$it.SubItems[1].Text } catch {}
                    if ($t -eq $sel.Type -and $n -eq $sel.Name) { return $it }
                }
            } catch {}
        }
    } catch {}

    return $null
}

# --- PDQ Inventory CLI async prefetch (keeps UI responsive) ---
if (-not $script:PDQAutoQueryJobs) { $script:PDQAutoQueryJobs = New-Object System.Collections.ArrayList }
if (-not $script:PDQAutoQueryGeneration) { $script:PDQAutoQueryGeneration = 0 }
try {
    # Expose for other modules (e.g., PDQ CLI dialog) to detect "in-flight" background queries
    if (-not $global:ADappPDQAutoQueryJobs) { $global:ADappPDQAutoQueryJobs = $script:PDQAutoQueryJobs }
} catch {}

# --- QUser async lookup (keeps UI responsive; streams results as they return) ---
if (-not $script:QUserAutoQueryJobs) { $script:QUserAutoQueryJobs = New-Object System.Collections.ArrayList }
if (-not $script:QUserAutoQueryGeneration) { $script:QUserAutoQueryGeneration = 0 }
if (-not $script:QUserAutoQueryStats) { $script:QUserAutoQueryStats = @{} }

function Initialize-QUserAutoQueryInfrastructure {
    try {
        if (-not $script:QUserAutoQueryPool) {
            $min = 1
            $max = 5
            try {
                if ($global:Settings -and $global:Settings.Performance -and $global:Settings.Performance.MaxConcurrentJobs) {
                    $max = [Math]::Max(1, [int]$global:Settings.Performance.MaxConcurrentJobs)
                    $max = [Math]::Min(10, $max)
                }
            } catch { $max = 5 }
            $script:QUserAutoQueryPool = [runspacefactory]::CreateRunspacePool($min, $max)
            $script:QUserAutoQueryPool.ApartmentState = [System.Threading.ApartmentState]::MTA
            $script:QUserAutoQueryPool.Open()
        }
    } catch {}

    try {
        if (-not $script:QUserAutoQueryTimer) {
            $script:QUserAutoQueryTimer = New-Object System.Windows.Forms.Timer
            $script:QUserAutoQueryTimer.Interval = 250
            $script:QUserAutoQueryTimer.Add_Tick({
                try { Process-QUserAutoQueryCompletions } catch {}
            })
            $script:QUserAutoQueryTimer.Start()
        } elseif (-not $script:QUserAutoQueryTimer.Enabled) {
            $script:QUserAutoQueryTimer.Start()
        }
    } catch {}
}

function Stop-QUserAutoQueryJobs {
    # Cancels any in-flight jobs and prevents stale UI updates.
    try { $script:QUserAutoQueryGeneration++ } catch {}
    try { $script:QUserAutoQueryStats = @{} } catch {}
    try {
        if ($script:QUserAutoQueryJobs -and $script:QUserAutoQueryJobs.Count -gt 0) {
            for ($i = $script:QUserAutoQueryJobs.Count - 1; $i -ge 0; $i--) {
                $j = $null
                try { $j = $script:QUserAutoQueryJobs[$i] } catch { $j = $null }
                try { if ($j -and $j.PowerShell) { $j.PowerShell.Dispose() } } catch {}
                try { [void]$script:QUserAutoQueryJobs.RemoveAt($i) } catch {}
            }
        }
    } catch {}
    try {
        if ($script:QUserAutoQueryTimer -and $script:QUserAutoQueryTimer.Enabled) {
            $script:QUserAutoQueryTimer.Stop()
        }
    } catch {}
}

function Normalize-QUserUsername {
    param([string]$Username)
    try {
        if ([string]::IsNullOrWhiteSpace($Username)) { return "" }
        $u = [string]$Username
        $u = $u.Trim()
        # strip common "current session" prefix
        $u = $u -replace '^\s*>', ''
        # DOMAIN\user -> user
        if ($u -match '\\') { $u = ($u -split '\\')[-1] }
        # user@domain -> user
        if ($u -match '@') { $u = ($u -split '@')[0] }
        return $u.ToUpperInvariant()
    } catch {
        return ([string]$Username).ToUpperInvariant()
    }
}

function Process-QUserAutoQueryCompletions {
    # Runs on UI thread (WinForms Timer), safe to update UI here.
    if (-not $script:QUserAutoQueryJobs -or $script:QUserAutoQueryJobs.Count -eq 0) {
        try { if ($script:QUserAutoQueryTimer -and $script:QUserAutoQueryTimer.Enabled) { $script:QUserAutoQueryTimer.Stop() } } catch {}
        return
    }

    for ($i = $script:QUserAutoQueryJobs.Count - 1; $i -ge 0; $i--) {
        $job = $null
        try { $job = $script:QUserAutoQueryJobs[$i] } catch { $job = $null }
        if (-not $job) { continue }

        $done = $false
        try { $done = [bool]$job.Handle.IsCompleted } catch { $done = $true }
        if (-not $done) { continue }

        $result = $null
        $err = $null
        try { $result = $job.PowerShell.EndInvoke($job.Handle) } catch { $err = $_ }
        try { $job.PowerShell.Dispose() } catch {}
        try { [void]$script:QUserAutoQueryJobs.RemoveAt($i) } catch {}

        # Update progress counters even if we discard UI update
        try {
            if (-not $script:QUserAutoQueryStats.ContainsKey('Completed')) { $script:QUserAutoQueryStats['Completed'] = 0 }
            $script:QUserAutoQueryStats['Completed'] = [int]$script:QUserAutoQueryStats['Completed'] + 1
        } catch {}

        if ($job.Generation -ne $script:QUserAutoQueryGeneration) { continue }
        if ($err) { continue }

        $payload = $null
        try { $payload = if ($result -and $result.Count -gt 0) { $result[0] } else { $result } } catch { $payload = $result }
        if (-not $payload -or -not $payload.ComputerName) { continue }

        $comp = [string]$payload.ComputerName
        $sessions = @()
        try { $sessions = @($payload.Sessions) } catch { $sessions = @() }
        try {
            $ms = 0
            try { $ms = [int](((Get-Date) - $job.Started).TotalMilliseconds) } catch { $ms = 0 }
            $sc = if ($sessions) { $sessions.Count } else { 0 }
            Write-Log -Message "QUser async completed for $comp in ${ms}ms (sessions=$sc)" -Level "Debug"
        } catch {}

        # Cache the sessions in this process so future lookups are fast.
        try {
            if (Get-Command Initialize-QUserCache -ErrorAction SilentlyContinue) {
                if (-not $global:QUserCache) { Initialize-QUserCache }
            }
            if ($global:QUserCache -and $global:QUserCache.Data) {
                $key = $comp.ToUpperInvariant()
                $now = Get-Date
                # We're on the UI thread here (WinForms timer), so a direct write is safe.
                $global:QUserCache.Data[$key] = @{
                    Sessions = $sessions
                    Timestamp = $now
                }
                $global:QUserCache.LastUpdated = $now
                if (Get-Command Update-QUserHistoricalData -ErrorAction SilentlyContinue) {
                    Update-QUserHistoricalData -ComputerName $comp -Sessions $sessions
                }
            }
        } catch {}

        # Only update the UI if the current selection is the matching user
        $sel = $null
        try { $sel = Get-CurrentSelection } catch { $sel = $null }
        if (-not $sel -or $sel.Type -ne 'User' -or [string]::IsNullOrWhiteSpace($sel.Name)) { continue }
        if ($job.Username -and ((Normalize-QUserUsername -Username $sel.Name) -ne (Normalize-QUserUsername -Username $job.Username))) { continue }

        # Find matching sessions for the selected user
        $userSessions = @()
        try {
            $targetKey = Normalize-QUserUsername -Username $job.Username
            $userSessions = @($sessions | Where-Object { $_.Username -and (Normalize-QUserUsername -Username $_.Username) -eq $targetKey })
        } catch { $userSessions = @() }
        if (-not $userSessions -or $userSessions.Count -eq 0) {
            # No live session for this user; leave existing entry as-is.
        } else {
            # Replace any existing non-live entry for this computer (Historical/PDQ/etc.)
            try {
                for ($x = $locationListView.Items.Count - 1; $x -ge 0; $x--) {
                    if (-not $locationListView.Items[$x]) { continue }
                    if ($locationListView.Items[$x].Text -eq $comp) {
                        $d = ""
                        try { if ($locationListView.Items[$x].SubItems.Count -ge 2) { $d = [string]$locationListView.Items[$x].SubItems[1].Text } } catch { $d = "" }
                        if ($d -notlike "*Live Session (QUser)*") {
                            $locationListView.Items.RemoveAt($x)
                        }
                    }
                }
            } catch {}

            # Upsert a live-session row (one row per computer; show first session)
            try {
                $s0 = $userSessions[0]
                $details = "Live Session (QUser) ($($s0.State)) - $($s0.SessionName) (ID: $($s0.SessionId))"

                $existingItem = $null
                try {
                    foreach ($it in $locationListView.Items) {
                        if ($it -and $it.Text -eq $comp -and $it.SubItems.Count -ge 2 -and $it.SubItems[1].Text -like "*Live Session (QUser)*") {
                            $existingItem = $it
                            break
                        }
                    }
                } catch { $existingItem = $null }

                # Insert live-session rows above the first non-live row so they stay at the top.
                $insertIndex = 0
                try {
                    $insertIndex = $locationListView.Items.Count
                    for ($z = 0; $z -lt $locationListView.Items.Count; $z++) {
                        $it2 = $locationListView.Items[$z]
                        if (-not $it2) { continue }
                        $d2 = ""
                        try { if ($it2.SubItems.Count -ge 2) { $d2 = [string]$it2.SubItems[1].Text } } catch { $d2 = "" }
                        if ($d2 -notlike "*Live Session (QUser)*") { $insertIndex = $z; break }
                    }
                } catch { $insertIndex = 0 }

                if ($existingItem) {
                    $existingItem.SubItems[1].Text = $details
                    $existingItem.BackColor = [System.Drawing.Color]::LightGreen
                    # Move to top group if needed
                    try {
                        $curIndex = -1
                        try { $curIndex = [int]$existingItem.Index } catch { $curIndex = -1 }
                        if ($curIndex -ge 0 -and $curIndex -ne $insertIndex) {
                            $locationListView.Items.Remove($existingItem)
                            $locationListView.Items.Insert($insertIndex, $existingItem) | Out-Null
                        }
                    } catch {}
                } else {
                    $lv = New-Object System.Windows.Forms.ListViewItem($comp)
                    $lv.SubItems.Add($details) | Out-Null
                    $lv.BackColor = [System.Drawing.Color]::LightGreen
                    $locationListView.Items.Insert($insertIndex, $lv) | Out-Null
                }
            } catch {}

            try {
                if (-not $script:QUserAutoQueryStats.ContainsKey('Found')) { $script:QUserAutoQueryStats['Found'] = 0 }
                $script:QUserAutoQueryStats['Found'] = [int]$script:QUserAutoQueryStats['Found'] + 1
            } catch {}
        }

        # Update status label progress
        try {
            $total = 0; $doneCount = 0; $found = 0
            try { $total = [int]$script:QUserAutoQueryStats['Total'] } catch { $total = 0 }
            try { $doneCount = [int]$script:QUserAutoQueryStats['Completed'] } catch { $doneCount = 0 }
            try { $found = [int]$script:QUserAutoQueryStats['Found'] } catch { $found = 0 }
            if ($statusLabel -and $total -gt 0 -and $doneCount -le $total) {
                $statusLabel.Text = "Checking live sessions... ($doneCount/$total) found: $found"
            }
        } catch {}
    }
}

function Start-QUserAutoQueryForUser {
    param(
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][string[]]$ComputerNames
    )

    if ([string]::IsNullOrWhiteSpace($Username)) { return }
    if (-not $ComputerNames -or $ComputerNames.Count -eq 0) { return }

    Stop-QUserAutoQueryJobs
    Initialize-QUserAutoQueryInfrastructure

    $gen = $script:QUserAutoQueryGeneration
    $timeout = 10
    try { if ($global:Settings -and $global:Settings.QUser -and $global:Settings.QUser.TimeoutSeconds) { $timeout = [Math]::Max(1, [int]$global:Settings.QUser.TimeoutSeconds) } } catch { $timeout = 10 }

    $script:QUserAutoQueryStats = @{ Total = ($ComputerNames.Count); Completed = 0; Found = 0 }
    try { if ($statusLabel) { $statusLabel.Text = "Checking live sessions... (0/$($ComputerNames.Count))" } } catch {}
    try { Write-Log -Message "Starting async QUser lookups for user '$Username' on $($ComputerNames.Count) computers (timeout=${timeout}s)" -Level "Info" } catch {}

    $modulePath = $null
    try { $modulePath = (Join-Path -Path $PSScriptRoot -ChildPath "Modules\QUserQuery.psm1") } catch { $modulePath = ".\Modules\QUserQuery.psm1" }

    foreach ($compName in $ComputerNames) {
        if ([string]::IsNullOrWhiteSpace($compName)) { continue }
        $comp = $compName.Trim()

        try {
            $ps = [powershell]::Create()
            if ($script:QUserAutoQueryPool) { $ps.RunspacePool = $script:QUserAutoQueryPool }

            $sb = {
                param([string]$QUserModulePath, [string]$ComputerName, [int]$TimeoutSeconds)
                try {
                    $already = $false
                    try { $already = [bool](Get-Module | Where-Object { $_.Path -eq $QUserModulePath }) } catch { $already = $false }
                    if (-not $already) { Import-Module $QUserModulePath -Force -ErrorAction SilentlyContinue | Out-Null }
                } catch {}
                $sessions = @()
                try {
                    if (Get-Command Get-QUserInfo -ErrorAction SilentlyContinue) {
                        $sessions = Get-QUserInfo -ComputerName $ComputerName -TimeoutSeconds $TimeoutSeconds
                    }
                } catch { $sessions = @() }
                return [PSCustomObject]@{ ComputerName = $ComputerName; Sessions = $sessions }
            }

            [void]$ps.AddScript($sb).AddArgument($modulePath).AddArgument($comp).AddArgument($timeout)
            $handle = $ps.BeginInvoke()
            $job = [PSCustomObject]@{
                Username = $Username
                ComputerName = $comp
                Generation = $gen
                Started = Get-Date
                PowerShell = $ps
                Handle = $handle
            }
            [void]$script:QUserAutoQueryJobs.Add($job)
        } catch {
            try { if ($ps) { $ps.Dispose() } } catch {}
        }
    }
}

function Initialize-PDQAutoQueryInfrastructure {
    try {
        if (-not $script:PDQAutoQueryPool) {
            # Keep concurrency low so we don't swamp PDQInventory.exe or the network
            $script:PDQAutoQueryPool = [runspacefactory]::CreateRunspacePool(1, 2)
            $script:PDQAutoQueryPool.ApartmentState = [System.Threading.ApartmentState]::MTA
            $script:PDQAutoQueryPool.Open()
        }
    } catch {}

    try {
        if (-not $script:PDQAutoQueryTimer) {
            $script:PDQAutoQueryTimer = New-Object System.Windows.Forms.Timer
            $script:PDQAutoQueryTimer.Interval = 250
            $script:PDQAutoQueryTimer.Add_Tick({
                try { Process-PDQAutoQueryCompletions } catch {}
            })
            $script:PDQAutoQueryTimer.Start()
        } elseif (-not $script:PDQAutoQueryTimer.Enabled) {
            $script:PDQAutoQueryTimer.Start()
        }
    } catch {}
}

function Process-PDQAutoQueryCompletions {
    # Runs on UI thread (WinForms Timer), safe to update UI + global cache here.
    if (-not $script:PDQAutoQueryJobs -or $script:PDQAutoQueryJobs.Count -eq 0) { return }

    # Iterate backwards so we can remove safely
    for ($i = $script:PDQAutoQueryJobs.Count - 1; $i -ge 0; $i--) {
        $job = $null
        try { $job = $script:PDQAutoQueryJobs[$i] } catch { $job = $null }
        if (-not $job) { continue }

        $done = $false
        try { $done = [bool]$job.Handle.IsCompleted } catch { $done = $true }
        if (-not $done) { continue }

        $result = $null
        $err = $null
        try {
            $result = $job.PowerShell.EndInvoke($job.Handle)
        } catch {
            $err = $_
        }

        try { $job.PowerShell.Dispose() } catch {}
        try { [void]$script:PDQAutoQueryJobs.RemoveAt($i) } catch {}

        if ($err) {
            try { Write-Log -Message "PDQ async query failed for '$($job.ComputerName)': $err" -Level "Warning" } catch {}
            continue
        }

        # EndInvoke returns a collection; normalize to first object
        $data = $null
        try {
            if ($result -is [System.Collections.IEnumerable] -and $result.Count -gt 0) { $data = $result[0] } else { $data = $result }
        } catch { $data = $result }

        if ($data) {
            # Ensure the CLI cache is actually updated in this process.
            # Using Update-PDQCLICache is preferred, but we also write to $global:PDQInventoryCLICache directly
            # so the PDQ details dialog can always observe the update (even if the module function isn't available).
            $didCache = $false
            try {
                if (Get-Command Update-PDQCLICache -ErrorAction SilentlyContinue) {
                    Update-PDQCLICache -ComputerName $job.ComputerName -Data $data
                    $didCache = $true
                }
            } catch { $didCache = $false }
            try {
                if (-not $didCache) {
                    if (-not $global:PDQInventoryCLICache) { $global:PDQInventoryCLICache = @{} }
                    $key = $job.ComputerName.ToUpperInvariant()
                    $global:PDQInventoryCLICache[$key] = [PSCustomObject]@{
                        Data = $data
                        Timestamp = Get-Date
                    }
                    $didCache = $true
                }
            } catch {}
            try {
                $ms = 0
                try { $ms = [int](((Get-Date) - $job.Started).TotalMilliseconds) } catch { $ms = 0 }
                if ($job.Reason -eq "SingleResult") {
                    Write-Log -Message "PDQ async prefetch completed (cached) for $($job.ComputerName) in ${ms}ms" -Level "Info"
                } else {
                    Write-Log -Message "PDQ async prefetch completed (cached) for $($job.ComputerName) in ${ms}ms (Reason=$($job.Reason))" -Level "Debug"
                }
            } catch {}
        } else {
            try {
                $ms = 0
                try { $ms = [int](((Get-Date) - $job.Started).TotalMilliseconds) } catch { $ms = 0 }
                if ($job.Reason -eq "SingleResult") {
                    Write-Log -Message "PDQ async prefetch completed with no data for $($job.ComputerName) in ${ms}ms" -Level "Warning"
                } else {
                    Write-Log -Message "PDQ async prefetch completed with no data for $($job.ComputerName) in ${ms}ms (Reason=$($job.Reason))" -Level "Debug"
                }
            } catch {}
        }

        # If the currently selected item is this computer, trigger a lightweight refresh so PDQ fields appear without user re-click
        try {
            if ($resultsListView -and $resultsListView.SelectedItems.Count -gt 0) {
                $selItem = $resultsListView.SelectedItems[0]
                $selName = $null
                try { $selName = [string]$selItem.SubItems[1].Text } catch { $selName = $null }
                if ($selName -and $selName -eq $job.ComputerName) {
                    # Selection refresh hack (reuses existing rendering logic)
                    $resultsListView.SelectedItems.Clear()
                    $selItem.Selected = $true
                }
            }
        } catch {}
    }
}

function Start-PDQInventoryCLIPrefetchAsync {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][string]$ExecutablePath,
        [string]$Reason = "Prefetch"
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName) -or [string]::IsNullOrWhiteSpace($ExecutablePath)) { return $false }
    if (-not (Test-Path $ExecutablePath)) { return $false }

    # If a query is already running for this computer, don't spawn a duplicate
    try {
        if ($script:PDQAutoQueryJobs -and $script:PDQAutoQueryJobs.Count -gt 0) {
            foreach ($j in @($script:PDQAutoQueryJobs)) {
                try {
                    if ($j -and $j.ComputerName -eq $ComputerName -and $j.Handle -and (-not $j.Handle.IsCompleted)) {
                        try {
                            if ($Reason -eq "SingleResult") {
                                Write-Log -Message "Skipped PDQ async prefetch (already running) for $ComputerName" -Level "Info"
                            } else {
                                Write-Log -Message "Skipped PDQ async prefetch (already running) for $ComputerName (Reason=$Reason)" -Level "Debug"
                            }
                        } catch {}
                        return $true
                    }
                } catch {}
            }
        }
    } catch {}

    # If data is already cached and fresh, don't spawn a background query
    try {
        if (Get-Command Get-PDQCLICachedComputer -ErrorAction SilentlyContinue) {
            $cached = Get-PDQCLICachedComputer -ComputerName $ComputerName
            if ($cached) {
                try {
                    if ($Reason -eq "SingleResult") {
                        # Info-level so it's obvious why we didn't run PDQInventory.exe again
                        $ts = $null
                        try { if ($global:PDQInventoryCLICache) { $ts = $global:PDQInventoryCLICache[$ComputerName.ToUpperInvariant()].Timestamp } } catch { $ts = $null }
                        if ($ts) {
                            Write-Log -Message "Skipped PDQ async prefetch (cache hit) for $ComputerName (Retrieved=$($ts.ToString('yyyy-MM-dd HH:mm:ss')))" -Level "Info"
                        } else {
                            Write-Log -Message "Skipped PDQ async prefetch (cache hit) for $ComputerName" -Level "Info"
                        }
                    } else {
                        Write-Log -Message "Skipped PDQ async prefetch (cache hit) for $ComputerName (Reason=$Reason)" -Level "Debug"
                    }
                } catch {}
                return $true
            }
        }
    } catch {}

    Initialize-PDQAutoQueryInfrastructure

    try {
        $ps = [powershell]::Create()
        if ($script:PDQAutoQueryPool) { $ps.RunspacePool = $script:PDQAutoQueryPool }

        $sb = {
            param([string]$ExePath, [string]$Comp)
            try {
                $output = & $ExePath GetComputer -computer $Comp 2>&1 | Out-String
                if ([string]::IsNullOrWhiteSpace($output)) { return $null }
                $data = @{}
                foreach ($line in ($output -split "`r?`n")) {
                    if ($line -match '^\s*([^:]+?)\s*:\s*(.+?)\s*$') {
                        $k = $matches[1].Trim()
                        $v = $matches[2].Trim()
                        if (-not [string]::IsNullOrWhiteSpace($k)) { $data[$k] = $v }
                    }
                }
                if ($data.Count -eq 0) { return $null }
                return [PSCustomObject]@{
                    Name = $data['Name']
                    HostName = $data['Host Name']
                    Online = $data['Online']
                    Uptime = $data['Uptime']
                    BootTime = $data['Boot Time']
                    CurrentUser = $data['Current User']
                    IPAddress = $data['IP Address']
                    MACAddress = $data['MAC Address']
                    TimeZone = $data['Time Zone']
                    OperatingSystem = $data['Name']
                    OSVersion = $data['Version']
                    OSRelease = $data['SP / Release']
                    OSInstalled = $data['Installed']
                    SerialNumber = $data['Serial Number']
                    SystemDrive = $data['System Drive']
                    PowerShellVersion = $data['PowerShell Version']
                    Architecture = $data['Architecture']
                    NeedsReboot = $data['Needs Reboot']
                    ADPath = $data['Path']
                    Domain = $data['Domain']
                    ADCreated = $data['Created']
                    Manufacturer = $data['Manufacturer']
                    Model = $data['Model']
                    Memory = $data['Memory']
                    BIOSVersion = $data['BIOS Version']
                    BIOSManufacturer = $data['BIOS Manufacturer']
                    RawData = $data
                }
            } catch {
                return $null
            }
        }

        [void]$ps.AddScript($sb).AddArgument($ExecutablePath).AddArgument($ComputerName)
        $handle = $ps.BeginInvoke()
        $job = [PSCustomObject]@{
            ComputerName = $ComputerName
            Reason = $Reason
            Started = Get-Date
            PowerShell = $ps
            Handle = $handle
        }
        [void]$script:PDQAutoQueryJobs.Add($job)
        try {
            if ($Reason -eq "SingleResult") {
                Write-Log -Message "Started PDQ async prefetch (SingleResult) for $ComputerName" -Level "Info"
            } else {
                Write-Log -Message "Started PDQ async prefetch ($Reason) for $ComputerName" -Level "Debug"
            }
        } catch {}
        return $true
    } catch {
        try { Write-Log -Message "Failed to start PDQ async prefetch ($Reason) for $ComputerName`: $_" -Level "Warning" } catch {}
        try { if ($ps) { $ps.Dispose() } } catch {}
        return $false
    }
}

function Require-CurrentSelection {
    param(
        [string]$ExpectedType,
        [string]$Title = "Selection Required",
        [string]$Message = "Please select an item from the results list."
    )

    $sel = $null
    try { $sel = Get-CurrentSelection } catch { $sel = $null }
    if (-not $sel -or [string]::IsNullOrWhiteSpace($sel.Type) -or [string]::IsNullOrWhiteSpace($sel.Name)) {
        try { [System.Windows.Forms.MessageBox]::Show($Message, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null } catch {}
        return $null
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedType) -and $sel.Type -ne $ExpectedType) {
        try { [System.Windows.Forms.MessageBox]::Show($Message, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null } catch {}
        return $null
    }

    return $sel
}

# --- Cached selection visual highlight (independent of ListView selection) ---
$script:HighlightedSelectionKey = $null
$script:HighlightOriginalColors = @{}

function Clear-SelectionHighlight {
    try {
        if (-not $resultsListView) { $script:HighlightedSelectionKey = $null; $script:HighlightOriginalColors = @{}; return }
        if (-not [string]::IsNullOrWhiteSpace($script:HighlightedSelectionKey)) {
            foreach ($it in $resultsListView.Items) {
                try {
                    if (-not $it -or $it.SubItems.Count -lt 2) { continue }
                    $k = "$([string]$it.SubItems[0].Text)|$([string]$it.SubItems[1].Text)"
                    if ($k -eq $script:HighlightedSelectionKey) {
                        if ($script:HighlightOriginalColors.ContainsKey($k)) {
                            $orig = $script:HighlightOriginalColors[$k]
                            try { $it.UseItemStyleForSubItems = [bool]$orig.UseItemStyleForSubItems } catch {}
                            try { $it.BackColor = $orig.ItemBackColor } catch {}
                            try { $it.ForeColor = $orig.ItemForeColor } catch {}
                            try {
                                for ($i = 0; $i -lt $it.SubItems.Count; $i++) {
                                    if ($orig.SubItemBackColors -and $i -lt $orig.SubItemBackColors.Count) {
                                        try { $it.SubItems[$i].BackColor = $orig.SubItemBackColors[$i] } catch {}
                                    }
                                    if ($orig.SubItemForeColors -and $i -lt $orig.SubItemForeColors.Count) {
                                        try { $it.SubItems[$i].ForeColor = $orig.SubItemForeColors[$i] } catch {}
                                    }
                                }
                            } catch {}
                        }
                        break
                    }
                } catch {}
            }
        }
    } catch {}
    $script:HighlightedSelectionKey = $null
    $script:HighlightOriginalColors = @{}
}

function Update-SelectionHighlight {
    param(
        [string]$Type,
        [string]$Name
    )

    if (-not $resultsListView -or [string]::IsNullOrWhiteSpace($Type) -or [string]::IsNullOrWhiteSpace($Name)) { return }

    $newKey = "$Type|$Name"

    # Restore previous highlight if different
    try {
        if (-not [string]::IsNullOrWhiteSpace($script:HighlightedSelectionKey) -and $script:HighlightedSelectionKey -ne $newKey) {
            foreach ($it in $resultsListView.Items) {
                try {
                    if (-not $it -or $it.SubItems.Count -lt 2) { continue }
                    $k = "$([string]$it.SubItems[0].Text)|$([string]$it.SubItems[1].Text)"
                    if ($k -eq $script:HighlightedSelectionKey) {
                        if ($script:HighlightOriginalColors.ContainsKey($k)) {
                            $orig = $script:HighlightOriginalColors[$k]
                            try { $it.UseItemStyleForSubItems = [bool]$orig.UseItemStyleForSubItems } catch {}
                            try { $it.BackColor = $orig.ItemBackColor } catch {}
                            try { $it.ForeColor = $orig.ItemForeColor } catch {}
                            try {
                                for ($i = 0; $i -lt $it.SubItems.Count; $i++) {
                                    if ($orig.SubItemBackColors -and $i -lt $orig.SubItemBackColors.Count) {
                                        try { $it.SubItems[$i].BackColor = $orig.SubItemBackColors[$i] } catch {}
                                    }
                                    if ($orig.SubItemForeColors -and $i -lt $orig.SubItemForeColors.Count) {
                                        try { $it.SubItems[$i].ForeColor = $orig.SubItemForeColors[$i] } catch {}
                                    }
                                }
                            } catch {}
                        }
                        break
                    }
                } catch {}
            }
        }
    } catch {}

    # Apply highlight to the new item
    try {
        foreach ($it in $resultsListView.Items) {
            try {
                if (-not $it -or $it.SubItems.Count -lt 2) { continue }
                $t = [string]$it.SubItems[0].Text
                $n = [string]$it.SubItems[1].Text
                if ($t -eq $Type -and $n -eq $Name) {
                    if (-not $script:HighlightOriginalColors.ContainsKey($newKey)) {
                        $subBack = New-Object System.Collections.Generic.List[object]
                        $subFore = New-Object System.Collections.Generic.List[object]
                        try {
                            for ($i = 0; $i -lt $it.SubItems.Count; $i++) {
                                try { [void]$subBack.Add($it.SubItems[$i].BackColor) } catch { [void]$subBack.Add($null) }
                                try { [void]$subFore.Add($it.SubItems[$i].ForeColor) } catch { [void]$subFore.Add($null) }
                            }
                        } catch {}
                        $script:HighlightOriginalColors[$newKey] = [PSCustomObject]@{
                            UseItemStyleForSubItems = $it.UseItemStyleForSubItems
                            ItemBackColor = $it.BackColor
                            ItemForeColor = $it.ForeColor
                            SubItemBackColors = $subBack
                            SubItemForeColors = $subFore
                        }
                    }

                    # Highlight ONLY the "Name" column (subitem index 1) so row status colors remain visible
                    try {
                        $it.UseItemStyleForSubItems = $false
                    } catch {}
                    # Ensure all other columns keep the row's original colors
                    try {
                        $rowBack = $it.BackColor
                        $rowFore = $it.ForeColor
                        for ($i = 0; $i -lt $it.SubItems.Count; $i++) {
                            try { $it.SubItems[$i].BackColor = $rowBack } catch {}
                            try { $it.SubItems[$i].ForeColor = $rowFore } catch {}
                        }
                    } catch {}
                    try { $it.SubItems[1].BackColor = [System.Drawing.Color]::FromArgb(255, 230, 160) } catch {}
                    try { $it.SubItems[1].ForeColor = [System.Drawing.Color]::Black } catch {}

                    $script:HighlightedSelectionKey = $newKey
                    break
                }
            } catch {}
        }
    } catch {}
}

function Apply-SelectionHighlightFromCache {
    try {
        $sel = Get-CurrentSelection
        if ($sel -and -not [string]::IsNullOrWhiteSpace($sel.Type) -and -not [string]::IsNullOrWhiteSpace($sel.Name)) {
            Update-SelectionHighlight -Type $sel.Type -Name $sel.Name
        }
    } catch {}
}

function Clear-SearchFilters {
    try {
        try { if ($typeComboBox) { $typeComboBox.SelectedIndex = 0 } } catch {}
        try { if ($locationComboBox -and ($locationComboBox.Items.Count -gt 0)) { $locationComboBox.SelectedIndex = ($locationComboBox.Items.IndexOf('All Locations')) } } catch {}
        try { if ($statusComboBox -and ($statusComboBox.Items.Count -gt 0)) { $statusComboBox.SelectedIndex = ($statusComboBox.Items.IndexOf('All')) } } catch {}
        try { if ($dateRangeComboBox -and ($dateRangeComboBox.Items.Count -gt 0)) { $dateRangeComboBox.SelectedIndex = ($dateRangeComboBox.Items.IndexOf('Any time')) } } catch {}
        try { if ($exactMatchCheckBox) { $exactMatchCheckBox.Checked = $false } } catch {}
        try { if ($includeDisabledCheckBox) { $includeDisabledCheckBox.Checked = $false } } catch {}
    } catch {}
}

function Invoke-RDPForSelected {
    $sel = Get-CurrentSelection
    if ($sel -and $sel.Type -eq "Computer" -and -not [string]::IsNullOrWhiteSpace($sel.Name)) {
        $computerName = $sel.Name
        try { Start-Process "mstsc.exe" -ArgumentList "/v:$computerName" } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to start Remote Desktop: $_","Remote Desktop",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please select a computer from the results list.", "Remote Desktop", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    }
}

function Invoke-VNCForSelected {
    $sel = Get-CurrentSelection
    if (-not $sel -or $sel.Type -ne "Computer" -or [string]::IsNullOrWhiteSpace($sel.Name)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a computer from the results list.", "VNC Connection", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }
    $computerName = $sel.Name
    $vncPath = $Settings.Connections.VNCPath
    if (-not (Test-Path $vncPath)) {
        [System.Windows.Forms.MessageBox]::Show("VNC viewer not found at $vncPath", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return
    }
    try {
        # Build UltraVNC arguments based on settings
        $viewOnly = $true
        try {
            if ($Settings.Connections -and ($null -ne $Settings.Connections.VNCViewOnly)) {
                $viewOnly = [bool]$Settings.Connections.VNCViewOnly
            }
        } catch {}

        $baseArgs = "-dsmplugin SecureVNCPlugin64.dsm"
        if ($viewOnly) {
            $baseArgs += " -viewonly"
        }
        $baseArgs += " -autoscaling"

        # Optional password, if configured. This assumes UltraVNC supports -password on the viewer.
        $passwordArgs = ""
        try {
            $pwd = if ($Settings.Connections -and $Settings.Connections.VNCPassword) { [string]$Settings.Connections.VNCPassword } else { "" }
            if (-not [string]::IsNullOrWhiteSpace($pwd)) {
                $passwordArgs = " -password `"$pwd`""
            }
        } catch {}

        $fullArgs = "$baseArgs$passwordArgs -connect $computerName"

        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $vncPath
        $processInfo.Arguments = $fullArgs
        $processInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardOutput = $true
        [void][System.Diagnostics.Process]::Start($processInfo)
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error launching VNC: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
}

function Start-PingForSelected {
    $sel = Get-CurrentSelection
    if (-not $sel -or $sel.Type -ne "Computer" -or [string]::IsNullOrWhiteSpace($sel.Name)) {
        [System.Windows.Forms.MessageBox]::Show("Please select a computer from the results list.", "Ping Computer", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }
    $computerName = $sel.Name
    
    try {
        # Normalize computer name - strip domain if present
        $pingTarget = $computerName.Split('.')[0]
        
        # Try to resolve IP address
        $pingIP = $null
        try {
            $resolved = [System.Net.Dns]::GetHostEntry($pingTarget)
            if ($resolved.AddressList -and $resolved.AddressList.Count -gt 0) {
                # Get the first IPv4 address
                $ipv4 = $resolved.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
                if ($ipv4) {
                    $pingIP = $ipv4.IPAddressToString
                }
            }
        } catch {
            # If resolution fails, we'll just use the hostname
            $pingIP = $null
        }
        
        # Create ping dialog form
        $displayTitle = if ($pingIP) { "Pinging $pingTarget [$pingIP]" } else { "Pinging $pingTarget" }
        $pingForm = New-Object System.Windows.Forms.Form
        $pingForm.Text = $displayTitle
        $pingForm.Size = New-Object System.Drawing.Size(600, 450)
        $pingForm.StartPosition = "CenterScreen"
        $pingForm.MinimizeBox = $false
        $pingForm.MaximizeBox = $false
        $pingForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        
        # Create RichTextBox for ping output
        $pingOutput = New-Object System.Windows.Forms.RichTextBox
        $pingOutput.Location = New-Object System.Drawing.Point(10, 10)
        $pingOutput.Size = New-Object System.Drawing.Size(570, 360)
        $pingOutput.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $pingOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
        $pingOutput.ReadOnly = $true
        $pingOutput.BackColor = [System.Drawing.Color]::Black
        $pingOutput.ForeColor = [System.Drawing.Color]::LimeGreen
        $pingForm.Controls.Add($pingOutput)
        
        # Create bottom panel for controls
        $bottomPanel = New-Object System.Windows.Forms.Panel
        $bottomPanel.Location = New-Object System.Drawing.Point(0, 375)
        $bottomPanel.Size = New-Object System.Drawing.Size(600, 40)
        $bottomPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $pingForm.Controls.Add($bottomPanel)
        
        # Create status label for statistics
        $statsLabel = New-Object System.Windows.Forms.Label
        $statsLabel.Location = New-Object System.Drawing.Point(10, 10)
        $statsLabel.Size = New-Object System.Drawing.Size(480, 20)
        $statsLabel.Text = "Starting ping..."
        $bottomPanel.Controls.Add($statsLabel)
        
        # Create Close button
        $closeButton = New-Object System.Windows.Forms.Button
        $closeButton.Text = "Close"
        $closeButton.Size = New-Object System.Drawing.Size(75, 25)
        $closeButton.Location = New-Object System.Drawing.Point(505, 8)
        $bottomPanel.Controls.Add($closeButton)
        
        # Statistics tracking - use unique variables for this ping instance
        $pingState = @{
            Count = 0
            Success = 0
            Failed = 0
            ResponseTimes = @()
            IsRunning = $true
            IsPinging = $false  # Track if a ping is currently in progress
        }
        
        # Function to append text to output
        $appendText = {
            param($text, $color)
            try {
                if ($pingForm -and -not $pingForm.IsDisposed -and $pingOutput -and -not $pingOutput.IsDisposed) {
                    $pingOutput.SelectionStart = $pingOutput.TextLength
                    $pingOutput.SelectionLength = 0
                    $pingOutput.SelectionColor = $color
                    $pingOutput.AppendText($text)
                    $pingOutput.ScrollToCaret()
                }
            } catch {
                # Silently ignore if control is disposed
            }
        }.GetNewClosure()
        
        # Function to update statistics
        $updateStats = {
            try {
                if ($pingForm -and -not $pingForm.IsDisposed -and $statsLabel -and -not $statsLabel.IsDisposed) {
                    $total = $pingState.Count
                    $received = $pingState.Success
                    $lost = $pingState.Failed
                    $lossPercent = if ($total -gt 0) { [math]::Round(($lost / $total) * 100, 1) } else { 0 }
                    
                    $statsText = "Packets: Sent = $total, Received = $received, Lost = $lost ($lossPercent% loss)"
                    
                    if ($pingState.ResponseTimes.Count -gt 0) {
                        $minTime = ($pingState.ResponseTimes | Measure-Object -Minimum).Minimum
                        $maxTime = ($pingState.ResponseTimes | Measure-Object -Maximum).Maximum
                        $avgTime = [math]::Round(($pingState.ResponseTimes | Measure-Object -Average).Average, 1)
                        $statsText += " | Min = ${minTime}ms, Max = ${maxTime}ms, Avg = ${avgTime}ms"
                    }
                    
                    $statsLabel.Text = $statsText
                }
            } catch {
                # Silently ignore if control is disposed
            }
        }.GetNewClosure()
        
        # Initial message
        $initialMsg = if ($pingIP) { "Pinging $pingTarget [$pingIP] with 32 bytes of data:`n`n" } else { "Pinging $pingTarget with 32 bytes of data:`n`n" }
        $pingOutput.AppendText($initialMsg)
        
        # Timer for continuous pinging
        $pingTimer = New-Object System.Windows.Forms.Timer
        $pingTimer.Interval = 1000  # 1 second between pings
        
        $pingTimer.Add_Tick({
            if (-not $pingState.IsRunning -or $pingForm.IsDisposed) {
                $pingTimer.Stop()
                return
            }
            
            # Skip if previous ping is still in progress
            if ($pingState.IsPinging) {
                return
            }
            
            $pingState.IsPinging = $true
            $pingState.Count++
            
            # Use BeginSendAsync for non-blocking ping
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                
                # Create callback for when ping completes
                $callback = {
                    param($sender, $e)
                    
                    try {
                        # Check if Reply is null (can happen if ping was cancelled or interrupted)
                        if ($null -eq $e.Reply) {
                            $pingState.Failed++
                            & $appendText "Ping cancelled or interrupted.`n" ([System.Drawing.Color]::Orange)
                        }
                        elseif ($e.Reply.Status -eq 'Success') {
                            $pingState.Success++
                            $responseTime = $e.Reply.RoundtripTime
                            $pingState.ResponseTimes += $responseTime
                            $replyFrom = if ($pingIP) { "$pingTarget [$pingIP]" } else { $pingTarget }
                            & $appendText "Reply from $replyFrom`: bytes=32 time=${responseTime}ms`n" ([System.Drawing.Color]::LimeGreen)
                        } else {
                            $pingState.Failed++
                            & $appendText "Request timed out.`n" ([System.Drawing.Color]::Red)
                        }
                        
                        & $updateStats
                    } catch {
                        $pingState.Failed++
                        & $appendText "Error: $_`n" ([System.Drawing.Color]::Red)
                        & $updateStats
                    } finally {
                        $pingState.IsPinging = $false
                        $ping.Dispose()
                    }
                }
                
                # Register the callback and start async ping
                $ping.add_PingCompleted($callback)
                $ping.SendAsync($pingTarget, 1000, $null)
                
            } catch {
                $pingState.Failed++
                $pingState.IsPinging = $false
                & $appendText "Error: $_`n" ([System.Drawing.Color]::Red)
                & $updateStats
            }
        }.GetNewClosure())
        
        # Wire up close button after timer is created
        $closeButton.Add_Click({ 
            $pingState.IsRunning = $false
            $pingTimer.Stop()
            $pingForm.Close() 
        }.GetNewClosure())
        
        # Handle form closing
        $pingForm.Add_FormClosing({
            try {
                $pingState.IsRunning = $false
                if ($pingTimer) {
                    $pingTimer.Stop()
                }
            } catch {}
        }.GetNewClosure())
        
        # Handle form closed (cleanup after form is disposed)
        $pingForm.Add_FormClosed({
            try {
                if ($pingTimer) {
                    $pingTimer.Dispose()
                }
            } catch {}
        }.GetNewClosure())
        
        # Start pinging
        $pingTimer.Start()
        
        # Show dialog (non-modal so main app remains interactive)
        $pingForm.Show()
        
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error starting ping: $_", "Ping Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
}

function Invoke-ComputerPowerAction {
    param(
        [ValidateSet("Shutdown", "Restart")]
        [string]$Action
    )

    $sel = Require-CurrentSelection -ExpectedType "Computer" -Title "$Action Computer" -Message "Please select a computer from the results list."
    if (-not $sel) { return }
    $computerName = [string]$sel.Name
    if ([string]::IsNullOrWhiteSpace($computerName)) { return }

    $targetName = $computerName.Trim()
    $actionVerb = if ($Action -eq "Shutdown") { "shut down" } else { "restart" }

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Are you sure you want to $actionVerb $targetName?",
        "Confirm $Action",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    $isOnline = $null
    try {
        if (Get-Command Test-ComputerOnline -ErrorAction SilentlyContinue) {
            $isOnline = Test-ComputerOnline -ComputerName $targetName
        }
    } catch {}

    if ($null -ne $isOnline -and -not $isOnline) {
        $offlineConfirm = [System.Windows.Forms.MessageBox]::Show(
            "$targetName appears offline. Send the $actionVerb command anyway?",
            "Computer Offline",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($offlineConfirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    }

    try {
        if ($Action -eq "Shutdown") {
            if (-not (Get-Command Stop-Computer -ErrorAction SilentlyContinue)) {
                throw "Stop-Computer is not available in this PowerShell session."
            }
            Stop-Computer -ComputerName $targetName -Force -ErrorAction Stop
        } else {
            if (-not (Get-Command Restart-Computer -ErrorAction SilentlyContinue)) {
                throw "Restart-Computer is not available in this PowerShell session."
            }
            Restart-Computer -ComputerName $targetName -Force -ErrorAction Stop
        }

        try { Write-Log -Message "Issued $Action for computer '$targetName'" -Level "Info" } catch {}
        [System.Windows.Forms.MessageBox]::Show(
            "$Action command sent to $targetName.",
            "Power",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    } catch {
        try { Write-Log -Message "Failed to $Action computer '$targetName': $_" -Level "Error" } catch {}
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to $actionVerb ${targetName}:`n`n$($_.Exception.Message)",
            "Power Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
}

# Initial merge/sync for shared data (best-effort)
try {
    if (Get-Command Sync-SharedData -ErrorAction SilentlyContinue) {
        Sync-SharedData -Trigger "Startup"
    }
} catch {}

# Enforce admin privileges if configured
try {
    $requireAdmin = $false
    if ($global:Settings -and $global:Settings.Security -and ($null -ne $global:Settings.Security.RequireAdminPrivileges)) {
        $requireAdmin = [bool]$global:Settings.Security.RequireAdminPrivileges
    }
    if ($requireAdmin) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            try {
                [System.Windows.Forms.MessageBox]::Show(
                    "This application requires administrator privileges and will relaunch elevated.",
                    "Elevation Required",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                ) | Out-Null
            } catch {}
            $self = $MyInvocation.MyCommand.Path
            if ([string]::IsNullOrEmpty($self)) { $self = (Join-Path -Path $ScriptPath -ChildPath 'ADapp.ps1') }
            Start-Process -FilePath "powershell.exe" -Verb RunAs -WindowStyle Hidden -ArgumentList "-NoProfile -NoLogo -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$self`"" | Out-Null
            return
        }
    }
} catch {}

# Initialize logging
Write-Log -Message "Application started" -Level "Info"

# Periodically re-check shared data availability and sync (non-blocking)
try {
    $script:SharedDataTimer = New-Object System.Timers.Timer
    $script:SharedDataTimer.Interval = 120000
    $script:SharedDataTimer.AutoReset = $true
    $script:SharedDataTimer.add_Elapsed({
        try {
            if (Get-Command Resolve-SharedDataPaths -ErrorAction SilentlyContinue) {
                $ctx = Resolve-SharedDataPaths -Settings $global:Settings
                $currentActiveDir = try { Split-Path -Path $global:AppConfig.FavoritesFile -Parent } catch { $null }
                if ($null -eq $currentActiveDir) { return }
                if ($ctx.ActivePath -ne $currentActiveDir -or $ctx.PreferredAvailable) {
                    # Store favorites and history file timestamps before sync to detect changes
                    $favFileBefore = $null
                    $histFileBefore = $null
                    try {
                        if ($global:AppConfig) {
                            if ($global:AppConfig.FavoritesFile -and (Test-Path $global:AppConfig.FavoritesFile)) {
                                $favFileBefore = (Get-Item $global:AppConfig.FavoritesFile).LastWriteTime
                            }
                            if ($global:AppConfig.SearchHistoryFile -and (Test-Path $global:AppConfig.SearchHistoryFile)) {
                                $histFileBefore = (Get-Item $global:AppConfig.SearchHistoryFile).LastWriteTime
                            }
                        }
                    } catch {}
                    
                    if (Get-Command Sync-SharedData -ErrorAction SilentlyContinue) {
                        Sync-SharedData -Trigger "Recheck"
                    }
                    
                    # Refresh menus if files changed (check timestamps after sync)
                    $favChanged = $false
                    $histChanged = $false
                    try {
                        if ($global:AppConfig) {
                            if ($global:AppConfig.FavoritesFile -and (Test-Path $global:AppConfig.FavoritesFile)) {
                                $favFileAfter = (Get-Item $global:AppConfig.FavoritesFile).LastWriteTime
                                if ($favFileBefore -eq $null -or $favFileAfter -ne $favFileBefore) {
                                    $favChanged = $true
                                }
                            }
                            if ($global:AppConfig.SearchHistoryFile -and (Test-Path $global:AppConfig.SearchHistoryFile)) {
                                $histFileAfter = (Get-Item $global:AppConfig.SearchHistoryFile).LastWriteTime
                                if ($histFileBefore -eq $null -or $histFileAfter -ne $histFileBefore) {
                                    $histChanged = $true
                                }
                            }
                        }
                    } catch {}
                    
                    # Refresh menus if changes detected (or if preferred available, refresh to ensure sync with other devices)
                    if ($favChanged -or ($ctx.PreferredAvailable -and $ctx.PreferredDataPath)) {
                        try {
                            $mainForm.Invoke([Action]{ 
                                try { Refresh-FavoritesMenu } catch {} 
                            })
                        } catch {}
                    }
                    if ($histChanged -or ($ctx.PreferredAvailable -and $ctx.PreferredDataPath)) {
                        try {
                            $mainForm.Invoke([Action]{ 
                                try { Update-SearchHistoryMenu } catch {}
                            })
                        } catch {}
                    }
                }
            }
        } catch {}
    })
    $script:SharedDataTimer.Start()
} catch {}

# Initialize Log Refresh Timer (auto-refresh for the log panel)
try {
    $script:LogRefreshTimer = New-Object System.Timers.Timer
    $script:LogRefreshTimer.AutoReset = $true
    $script:LogRefreshTimer.add_Elapsed({
        # Only refresh if the log panel is actually visible
        if ($logPanelCheckBox.Checked) {
            # Use the form's Invoke method to safely update the UI from a timer thread
            $mainForm.Invoke([Action]{ Update-LogView })
        }
    })
} catch {
    Write-Log -Message "Failed to initialize Log Refresh Timer: $_" -Level "Warning"
}

# Initialize PDQ cache automatically (best-effort)
try {
    if (Get-Command Update-PDQCache -ErrorAction SilentlyContinue) { Update-PDQCache | Out-Null }
} catch { Write-Log -Message "PDQ cache init failed: $_" -Level "Warning" }

# Initialize QUser cache structure (no bulk querying)
try {
    if (Get-Command Initialize-QUserCache -ErrorAction SilentlyContinue) { 
        Write-Log -Message "QUser module available - initializing cache and loading historical data" -Level "Info"
        # Use the proper initialization function that includes historical data
        Initialize-QUserCache
        Write-Log -Message "QUser cache initialized successfully" -Level "Info"
    } else {
        Write-Log -Message "QUser functions not available" -Level "Warning"
    }
} catch { Write-Log -Message "QUser cache structure init failed: $_" -Level "Warning" }

# Create main form
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = $Settings.Application.Title
$minWidth = 800
$minHeight = 600
try { if ($Settings.Application.MinFormSize.Width -gt 0) { $minWidth = [int]$Settings.Application.MinFormSize.Width } } catch {}
try { if ($Settings.Application.MinFormSize.Height -gt 0) { $minHeight = [int]$Settings.Application.MinFormSize.Height } } catch {}

$mainWidth = 1200
$mainHeight = 800
try { if ($Settings.Application.MainFormSize.Width -gt 0) { $mainWidth = [int]$Settings.Application.MainFormSize.Width } } catch {}
try { if ($Settings.Application.MainFormSize.Height -gt 0) { $mainHeight = [int]$Settings.Application.MainFormSize.Height } } catch {}

if ($mainWidth -lt $minWidth) { $mainWidth = $minWidth }
if ($mainHeight -lt $minHeight) { $mainHeight = $minHeight }

$mainForm.Size = New-Object System.Drawing.Size($mainWidth, $mainHeight)
$mainForm.MinimumSize = New-Object System.Drawing.Size($minWidth, $minHeight)
$mainForm.StartPosition = "CenterScreen"
$iconFile = Join-Path -Path (Join-Path -Path $ScriptPath -ChildPath "assets\\icons") -ChildPath "adapp.ico"
if (Test-Path $iconFile) { $mainForm.Icon = New-Object System.Drawing.Icon ($iconFile) }

# Theme functions are now in Modules/Theme.psm1 (loaded automatically)

# Apply theme and fonts from settings
$resolvedColors = Get-EffectiveThemeColors -Settings $Settings
$primaryColor = $resolvedColors.Primary
$secondaryColor = $resolvedColors.Secondary
$backgroundColor = $resolvedColors.Background
$textColor = $resolvedColors.Text

try {
    $defaultFontName = if ($Settings.UI.Fonts.Default) { $Settings.UI.Fonts.Default } else { 'Segoe UI' }
    $defaultFontSize = if ($Settings.UI.Fonts.DefaultSize) { [float]$Settings.UI.Fonts.DefaultSize } else { 9 }
    $mainForm.Font = New-Object System.Drawing.Font($defaultFontName, $defaultFontSize)
} catch {}

$mainForm.BackColor = $backgroundColor

# Add FormClosing event to ensure transcript is properly stopped
$mainForm.Add_FormClosing({
    # Only attempt to stop transcript if feature enabled and one is running
    if ($Settings.Logging.EnableTranscript) {
        try {
            Stop-FilteredTranscript
            Write-Log -Message "Transcript logging stopped" -Level "Info"
        } catch {
            Write-Log -Message "Error stopping transcript: $_" -Level "Warning"
        }
    }
    Write-Log -Message "Application closing" -Level "Info"
})

# Function to add menu items without console output
<#
.SYNOPSIS
    Adds a menu item to a ToolStripDropDownItem without console output.
.PARAMETER Parent
    The parent menu item to add to.
.PARAMETER Text
    The text to display on the menu item.
.PARAMETER ClickAction
    Script block to execute when clicked.
.PARAMETER IsSeparator
    If set, adds a separator instead of a menu item.
#>
function Add-MenuItemSilently {
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.ToolStripDropDownItem]$Parent,
        
        [Parameter(Mandatory=$false)]
        [string]$Text,
        
        [Parameter(Mandatory=$false)]
        [scriptblock]$ClickAction,
        
        [Parameter(Mandatory=$false)]
        [switch]$IsSeparator
    )
    
    try {
        if ($IsSeparator) {
            $null = $Parent.DropDownItems.Add("-")
            return
        }
        
        $menuItem = New-Object System.Windows.Forms.ToolStripMenuItem
        $menuItem.Text = $Text
        
        if ($null -ne $ClickAction) {
            $menuItem.Add_Click($ClickAction)
        }
        
        $null = $Parent.DropDownItems.Add($menuItem)
        return $menuItem
    } catch {
        Write-Log -Message "Error adding menu item: $_" -Level "Error"
        return $null
    }
}

# Enable double buffering on list-based controls to reduce flicker
<#
.SYNOPSIS
    Enables double buffering on a control to reduce flicker.
.PARAMETER Control
    The control to enable double buffering on.
#>

function Enable-ControlDoubleBuffering {
    param([System.Windows.Forms.Control]$Control)
    try {
        if ($null -eq $Control) { return }
        $pi = $Control.GetType().GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance)
        if ($pi) { $pi.SetValue($Control, $true, $null) }
    } catch {}
}

# Create menu strip - must be first control added
$menuStrip = New-Object System.Windows.Forms.MenuStrip
$menuStrip.BackColor = $primaryColor
$menuStrip.ForeColor = $textColor
$menuHeaderSize = if ($Settings.UI.Fonts.HeaderSize) { [float]$Settings.UI.Fonts.HeaderSize } else { $mainForm.Font.Size }
try { $menuStrip.Font = New-Object System.Drawing.Font($mainForm.Font.FontFamily, $menuHeaderSize) } catch {}
$mainForm.MainMenuStrip = $menuStrip
[void]$mainForm.Controls.Add($menuStrip)

# Create a TableLayoutPanel to manage all other controls
$tableLayoutPanel = New-Object System.Windows.Forms.TableLayoutPanel
$tableLayoutPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$tableLayoutPanel.RowCount = 4
$tableLayoutPanel.ColumnCount = 1
# Reduce search panel height from 110 to 85 to minimize whitespace
$tableLayoutPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 85))) | Out-Null
$tableLayoutPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
$tableLayoutPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 255))) | Out-Null
$tableLayoutPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 0))) | Out-Null

# Add top margin to avoid menu overlap - use MenuStrip height + 5px extra margin
$menuHeight = $menuStrip.Height + 5 
$tableLayoutPanel.Padding = New-Object System.Windows.Forms.Padding(5, $menuHeight, 5, 0)

[void]$mainForm.Controls.Add($tableLayoutPanel)

# Create menu items
$fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$fileMenu.Text = "File"
$null = $menuStrip.Items.Add($fileMenu)

# Create File menu items with the silent function
$aboutAction = {
    try {
        $aboutPath = Join-Path -Path $ScriptPath -ChildPath "ABOUT.md"
        if (Test-Path $aboutPath) {
            $aboutContent = Get-Content -Path $aboutPath -Raw
            Show-MarkdownDialog -Title "About AD Management Tool" -MarkdownContent $aboutContent
        } else {
            [System.Windows.Forms.MessageBox]::Show(
                "About information file not found.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    } catch {
        Write-Log -Message "Error reading about information: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "Error reading about information: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}
$null = Add-MenuItemSilently -Parent $fileMenu -Text "About" -ClickAction $aboutAction

$changeLogAction = {
    try {
        $changelogPath = Join-Path -Path $ScriptPath -ChildPath "CHANGELOG.md"
        if (Test-Path $changelogPath) {
            $changeLog = Get-Content -Path $changelogPath -Raw
            Show-MarkdownDialog -Title "Change Log" -MarkdownContent $changeLog
        } else {
            [System.Windows.Forms.MessageBox]::Show(
                "Change log file not found.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    } catch {
        Write-Log -Message "Error reading changelog: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "Error reading changelog: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
}
$null = Add-MenuItemSilently -Parent $fileMenu -Text "Change Log" -ClickAction $changeLogAction

# Helper: rebuild PDQ Deploy menu from current settings (called after Settings changes and on menu open)
function Update-PDQDeployMenu {
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.ToolStripMenuItem]$DeployMenu
    )

    try {
        $DeployMenu.DropDownItems.Clear()
    } catch {}

    # Rebuild menu items based on latest settings
    try {
        if (Get-Command Get-PDQDeploySettings -ErrorAction SilentlyContinue) {
            $deploySettings = Get-PDQDeploySettings
            if ($deploySettings.Enabled -and $deploySettings.Packages -and $deploySettings.Packages.Count -gt 0) {
                foreach ($packageName in @($deploySettings.Packages)) {
                    if ([string]::IsNullOrWhiteSpace($packageName)) { continue }
                    $packageMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
                    $packageMenuItem.Text = [string]$packageName
                    $packageMenuItem.Tag = [string]$packageName
                    $packageMenuItem.Enabled = $false  # Will be enabled when computer is selected
                    $packageMenuItem.Add_Click({
                        param($sender, $e)
                        try {
                            $pkgName = $sender.Tag
                            $computerName = Resolve-PDQTargetComputerNameFromSelection -Title "PDQ Deploy" -ParentForm $mainForm
                            if (-not [string]::IsNullOrWhiteSpace($computerName)) {
                                $result = Invoke-PDQDeployPackage -PackageName $pkgName -ComputerName $computerName
                                Show-DeploymentResult -Result $result
                            }
                        } catch {
                            Write-Log -Message "Error deploying package: $_" -Level "Error"
                            [System.Windows.Forms.MessageBox]::Show(
                                "Error deploying package: $_",
                                "PDQ Deploy Error",
                                [System.Windows.Forms.MessageBoxButtons]::OK,
                                [System.Windows.Forms.MessageBoxIcon]::Error
                            ) | Out-Null
                        }
                    })
                    $DeployMenu.DropDownItems.Add($packageMenuItem) | Out-Null
                }
            } else {
                $noPackagesItem = New-Object System.Windows.Forms.ToolStripMenuItem
                $noPackagesItem.Text = "No packages configured"
                $noPackagesItem.Enabled = $false
                $DeployMenu.DropDownItems.Add($noPackagesItem) | Out-Null
            }
        }
    } catch {
        try { Write-Log -Message "Error rebuilding PDQ Deploy menu: $_" -Level "Warning" } catch {}
    }

    # Refresh enable/disable tracking list used by the selection-change timer.
    try {
        $script:pdqDeployMenuItems = @()
        $DeployMenu.DropDownItems | ForEach-Object {
            if ($_.Text -ne "No packages configured") {
                $script:pdqDeployMenuItems += $_
            }
        }
    } catch {}

    # Immediately apply enabled/disabled state based on current selection.
    # (Menu items are created disabled by default; selection change may not fire after a rebuild.)
    try {
        $sel = $null
        try { $sel = Get-CurrentSelection } catch { $sel = $null }
        $isTargetSelected = ($sel -and (($sel.Type -eq "Computer") -or ($sel.Type -eq "User")) -and -not [string]::IsNullOrWhiteSpace($sel.Name))
        $deployAvailable = $false
        try { $deployAvailable = [bool](Test-PDQDeployAvailable) } catch { $deployAvailable = $false }
        if ($script:pdqDeployMenuItems) {
            foreach ($item in $script:pdqDeployMenuItems) {
                try { $item.Enabled = ($isTargetSelected -and $deployAvailable) } catch {}
            }
        }
    } catch {}
}

# Add 'Settings' submenu under File menu
$settingsMenuAction = {
    try {
        try { Import-Module "$ModulesPath\Settings.psm1" -Force -DisableNameChecking | Out-Null } catch {}
        # Load fresh settings each time to ensure we have validated values
        $freshSettings = Load-Settings -ScriptPath $ScriptPath
        Show-SettingsDialog -Settings $freshSettings -settingsPath $settingsPath
        # Reload global settings to pick up any changes made in the dialog
        $global:Settings = Load-Settings -ScriptPath $ScriptPath

        # Rebuild PDQ Deploy menu to reflect newly configured packages (if menu is initialized)
        try {
            if ($script:pdqDeployMenu) { Update-PDQDeployMenu -DeployMenu $script:pdqDeployMenu }
        } catch {}

        # Recompute theme and apply immediately
        try {
            Apply-Theme -Root $mainForm
        } catch {}
    } catch {
        Write-Log -Message "Error in Settings dialog: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show("Error editing settings: $_","Error",[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error)
    }
}
$null = Add-MenuItemSilently -Parent $fileMenu -Text "Edit Settings" -ClickAction $settingsMenuAction
# Add separator
$null = Add-MenuItemSilently -Parent $fileMenu -IsSeparator

$exitAction = {
    # Stop timers
    try { $script:LogRefreshTimer.Stop() } catch {}
    
    # Only attempt to stop transcript if feature enabled and one is running
    if ($Settings.Logging.EnableTranscript) {
        try {
            Stop-FilteredTranscript
        } catch {
            # Ignore errors when exiting
        }
    }
    $mainForm.Close()
}
$null = Add-MenuItemSilently -Parent $fileMenu -Text "Exit" -ClickAction $exitAction

$searchMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$searchMenu.Text = "Search"
$null = $menuStrip.Items.Add($searchMenu)

# Disable normal PowerShell output during UI initialization operations
$ErrorActionPreference = 'SilentlyContinue'

# Add New Search option to Search menu
$newSearchMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$newSearchMenuItem.Text = "New Search"
$newSearchMenuItem.Add_Click({ Invoke-NewSearch })
[void]$searchMenu.DropDownItems.Add($newSearchMenuItem)

# Add Locked Accounts submenu
$lockedMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$lockedMenu.Text = "Locked Accounts"
[void]$searchMenu.DropDownItems.Add($lockedMenu)

# Show locked
$showLockedMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$showLockedMenuItem.Text = "Show locked"
$showLockedMenuItem.Add_Click({
    $searchTextBox.Text = "*"
    try { $typeComboBox.SelectedIndex = $typeComboBox.Items.IndexOf("Users") } catch {}
    $statusLabel.Text = "Searching for locked accounts..."
    
    try {
        # Clear cached selection because the result set is changing
        $script:CurrentSelection = $null
        try { Clear-SelectionHighlight } catch {}
        $resultsListView.Items.Clear()

        # Use module function to retrieve locked accounts
        $lockedUsers = Get-LockedADAccounts

        if ($null -eq $lockedUsers -or $lockedUsers.Count -eq 0) {
            $item = New-Object System.Windows.Forms.ListViewItem("No locked accounts found")
            [void]$resultsListView.Items.Add($item)
            $statusLabel.Text = "No locked accounts found"
            return
        }

        foreach ($user in $lockedUsers) {
            $userDetails = [PSCustomObject]@{
                Type = 'User'
                Name = $user.SamAccountName
                ObjectType = 'User'
                Description = "$($user.GivenName) $($user.Surname)"
                FullName = "$($user.GivenName) $($user.Surname)"
                Title = $user.Title
                Department = $user.Department
                Phone = $user.telephoneNumber
                Email = $user.EmailAddress
                Enabled = $user.Enabled
                LockedOut = $true
                LastLogon = if($null -ne $user.LastLogon) { [datetime]::FromFileTime($user.LastLogon).ToString('g') } else { 'Never' }
                PasswordLastSet = if($null -ne $user.PasswordLastSet) { $user.PasswordLastSet.ToString('g') } else { 'Never' }
                OUPath = $user.CanonicalName
                Groups = ($user.MemberOf | ForEach-Object { (Get-ADGroup -Identity $_).Name })
            }
            
            $item = New-Object System.Windows.Forms.ListViewItem("User")
            [void]$item.SubItems.Add($user.SamAccountName)
            [void]$item.SubItems.Add("$($user.GivenName) $($user.Surname)")
            [void]$item.SubItems.Add("LOCKED")
            [void]$item.SubItems.Add($(if($null -ne $user.PasswordLastSet) { $user.PasswordLastSet.ToString("g") } else { "Never" }))
            $item.BackColor = [System.Drawing.Color]::MistyRose
            $item.Tag = $userDetails
            [void]$resultsListView.Items.Add($item)
        }

        $statusLabel.Text = "Found $($resultsListView.Items.Count) locked accounts"
    }
    catch {
        Write-Log -Message "Error searching for locked accounts: $_" -Level "Error"
        $statusLabel.Text = "Error searching for locked accounts"
    }
})
[void]$lockedMenu.DropDownItems.Add($showLockedMenuItem)

# Monitor locked (launch separate monitor)
$monitorLockedMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$monitorLockedMenuItem.Text = "Monitor Locked"
$monitorLockedMenuItem.Add_Click({
    try {
        $exe = Join-Path $ScriptPath 'LockedMonitor.exe'
        if (Test-Path $exe) {
            Start-Process -FilePath $exe -WindowStyle Normal | Out-Null
            return
        }
        $monitorPath = Join-Path $ScriptPath 'LockedMonitor.ps1'
        if (Test-Path $monitorPath) {
            Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-NoLogo','-ExecutionPolicy','Bypass','-STA','-File',"`"$monitorPath`"") -WindowStyle Normal | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show("Locked Users Monitor not found.", "Monitor Locked", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        }
    } catch {
        Write-Log -Message "Error launching Locked Users Monitor: $_" -Level "Error"
    }
})
[void]$lockedMenu.DropDownItems.Add($monitorLockedMenuItem)

# Add Refresh option
$refreshMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$refreshMenuItem.Text = "Refresh"
$refreshMenuItem.Add_Click({
    if ($searchTextBox.Text -ne "") {
        $searchButton.PerformClick()
    }
})
[void]$searchMenu.DropDownItems.Add($refreshMenuItem)

$toolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$toolsMenu.Text = "Tools"
$null = $menuStrip.Items.Add($toolsMenu)



# Add Computer Management option directly under Tools
$compMgmtMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$compMgmtMenuItem.Text = "Computer Management"
$compMgmtMenuItem.Add_Click({
    $sel = Require-CurrentSelection -ExpectedType "Computer" -Title "Computer Management" -Message "Please select a computer from the results list."
    if (-not $sel) { return }
    $computerName = $sel.Name
    if ([string]::IsNullOrWhiteSpace($computerName)) { return }
    try {
        # Prefer NetBIOS-style name for MMC snap-ins
        $target = $computerName.Trim().Split('.')[0]
        Start-Process "compmgmt.msc" -ArgumentList "/computer:$target"
    } catch {
        try {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to open Computer Management for '$computerName': $_",
                "Computer Management",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        } catch {}
    }
})
[void]$toolsMenu.DropDownItems.Add($compMgmtMenuItem)

# Add File Explorer option to Tools menu
$explorerMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$explorerMenuItem.Text = "File Explorer"
$explorerMenuItem.Add_Click({
    $sel = Require-CurrentSelection -ExpectedType "Computer" -Title "File Explorer" -Message "Please select a computer from the results list."
    if (-not $sel) { return }
    $computerName = $sel.Name
    if ([string]::IsNullOrWhiteSpace($computerName)) { return }
    try {
        $target = $computerName.Trim().Split('.')[0]
        $unc = "\\$target\c$"

        # Most reliable: let Windows shell open the UNC path directly
        try {
            Start-Process -FilePath $unc -ErrorAction Stop | Out-Null
            return
        } catch {}

        # Fallback: explicitly invoke explorer with a quoted path
        Start-Process -FilePath "explorer.exe" -ArgumentList @("`"$unc`"") -ErrorAction Stop | Out-Null
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error opening File Explorer for ${computerName}:`n`n$($_.Exception.Message)",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})
[void]$toolsMenu.DropDownItems.Add($explorerMenuItem)

# Add Power submenu to Tools menu
$shutdownMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$shutdownMenuItem.Text = "Shutdown"
$shutdownMenuItem.Add_Click({ Invoke-ComputerPowerAction -Action "Shutdown" })

$restartMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$restartMenuItem.Text = "Restart"
$restartMenuItem.Add_Click({ Invoke-ComputerPowerAction -Action "Restart" })

$powerSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$powerSubMenu.Text = "Power"
$null = $powerSubMenu.DropDownItems.Add("-") # Bug fix: don't add itself
[void]$powerSubMenu.DropDownItems.Add($shutdownMenuItem)
[void]$powerSubMenu.DropDownItems.Add($restartMenuItem)
[void]$toolsMenu.DropDownItems.Add($powerSubMenu)



# Create Connection menu
$connectionMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$connectionMenu.Text = "Connection"
$null = $menuStrip.Items.Add($connectionMenu)

# Add Remote Desktop option to Connection menu
$rdpMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$rdpMenuItem.Text = "Remote Desktop Connection"
$rdpMenuItem.Add_Click({ Invoke-RDPForSelected })
[void]$connectionMenu.DropDownItems.Add($rdpMenuItem)

# Add VNC option to Connection menu
$vncMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$vncMenuItem.Text = "VNC Connection"
$vncMenuItem.Add_Click({ Invoke-VNCForSelected })
[void]$connectionMenu.DropDownItems.Add($vncMenuItem)

# Add Ping option to Connection menu
$pingMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$pingMenuItem.Text = "Ping Computer"
$pingMenuItem.Add_Click({ Start-PingForSelected })
[void]$connectionMenu.DropDownItems.Add($pingMenuItem)

# Add Web UI option to Connection menu (for Printers)
$webUiMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$webUiMenuItem.Text = "Open Printer Web UI"
$webUiMenuItem.Add_Click({
    $sel = Require-CurrentSelection -ExpectedType "Printer" -Title "Printer Web UI" -Message "Please select a printer from the results list."
    if (-not $sel) { return }

    $printerObj = $sel.Tag
    $portName = $null
    if ($printerObj -and ($printerObj.PSObject.Properties.Name -contains "Port")) { $portName = $printerObj.Port }

    $printerIp = $null

    # 1) Try to parse IP directly from the port name (e.g., IP_10.1.2.3)
    if ($portName) {
        try {
            $match = [System.Text.RegularExpressions.Regex]::Match($portName, "\b\d{1,3}(\.\d{1,3}){3}\b")
            if ($match.Success) { $printerIp = $match.Value }
        } catch {}
    }

    # 2) Query the print server for the port's configured IP
    if (-not $printerIp) {
        $printServer = if ($Settings.Printers -and $Settings.Printers.PrintServer) { $Settings.Printers.PrintServer.Trim() } else { "" }
        if (-not [string]::IsNullOrWhiteSpace($printServer) -and $portName) {
            try {
                if (Get-Command Get-PrinterPort -ErrorAction SilentlyContinue) {
                    $port = Get-PrinterPort -ComputerName $printServer -Name $portName -ErrorAction Stop
                    if ($port -and ($port.PSObject.Properties.Name -contains "PrinterHostAddress") -and $port.PrinterHostAddress) {
                        $printerIp = $port.PrinterHostAddress
                    }
                }
            } catch {
                try { Write-Log -Message "Get-PrinterPort failed for port '$portName' on '$printServer': $_" -Level "Warning" } catch {}
            }
        }
    }

    # 3) Fallback: try DNS resolution using the printer name
    if (-not $printerIp -and $printerObj -and ($printerObj.PSObject.Properties.Name -contains "Name") -and $printerObj.Name) {
        try {
            $addrs = [System.Net.Dns]::GetHostAddresses($printerObj.Name)
            $ipv4 = $addrs | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1
            if ($ipv4) { $printerIp = $ipv4.IPAddressToString }
        } catch {}
    }

    if ([string]::IsNullOrWhiteSpace($printerIp)) {
        [System.Windows.Forms.MessageBox]::Show(
            "Unable to determine the printer IP address.",
            "Printer Web UI",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }

    $url = "http://$printerIp"
    try {
        Start-Process $url
    } catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Failed to open $url : $_",
            "Printer Web UI",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})
[void]$connectionMenu.DropDownItems.Add($webUiMenuItem)

# Create AD menu
$adMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$adMenu.Text = "AD"
$null = $menuStrip.Items.Add($adMenu)

# Add AD Sync menu item
$adSyncMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$adSyncMenuItem.Text = "AD Sync"
$adSyncMenuItem.Add_Click({
    try {
        # Show progress bar
        if ($global:progressBar -and $global:progressBar.PSObject.Properties.Name -contains "Visible") {
            $global:progressBar.Value = 0
            $global:progressBar.Visible = $true
        }
        $statusLabel.Text = "Initiating AD Delta Sync..."
        if ($mainForm -and $mainForm.PSObject.Properties.Name -contains "Refresh") { $mainForm.Refresh() }
        
        # Get AD Sync settings from nested structure
        $adSyncDC = if ($Settings.AD.ADSyncDC) { [string]$Settings.AD.ADSyncDC.Trim() } else { "" }
        $adSyncScriptPath = $Settings.AD.ADSyncScriptPath
        if ([string]::IsNullOrWhiteSpace($adSyncScriptPath)) { throw "ADSync script path is not configured." }
        if ([string]::IsNullOrWhiteSpace($adSyncDC)) { throw "AD Sync DC is not configured. Set AD.ADSyncDC in Settings." }

        # Execute the sync script using WinRM
        Invoke-Command -ComputerName $adSyncDC -ScriptBlock {
            param($scriptPath)
            & $scriptPath
        } -ArgumentList $adSyncScriptPath
        
        # Hide progress bar and show success
        if ($global:progressBar -and $global:progressBar.PSObject.Properties.Name -contains "Visible") {
            $global:progressBar.Visible = $false
        }
        $statusLabel.Text = "AD Sync complete"
        [System.Windows.Forms.MessageBox]::Show(
            "AD Sync completed successfully",
            "Success",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    catch {
        if ($global:progressBar -and $global:progressBar.PSObject.Properties.Name -contains "Visible") {
            $global:progressBar.Visible = $false
        }
        $statusLabel.Text = "Error during AD Sync"
        [System.Windows.Forms.MessageBox]::Show(
            "Error executing AD Sync: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})
[void]$adMenu.DropDownItems.Add($adSyncMenuItem)

# Organize AD menu actions by target type
[void]$adMenu.DropDownItems.Add("-")

$adUserMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$adUserMenu.Text = "User"
[void]$adMenu.DropDownItems.Add($adUserMenu)

$adComputerMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$adComputerMenu.Text = "Computer"
[void]$adMenu.DropDownItems.Add($adComputerMenu)

[void]$adMenu.DropDownItems.Add("-")

# Add Reset Password menu item
$resetPasswordMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$resetPasswordMenuItem.Text = "Reset Password"
$resetPasswordMenuItem.Add_Click({
    $sel = Require-CurrentSelection -ExpectedType "User" -Title "Reset Password" -Message "Please select a user from the results list."
    if (-not $sel) { return }
    $username = $sel.Name
    if ([string]::IsNullOrWhiteSpace($username)) { return }
    
    # Create password reset form
    $resetForm = New-Object System.Windows.Forms.Form
    $resetForm.Text = "Reset Password - $username"
    $resetForm.Size = New-Object System.Drawing.Size(400, 200)
    $resetForm.StartPosition = "CenterParent"
    $resetForm.FormBorderStyle = "FixedDialog"
    $resetForm.MaximizeBox = $false
    $resetForm.MinimizeBox = $false
    
    # Password field
    $pwLabel = New-Object System.Windows.Forms.Label
    $pwLabel.Location = New-Object System.Drawing.Point(10, 20)
    $pwLabel.Size = New-Object System.Drawing.Size(100, 20)
    $pwLabel.Text = "New Password:"
    [void]$resetForm.Controls.Add($pwLabel)
    
    $pwBox = New-Object System.Windows.Forms.TextBox
    $pwBox.Location = New-Object System.Drawing.Point(110, 20)
    $pwBox.Size = New-Object System.Drawing.Size(260, 20)
    $pwBox.UseSystemPasswordChar = $true
    [void]$resetForm.Controls.Add($pwBox)
    
    # Confirm password field
    $confirmLabel = New-Object System.Windows.Forms.Label
    $confirmLabel.Location = New-Object System.Drawing.Point(10, 50)
    $confirmLabel.Size = New-Object System.Drawing.Size(100, 20)
    $confirmLabel.Text = "Confirm:"
    [void]$resetForm.Controls.Add($confirmLabel)
    
    $confirmBox = New-Object System.Windows.Forms.TextBox
    $confirmBox.Location = New-Object System.Drawing.Point(110, 50)
    $confirmBox.Size = New-Object System.Drawing.Size(260, 20)
    $confirmBox.UseSystemPasswordChar = $true
    [void]$resetForm.Controls.Add($confirmBox)
    
    # Force change at logon checkbox
    $forceChangeBox = New-Object System.Windows.Forms.CheckBox
    $forceChangeBox.Location = New-Object System.Drawing.Point(110, 80)
    $forceChangeBox.Size = New-Object System.Drawing.Size(260, 20)
    $forceChangeBox.Text = "User must change password at next logon"
    $forceChangeBox.Checked = $true
    [void]$resetForm.Controls.Add($forceChangeBox)
    
    # Reset button
    $resetButton = New-Object System.Windows.Forms.Button
    $resetButton.Location = New-Object System.Drawing.Point(110, 110)
    $resetButton.Size = New-Object System.Drawing.Size(75, 23)
    $resetButton.Text = "Reset"
    $resetButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $resetForm.AcceptButton = $resetButton
    [void]$resetForm.Controls.Add($resetButton)
    
    # Cancel button
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(190, 110)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 23)
    $cancelButton.Text = "Cancel"
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $resetForm.CancelButton = $cancelButton
    [void]$resetForm.Controls.Add($cancelButton)
    
    # Show the form
    $result = $resetForm.ShowDialog()
    
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        # Validate passwords match
        if ($pwBox.Text -ne $confirmBox.Text) {
            [System.Windows.Forms.MessageBox]::Show(
                "Passwords do not match!",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }
        
        # Validate password complexity
        if (Get-Command Test-PasswordComplexity -ErrorAction SilentlyContinue) {
            $validation = Test-PasswordComplexity -Password $pwBox.Text
            if (-not $validation.IsValid) {
                [System.Windows.Forms.MessageBox]::Show(
                    $validation.ErrorMessage,
                    "Password Complexity Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
                return
            }
        }
        
        try {
            # Convert password to secure string
            $securePassword = ConvertTo-SecureString $pwBox.Text -AsPlainText -Force
            
            # Reset the password
            Set-ADAccountPassword -Identity $username -NewPassword $securePassword -Reset -ErrorAction Stop
            Write-AuditEvent -Action 'ResetPassword' -Target $username -Result 'Success'
            
            # Set "Change Password at Logon" if checked
            if ($forceChangeBox.Checked) {
                Set-ADUser -Identity $username -ChangePasswordAtLogon $true
            }
            
            [System.Windows.Forms.MessageBox]::Show(
                "Password reset successful for $username",
                "Success",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
        catch {
            Write-AuditEvent -Action 'ResetPassword' -Target $username -Result 'Error' -Metadata @{ error = "$_" }
            
            # Format AD error message for user-friendly display
            $errorMessage = $_.Exception.Message
            if (Get-Command Format-ADPasswordError -ErrorAction SilentlyContinue) {
                $errorMessage = Format-ADPasswordError -Exception $_.Exception
            }
            
            [System.Windows.Forms.MessageBox]::Show(
                "Error resetting password: $errorMessage",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
})
[void]$adUserMenu.DropDownItems.Add($resetPasswordMenuItem)

# Add Unlock Account menu item
$unlockAccountMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$unlockAccountMenuItem.Text = "Unlock Account"
$unlockAccountMenuItem.Add_Click({
    $sel = Require-CurrentSelection -ExpectedType "User" -Title "Unlock Account" -Message "Please select a user from the results list."
    if (-not $sel) { return }
    $username = $sel.Name
    if ([string]::IsNullOrWhiteSpace($username)) { return }
    
    try {
        Unlock-ADAccount -Identity $username
        Write-AuditEvent -Action 'UnlockAccount' -Target $username -Result 'Success'
        [System.Windows.Forms.MessageBox]::Show(
            "Account unlocked successfully",
            "Success",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        
        # Refresh the view
        try {
            $lv = Get-ResultsListViewItemForCurrentSelection
            if ($lv) { $lv.Selected = $false; $lv.Selected = $true }
        } catch {}
    }
    catch {
        Write-AuditEvent -Action 'UnlockAccount' -Target $username -Result 'Error' -Metadata @{ error = "$_" }
        [System.Windows.Forms.MessageBox]::Show(
            "Error unlocking account: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})
[void]$adUserMenu.DropDownItems.Add($unlockAccountMenuItem)

# Add Enable/Disable menu item
$enableDisableMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$enableDisableMenuItem.Text = "Enable/Disable"
$enableDisableMenuItem.Add_Click({
    $sel = Require-CurrentSelection -ExpectedType "" -Title "Enable/Disable" -Message "Please select a user or computer from the results list."
    if (-not $sel) { return }
    
    if ($sel.Type -ne "Computer" -and $sel.Type -ne "User") {
        try {
            [System.Windows.Forms.MessageBox]::Show(
                "Please select a user or computer from the results list.",
                "Enable/Disable",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
        } catch {}
        return
    }

    $itemName = $sel.Name
    if ([string]::IsNullOrWhiteSpace($itemName)) { return }
    $isComputer = ($sel.Type -eq "Computer")

    # Determine the current state (prefer cached Tag.Enabled, fallback to ListView Status column)
    $isCurrentlyEnabled = $true
    try {
        if ($sel.Tag -and ($sel.Tag.PSObject.Properties.Name -contains 'Enabled') -and ($null -ne $sel.Tag.Enabled)) {
            $isCurrentlyEnabled = [bool]$sel.Tag.Enabled
        } else {
            $lv = Get-ResultsListViewItemForCurrentSelection
            if ($lv -and $lv.SubItems.Count -ge 4) {
                $isCurrentlyEnabled = ([string]$lv.SubItems[3].Text -eq "Enabled")
            }
        }
    } catch {}
    
    try {
        $targetIdentity = $itemName
        if ($isComputer) {
            # Avoid ambiguity around computer SAM account names (NAME$) by using the AD object's DN
            $comp = Get-ADComputer -Identity $itemName -ErrorAction Stop
            $targetIdentity = $comp.DistinguishedName
        }

        if ($isCurrentlyEnabled) {
            Disable-ADAccount -Identity $targetIdentity
            Write-AuditEvent -Action 'DisableAccount' -Target $itemName -Result 'Success' -Metadata @{ type = $sel.Type }
        }
        else {
            Enable-ADAccount -Identity $targetIdentity
            Write-AuditEvent -Action 'EnableAccount' -Target $itemName -Result 'Success' -Metadata @{ type = $sel.Type }
        }
        
        # Update cached Tag + list view when possible
        try {
            if ($sel.Tag -and ($sel.Tag.PSObject.Properties.Name -contains 'Enabled')) {
                $sel.Tag.Enabled = (-not $isCurrentlyEnabled)
            }
        } catch {}
        try {
            $lv = Get-ResultsListViewItemForCurrentSelection
            if ($lv -and $lv.SubItems.Count -ge 4) {
                $lv.SubItems[3].Text = if ($isCurrentlyEnabled) { "Disabled" } else { "Enabled" }
            }
        } catch {}
        [System.Windows.Forms.MessageBox]::Show(
            "Action completed successfully",
            "Success",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    catch {
        $act = if ($isCurrentlyEnabled) { 'DisableAccount' } else { 'EnableAccount' }
        Write-AuditEvent -Action $act -Target $itemName -Result 'Error' -Metadata @{ error = "$_"; type = $sel.Type }
        [System.Windows.Forms.MessageBox]::Show(
            "Error toggling account state: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})
[void]$adMenu.DropDownItems.Add($enableDisableMenuItem)

# Add Attribute Editor menu item (User + Computer)
$attributeEditorMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$attributeEditorMenuItem.Text = "Attribute Editor..."
$attributeEditorMenuItem.Add_Click({
    $sel = Require-CurrentSelection -ExpectedType "" -Title "Attribute Editor" -Message "Please select a user or computer from the results list."
    if (-not $sel) { return }

    if ($sel.Type -ne "Computer" -and $sel.Type -ne "User") {
        try {
            [System.Windows.Forms.MessageBox]::Show(
                "Please select a user or computer from the results list.",
                "Attribute Editor",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
        } catch {}
        return
    }

    $itemName = $sel.Name
    if ([string]::IsNullOrWhiteSpace($itemName)) { return }

    # Fetch full AD object with all properties
    $adObj = $null
    $normName = $itemName
    if ($sel.Type -eq "Computer") {
        $normName = $normName.Split('.')[0]
        $normName = $normName.TrimEnd('$')
    }

    try {
        if ($sel.Type -eq "User") {
            $adObj = Get-ADUser -Identity $normName -Properties * -ErrorAction Stop
        } else {
            $adObj = Get-ADComputer -Identity $normName -Properties * -ErrorAction Stop
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error retrieving $($sel.Type) attributes for '$itemName': $_",
            "Attribute Editor",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return
    }

    $displayId = if ($sel.Type -eq "User") { $adObj.SamAccountName } else { $adObj.Name }
    if ([string]::IsNullOrWhiteSpace($displayId)) { $displayId = $normName }

    $attrForm = New-Object System.Windows.Forms.Form
    $attrForm.Text = "Attribute Editor - $($sel.Type): $displayId"
    $attrForm.Size = New-Object System.Drawing.Size(900, 650)
    $attrForm.StartPosition = "CenterParent"
    $attrForm.FormBorderStyle = "Sizable"
    $attrForm.MinimizeBox = $false

    # Top controls
    $topPanel = New-Object System.Windows.Forms.Panel
    $topPanel.Dock = [System.Windows.Forms.DockStyle]::Top
    $topPanel.Height = 34
    $topPanel.Padding = New-Object System.Windows.Forms.Padding(8, 6, 8, 6)
    [void]$attrForm.Controls.Add($topPanel)

    $onlySetCheckBox = New-Object System.Windows.Forms.CheckBox
    $onlySetCheckBox.Text = "Only show attributes with values"
    $onlySetCheckBox.AutoSize = $true
    $onlySetCheckBox.Checked = $true
    $onlySetCheckBox.Location = New-Object System.Drawing.Point(8, 7)
    [void]$topPanel.Controls.Add($onlySetCheckBox)

    $countLabel = New-Object System.Windows.Forms.Label
    $countLabel.AutoSize = $true
    $countLabel.Location = New-Object System.Drawing.Point(280, 9)
    [void]$topPanel.Controls.Add($countLabel)

    # Attribute list
    $attrListView = New-Object System.Windows.Forms.ListView
    $attrListView.Dock = [System.Windows.Forms.DockStyle]::Fill
    $attrListView.View = [System.Windows.Forms.View]::Details
    $attrListView.FullRowSelect = $true
    $attrListView.GridLines = $true
    $attrListView.HideSelection = $false
    $attrListView.MultiSelect = $false
    [void]$attrListView.Columns.Add("Attribute", 260)
    [void]$attrListView.Columns.Add("Value", 600)
    [void]$attrForm.Controls.Add($attrListView)

    # Bottom controls
    $bottomPanel = New-Object System.Windows.Forms.Panel
    $bottomPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $bottomPanel.Height = 44
    $bottomPanel.Padding = New-Object System.Windows.Forms.Padding(8, 8, 8, 8)
    [void]$attrForm.Controls.Add($bottomPanel)

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = "Close"
    $closeButton.Width = 90
    $closeButton.Anchor = [System.Windows.Forms.AnchorStyles]::Right
    $closeButton.Location = New-Object System.Drawing.Point(($attrForm.ClientSize.Width - 110), 8)
    $closeButton.Add_Click({ $attrForm.Close() })
    [void]$bottomPanel.Controls.Add($closeButton)

    $attrForm.Add_Resize({
        try {
            $closeButton.Left = $attrForm.ClientSize.Width - $closeButton.Width - 20
        } catch {}
    })

    # Helpers
    $isValueSet = {
        param($v)
        if ($null -eq $v) { return $false }
        if ($v -is [string]) {
            if ([string]::IsNullOrWhiteSpace($v)) { return $false }
            if ($v -eq "<not set>") { return $false }
            return $true
        }
        if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
            $arr = @($v)
            if ($arr.Count -eq 0) { return $false }
            foreach ($x in $arr) {
                if (& $isValueSet $x) { return $true }
            }
            return $false
        }
        return $true
    }

    $formatValue = {
        param($v)
        if (-not (& $isValueSet $v)) { return "<not set>" }

        try {
            if ($v -is [DateTime]) { return $v.ToString('g') }
            if ($v -is [bool]) { return $v.ToString() }
            # Auto-convert common timestamp epochs (FILETIME / Unix seconds / Unix milliseconds)
            try {
                $n = $null
                if ($v -is [Int64] -or $v -is [Int32] -or $v -is [Int16] -or $v -is [UInt64] -or $v -is [UInt32] -or $v -is [UInt16]) {
                    $n = [Int64]$v
                } elseif ($v -is [string] -and $v -match '^\d{13,18}$') {
                    $n = [Int64]$v
                }

                if ($null -ne $n) {
                    $tz = [TimeZoneInfo]::Local

                    # FILETIME: 100-ns ticks since 1601-01-01 UTC
                    $fileTimeMin = 116444736000000000  # 1970-01-01 in FILETIME
                    $fileTimeMax = [DateTime]::MaxValue.ToFileTimeUtc()
                    if ($n -ge $fileTimeMin -and $n -le $fileTimeMax) {
                        $dt = [DateTime]::FromFileTimeUtc($n).ToLocalTime()
                        $tzName = if ($dt.IsDaylightSavingTime()) { $tz.DaylightName } else { $tz.StandardName }
                        return ($dt.ToString('MM/dd/yyyy HH:mm:ss') + " " + $tzName)
                    }

                    # Unix milliseconds: ms since 1970-01-01 UTC
                    if ($n -ge 1000000000000 -and $n -le 9999999999999) {
                        $dto = [DateTimeOffset]::FromUnixTimeMilliseconds($n).ToLocalTime()
                        $dt2 = $dto.DateTime
                        $tzName2 = if ($dt2.IsDaylightSavingTime()) { $tz.DaylightName } else { $tz.StandardName }
                        return ($dt2.ToString('MM/dd/yyyy HH:mm:ss') + " " + $tzName2)
                    }

                    # Unix seconds: seconds since 1970-01-01 UTC (only for numeric types to avoid mis-parsing short digit strings)
                    if ($v -isnot [string] -and $n -ge 1000000000 -and $n -le 9999999999) {
                        $dto = [DateTimeOffset]::FromUnixTimeSeconds($n).ToLocalTime()
                        $dt3 = $dto.DateTime
                        $tzName3 = if ($dt3.IsDaylightSavingTime()) { $tz.DaylightName } else { $tz.StandardName }
                        return ($dt3.ToString('MM/dd/yyyy HH:mm:ss') + " " + $tzName3)
                    }
                }
            } catch {}
            if ($v -is [byte[]]) {
                $len = $v.Length
                $take = [Math]::Min($len, 32)
                $hex = ($v[0..($take-1)] | ForEach-Object { $_.ToString("X2") }) -join " "
                if ($len -gt $take) { return "[byte[]] len=${len}: $hex ..." }
                return "[byte[]] len=${len}: $hex"
            }
            if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
                $vals = @($v) | ForEach-Object { & $formatValue $_ }
                $vals = $vals | Where-Object { $_ -ne "<not set>" }
                if ($vals.Count -eq 0) { return "<not set>" }
                if ($vals.Count -gt 50) { return (($vals[0..49] -join "; ") + " ...") }
                return ($vals -join "; ")
            }
            return [string]$v
        } catch {
            return [string]$v
        }
    }

    $refreshList = {
        try {
            $attrListView.BeginUpdate()
            $attrListView.Items.Clear()

            $props = $adObj.PSObject.Properties | Sort-Object Name
            foreach ($p in $props) {
                $hasVal = & $isValueSet $p.Value
                if ($onlySetCheckBox.Checked -and -not $hasVal) { continue }

                $valText = & $formatValue $p.Value
                $item = New-Object System.Windows.Forms.ListViewItem([string]$p.Name)
                [void]$item.SubItems.Add([string]$valText)
                [void]$attrListView.Items.Add($item)
            }

            $countLabel.Text = "$($attrListView.Items.Count) attributes"
        }
        finally {
            $attrListView.EndUpdate()
        }
    }

    if (Get-Command Add-ListViewSorting -ErrorAction SilentlyContinue) {
        try { Add-ListViewSorting -ListView $attrListView } catch {}
    }

    $onlySetCheckBox.Add_CheckedChanged({ & $refreshList })

    & $refreshList

    # Show dialog
    try {
        if ($mainForm) { $attrForm.ShowDialog($mainForm) | Out-Null }
        else { $attrForm.ShowDialog() | Out-Null }
    } finally {
        $attrForm.Dispose()
    }
})
[void]$adMenu.DropDownItems.Add($attributeEditorMenuItem)

# Add Manage Groups menu item
$manageGroupsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$manageGroupsMenuItem.Text = "Manage Groups"
$manageGroupsMenuItem.Add_Click({
    $sel = Require-CurrentSelection -ExpectedType "" -Title "Manage Groups" -Message "Please select a user or computer from the results list."
    if (-not $sel) { return }

    if ($sel.Type -ne "Computer" -and $sel.Type -ne "User") {
        try {
            [System.Windows.Forms.MessageBox]::Show(
                "Please select a user or computer from the results list.",
                "Manage Groups",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
        } catch {}
        return
    }

    $itemName = $sel.Name
    $isComputer = ($sel.Type -eq "Computer")
    
    try {
        # Get current groups
        $currentGroups = @()  # Initialize as empty array
        
        if ($isComputer) {
            $groups = Get-WorkstationSecurityGroups -ComputerName $itemName
            if ($groups) {
                $currentGroups = $groups | Where-Object { $_ -ne $null } | Select-Object -ExpandProperty Name
            }
        } else {
            $groups = Get-UserSecurityGroups -Username $itemName
            if ($groups) {
                $currentGroups = $groups | Where-Object { $_ -ne $null } | Select-Object -ExpandProperty Name
            }
        }
        
        # Show group management dialog
        $title = if ($isComputer) {
            "Manage Groups - Computer: $itemName"
        } else {
            "Manage Groups - User: $itemName"
        }
        
        $changes = Show-GroupManagementDialog -Title $title -CurrentGroups $currentGroups -IsComputer $isComputer
        
        if ($changes) {
            if ($global:progressBar -and $global:progressBar.PSObject.Properties.Name -contains "Visible") {
                $global:progressBar.Value = 0
                $global:progressBar.Maximum = ($changes.ToAdd.Count + $changes.ToRemove.Count)
                $global:progressBar.Visible = $true
            }
            if ($global:statusLabel -and $global:statusLabel.PSObject.Properties.Name -contains "Text") {
                $global:statusLabel.Text = "Updating group memberships..."
            }
            
            # Process removals
            foreach ($group in $changes.ToRemove) {
                if ([string]::IsNullOrWhiteSpace($group)) { continue }
                
                if ($global:statusLabel -and $global:statusLabel.PSObject.Properties.Name -contains "Text") {
                    $global:statusLabel.Text = "Removing from group: $group"
                }
                if ($form -and $form.PSObject.Properties.Name -contains "Refresh") {
                    $form.Refresh()
                }
                
                if ($isComputer) {
                    $result = Remove-WorkstationFromSecurityGroup -ComputerName $itemName -GroupName $group
                    if (-not $result) {
                        throw "Failed to remove computer from group $group"
                    }
                } else {
                    $result = Remove-UserFromSecurityGroup -Username $itemName -GroupName $group
                    if (-not $result) {
                        throw "Failed to remove user from group $group"
                    }
                }
                
                if ($global:progressBar -and $global:progressBar.PSObject.Properties.Name -contains "Visible") {
                    $global:progressBar.Value++
                }
            }
            
            # Process additions
            foreach ($group in $changes.ToAdd) {
                if ([string]::IsNullOrWhiteSpace($group)) { continue }
                
                if ($global:statusLabel -and $global:statusLabel.PSObject.Properties.Name -contains "Text") {
                    $global:statusLabel.Text = "Adding to group: $group"
                }
                if ($form -and $form.PSObject.Properties.Name -contains "Refresh") {
                    $form.Refresh()
                }
                
                if ($isComputer) {
                    $result = Add-WorkstationToSecurityGroup -ComputerName $itemName -GroupName $group
                    if (-not $result) {
                        throw "Failed to add computer to group $group"
                    }
                } else {
                    $result = Add-UserToSecurityGroup -Username $itemName -GroupName $group
                    if (-not $result) {
                        throw "Failed to add user to group $group"
                    }
                }
                
                if ($global:progressBar -and $global:progressBar.PSObject.Properties.Name -contains "Visible") {
                    $global:progressBar.Value++
                }
            }
            
            if ($global:progressBar -and $global:progressBar.PSObject.Properties.Name -contains "Visible") {
                $global:progressBar.Visible = $false
            }
            if ($global:statusLabel -and $global:statusLabel.PSObject.Properties.Name -contains "Text") {
                $global:statusLabel.Text = "Group memberships updated successfully"
            }
            
            # Refresh the group membership display
            Update-GroupMembershipDisplay -ItemName $itemName -IsComputer $isComputer
            
            # Refresh the view
            try {
                $lv = Get-ResultsListViewItemForCurrentSelection
                if ($lv) { $lv.Selected = $false; $lv.Selected = $true }
            } catch {}
        }
    }
    catch {
        if ($global:progressBar -and $global:progressBar.PSObject.Properties.Name -contains "Visible") {
            $global:progressBar.Visible = $false
        }
        if ($global:statusLabel -and $global:statusLabel.PSObject.Properties.Name -contains "Text") {
            $global:statusLabel.Text = "Error managing groups"
        }
        
        # Still try to refresh the group display in case some changes were made
        try {
            Update-GroupMembershipDisplay -ItemName $itemName -IsComputer $isComputer
        } catch {
            # Ignore any errors during refresh after an error
        }
        
        [System.Windows.Forms.MessageBox]::Show(
            "Error managing groups: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

# Add Manage Group Members menu item
$manageGroupMembersMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$manageGroupMembersMenuItem.Text = "Manage Group Members"
$manageGroupMembersMenuItem.Add_Click({
    $sel = Require-CurrentSelection -ExpectedType "Group" -Title "Manage Group Members" -Message "Please select a group to manage its members."
    if (-not $sel) { return }

    $groupName = $sel.Name
    if ([string]::IsNullOrWhiteSpace($groupName)) { return }
    try {
        $itemDetails = $sel.Tag
        $groupIdentity = $null
        if ($itemDetails -and $itemDetails.PSObject.Properties['DistinguishedName'] -and $itemDetails.DistinguishedName) {
            $groupIdentity = $itemDetails.DistinguishedName
        } elseif ($itemDetails -and $itemDetails.PSObject.Properties['SamAccountName'] -and $itemDetails.SamAccountName) {
            $groupIdentity = $itemDetails.SamAccountName
        } else {
            $groupIdentity = $groupName
        }

        $result = Show-GroupMembersDialog -GroupName $groupIdentity
        if ($result) {
            # Refresh the group members display
            try {
                $groupMembers = Get-ADGroupMember -Identity $groupIdentity -Recursive | Get-ADObject -Properties Name, ObjectClass, DistinguishedName
                $groupsListView.Items.Clear()
                
                if ($groupMembers) {
                    foreach ($member in $groupMembers) {
                        $lvItem = New-Object System.Windows.Forms.ListViewItem($member.Name)
                        [void]$lvItem.SubItems.Add($member.ObjectClass)
                        [void]$lvItem.SubItems.Add($member.DistinguishedName)
                        $groupsListView.Items.Add($lvItem) | Out-Null
                    }
                } else {
                    $lvItem = New-Object System.Windows.Forms.ListViewItem("No members found")
                    $groupsListView.Items.Add($lvItem) | Out-Null
                }
            } catch {
                $lvItem = New-Object System.Windows.Forms.ListViewItem("Error retrieving group members")
                [void]$lvItem.SubItems.Add($_.Exception.Message)
                $groupsListView.Items.Add($lvItem) | Out-Null
            }
        }
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error managing group members: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

# Create Group Management submenu
$groupManagementMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$groupManagementMenu.Text = "Group Management"

# Add items to the Group Management submenu
[void]$groupManagementMenu.DropDownItems.Add($manageGroupsMenuItem)
[void]$groupManagementMenu.DropDownItems.Add($manageGroupMembersMenuItem)

# Add the Group Management submenu to the AD menu
[void]$adMenu.DropDownItems.Add($groupManagementMenu)

# Add BitLocker Recovery menu item
$bitlockerRecoveryMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$bitlockerRecoveryMenuItem.Text = "BitLocker Recovery"
$bitlockerRecoveryMenuItem.Add_Click({
    $sel = Require-CurrentSelection -ExpectedType "Computer" -Title "BitLocker Recovery" -Message "Please select a computer from the results list."
    if (-not $sel) { return }
    $computerName = $sel.Name
    if ([string]::IsNullOrWhiteSpace($computerName)) { return }
    
    # Show BitLocker recovery dialog
    try {
        Show-BitLockerRecoveryDialog -ComputerName $computerName
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error retrieving BitLocker recovery information: $_",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})
[void]$adComputerMenu.DropDownItems.Add($bitlockerRecoveryMenuItem)

# Create favorites menu
$favoritesMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$favoritesMenu.Text = "Favorites"
$global:favoritesMenu = $favoritesMenu
$historyMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$historyMenu.Text = "History"

# Helper function to check if advanced search settings are non-default
function Test-AdvancedSearchHasNonDefaults {
    param(
        [object]$AdvancedSearch
    )
    
    if (-not $AdvancedSearch) { return $false }
    
    # Check if location is non-default (not "All Locations" or null)
    $hasLocation = $AdvancedSearch.Location -and $AdvancedSearch.Location -ne "All Locations"
    
    # Check if status is non-default (not "All" or null)
    $hasStatus = $AdvancedSearch.Status -and $AdvancedSearch.Status -ne "All"
    
    # Check if date range is non-default (not "Any time" or null)
    $hasDateRange = $AdvancedSearch.DateRange -and $AdvancedSearch.DateRange -ne "Any time"
    
    # Check if custom dates are set
    $hasCustomDates = $AdvancedSearch.CustomDateStart -and $AdvancedSearch.CustomDateEnd
    
    # Check if exact match is enabled
    $hasExactMatch = $AdvancedSearch.ExactMatch -eq $true
    
    # Check if include inactive is enabled
    $hasIncludeInactive = $AdvancedSearch.IncludeInactive -eq $true
    
    # Return true if any non-default value is set
    return ($hasLocation -or $hasStatus -or $hasDateRange -or $hasCustomDates -or $hasExactMatch -or $hasIncludeInactive)
}

# Helper function to build a concise summary string for advanced search settings
function Get-AdvancedSearchSummary {
    param(
        [object]$AdvancedSearch
    )
    
    if (-not $AdvancedSearch) { return "" }
    
    $parts = @()
    
    # Add location if non-default
    if ($AdvancedSearch.Location -and $AdvancedSearch.Location -ne "All Locations") {
        $parts += "Loc=$($AdvancedSearch.Location)"
    }
    
    # Add status if non-default
    if ($AdvancedSearch.Status -and $AdvancedSearch.Status -ne "All") {
        $parts += "Status=$($AdvancedSearch.Status)"
    }
    
    # Add date range if non-default
    if ($AdvancedSearch.DateRange -and $AdvancedSearch.DateRange -ne "Any time") {
        if ($AdvancedSearch.DateRange -eq "Custom range..." -and $AdvancedSearch.CustomDateStart -and $AdvancedSearch.CustomDateEnd) {
            # Handle dates that might be strings from JSON
            $startDate = if ($AdvancedSearch.CustomDateStart -is [DateTime]) { $AdvancedSearch.CustomDateStart } else { [DateTime]::Parse($AdvancedSearch.CustomDateStart.ToString()) }
            $endDate = if ($AdvancedSearch.CustomDateEnd -is [DateTime]) { $AdvancedSearch.CustomDateEnd } else { [DateTime]::Parse($AdvancedSearch.CustomDateEnd.ToString()) }
            $startStr = $startDate.ToString('MM/dd/yyyy')
            $endStr = $endDate.ToString('MM/dd/yyyy')
            $parts += "Date=$startStr-$endStr"
        } else {
            $parts += "Date=$($AdvancedSearch.DateRange)"
        }
    }
    
    # Add exact match flag
    if ($AdvancedSearch.ExactMatch -eq $true) {
        $parts += "Exact"
    }
    
    # Add include inactive flag
    if ($AdvancedSearch.IncludeInactive -eq $true) {
        $parts += "Inactive"
    }
    
    if ($parts.Count -eq 0) { return "" }
    return " [" + ($parts -join ", ") + "]"
}

# Helper function to build a detailed tooltip string for advanced search settings
function Get-AdvancedSearchTooltip {
    param(
        [object]$AdvancedSearch
    )
    
    if (-not $AdvancedSearch) { return "" }
    
    $lines = @()
    
    if ($AdvancedSearch.Location) {
        $lines += "Location: $($AdvancedSearch.Location)"
    }
    
    if ($AdvancedSearch.Status) {
        $lines += "Status: $($AdvancedSearch.Status)"
    }
    
    if ($AdvancedSearch.DateRange) {
        if ($AdvancedSearch.DateRange -eq "Custom range..." -and $AdvancedSearch.CustomDateStart -and $AdvancedSearch.CustomDateEnd) {
            # Handle dates that might be strings from JSON
            $startDate = if ($AdvancedSearch.CustomDateStart -is [DateTime]) { $AdvancedSearch.CustomDateStart } else { [DateTime]::Parse($AdvancedSearch.CustomDateStart.ToString()) }
            $endDate = if ($AdvancedSearch.CustomDateEnd -is [DateTime]) { $AdvancedSearch.CustomDateEnd } else { [DateTime]::Parse($AdvancedSearch.CustomDateEnd.ToString()) }
            $startStr = $startDate.ToString('MM/dd/yyyy')
            $endStr = $endDate.ToString('MM/dd/yyyy')
            $lines += "Date Range: $startStr to $endStr"
        } else {
            $lines += "Date Range: $($AdvancedSearch.DateRange)"
        }
    }
    
    if ($AdvancedSearch.ExactMatch -eq $true) {
        $lines += "Exact Match: Yes"
    }
    
    if ($AdvancedSearch.IncludeInactive -eq $true) {
        $lines += "Include Inactive: Yes"
    }
    
    if ($lines.Count -eq 0) { return "" }
    return $lines -join "`n"
}

# Function to update favorites menu
<#
.SYNOPSIS
    Rebuilds the Favorites menu with current saved favorites.
#>
function Refresh-FavoritesMenu {
    # Prefer globally exported menu from UI module if present
    $menuToUse = if ($global:favoritesMenu) { $global:favoritesMenu } else { $favoritesMenu }

    # Clear ALL existing menu items
    $menuToUse.DropDownItems.Clear()
    
    # Add "Add Current" option first
    $addToFavoritesMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $addToFavoritesMenuItem.Text = "Add Current Search"
    $addToFavoritesMenuItem.Add_Click({
        if ($searchTextBox.Text -eq "") {
            [System.Windows.Forms.MessageBox]::Show("No active search to add to favorites.", "Favorites", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            return
        }
        
        # Prompt for a name
        $favoriteNameForm = New-Object System.Windows.Forms.Form
        $favoriteNameForm.Text = "Add to Favorites"
        $favoriteNameForm.Size = New-Object System.Drawing.Size(350, 150)
        $favoriteNameForm.StartPosition = "CenterScreen"
        $favoriteNameForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        $favoriteNameForm.MaximizeBox = $false
        $favoriteNameForm.MinimizeBox = $false
        
        $nameLabel = New-Object System.Windows.Forms.Label
        $nameLabel.Text = "Enter a name for this favorite:"
        $nameLabel.Location = New-Object System.Drawing.Point(20, 20)
        $nameLabel.Size = New-Object System.Drawing.Size(300, 20)
        $favoriteNameForm.Controls.Add($nameLabel)
        
        $nameTextBox = New-Object System.Windows.Forms.TextBox
        $nameTextBox.Text = $searchTextBox.Text
        $nameTextBox.Location = New-Object System.Drawing.Point(20, 45)
        $nameTextBox.Size = New-Object System.Drawing.Size(300, 20)
        $favoriteNameForm.Controls.Add($nameTextBox)
        
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Text = "OK"
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $okButton.Location = New-Object System.Drawing.Point(170, 80)
        $okButton.Size = New-Object System.Drawing.Size(70, 25)
        $favoriteNameForm.Controls.Add($okButton)
        
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Text = "Cancel"
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $cancelButton.Location = New-Object System.Drawing.Point(250, 80)
        $cancelButton.Size = New-Object System.Drawing.Size(70, 25)
        $favoriteNameForm.Controls.Add($cancelButton)
        
        $favoriteNameForm.AcceptButton = $okButton
        $favoriteNameForm.CancelButton = $cancelButton
        
        $result = $favoriteNameForm.ShowDialog()
        
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $favoriteName = $nameTextBox.Text
            
            if ([string]::IsNullOrWhiteSpace($favoriteName)) {
                [System.Windows.Forms.MessageBox]::Show("Favorite name cannot be empty.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                return
            }
            
            # Create favorite object with advanced search parameters if enabled
            $favorite = @{
                Name = $favoriteName
                SearchTerm = $searchTextBox.Text
                SearchType = $typeComboBox.SelectedItem
                DateAdded = Get-Date
            }
            try { Write-Log -Message "Add-Favorite clicked: term='$($favorite.SearchTerm)', type='$($favorite.SearchType)'" -Level "Info" } catch {}
            
            # Add advanced search parameters if enabled and has non-default values
            if ($advancedSearchCheckBox.Checked) {
                $advancedSearch = @{
                    Location = $locationComboBox.SelectedItem
                    Status = $statusComboBox.SelectedItem
                    DateRange = $dateRangeComboBox.SelectedItem
                    ExactMatch = $exactMatchCheckBox.Checked
                    IncludeInactive = $includeDisabledCheckBox.Checked
                }
                
                # Add custom date range if selected
                if ($dateRangeComboBox.SelectedItem -eq "Custom range..." -and $script:customDateStart -and $script:customDateEnd) {
                    $advancedSearch.CustomDateStart = $script:customDateStart
                    $advancedSearch.CustomDateEnd = $script:customDateEnd
                }
                
                # Only save AdvancedSearch if it has non-default values
                if (Test-AdvancedSearchHasNonDefaults -AdvancedSearch $advancedSearch) {
                    $favorite.AdvancedSearch = $advancedSearch
                }
            }
            
            # Add to favorites
            $favorites = @()
            
            # Load existing favorites (JSON)
            try { $favorites = Read-Favorites } catch { $favorites = @() }
            
            # De-duplicate by SearchTerm + SearchType + Advanced signature, then append
            $advNew = if ($favorite.AdvancedSearch) { ($favorite.AdvancedSearch | ConvertTo-Json -Depth 7) } else { "" }
            $favorites = @($favorites) | Where-Object {
                $advExisting = if ($_.AdvancedSearch) { ($_.AdvancedSearch | ConvertTo-Json -Depth 7) } else { "" }
                -not (($_.SearchTerm -eq $favorite.SearchTerm) -and ($_.SearchType -eq $favorite.SearchType) -and ($advExisting -eq $advNew))
            }
            $favorites = @($favorites) + @($favorite)
            
            # Save favorites (JSON)
            try {
                Save-Favorites -Favorites $favorites
                # Sync to shared location immediately to prevent other devices from overwriting
                if (Get-Command Sync-SharedData -ErrorAction SilentlyContinue) {
                    Sync-SharedData -Trigger "FavoritesSaved"
                }
                Refresh-FavoritesMenu
                [System.Windows.Forms.MessageBox]::Show("Search added to favorites.", "Favorites", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } catch {
                Write-Log -Message "Error saving favorites: $_" -Level "Error"
                [System.Windows.Forms.MessageBox]::Show("Failed to save favorite: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    })
    [void]$menuToUse.DropDownItems.Add($addToFavoritesMenuItem)
    
    # Add separator
    [void]$menuToUse.DropDownItems.Add("-")
    
    # Load favorites (JSON)
    try { $favorites = Read-Favorites } catch { $favorites = @() }
    $favList = @($favorites)
    try { Write-Log -Message "Refreshing favorites menu; items=$($favList.Count)" -Level "Info" } catch {}
    
    # Sort favorites by Name (case-insensitive), then SearchType
    if ($favList.Count -gt 0) {
        $favList = $favList | Sort-Object -Property @(
            @{ Expression = { if ($_.Name) { $_.Name.ToString().ToLowerInvariant() } else { "" } }; Ascending = $true },
            @{ Expression = { if ($_.SearchType) { $_.SearchType.ToString().ToLowerInvariant() } else { "" } }; Ascending = $true }
        )
        foreach ($favorite in $favList) {
            $menuItem = New-Object System.Windows.Forms.ToolStripMenuItem
            
            # Create display text with search type and advanced search summary
            $displayText = $favorite.Name
            # Add search type in parentheses
            if ($favorite.SearchType) {
                $displayText += " ($($favorite.SearchType))"
            }
            # Add advanced search summary
            $summary = Get-AdvancedSearchSummary -AdvancedSearch $favorite.AdvancedSearch
            if ($summary) {
                $displayText += $summary
            }
            
            $menuItem.Text = $displayText
            $menuItem.Tag = $favorite
            
            # Add tooltip with full advanced search details if available
            $tooltipText = Get-AdvancedSearchTooltip -AdvancedSearch $favorite.AdvancedSearch
            if ($tooltipText) {
                $menuItem.ToolTipText = $tooltipText
            }
            
            # Add click handler
            $menuItem.Add_Click({
                # Close the dropdown so the menu doesn't stay open after selecting a favorite
                try {
                    $p = $this.GetCurrentParent()
                    if ($p -and ($p -is [System.Windows.Forms.ToolStripDropDown])) { $p.Close() }
                } catch {}

                $favorite = $this.Tag
                
                # Set basic search parameters
                $searchTextBox.Text = $favorite.SearchTerm
                $typeComboBox.SelectedIndex = $typeComboBox.Items.IndexOf($favorite.SearchType)
                
                # Set advanced search parameters if they exist
                if ($favorite.AdvancedSearch) {
                    $advancedSearchCheckBox.Checked = $true
                    
                    # Set location
                    if ($favorite.AdvancedSearch.Location) {
                        $locationComboBox.SelectedItem = $favorite.AdvancedSearch.Location
                    }
                    
                    # Set status
                    if ($favorite.AdvancedSearch.Status) {
                        $statusComboBox.SelectedItem = $favorite.AdvancedSearch.Status
                    }
                    
                    # Set date range
                    if ($favorite.AdvancedSearch.DateRange) {
                        $dateRangeComboBox.SelectedItem = $favorite.AdvancedSearch.DateRange
                        
                        # Set custom date range if it exists
                        if ($favorite.AdvancedSearch.DateRange -eq "Custom range..." -and 
                            $favorite.AdvancedSearch.CustomDateStart -and 
                            $favorite.AdvancedSearch.CustomDateEnd) {
                            $script:customDateStart = $favorite.AdvancedSearch.CustomDateStart
                            $script:customDateEnd = $favorite.AdvancedSearch.CustomDateEnd
                            $customDateRangeStatusLabel.Text = "Range: $($script:customDateStart.ToString('MM/dd/yyyy')) to $($script:customDateEnd.ToString('MM/dd/yyyy'))"
                        }
                    }
                    
                    # Set exact match and include inactive
                    $exactMatchCheckBox.Checked = $favorite.AdvancedSearch.ExactMatch
                    $includeDisabledCheckBox.Checked = $favorite.AdvancedSearch.IncludeInactive
                } else {
                    # Reset advanced search if not present
                    $advancedSearchCheckBox.Checked = $false
                }
                
                # Perform search
                $searchButton.PerformClick()
            })
            
            # Add Remove submenu
            $removeMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
            $removeMenuItem.Text = "Remove"
            $removeMenuItem.Tag = $favorite
            
            $removeMenuItem.Add_Click({
                $favoriteToRemove = $this.Tag
                
                # Load favorites (JSON)
                $favorites = @()
                try { 
                    $favorites = Read-Favorites 
                    if ($favorites.Count -eq 0) {
                        [System.Windows.Forms.MessageBox]::Show("No favorites found to remove.", "Remove Favorite", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                        return
                    }
                } catch { 
                    Write-Log -Message "Error loading favorites for removal: $_" -Level "Error"
                    [System.Windows.Forms.MessageBox]::Show("Failed to load favorites. Cannot remove favorite.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                    return
                }
                
                # Remove favorite by matching SearchTerm + SearchType + Advanced signature (same as deduplication logic)
                $advToRemove = if ($favoriteToRemove.AdvancedSearch) { ($favoriteToRemove.AdvancedSearch | ConvertTo-Json -Depth 7) } else { "" }
                $originalCount = $favorites.Count
                $favorites = @($favorites) | Where-Object {
                    $advExisting = if ($_.AdvancedSearch) { ($_.AdvancedSearch | ConvertTo-Json -Depth 7) } else { "" }
                    -not (($_.SearchTerm -eq $favoriteToRemove.SearchTerm) -and ($_.SearchType -eq $favoriteToRemove.SearchType) -and ($advExisting -eq $advToRemove))
                }
                
                # Safety check: if we're removing all favorites, ask for confirmation
                if ($favorites.Count -eq 0 -and $originalCount -gt 1) {
                    $result = [System.Windows.Forms.MessageBox]::Show("Removing this favorite would remove all favorites. Continue?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
                    if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
                        return
                    }
                }
                
                # Save favorites (JSON)
                try {
                    Save-Favorites -Favorites $favorites
                    # Sync to shared location immediately to prevent other devices from overwriting
                    if (Get-Command Sync-SharedData -ErrorAction SilentlyContinue) {
                        Sync-SharedData -Trigger "FavoritesSaved"
                    }
                    Refresh-FavoritesMenu
                } catch {
                    Write-Log -Message "Error saving favorites: $_" -Level "Error"
                    [System.Windows.Forms.MessageBox]::Show("Failed to save favorites: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                }
            })
            
            [void]$menuItem.DropDownItems.Add($removeMenuItem)
            try { $menuToUse.DropDownItems.Add($menuItem) | Out-Null } catch { try { Write-Log -Message "Failed adding favorite menu item: $_" -Level "Warning" } catch {} }
        }
    }
    else {
        $noFavoritesMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
        $noFavoritesMenuItem.Text = "No favorites"
        $noFavoritesMenuItem.Enabled = $false
        [void]$menuToUse.DropDownItems.Add($noFavoritesMenuItem)
    }
    
    # Add Clear All option if there are favorites
    if ($favList.Count -gt 0) {
        [void]$menuToUse.DropDownItems.Add("-")
        $clearAllMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
        $clearAllMenuItem.Text = "Clear All"
        $clearAllMenuItem.Add_Click({
            $result = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to clear all favorites?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
            
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                # Clear favorites (JSON)
                try {
                    Save-Favorites -Favorites @()
                    # Sync to shared location immediately to prevent other devices from overwriting
                    if (Get-Command Sync-SharedData -ErrorAction SilentlyContinue) {
                        Sync-SharedData -Trigger "FavoritesSaved"
                    }
                    Refresh-FavoritesMenu
                } catch {
                    Write-Log -Message "Error clearing favorites: $_" -Level "Error"
                    [System.Windows.Forms.MessageBox]::Show("Failed to clear favorites: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                }
            }
        })
        [void]$menuToUse.DropDownItems.Add($clearAllMenuItem)
    }
}

# Function to add search to history
<#
.SYNOPSIS
    Adds the current search to the history and updates the History menu.
#>

function Add-SearchToHistory {
    param($searchTerm, $searchType)
    try {
        if (Get-Command Update-SearchHistory -ErrorAction SilentlyContinue) {
            Update-SearchHistory -SearchTerm $searchTerm -SearchType $searchType
        } else {
            # Fallback if module not available
            $history = @()
            try { $history = Read-SearchHistory } catch { $history = @() }
            $history = @([PSCustomObject]@{ SearchTerm = $searchTerm; SearchType = $searchType; Timestamp = Get-Date }) + $history
            Save-SearchHistory -History $history
        }
        Update-SearchHistoryMenu
    } catch {
        Write-Log -Message "Error updating search history: $_" -Level "Error"
    }
}

# Function to update search history menu
<#
.SYNOPSIS
Brief description of Update-SearchHistoryMenu.
.DESCRIPTION
Extended description of Update-SearchHistoryMenu.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Update-SearchHistoryMenu
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

<#
.SYNOPSIS
Brief description of Update-SearchHistoryMenu.
.DESCRIPTION
Extended description of Update-SearchHistoryMenu.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Update-SearchHistoryMenu
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Update-SearchHistoryMenu {
    # Clear existing menu items
    $historyMenu.DropDownItems.Clear()
    
    # Load history (JSON)
    try { $history = Read-SearchHistory } catch { $history = @() }
    
    # Add history items to menu
    if ($history.Count -gt 0) {
        foreach ($historyItem in $history) {
            $menuItem = New-Object System.Windows.Forms.ToolStripMenuItem
            $menuItem.Text = "$($historyItem.SearchTerm) ($($historyItem.SearchType))"
            $menuItem.Tag = $historyItem
            
            $menuItem.Add_Click({
                # Close the dropdown so the menu doesn't stay open after selecting a history entry
                try {
                    $p = $this.GetCurrentParent()
                    if ($p -and ($p -is [System.Windows.Forms.ToolStripDropDown])) { $p.Close() }
                } catch {}

                $historyItem = $this.Tag
                $searchTextBox.Text = $historyItem.SearchTerm
                $typeComboBox.SelectedIndex = $typeComboBox.Items.IndexOf($historyItem.SearchType)
                $searchButton.PerformClick()
            })
            
            # Add per-item Remove action
            $removeMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
            $removeMenuItem.Text = "Remove"
            $removeMenuItem.Tag = $historyItem
            $removeMenuItem.Add_Click({
                $itemToRemove = $this.Tag
                try { $allHistory = Read-SearchHistory } catch { $allHistory = @() }
                $updated = @($allHistory) | Where-Object { -not (($_.SearchTerm -eq $itemToRemove.SearchTerm) -and ($_.SearchType -eq $itemToRemove.SearchType)) }
                try {
                    Save-SearchHistory -History $updated
                    Update-SearchHistoryMenu
                } catch {
                    Write-Log -Message "Error removing history item: $_" -Level "Error"
                }
            })
            [void]$menuItem.DropDownItems.Add($removeMenuItem)
            
            [void]$historyMenu.DropDownItems.Add($menuItem)
        }
        
        # Add separator and clear option
        [void]$historyMenu.DropDownItems.Add("-")
        $clearHistoryMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
        $clearHistoryMenuItem.Text = "Clear Search History"
        $clearHistoryMenuItem.Add_Click({
            $result = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to clear search history?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
            
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                try {
                    Save-SearchHistory -History @()
                    Update-SearchHistoryMenu
                } catch {
                    Write-Log -Message "Error clearing search history: $_" -Level "Error"
                }
            }
        })
        [void]$historyMenu.DropDownItems.Add($clearHistoryMenuItem)
    }
    else {
        $noHistoryMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
        $noHistoryMenuItem.Text = "No search history"
        $noHistoryMenuItem.Enabled = $false
        [void]$historyMenu.DropDownItems.Add($noHistoryMenuItem)
    }
}

# Create PDQ menu
$pdqMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$pdqMenu.Text = "PDQ"

# PDQ Deploy submenu
$pdqDeployMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$pdqDeployMenu.Text = "Deploy"
[void]$pdqMenu.DropDownItems.Add($pdqDeployMenu)
$script:pdqDeployMenu = $pdqDeployMenu

# Initial load of PDQ Deploy menu (will also rebuild on menu open and after Settings changes)
try { Update-PDQDeployMenu -DeployMenu $pdqDeployMenu } catch {}

# Keep menu always in sync with settings at time of use
try {
    $pdqDeployMenu.Add_DropDownOpening({
        try { Update-PDQDeployMenu -DeployMenu $pdqDeployMenu } catch {}
    })
} catch {}

# PDQ Inventory submenu
$pdqInventoryMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$pdqInventoryMenu.Text = "Inventory"
[void]$pdqMenu.DropDownItems.Add($pdqInventoryMenu)

# View Computer Details menu item
$viewComputerDetailsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$viewComputerDetailsMenuItem.Text = "View Computer Details"
$viewComputerDetailsMenuItem.Enabled = $false  # Will be enabled when computer is selected
$viewComputerDetailsMenuItem.Add_Click({
    try {
        $computerName = Resolve-PDQTargetComputerNameFromSelection -Title "PDQ Inventory" -ParentForm $mainForm
        if ([string]::IsNullOrWhiteSpace($computerName)) { return }

        # Ensure data is queried without requiring the user to click Refresh in the dialog.
        # The dialog will auto-refresh itself when the async prefetch updates the cache.
        try {
            if ((Get-Command Start-PDQInventoryCLIPrefetchAsync -ErrorAction SilentlyContinue) -and
                (Get-Command Get-PDQInventoryCLISettings -ErrorAction SilentlyContinue)) {
                $pdqCLISettings = Get-PDQInventoryCLISettings
                if ($pdqCLISettings -and $pdqCLISettings.Enabled -and -not [string]::IsNullOrWhiteSpace($pdqCLISettings.ExecutablePath)) {
                    $null = Start-PDQInventoryCLIPrefetchAsync -ComputerName $computerName -ExecutablePath $pdqCLISettings.ExecutablePath -Reason "MenuDetails"
                }
            }
        } catch {}

        if (Get-Command Show-PDQCLIDialog -ErrorAction SilentlyContinue) {
            Show-PDQCLIDialog -ComputerName $computerName -ParentForm $mainForm
        } else {
            [System.Windows.Forms.MessageBox]::Show(
                "PDQ CLI dialog function not available. Please check module loading.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    } catch {
        Write-Log -Message "Error showing PDQ CLI dialog: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "Error showing PDQ Inventory details: $_",
            "PDQ Inventory Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
})
[void]$pdqInventoryMenu.DropDownItems.Add($viewComputerDetailsMenuItem)

# Refresh Computer Info menu item
$refreshComputerMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$refreshComputerMenuItem.Text = "Refresh Computer Info"
$refreshComputerMenuItem.Enabled = $false  # Will be enabled when computer is selected
$refreshComputerMenuItem.Add_Click({
    try {
        $computerName = Resolve-PDQTargetComputerNameFromSelection -Title "PDQ Inventory" -ParentForm $mainForm
        if ([string]::IsNullOrWhiteSpace($computerName)) { return }

        # Force-refresh PDQ CLI data (ignore cache)
        $pdqData = Invoke-PDQGetComputer -ComputerName $computerName -NoCache
            if ($pdqData) {
                # Trigger re-render of info panel
                if ($resultsListView.SelectedItems.Count -gt 0) {
                    $selectedItem = $resultsListView.SelectedItems[0]
                    # Trigger the selection changed event to refresh display
                    $resultsListView.SelectedItems.Clear()
                    $selectedItem.Selected = $true
                }
                [System.Windows.Forms.MessageBox]::Show(
                    "PDQ Inventory data refreshed successfully.",
                    "PDQ Inventory",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                ) | Out-Null
            } else {
                [System.Windows.Forms.MessageBox]::Show(
                    "Failed to retrieve PDQ Inventory data. Check logs for details.",
                    "PDQ Inventory",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
            }
    } catch {
        Write-Log -Message "Error refreshing PDQ Inventory data: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show(
            "Error refreshing PDQ Inventory data: $_",
            "PDQ Inventory Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    }
})
[void]$pdqInventoryMenu.DropDownItems.Add($refreshComputerMenuItem)

# Store references for enable/disable logic
$script:pdqDeployMenuItems = @()
$pdqDeployMenu.DropDownItems | ForEach-Object {
    if ($_.Text -ne "No packages configured") {
        $script:pdqDeployMenuItems += $_
    }
}
$script:pdqInventoryRefreshMenuItem = $refreshComputerMenuItem
$script:pdqInventoryDetailsMenuItem = $viewComputerDetailsMenuItem

# Add all menus to the menu strip
$menuStrip.Items.AddRange(@($fileMenu, $searchMenu, $toolsMenu, $connectionMenu, $adMenu, $pdqMenu, $favoritesMenu, $historyMenu))

# Initialize both menus
Refresh-FavoritesMenu
Update-SearchHistoryMenu


# (moved to module) Add-SearchToHistory removed. See Modules/SearchHistory.psm1 for Update-SearchHistory implementation.

# Function to update the basic info panel with item properties
<#
.SYNOPSIS
Brief description of Update-BasicInfoPanel.
.DESCRIPTION
Extended description of Update-BasicInfoPanel.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Update-BasicInfoPanel
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

<#
.SYNOPSIS
Brief description of Update-BasicInfoPanel.
.DESCRIPTION
Extended description of Update-BasicInfoPanel.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Update-BasicInfoPanel
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Update-BasicInfoPanel {
    param (
        [PSObject]$ItemProperties,
        [string]$ItemType
    )
    
    # Clear the existing info panel
    $fieldListView.Items.Clear()
    
    try {
        # Create and process items based on type
        if ($ItemType -eq "Computer") {
            # Add computer-specific properties
            $addProperty = {
                param($name, $value, $format = $null)
                
                $item = New-Object System.Windows.Forms.ListViewItem($name)
                
                # Format the value if a format is specified
                if ($format -and $value) {
                    if ($format -eq "datetime") {
                        $displayValue = $value.ToString("g")
                    } elseif ($format -eq "enabled") {
                        $displayValue = if ($value) { "Enabled" } else { "Disabled" }
                    } elseif ($format -eq "fileTime") {
                        $displayValue = if ($value) { [datetime]::FromFileTime($value).ToString("g") } else { "Never" }
                    } else {
                        $displayValue = if ($null -eq $value) { "N/A" } else { $value.ToString() }
                    }
                } else {
                $displayValue = if ($null -eq $value) { "N/A" } else { $value.ToString() }
            }
            
            [void]$item.SubItems.Add($displayValue)
            [void]$fieldListView.Items.Add($item)
        }

            # Add computer properties with correct property names
            & $addProperty "Computer Name" $ItemProperties.Name
            & $addProperty "IP Address" $ItemProperties.IPv4Address
            & $addProperty "DNS Name" $ItemProperties.DNSHostName
            & $addProperty "Operating System" $ItemProperties.OperatingSystem
            & $addProperty "OS Version" $ItemProperties.OperatingSystemVersion
            & $addProperty "Status" $ItemProperties.Enabled "enabled"
            & $addProperty "Last Logon" $ItemProperties.LastLogon "fileTime"
            & $addProperty "Pwd Last Set" $ItemProperties.PasswordLastSet "datetime"
            & $addProperty "When Created" $ItemProperties.WhenCreated "datetime"
            & $addProperty "When Changed" $ItemProperties.WhenChanged "datetime"
            & $addProperty "OU Path" (Format-ADappOUPath -Path $ItemProperties.CanonicalName)
            & $addProperty "Distinguished Name" $ItemProperties.DistinguishedName
            
            # Update group membership display
            Update-GroupMembershipDisplay -ItemName $ItemProperties.Name -IsComputer $true
        }
        elseif ($ItemType -eq "User") {
            # User properties (kept for user handling)
            # Add user-specific properties
            $addProperty = {
                param($name, $value, $format = $null)
                
                $item = New-Object System.Windows.Forms.ListViewItem($name)
                
                # Format the value if a format is specified
                if ($format -and $value) {
                    if ($format -eq "datetime") {
                        $displayValue = $value.ToString("g")
                    } elseif ($format -eq "enabled") {
                        $displayValue = if ($value) { "Enabled" } else { "Disabled" }
                    } elseif ($format -eq "locked") {
                        $displayValue = if ($value) { "LOCKED" } else { "Not locked" }
                    } elseif ($format -eq "fileTime") {
                        $displayValue = if ($value) { [datetime]::FromFileTime($value).ToString("g") } else { "Never" }
                    } else {
                        $displayValue = if ($null -eq $value) { "N/A" } else { $value.ToString() }
                    }
                } else {
                $displayValue = if ($null -eq $value) { "N/A" } else { $value.ToString() }
            }
            
            [void]$item.SubItems.Add($displayValue)
            [void]$fieldListView.Items.Add($item)
        }

            # Add user properties
            & $addProperty "Username" $ItemProperties.SamAccountName
            & $addProperty "Full Name" "$($ItemProperties.GivenName) $($ItemProperties.Surname)"
            & $addProperty "Display Name" $ItemProperties.DisplayName
            & $addProperty "Email" $ItemProperties.EmailAddress
            & $addProperty "Title" $ItemProperties.Title
            & $addProperty "Department" $ItemProperties.Department
            & $addProperty "Phone" $ItemProperties.telephoneNumber
            & $addProperty "Status" $ItemProperties.Enabled "enabled"
            & $addProperty "Locked" $ItemProperties.LockedOut "locked"
            & $addProperty "Last Logon" $ItemProperties.LastLogon "fileTime"
            & $addProperty "Pwd Last Set" $ItemProperties.PasswordLastSet "datetime"
            & $addProperty "When Created" $ItemProperties.WhenCreated "datetime"
            & $addProperty "When Changed" $ItemProperties.WhenChanged "datetime"
            & $addProperty "OU Path" (Format-ADappOUPath -Path $ItemProperties.CanonicalName)
            & $addProperty "Distinguished Name" $ItemProperties.DistinguishedName
            
            # Update group membership display
            Update-GroupMembershipDisplay -ItemName $ItemProperties.SamAccountName -IsComputer $false
        }
    }
    catch {
        Write-Log -Message "Error updating basic info panel: $_" -Level "Error"
        $item = New-Object System.Windows.Forms.ListViewItem("Error")
        [void]$item.SubItems.Add("Failed to retrieve item properties: $_")
        [void]$fieldListView.Items.Add($item)
    }
}



# Create search panel - Row 0
$searchPanel = New-Object System.Windows.Forms.Panel
$searchPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$searchPanel.BackColor = $backgroundColor
# Add to row 0
[void]$tableLayoutPanel.Controls.Add($searchPanel, 0, 0)

# Create search term label and textbox
$searchTermLabel = New-Object System.Windows.Forms.Label
$searchTermLabel.Text = "Search Term:"
$searchTermLabel.Location = New-Object System.Drawing.Point(10, 15)
$searchTermLabel.AutoSize = $true
[void]$searchPanel.Controls.Add($searchTermLabel)

$searchTextBox = New-Object System.Windows.Forms.TextBox
$searchTextBox.Location = New-Object System.Drawing.Point(90, 12)
$searchTextBox.Size = New-Object System.Drawing.Size(300, 23)
$searchTextBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$searchTextBox.Add_KeyDown({
    # Check if the Enter key was pressed
    if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        # Prevent the default behavior (beep sound)
        $_.SuppressKeyPress = $true
        # Trigger the search button click
        $searchButton.PerformClick()
    }
})
[void]$searchPanel.Controls.Add($searchTextBox)

# Create type label and combobox
$typeLabel = New-Object System.Windows.Forms.Label
$typeLabel.Text = "Type:"
$typeLabel.Location = New-Object System.Drawing.Point(400, 15)
$typeLabel.AutoSize = $true
[void]$searchPanel.Controls.Add($typeLabel)

$typeComboBox = New-Object System.Windows.Forms.ComboBox
$typeComboBox.Location = New-Object System.Drawing.Point(440, 12)
$typeComboBox.Size = New-Object System.Drawing.Size(150, 23)
$typeComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$typeComboBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
[void]$typeComboBox.Items.AddRange(@("All", "Users", "Computers", "Servers", "Groups", "Printers"))
$typeComboBox.SelectedIndex = 0
$typeComboBox.Add_SelectedIndexChanged({
    # Refresh location dropdown when type changes
    if ($locationComboBox) {
        Update-LocationDropdown
    }
})
[void]$searchPanel.Controls.Add($typeComboBox)

# Add search button
$searchButton = New-Object System.Windows.Forms.Button
$searchButton.Location = New-Object System.Drawing.Point(600, 12)
$searchButton.Size = New-Object System.Drawing.Size(75, 25)
$searchButton.Text = "Search"
$searchButton.BackColor = [System.Drawing.ColorTranslator]::FromHtml($Settings.UI.SearchButtonBackColor)
$searchButton.ForeColor = [System.Drawing.ColorTranslator]::FromHtml($Settings.UI.SearchButtonForeColor)
$searchButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
[void]$searchPanel.Controls.Add($searchButton)

function Update-LogPanelVisibility {
    if ($logPanelCheckBox.Checked) {
        # Set the row height to accommodate the log panel
        $tableLayoutPanel.RowStyles[3] = New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 200)
        Update-LogView
    } else {
        # Hide the log panel
        $tableLayoutPanel.RowStyles[3] = New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 0)
    }
}

function Update-LogView {
    try {
        $logDir = if ($global:AppConfig -and $global:AppConfig.LogPath) { $global:AppConfig.LogPath } else { Join-Path -Path $env:ProgramData -ChildPath 'ADapp\Logs' }
        $transcriptLog = Join-Path -Path $logDir -ChildPath "ADapp_Console.log"
        $appLog = Join-Path -Path $logDir -ChildPath "ADapp.log"
        
        $targetLog = if (Test-Path $transcriptLog) { $transcriptLog } else { $appLog }
        
        if (Test-Path $targetLog) {
            # Read tail lines from settings
            $tailLimit = if ($Settings.Logging.LogViewTailLimit) { [int]$Settings.Logging.LogViewTailLimit } else { 100 }
            $logLines = Get-Content -Path $targetLog -Tail $tailLimit
            $logRichTextBox.Text = $logLines -join "`r`n"
            
            # Scroll to bottom
            $logRichTextBox.SelectionStart = $logRichTextBox.Text.Length
            $logRichTextBox.ScrollToCaret()
        } else {
            $logRichTextBox.Text = "Log file not found at: $targetLog"
        }
    } catch {
        $logRichTextBox.Text = "Error reading log: $_"
    }
}

# Function to toggle advanced search panel visibility
<#
.SYNOPSIS
Brief description of Update-AdvancedSearchVisibility.
.DESCRIPTION
Extended description of Update-AdvancedSearchVisibility.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Update-AdvancedSearchVisibility
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

<#
.SYNOPSIS
Brief description of Update-AdvancedSearchVisibility.
.DESCRIPTION
Extended description of Update-AdvancedSearchVisibility.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Update-AdvancedSearchVisibility
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Update-AdvancedSearchVisibility {
    if ($advancedSearchCheckBox.Checked) {
        # Set the row height to accommodate the advanced panel
        $tableLayoutPanel.RowStyles[0] = New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 130)
        $advancedPanel.Visible = $true
    } else {
        # Return to original row height
        $tableLayoutPanel.RowStyles[0] = New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 85)
        $advancedPanel.Visible = $false
    }
}

# Add advanced search options
$advancedSearchCheckBox = New-Object System.Windows.Forms.CheckBox
$advancedSearchCheckBox.Text = "Advanced Search"
$advancedSearchCheckBox.Location = New-Object System.Drawing.Point(700, 12)
$advancedSearchCheckBox.Size = New-Object System.Drawing.Size(130, 20)
$advancedSearchCheckBox.Add_CheckedChanged({
    Update-AdvancedSearchVisibility
})
[void]$searchPanel.Controls.Add($advancedSearchCheckBox)

# Add log panel toggle
$logPanelCheckBox = New-Object System.Windows.Forms.CheckBox
$logPanelCheckBox.Text = "Show Logs"
$logPanelCheckBox.Location = New-Object System.Drawing.Point(840, 12)
$logPanelCheckBox.Size = New-Object System.Drawing.Size(100, 20)
$logPanelCheckBox.Add_CheckedChanged({
    Update-LogPanelVisibility
    # Start or stop the auto-refresh timer based on the checkbox state
    if ($logPanelCheckBox.Checked -and $Settings.Logging.EnableLogAutoRefresh) {
        $refreshInterval = if ($Settings.Logging.LogAutoRefreshInterval) { $Settings.Logging.LogAutoRefreshInterval } else { 5 }
        $script:LogRefreshTimer.Interval = $refreshInterval * 1000
        $script:LogRefreshTimer.Start()
    } else {
        $script:LogRefreshTimer.Stop()
    }
})
[void]$searchPanel.Controls.Add($logPanelCheckBox)

# Set initial state based on settings (will be applied after all controls are created)
if ($Settings.Search.AdvancedSearchDefault) {
    $advancedSearchCheckBox.Checked = $true
}

# Create advanced search panel - adjust position to avoid overlapping with menu
$advancedPanel = New-Object System.Windows.Forms.Panel
$advancedPanel.Location = New-Object System.Drawing.Point(10, 40)
$advancedPanel.Size = New-Object System.Drawing.Size(1160, 45)
$advancedPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$advancedPanel.Visible = $false
[void]$searchPanel.Controls.Add($advancedPanel)

# Add advanced search fields
$locationLabel = New-Object System.Windows.Forms.Label
$locationLabel.Text = "Location:"
$locationLabel.Location = New-Object System.Drawing.Point(10, 10)
$locationLabel.Size = New-Object System.Drawing.Size(80, 20)
[void]$advancedPanel.Controls.Add($locationLabel)

$locationComboBox = New-Object System.Windows.Forms.ComboBox
$locationComboBox.Location = New-Object System.Drawing.Point(90, 10)
$locationComboBox.Size = New-Object System.Drawing.Size(200, 20)
$locationComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
[void]$advancedPanel.Controls.Add($locationComboBox)

# Function to refresh location dropdown based on selected Type
function Update-LocationDropdown {
    param()
    
    try {
        $locationComboBox.Items.Clear()
        $selectedType = if ($typeComboBox.SelectedItem) { $typeComboBox.SelectedItem.ToString() } else { "All" }
        
        # Use global Settings if available, otherwise fall back to local
        $settingsToUse = if ($global:Settings) { $global:Settings } else { $Settings }
        
        # Determine base OU based on type
        $baseOU = $null
        $rootLabel = "All Locations"
        
        switch ($selectedType) {
            "Users" {
                if ($settingsToUse.AD -and $settingsToUse.AD.UserBaseOU -and $settingsToUse.AD.UserBaseOU.Count -gt 0) {
                    $baseOU = $settingsToUse.AD.UserBaseOU
                }
                $rootLabel = "All Users"
            }
            "Computers" {
                if ($settingsToUse.AD -and $settingsToUse.AD.ComputerBaseOU -and $settingsToUse.AD.ComputerBaseOU.Count -gt 0) {
                    $baseOU = $settingsToUse.AD.ComputerBaseOU
                }
                $rootLabel = "All Computers"
            }
            "Servers" {
                if ($settingsToUse.AD -and $settingsToUse.AD.ServerBaseOU -and $settingsToUse.AD.ServerBaseOU.Count -gt 0) {
                    $baseOU = $settingsToUse.AD.ServerBaseOU
                }
                $rootLabel = "All Servers"
            }
            "Groups" {
                if ($settingsToUse.AD -and $settingsToUse.AD.GroupBaseOU -and $settingsToUse.AD.GroupBaseOU.Count -gt 0) {
                    $baseOU = $settingsToUse.AD.GroupBaseOU
                }
                $rootLabel = "All Groups"
            }
            "Printers" {
                # Printers don't use OUs, so show empty or all locations
                $rootLabel = "All Locations"
            }
            default {
                # "All" - show all locations
                $rootLabel = "All Locations"
            }
        }
        
        # Get locations (filtered by base OU if specified)
        if ($baseOU) {
            $locations = Get-ADLocations -BaseOU $baseOU
        } else {
            $locations = Get-ADLocations
        }
        
        # Add root label first
        [void]$locationComboBox.Items.Add($rootLabel)
        
        # Add filtered locations
        foreach ($location in $locations) {
            [void]$locationComboBox.Items.Add($location)
        }
        
        # Select the root label
        $locationComboBox.SelectedIndex = 0
    }
    catch {
        Write-Log -Message "Error refreshing location dropdown: $_" -Level "Error"
        # Ensure at least "All Locations" is available
        if ($locationComboBox.Items.Count -eq 0) {
            [void]$locationComboBox.Items.Add("All Locations")
            $locationComboBox.SelectedIndex = 0
        }
    }
}

# Initial population of location dropdown
Update-LocationDropdown

$advancedStatusLabel = New-Object System.Windows.Forms.Label
$advancedStatusLabel.Text = "Status:"
$advancedStatusLabel.Location = New-Object System.Drawing.Point(310, 10)
$advancedStatusLabel.Size = New-Object System.Drawing.Size(50, 20)
[void]$advancedPanel.Controls.Add($advancedStatusLabel)

$statusComboBox = New-Object System.Windows.Forms.ComboBox
$statusComboBox.Location = New-Object System.Drawing.Point(360, 10)
$statusComboBox.Size = New-Object System.Drawing.Size(120, 20)
$statusComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
[void]$statusComboBox.Items.Add("All")
[void]$statusComboBox.Items.Add("Enabled")
[void]$statusComboBox.Items.Add("Disabled")
$statusComboBox.SelectedIndex = 0
[void]$advancedPanel.Controls.Add($statusComboBox)

$dateRangeLabel = New-Object System.Windows.Forms.Label
$dateRangeLabel.Text = "Created:"
$dateRangeLabel.Location = New-Object System.Drawing.Point(500, 10)
$dateRangeLabel.Size = New-Object System.Drawing.Size(60, 20)
[void]$advancedPanel.Controls.Add($dateRangeLabel)

# Create date range combo box
$dateRangeComboBox = New-Object System.Windows.Forms.ComboBox
$dateRangeComboBox.Width = 150
$dateRangeComboBox.Location = New-Object System.Drawing.Point(560, 10)
$dateRangeComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
[void]$dateRangeComboBox.Items.Add("Any time")
[void]$dateRangeComboBox.Items.Add("Today")
[void]$dateRangeComboBox.Items.Add("This week")
[void]$dateRangeComboBox.Items.Add("This month")
[void]$dateRangeComboBox.Items.Add("This year")
[void]$dateRangeComboBox.Items.Add("Custom range...")
$dateRangeComboBox.SelectedIndex = 0
[void]$advancedPanel.Controls.Add($dateRangeComboBox)

# Create custom date range label
$customDateRangeStatusLabel = New-Object System.Windows.Forms.Label
$customDateRangeStatusLabel.Text = ""
$customDateRangeStatusLabel.Location = New-Object System.Drawing.Point(500, 30)
$customDateRangeStatusLabel.Size = New-Object System.Drawing.Size(300, 20)
$customDateRangeStatusLabel.ForeColor = [System.Drawing.Color]::Navy
[void]$advancedPanel.Controls.Add($customDateRangeStatusLabel)

# Script-level variables to store custom date range
$script:customDateStart = $null
$script:customDateEnd = $null

# Handle date range selection change
$dateRangeComboBox.Add_SelectedIndexChanged({
    if ($dateRangeComboBox.SelectedItem -eq "Custom range...") {
        # Create custom date range selection form
        $dateForm = New-Object System.Windows.Forms.Form
        $dateForm.Text = "Select Date Range"
        $dateForm.Size = New-Object System.Drawing.Size(400, 250)
        $dateForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
        $dateForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
        $dateForm.MaximizeBox = $false
        $dateForm.MinimizeBox = $false

        # Create start date label
        $startDateLabel = New-Object System.Windows.Forms.Label
        $startDateLabel.Text = "Start Date:"
        $startDateLabel.Location = New-Object System.Drawing.Point(20, 30)
        $startDateLabel.Size = New-Object System.Drawing.Size(80, 20)
        $dateForm.Controls.Add($startDateLabel)

        # Create start date picker
        $startDatePicker = New-Object System.Windows.Forms.DateTimePicker
        $startDatePicker.Location = New-Object System.Drawing.Point(120, 30)
        $startDatePicker.Size = New-Object System.Drawing.Size(200, 20)
        $startDatePicker.Format = [System.Windows.Forms.DateTimePickerFormat]::Short
        # Default to one month ago
        $startDatePicker.Value = (Get-Date).AddMonths(-1)
        $dateForm.Controls.Add($startDatePicker)

        # Create end date label
        $endDateLabel = New-Object System.Windows.Forms.Label
        $endDateLabel.Text = "End Date:"
        $endDateLabel.Location = New-Object System.Drawing.Point(20, 70)
        $endDateLabel.Size = New-Object System.Drawing.Size(80, 20)
        $dateForm.Controls.Add($endDateLabel)

        # Create end date picker
        $endDatePicker = New-Object System.Windows.Forms.DateTimePicker
        $endDatePicker.Location = New-Object System.Drawing.Point(120, 70)
        $endDatePicker.Size = New-Object System.Drawing.Size(200, 20)
        $endDatePicker.Format = [System.Windows.Forms.DateTimePickerFormat]::Short
        # Default to today
        $endDatePicker.Value = Get-Date
        $dateForm.Controls.Add($endDatePicker)

        # Create OK button
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Text = "OK"
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $okButton.Location = New-Object System.Drawing.Point(120, 120)
        $okButton.Size = New-Object System.Drawing.Size(75, 23)
        $dateForm.Controls.Add($okButton)
        $dateForm.AcceptButton = $okButton

        # Create Cancel button
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Text = "Cancel"
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $cancelButton.Location = New-Object System.Drawing.Point(210, 120)
        $cancelButton.Size = New-Object System.Drawing.Size(75, 23)
        $dateForm.Controls.Add($cancelButton)
        $dateForm.CancelButton = $cancelButton

        # Show the form
        $result = $dateForm.ShowDialog()

        # Process result
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $script:customDateStart = $startDatePicker.Value.Date
            $script:customDateEnd = $endDatePicker.Value.Date.AddDays(1).AddSeconds(-1)  # End of the selected day
            
            # Check if start date is after end date
            if ($script:customDateStart -gt $script:customDateEnd) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Start date cannot be after end date. Please select valid dates.",
                    "Invalid Date Range",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                # Reset the dropdown to "Any time"
                $dateRangeComboBox.SelectedIndex = 0
                $script:customDateStart = $null
                $script:customDateEnd = $null
                $customDateRangeStatusLabel.Text = ""
            } else {
                # Update the custom date range status label with selected range
                $customDateRangeStatusLabel.Text = "Range: $($script:customDateStart.ToString('MM/dd/yyyy')) to $($script:customDateEnd.ToString('MM/dd/yyyy'))"
            }
        } else {
            # User canceled, reset to "Any time"
            $dateRangeComboBox.SelectedIndex = 0
            $script:customDateStart = $null
            $script:customDateEnd = $null
            $customDateRangeStatusLabel.Text = ""
        }
    } else {
        # Clear the custom date range status label for other options
        $customDateRangeStatusLabel.Text = ""
    }
})

# Create exact match checkbox
$exactMatchCheckBox = New-Object System.Windows.Forms.CheckBox
$exactMatchCheckBox.Text = "Exact Match"
$exactMatchCheckBox.Location = New-Object System.Drawing.Point(730, 10)
$exactMatchCheckBox.Size = New-Object System.Drawing.Size(100, 20)
[void]$advancedPanel.Controls.Add($exactMatchCheckBox)

$includeDisabledCheckBox = New-Object System.Windows.Forms.CheckBox
$includeDisabledCheckBox.Text = "Include Inactive"
$includeDisabledCheckBox.Location = New-Object System.Drawing.Point(840, 10)
$includeDisabledCheckBox.Size = New-Object System.Drawing.Size(120, 20)
[void]$advancedPanel.Controls.Add($includeDisabledCheckBox)

# Now that all controls are created, apply the initial advanced search visibility
if ($Settings.Search.AdvancedSearchDefault) {
    # Manually trigger the visibility update since CheckedChanged doesn't fire when setting programmatically
    Update-AdvancedSearchVisibility
}

# Create results panel - Row 1
$resultsPanel = New-Object System.Windows.Forms.Panel
$resultsPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
# Add to row 1
[void]$tableLayoutPanel.Controls.Add($resultsPanel, 0, 1)

# Create results ListView
$resultsListView = New-Object System.Windows.Forms.ListView
$resultsListView.Name = "MainResultsListView"
$resultsListView.View = [System.Windows.Forms.View]::Details
$resultsListView.FullRowSelect = $true
$resultsListView.GridLines = $true
$resultsListView.Dock = [System.Windows.Forms.DockStyle]::Fill
# Enable text selection and copying
$resultsListView.LabelEdit = $false
$resultsListView.HideSelection = $false
$resultsListView.MultiSelect = $false
[void]$resultsPanel.Controls.Add($resultsListView)

# Track last selected index (used only for optional diagnostics / future enhancements)
$script:lastResultsSelectionIndex = $null

# Add consistent columns to match search function
[void]$resultsListView.Columns.Add("Type", 100)
[void]$resultsListView.Columns.Add("Name", 200)
[void]$resultsListView.Columns.Add("Details", 200)
[void]$resultsListView.Columns.Add("Status", 100)
[void]$resultsListView.Columns.Add("Last Logon", 150)
[void]$resultsListView.Columns.Add("Pwd Last Set", 150)

# Enable click-to-sort on the main results list with ^ / v indicators
if (Get-Command Add-ListViewSorting -ErrorAction SilentlyContinue) {
    Add-ListViewSorting -ListView $resultsListView
}

# Create context menu for results ListView
$resultsContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$copyNameMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyNameMenuItem.Text = "Copy Name"
$copyNameMenuItem.Add_Click({
    try {
        $it = Get-ResultsListViewItemForCurrentSelection
        if (-not $it) { return }
        $name = $null
        try { $name = [string]$it.SubItems[1].Text } catch {}
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            [System.Windows.Forms.Clipboard]::SetText($name)
        }
    } catch {}
})
[void]$resultsContextMenu.Items.Add($copyNameMenuItem)

$copyDetailsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyDetailsMenuItem.Text = "Copy Details"
$copyDetailsMenuItem.Add_Click({
    try {
        $it = Get-ResultsListViewItemForCurrentSelection
        if (-not $it) { return }
        $details = $null
        try { $details = [string]$it.SubItems[2].Text } catch {}
        if (-not [string]::IsNullOrWhiteSpace($details)) {
            [System.Windows.Forms.Clipboard]::SetText($details)
        }
    } catch {}
})
[void]$resultsContextMenu.Items.Add($copyDetailsMenuItem)

$copyAllMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyAllMenuItem.Text = "Copy All Columns"
$copyAllMenuItem.Add_Click({
    try {
        $it = Get-ResultsListViewItemForCurrentSelection
        if (-not $it) { return }
        $allText = @()
        for ($i = 0; $i -lt $it.SubItems.Count; $i++) {
            try { $allText += [string]$it.SubItems[$i].Text } catch {}
        }
        if ($allText.Count -gt 0) {
            [System.Windows.Forms.Clipboard]::SetText($allText -join "`t")
        }
    } catch {}
})
[void]$resultsContextMenu.Items.Add($copyAllMenuItem)

$resultsListView.ContextMenuStrip = $resultsContextMenu

# Reduce flicker on large updates
Enable-ControlDoubleBuffering -Control $resultsListView

# Create details panel - Row 2
$detailsPanel = New-Object System.Windows.Forms.Panel
$detailsPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$detailsPanel.BackColor = $backgroundColor
# Add to row 2
[void]$tableLayoutPanel.Controls.Add($detailsPanel, 0, 2)

# Create log panel - Row 3
$logPanel = New-Object System.Windows.Forms.Panel
$logPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$logPanel.BackColor = $backgroundColor
$logPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
# Add to row 3
[void]$tableLayoutPanel.Controls.Add($logPanel, 0, 3)

# Create log controls container
$logControlsPanel = New-Object System.Windows.Forms.Panel
$logControlsPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$logControlsPanel.Height = 30
[void]$logPanel.Controls.Add($logControlsPanel)

$logTitleLabel = New-Object System.Windows.Forms.Label
$logTitleLabel.Text = "Application Logs"
$logTitleLabel.Location = New-Object System.Drawing.Point(5, 7)
$logTitleLabel.AutoSize = $true
$logTitleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
[void]$logControlsPanel.Controls.Add($logTitleLabel)

$refreshLogButton = New-Object System.Windows.Forms.Button
$refreshLogButton.Text = "Refresh"
$refreshLogButton.Location = New-Object System.Drawing.Point(120, 4)
$refreshLogButton.Size = New-Object System.Drawing.Size(75, 23)
$refreshLogButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$refreshLogButton.Add_Click({ Update-LogView })
[void]$logControlsPanel.Controls.Add($refreshLogButton)

$copyLogButton = New-Object System.Windows.Forms.Button
$copyLogButton.Text = "Copy to Clipboard"
$copyLogButton.Location = New-Object System.Drawing.Point(200, 4)
$copyLogButton.Size = New-Object System.Drawing.Size(120, 23)
$copyLogButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$copyLogButton.Add_Click({ 
    if ($logRichTextBox.Text) { [System.Windows.Forms.Clipboard]::SetText($logRichTextBox.Text) }
})
[void]$logControlsPanel.Controls.Add($copyLogButton)

# Create the rich text box for logs
$logRichTextBox = New-Object System.Windows.Forms.RichTextBox
$logRichTextBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$logRichTextBox.ReadOnly = $true
$logRichTextBox.BackColor = [System.Drawing.Color]::Black
$logRichTextBox.ForeColor = [System.Drawing.Color]::LightGray
$logRichTextBox.Font = New-Object System.Drawing.Font("Consolas", 9)
[void]$logPanel.Controls.Add($logRichTextBox)
$logPanel.Controls.SetChildIndex($logRichTextBox, 0) # Ensure it fills below the controls panel

# Create a TableLayoutPanel for the details section to manage layout
$detailsTableLayoutPanel = New-Object System.Windows.Forms.TableLayoutPanel
$detailsTableLayoutPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$detailsTableLayoutPanel.RowCount = 2
$detailsTableLayoutPanel.ColumnCount = 3
[void]$detailsTableLayoutPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 20))) # Labels
[void]$detailsTableLayoutPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) # ListViews
[void]$detailsTableLayoutPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33))) # Field ListView
[void]$detailsTableLayoutPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33))) # Groups ListView
[void]$detailsTableLayoutPanel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 34))) # Location ListView
$detailsTableLayoutPanel.Padding = New-Object System.Windows.Forms.Padding(5) # Add some padding
[void]$detailsPanel.Controls.Add($detailsTableLayoutPanel)

# Add labels for the sections (using the detailsTableLayoutPanel)
$fieldLabel = New-Object System.Windows.Forms.Label
$fieldLabel.Text = "Details"
$fieldLabel.AutoSize = $true
[void]$detailsTableLayoutPanel.Controls.Add($fieldLabel, 0, 0) # Col 0, Row 0

$groupsLabel = New-Object System.Windows.Forms.Label
$groupsLabel.Text = "Groups"
$groupsLabel.AutoSize = $true
[void]$detailsTableLayoutPanel.Controls.Add($groupsLabel, 1, 0) # Col 1, Row 0

$locationLabel = New-Object System.Windows.Forms.Label
$locationLabel.Text = "Live Sessions & PDQ Data"
$locationLabel.AutoSize = $true
[void]$detailsTableLayoutPanel.Controls.Add($locationLabel, 2, 0) # Col 2, Row 0

# Create field ListView (add to detailsTableLayoutPanel)
$fieldListView = New-Object System.Windows.Forms.ListView
$fieldListView.View = [System.Windows.Forms.View]::Details
$fieldListView.Dock = [System.Windows.Forms.DockStyle]::Fill
# Enable text selection and copying
$fieldListView.LabelEdit = $false
$fieldListView.HideSelection = $false
$fieldListView.MultiSelect = $true
[void]$fieldListView.Columns.Add("Field", 150)
[void]$fieldListView.Columns.Add("Value", 300) # Adjusted width
[void]$detailsTableLayoutPanel.Controls.Add($fieldListView, 0, 1) # Col 0, Row 1

# Reduce flicker
Enable-ControlDoubleBuffering -Control $fieldListView

# Create context menu for field ListView
$fieldContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$copyFieldNameMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyFieldNameMenuItem.Text = "Copy Field Name"
$copyFieldNameMenuItem.Add_Click({
    if ($fieldListView.SelectedItems.Count -gt 0) {
        $selectedItem = $fieldListView.SelectedItems[0]
        $fieldName = $selectedItem.Text
        [System.Windows.Forms.Clipboard]::SetText($fieldName)
    }
})
[void]$fieldContextMenu.Items.Add($copyFieldNameMenuItem)

$copyFieldValueMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyFieldValueMenuItem.Text = "Copy Field Value"
$copyFieldValueMenuItem.Add_Click({
    if ($fieldListView.SelectedItems.Count -gt 0) {
        $selectedItem = $fieldListView.SelectedItems[0]
        $fieldValue = $selectedItem.SubItems[1].Text
        [System.Windows.Forms.Clipboard]::SetText($fieldValue)
    }
})
[void]$fieldContextMenu.Items.Add($copyFieldValueMenuItem)

$copyFieldAllMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyFieldAllMenuItem.Text = "Copy Field (Name: Value)"
$copyFieldAllMenuItem.Add_Click({
    if ($fieldListView.SelectedItems.Count -gt 0) {
        $selectedItem = $fieldListView.SelectedItems[0]
        $fieldName = $selectedItem.Text
        $fieldValue = $selectedItem.SubItems[1].Text
        [System.Windows.Forms.Clipboard]::SetText("$fieldName`: $fieldValue")
    }
})
[void]$fieldContextMenu.Items.Add($copyFieldAllMenuItem)

$fieldListView.ContextMenuStrip = $fieldContextMenu

# Create groups ListView (add to detailsTableLayoutPanel)
$groupsListView = New-Object System.Windows.Forms.ListView
$groupsListView.View = [System.Windows.Forms.View]::Details
$groupsListView.Dock = [System.Windows.Forms.DockStyle]::Fill
# Enable text selection and copying
$groupsListView.LabelEdit = $false
$groupsListView.HideSelection = $false
$groupsListView.MultiSelect = $true
$groupsListView.Columns.Add("Group Name", 200) | Out-Null
$groupsListView.Columns.Add("Group Type", 150) | Out-Null
[void]$detailsTableLayoutPanel.Controls.Add($groupsListView, 1, 1) # Col 1, Row 1

# Reduce flicker
Enable-ControlDoubleBuffering -Control $groupsListView

# Create context menu for groups ListView
$groupsContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$copyGroupNameMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyGroupNameMenuItem.Text = "Copy Group Name"
$copyGroupNameMenuItem.Add_Click({
    if ($groupsListView.SelectedItems.Count -gt 0) {
        $selectedItem = $groupsListView.SelectedItems[0]
        $groupName = $selectedItem.Text
        [System.Windows.Forms.Clipboard]::SetText($groupName)
    }
})
[void]$groupsContextMenu.Items.Add($copyGroupNameMenuItem)

$copyGroupAllMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyGroupAllMenuItem.Text = "Copy All Groups"
$copyGroupAllMenuItem.Add_Click({
    $allGroups = @()
    foreach ($item in $groupsListView.Items) {
        $allGroups += $item.Text
    }
    [System.Windows.Forms.Clipboard]::SetText($allGroups -join "`n")
})
[void]$groupsContextMenu.Items.Add($copyGroupAllMenuItem)

$groupsListView.ContextMenuStrip = $groupsContextMenu

# Create location ListView for PDQ data
$locationListView = New-Object System.Windows.Forms.ListView
$locationListView.View = [System.Windows.Forms.View]::Details
$locationListView.Dock = [System.Windows.Forms.DockStyle]::Fill
# Enable text selection and copying
$locationListView.LabelEdit = $false
$locationListView.HideSelection = $false
$locationListView.MultiSelect = $true
[void]$locationListView.Columns.Add("Item", 150)
[void]$locationListView.Columns.Add("Details", 150)
[void]$detailsTableLayoutPanel.Controls.Add($locationListView, 2, 1) # Col 2, Row 1

# Reduce flicker
Enable-ControlDoubleBuffering -Control $locationListView

# Create context menu for location ListView
$locationContextMenu = New-Object System.Windows.Forms.ContextMenuStrip
$copyLocationItemMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyLocationItemMenuItem.Text = "Copy Item"
$copyLocationItemMenuItem.Add_Click({
    if ($locationListView.SelectedItems.Count -gt 0) {
        $selectedItem = $locationListView.SelectedItems[0]
        $itemName = $selectedItem.Text
        [System.Windows.Forms.Clipboard]::SetText($itemName)
    }
})
[void]$locationContextMenu.Items.Add($copyLocationItemMenuItem)

$copyLocationDetailsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$copyLocationDetailsMenuItem.Text = "Copy Details"
$copyLocationDetailsMenuItem.Add_Click({
    if ($locationListView.SelectedItems.Count -gt 0) {
        $selectedItem = $locationListView.SelectedItems[0]
        $details = $selectedItem.SubItems[1].Text
        [System.Windows.Forms.Clipboard]::SetText($details)
    }
})
[void]$locationContextMenu.Items.Add($copyLocationDetailsMenuItem)

$locationListView.ContextMenuStrip = $locationContextMenu

# Add double-click event to search for the selected item
$locationListView.Add_DoubleClick({
    if ($locationListView.SelectedItems.Count -gt 0) {
        $clickedItem = $locationListView.SelectedItems[0].Text
        
        # Determine search type based on current context
        $searchType = "Computers"  # Default to computers
        
        try {
            $sel = Get-CurrentSelection
            if ($sel -and $sel.Type -eq 'User') {
                # When viewing a user, location list contains computers
                $searchType = "Computers"
            } elseif ($sel -and $sel.Type -eq 'Computer') {
                # When viewing a computer, location list contains users
                $searchType = "Users"
            }
        } catch {}
        
        # Search for the item
        $searchTextBox.Text = $clickedItem
        $typeComboBox.SelectedItem = $searchType
        $searchButton.PerformClick()
        
        # Auto-select the first result
        if ($resultsListView.Items.Count -gt 0) {
            $resultsListView.Items[0].Selected = $true
            $resultsListView.Items[0].Focused = $true
        }
    }
})

# Create status strip - add to the main form after the table layout panel
$statusStrip = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = "Ready"
[void][void]$statusStrip.Items.Add($statusLabel)
[void][void]$mainForm.Controls.Add($statusStrip)

# Update the search button click event
$searchButton.Add_Click({
    try {
        $searchText = $searchTextBox.Text
        $searchType = $typeComboBox.SelectedItem
        $correlationId = [guid]::NewGuid().ToString()
        $opStart = Get-Date
        Write-LogEvent -Operation 'SearchBegin' -EventId 2001 -CorrelationId $correlationId -Context @{ term=$searchText; type=$searchType }
        
        # Handle special case when using just wildcard character
        if ($searchText -eq '*') {
            $statusLabel.Text = "Searching for all items..."
        } else {
            $statusLabel.Text = "Searching..."
        }
        
        # Set cursor to wait cursor
        $mainForm.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        
        # Clear previous results
        $script:CurrentSelection = $null
        try { Clear-SelectionHighlight } catch {}
        $script:lastResultsSelectionIndex = $null
        $resultsListView.Items.Clear()
        
        # Determine the object type based on selection
        $objectType = switch ($searchType) {
            "Users" { "User" }
            "Computers" { "Computer" }
            "Servers" { "Computer" }
            "Groups" { "Group" }
            "Printers" { "Printer" }
            default { "All" }
        }
        
        # Build search parameters
        $searchParams = @{
            SearchTerm = $searchText
            ObjectType = $objectType
        }
        
        # Add advanced search parameters if enabled
        if ($advancedSearchCheckBox.Checked) {
            # Add location filter if not "All Locations" or root labels
            $selectedLocation = $locationComboBox.SelectedItem
            if ($selectedLocation -and $selectedLocation -ne "All Locations") {
                # Map friendly root labels to base OUs
                switch ($selectedLocation) {
                    "All Users" {
                        if ($Settings.AD.UserBaseOU -and $Settings.AD.UserBaseOU.Count -gt 0) {
                            $searchParams.Location = $Settings.AD.UserBaseOU
                        }
                    }
                    "All Computers" {
                        if ($Settings.AD.ComputerBaseOU -and $Settings.AD.ComputerBaseOU.Count -gt 0) {
                            $searchParams.Location = $Settings.AD.ComputerBaseOU
                        }
                    }
                    "All Servers" {
                        if ($Settings.AD.ServerBaseOU -and $Settings.AD.ServerBaseOU.Count -gt 0) {
                            $searchParams.Location = $Settings.AD.ServerBaseOU
                        }
                    }
                    "All Groups" {
                        if ($Settings.AD.GroupBaseOU -and $Settings.AD.GroupBaseOU.Count -gt 0) {
                            $searchParams.Location = $Settings.AD.GroupBaseOU
                        }
                    }
                    default {
                        # Regular OU selection
                        $searchParams.Location = $selectedLocation
                    }
                }
            }
            
            # Add status filter if not "All"
            if ($statusComboBox.SelectedItem -ne "All") {
                $searchParams.Status = $statusComboBox.SelectedItem
            }
            
            # Add date range filter
            $searchParams.DateRange = $dateRangeComboBox.SelectedItem
            
            # Handle custom date range
            if ($dateRangeComboBox.SelectedItem -eq "Custom range..." -and $script:customDateStart -and $script:customDateEnd) {
                $searchParams.CustomDateStart = $script:customDateStart
                $searchParams.CustomDateEnd = $script:customDateEnd
            }
            
            # Add exact match and include inactive flags
            $searchParams.ExactMatch = $exactMatchCheckBox.Checked
            $searchParams.IncludeInactive = $includeDisabledCheckBox.Checked
        }
        
        # Ensure advanced search function is available in this runspace
        try {
            if (-not (Get-Command Search-ADObjectsAdvanced -ErrorAction SilentlyContinue)) {
                $adSearchPath = Join-Path -Path $ModulesPath -ChildPath 'ADSearch.psm1'
                if (Test-Path -Path $adSearchPath) {
                    try {
                        Import-Module $adSearchPath -Force -DisableNameChecking -ErrorAction Stop | Out-Null
                    } catch {
                        # As a fallback, dot-source the file so its functions are available
                        . $adSearchPath
                    }
                }
            }
        } catch {
            Write-Log -Message "Error ensuring Search-ADObjectsAdvanced is available: $_" -Level "Error"
        }
        
        # Perform the search
        Write-Log -Message "Searching AD with parameters: $($searchParams | ConvertTo-Json -Compress)" -Level "Info"
        $results = Search-ADObjectsAdvanced @searchParams
        $resultCount = @($results).Count
        
        # Add results to the list view
        if ($resultCount -eq 0) {
            $statusLabel.Text = "No results found"
        } else {
            # Batch UI updates for performance
            $resultsListView.BeginUpdate()
            $addedCount = 0
            foreach ($item in $results) {
                try {
                    # Create the list view item with null checks for each property
                    $itemType = if ($null -eq $item.Type) { "Unknown" } else { $item.Type }
                    $listItem = New-Object System.Windows.Forms.ListViewItem($itemType)
                    
                    $itemName = if ($null -eq $item.Name) { "" } else { $item.Name }
                    [void]$listItem.SubItems.Add($itemName)
                    
                    # Add description/fullname with null check
                    if ($item.Type -eq "User") {
                        $fullName = if ($null -eq $item.FullName) { "" } else { $item.FullName }
                        [void]$listItem.SubItems.Add($fullName)
                    } elseif ($item.Type -eq "Printer") {
                        # For printers, show ShareName in Details column, or Port if ShareName is empty
                        $printerDetails = ""
                        if ($item.ShareName) {
                            $printerDetails = "Share: $($item.ShareName)"
                        } elseif ($item.Port) {
                            $printerDetails = "Port: $($item.Port)"
                        }
                        [void]$listItem.SubItems.Add($printerDetails)
                    } else {
                        $description = if ($null -eq $item.Description) { "" } else { $item.Description }
                        [void]$listItem.SubItems.Add($description)
                    }
                    
                    # Add enabled status with null check
                    if ($item.Type -eq "Printer") {
                        # Printers don't have enabled status, show port info instead or leave empty
                        $portInfo = if ($item.Port) { $item.Port } else { "" }
                        [void]$listItem.SubItems.Add($portInfo)
                    } elseif ($item.Type -eq "Group") {
                        # Groups don't have enabled/disabled status
                        [void]$listItem.SubItems.Add("")
                    } elseif ($null -eq $item.Enabled) {
                        [void]$listItem.SubItems.Add("Unknown")
                    } else {
                        [void]$listItem.SubItems.Add($(if ($item.Enabled) { "Enabled" } else { "Disabled" }))
                    }
                    
                    # Add last logon and password last set with null checks
                    if ($item.Type -eq "Printer" -or $item.Type -eq "Group") {
                        # Printers and groups don't have last logon or password last set
                        [void]$listItem.SubItems.Add("")  # Last Logon
                        [void]$listItem.SubItems.Add("")  # Password Last Set
                    } else {
                        $lastLogon = if ($null -eq $item.LastLogon) { "Never" } else { $item.LastLogon }
                        [void]$listItem.SubItems.Add($lastLogon)
                        
                        $pwdLastSet = if ($null -eq $item.PasswordLastSet) { "Never" } else { $item.PasswordLastSet }
                        [void]$listItem.SubItems.Add($pwdLastSet)
                    }
                    
                    # Store the full item details in the Tag property for later use
                    $listItem.Tag = $item
                    
                    # Color coding based on type and status
                    if ($item.Type -eq "Computer") {
                        # Check if computer is online
                        $isOnline = $false
                        if ($null -ne $item.IsOnline) {
                            $isOnline = $item.IsOnline
                        } else {
                            try {
                                $isOnline = Test-ComputerOnline -ComputerName $itemName
                            } catch {
                                Write-Log -Message "Error checking online status for ${itemName}: $_" -Level "Warning"
                            }
                        }
                        
                        if ($isOnline) {
                            $listItem.BackColor = [System.Drawing.Color]::FromArgb(235, 255, 235)  # Light green for online
                        } else {
                            $listItem.BackColor = [System.Drawing.Color]::FromArgb(255, 235, 235)  # Light red for offline
                        }
                    } elseif ($item.Type -eq "Group") {
                        $listItem.BackColor = [System.Drawing.Color]::FromArgb(235, 235, 255)  # Light blue for groups
                    } elseif ($item.Type -eq "Printer") {
                        # Light yellow/cream color for printers
                        $listItem.BackColor = [System.Drawing.Color]::FromArgb(255, 255, 235)  # Light yellow for printers
                    } elseif ($null -ne $item.Enabled -and $item.Enabled -eq $false) {
                        $listItem.BackColor = [System.Drawing.Color]::FromArgb(255, 235, 235)  # Light red for disabled
                    } elseif ($item.Type -eq "User" -and $null -ne $item.LockedOut -and $item.LockedOut -eq $true) {
                        $listItem.BackColor = [System.Drawing.Color]::MistyRose  # Misty rose for locked accounts
                    }
                    
                    [void]$resultsListView.Items.Add($listItem)
                    $addedCount++
                    if (($addedCount % 250) -eq 0) { [System.Windows.Forms.Application]::DoEvents() }
                }
                catch {
                    # Log any errors processing individual items but continue with the rest
                    Write-Log -Message "Error processing search result item: $_" -Level "Warning"
                }
            }
            $resultsListView.EndUpdate()

            # If there is exactly one result, cache it so actions/shortcuts work immediately
            Write-Log -Message "Single result check: resultCount=$resultCount, ListView.Items.Count=$($resultsListView.Items.Count), objectType=$objectType" -Level "Info"
            if ($resultCount -eq 1 -and $resultsListView.Items.Count -eq 1) {
                try {
                    # No need to "real-select" the row (which can change row coloring). Cached selection drives actions.
                    try { $resultsListView.EnsureVisible(0) } catch {}
                    Set-CurrentSelectionFromListViewItem -Item $resultsListView.Items[0]
                    try { Update-PDQMenuStateFromCurrentSelection } catch {}
                    try { Update-ResultsDetailsFromItem -SelectedItem $resultsListView.Items[0] } catch {}
                    
                    # Auto-query PDQ CLI for single computer result (if enabled)
                    try {
                        Write-Log -Message "Starting PDQ auto-query check for single result" -Level "Info"
                        $singleType = $null
                        try { $singleType = [string]$results[0].Type } catch { $singleType = $null }
                        $singleName = $null
                        try { $singleName = [string]$results[0].Name } catch { $singleName = $null }
                        if ($singleType -eq "Computer" -and 
                            (Get-Command Get-PDQInventoryCLISettings -ErrorAction SilentlyContinue) -and 
                            (Get-Command Invoke-PDQGetComputer -ErrorAction SilentlyContinue)) {
                            Write-Log -Message "PDQ commands available, getting settings" -Level "Info"
                            $pdqCLISettings = Get-PDQInventoryCLISettings
                            Write-Log -Message "PDQ CLI Settings - Enabled: $($pdqCLISettings.Enabled), AutoQueryOnSelection: $($pdqCLISettings.AutoQueryOnSelection)" -Level "Info"
                            if ($pdqCLISettings.Enabled -and $pdqCLISettings.AutoQueryOnSelection) {
                                Write-Log -Message "Results array count: $($results.Count), First result type: $($results[0].GetType().Name)" -Level "Info"
                                $computerName = $singleName
                                Write-Log -Message "Extracted computer name: '$computerName'" -Level "Info"
                                if (-not [string]::IsNullOrWhiteSpace($computerName)) {
                                    # Run PDQ query in background so UI doesn't freeze
                                    Write-Log -Message "Starting async PDQ GetComputer for: $computerName" -Level "Info"
                                    $started = Start-PDQInventoryCLIPrefetchAsync -ComputerName $computerName -ExecutablePath $pdqCLISettings.ExecutablePath -Reason "SingleResult"
                                    if ($started) {
                                        Write-Log -Message "Auto-queried PDQ CLI data for single result (async started): $computerName" -Level "Info"
                                    } else {
                                        Write-Log -Message "Failed to start async PDQ auto-query for single result: $computerName" -Level "Warning"
                                    }
                                } else {
                                    Write-Log -Message "Computer name is empty for single result auto-query" -Level "Warning"
                                }
                            } else {
                                Write-Log -Message "PDQ CLI auto-query disabled or not enabled for single results" -Level "Info"
                            }
                        } else {
                            Write-Log -Message "Skipping PDQ single-result auto-query (SingleType=$singleType, SearchType=$objectType)" -Level "Info"
                        }
                    } catch {
                        Write-Log -Message "Error in single result auto-query: $_ | StackTrace: $($_.ScriptStackTrace)" -Level "Error"
                    }
                } catch {
                    Write-Log -Message "Failed to cache single search result: $_" -Level "Warning"
                }
            }
            
            # Update status with count
            $statusLabel.Text = "Found $resultCount results"
            
            # Add search to history
            Add-SearchToHistory -SearchTerm $searchText -SearchType $searchType
            
            # Auto-query PDQ CLI data for computers (if enabled; limited to first N results)
            try {
                if ((Get-Command Get-PDQInventoryCLISettings -ErrorAction SilentlyContinue) -and 
                    (Get-Command Invoke-PDQGetComputer -ErrorAction SilentlyContinue)) {
                    $pdqCLISettings = Get-PDQInventoryCLISettings
                    # Prefetch PDQ CLI data in background (non-blocking; keeps UI responsive)
                    $computerNames = @($results | Where-Object { $_.Type -eq "Computer" } | Select-Object -ExpandProperty Name)
                    if ($pdqCLISettings.Enabled -and $pdqCLISettings.AutoQueryOnSearch -and $computerNames.Count -gt 0) {
                        $max = 0
                        try { $max = [int]$pdqCLISettings.AutoQueryMaxResults } catch { $max = 0 }
                        if ($max -lt 1) { $max = 1 }

                        $targets = @(
                            $computerNames |
                                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                                Select-Object -Unique -First $max
                        )

                        foreach ($compName in $targets) {
                            $null = Start-PDQInventoryCLIPrefetchAsync -ComputerName $compName -ExecutablePath $pdqCLISettings.ExecutablePath -Reason "Search"
                        }

                        if ($computerNames.Count -gt $targets.Count) {
                            Write-Log -Message "Started PDQ CLI async prefetch for first $($targets.Count) of $($computerNames.Count) computers (search; max=$max)" -Level "Info"
                        } else {
                            Write-Log -Message "Started PDQ CLI async prefetch for $($targets.Count) computers (search)" -Level "Info"
                        }
                    }
                }
            } catch {
                Write-Log -Message "Error auto-querying PDQ CLI data on search: $_" -Level "Warning"
            }
        }
        $duration = [int]((Get-Date) - $opStart).TotalMilliseconds
        Write-LogEvent -Operation 'SearchEnd' -EventId 2002 -CorrelationId $correlationId -Context @{ count = $resultCount } -DurationMs $duration
    } catch {
        Write-Log -Message "Error during search: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show("Error during search: $_", "Search Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        $statusLabel.Text = "Search failed"
    } finally {
        # Reset cursor
        $mainForm.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

function Update-ResultsDetailsFromItem {
    param(
        [System.Windows.Forms.ListViewItem]$SelectedItem
    )

    if (-not $SelectedItem) { return }

    $selectedItem = $SelectedItem
    $itemDetails = $selectedItem.Tag
    $itemType = $selectedItem.SubItems[0].Text # Get Type ("User", "Computer", etc.)
    $itemName = $selectedItem.SubItems[1].Text # Get Name (SAMAccountName or ComputerName)

    # Clear existing details
    $fieldListView.Items.Clear()
    $groupsListView.Items.Clear()
    $locationListView.Items.Clear()

    # Add field details in a structured way
    if ($null -ne $itemDetails -and ($itemDetails -is [hashtable] -or $itemDetails -is [pscustomobject])) {
        # Add specific fields based on item type
        if ($itemType -eq 'User') {
            # Add User fields in order
            $fieldListView.Items.Clear()
            
            # Define the fields to display for users
            $userFields = @(
                @{ Label = "Username"; PropertyName = "Name" },
                @{ Label = "Full Name"; PropertyName = "FullName" },
                @{ Label = "Title"; PropertyName = "Title" },
                @{ Label = "Department"; PropertyName = "Department" },
                @{ Label = "Phone"; PropertyName = "Phone" },
                @{ Label = "OU Path"; PropertyName = "OUPath" },
                @{ Label = "Email"; PropertyName = "Email" },
                @{ Label = "Account Status"; PropertyName = "Enabled"; },
                @{ Label = "Locked Status"; PropertyName = "LockedOut" }
            )
            
            # Add each field with appropriate label
            foreach ($field in $userFields) {
                $lvItem = New-Object System.Windows.Forms.ListViewItem($field.Label)
                $propertyValue = $null
                
                if ($itemDetails.PSObject.Properties[$field.PropertyName]) {
                    $propertyValue = $itemDetails.$($field.PropertyName)
                }

                if ($field.PropertyName -eq 'OUPath' -and $propertyValue) {
                    $propertyValue = Format-ADappOUPath -Path $propertyValue
                }

                $valueText = if ($null -eq $propertyValue -or [string]::IsNullOrEmpty($propertyValue)) { "N/A" } else { $propertyValue.ToString() }
                $null = $lvItem.SubItems.Add($valueText)
                $fieldListView.Items.Add($lvItem) | Out-Null
            }
        }
        elseif ($itemType -eq 'Computer') {
            # Add Computer fields in order
            $fieldListView.Items.Clear()
            
            # Define the fields to display for computers
            $computerFields = @(
                @{ Label = "Computer Name"; PropertyName = "Name" },
                @{ Label = "Operating System"; PropertyName = "OperatingSystem" },
                @{ Label = "OS Version"; PropertyName = "OSVersion" },
                @{ Label = "IP Address"; PropertyName = "IPv4Address" },
                @{ Label = "Status"; PropertyName = "Enabled" },
                @{ Label = "Last Logon"; PropertyName = "LastLogon" },
                @{ Label = "Pwd Last Set"; PropertyName = "PasswordLastSet" },
                @{ Label = "OU Path"; PropertyName = "OUPath" }
            )
            
            foreach ($field in $computerFields) {
                $lvItem = New-Object System.Windows.Forms.ListViewItem($field.Label)
                $propertyValue = $null
                
                if ($itemDetails.PSObject.Properties[$field.PropertyName]) {
                    $propertyValue = $itemDetails.$($field.PropertyName)
                }

                if ($field.PropertyName -eq 'OUPath' -and $propertyValue) {
                    $propertyValue = Format-ADappOUPath -Path $propertyValue
                }

                $valueText = if ($null -eq $propertyValue -or [string]::IsNullOrEmpty($propertyValue)) { "N/A" } else { $propertyValue.ToString() }
                $null = $lvItem.SubItems.Add($valueText)
                $fieldListView.Items.Add($lvItem) | Out-Null
            }

            # Append PDQ Inventory info when available
            try {
                if (Get-Command Get-PDQInfoForComputer -ErrorAction SilentlyContinue) {
                    $pdqRow = Get-PDQInfoForComputer -ComputerName $itemName
                    if ($pdqRow) {
                        $add = {
                            param($label, $candidates)
                            $val = $null
                            foreach ($c in $candidates) {
                                if ($pdqRow.PSObject.Properties.Name -contains $c) { $val = $pdqRow.$c; if ($val) { break } }
                            }
                            if ($val) {
                                $i = New-Object System.Windows.Forms.ListViewItem("PDQ: $label")
                                $i.SubItems.Add([string]$val) | Out-Null
                                $fieldListView.Items.Add($i) | Out-Null
                            }
                        }
                        & $add "Last Inventory" @('Last Scan','Last Inventory','Last Successful Inventory Scan','Scan Date','Last Scan Time')
                        & $add "Serial Number" @('Serial Number','Bios Serial Number','SerialNumber')
                        & $add "Manufacturer" @('Manufacturer','Make','Vendor')
                        & $add "Model" @('Model','Product')
                        & $add "Last Logged On User" @('Last Logged On User','Last LoggedOn User','User Logged On','Current Logged On User','Logged On User')
                        & $add "IP Address(es)" @('IP Addresses','IP Address','IPv4 Address','IPv4','IPv6 Address')
                        & $add "Uptime" @('Uptime','System Uptime')
                        & $add "Asset Tag" @('Asset Tag','AssetTag')
                        & $add "BIOS Version" @('BIOS Version','SMBIOS Version')
                        & $add "OS Build" @('OS Build','Build','OS Version')
                        & $add "Last Reboot" @('Last Reboot','Last Boot Time','Last Boot')
                        & $add "Free Space C:" @('Free Space (C:)','C: Free Space','C Drive Free Space','Free Space C')
                    }
                }
            } catch {}
        }
        elseif ($itemType -eq 'Group') {
            # Add Group fields in order
            $fieldListView.Items.Clear()
            
            # Define the fields to display for groups
            $groupFields = @(
                @{ Label = "Group Name"; PropertyName = "Name" },
                @{ Label = "Description"; PropertyName = "Description" },
                @{ Label = "Email"; PropertyName = "Email" },
                @{ Label = "Group Scope"; PropertyName = "GroupScope" },
                @{ Label = "Group Type"; PropertyName = "GroupType" },
                @{ Label = "OU Path"; PropertyName = "OUPath" }
            )
            
            foreach ($field in $groupFields) {
                $lvItem = New-Object System.Windows.Forms.ListViewItem($field.Label)
                $propertyValue = $null
                
                if ($itemDetails.PSObject.Properties[$field.PropertyName]) {
                    $propertyValue = $itemDetails.$($field.PropertyName)
                }

                if ($field.PropertyName -eq 'OUPath' -and $propertyValue) {
                    $propertyValue = Format-ADappOUPath -Path $propertyValue
                }

                $valueText = if ($null -eq $propertyValue -or [string]::IsNullOrEmpty($propertyValue)) { "N/A" } else { $propertyValue.ToString() }
                $null = $lvItem.SubItems.Add($valueText)
                $fieldListView.Items.Add($lvItem) | Out-Null
            }

            # Get and display group members
            try {
                $groupIdentity = $null
                if ($itemDetails -and $itemDetails.PSObject.Properties['DistinguishedName'] -and $itemDetails.DistinguishedName) {
                    $groupIdentity = $itemDetails.DistinguishedName
                } elseif ($itemDetails -and $itemDetails.PSObject.Properties['SamAccountName'] -and $itemDetails.SamAccountName) {
                    $groupIdentity = $itemDetails.SamAccountName
                } else {
                    $groupIdentity = $itemName
                }
                $groupMembers = Get-ADGroupMember -Identity $groupIdentity -Recursive | Get-ADObject -Properties Name, ObjectClass, DistinguishedName
                $groupsListView.Items.Clear()
                
                if ($groupMembers) {
                    foreach ($member in $groupMembers) {
                        $lvItem = New-Object System.Windows.Forms.ListViewItem($member.Name)
                        [void]$lvItem.SubItems.Add($member.ObjectClass)
                        [void]$lvItem.SubItems.Add($member.DistinguishedName)
                        $groupsListView.Items.Add($lvItem) | Out-Null
                    }
                } else {
                    $lvItem = New-Object System.Windows.Forms.ListViewItem("No members found")
                    $groupsListView.Items.Add($lvItem) | Out-Null
                }
            } catch {
                $lvItem = New-Object System.Windows.Forms.ListViewItem("Error retrieving group members")
                [void]$lvItem.SubItems.Add($_.Exception.Message)
                $groupsListView.Items.Add($lvItem) | Out-Null
            }
        }
        else {
            # For other types or fallback, show all properties
            Write-Log -Message "Showing generic properties for $itemType $itemName" -Level "Verbose"
            
            foreach ($property in $itemDetails.PSObject.Properties) {
                # Skip complex objects and arrays
                if ($property.Name -eq 'Groups') { continue }
                
                $lvItem = New-Object System.Windows.Forms.ListViewItem($property.Name)
                $valueText = if ($null -eq $property.Value) { "N/A" } else { $property.Value.ToString() }
                $null = $lvItem.SubItems.Add($valueText)
                $fieldListView.Items.Add($lvItem) | Out-Null
            }
        }
    } else {
         Write-Log -Message "Item Tag is not a valid object type or is null" -Level "Warning"
         $lvItem = New-Object System.Windows.Forms.ListViewItem("Error")
         $null = $lvItem.SubItems.Add("Could not load details.")
         $fieldListView.Items.Add($lvItem) | Out-Null
    }

    # Add group memberships if available
    if ($itemType -ne 'Group' -and $itemDetails -and $itemDetails.PSObject.Properties['Groups']) {
        $groupsListView.Items.Clear()
        $groups = $itemDetails.Groups
        
        if ($groups -and $groups.Count -gt 0) {
            foreach ($group in $groups) {
                if (-not [string]::IsNullOrWhiteSpace($group)) {
                    $lvItem = New-Object System.Windows.Forms.ListViewItem($group)
                    $groupsListView.Items.Add($lvItem) | Out-Null
                }
            }
        } else {
            $lvItem = New-Object System.Windows.Forms.ListViewItem("No groups found")
            $groupsListView.Items.Add($lvItem) | Out-Null
        }
    }

    # Populate location info using combined PDQ and QUser data
    try {
        if ($itemType -eq 'User') {
            # Show computers where this user is found via PDQ and QUser
            try {
                if (Get-Command Get-CombinedUserLocationData -ErrorAction SilentlyContinue) {
                    # Best-effort PDQ cache refresh to ensure PDQ data is available
                    try { if (Get-Command Update-PDQCache -ErrorAction SilentlyContinue) { if (-not $global:PDQInventoryCache) { Update-PDQCache | Out-Null } } } catch {}

                    try {
                        # Populate fast data first (PDQ + Historical). Live sessions (QUser) are streamed in asynchronously.
                        try { Stop-QUserAutoQueryJobs } catch {}
                        $combinedData = @(Get-CombinedUserLocationData -Username $itemName -IncludeQUser:$false -IncludePDQ -IncludeHistorical)
                        $resultCount = $combinedData.Count
                        Write-Log -Message "ADapp: Get-CombinedUserLocationData returned $resultCount results for user $itemName" -Level "Info"
                    } catch {
                        Write-Log -Message "ADapp: ERROR calling Get-CombinedUserLocationData for user $itemName`: $_" -Level "Error"
                        $combinedData = $null
                    }
                    if ($combinedData -and $combinedData.Count -gt 0) {
                        foreach ($location in $combinedData) {
                            Write-Log -Message "ADapp: Adding location - Computer: $($location.Computer), Source: $($location.Source), Status: $($location.Status)" -Level "Info"
                            $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$location.Computer)
                            $details = $location.Source
                            if ($location.Status -and $location.Status -ne "Offline/Cached") {
                                $details += " ($($location.Status))"
                            }
                            if ($location.SessionDetails) {
                                $details += " - $($location.SessionDetails)"
                            }
                            [void]$lvItem.SubItems.Add($details)
                            
                            # Color code different data sources
                            if ($location.Source -like "*Live Session*") {
                                $lvItem.BackColor = [System.Drawing.Color]::LightGreen
                            } elseif ($location.Source -like "*Recent Sessions*") {
                                $lvItem.BackColor = [System.Drawing.Color]::LightBlue
                            }
                            
                            $locationListView.Items.Add($lvItem) | Out-Null
                        }
                    } else {
                        # Fallback: manually populate from PDQ and QUser when combined call returns nothing
                        try {
                            if (Get-Command Get-PDQComputersForUser -ErrorAction SilentlyContinue) {
                                $pdqComputers = Get-PDQComputersForUser -Username $itemName
                                if ($pdqComputers -and $pdqComputers.Count -gt 0) {
                                    foreach ($pc in $pdqComputers) {
                                        if (-not [string]::IsNullOrWhiteSpace($pc)) {
                                            $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$pc)
                                            [void]$lvItem.SubItems.Add("From PDQ Inventory")
                                            $locationListView.Items.Add($lvItem) | Out-Null
                                        }
                                    }
                                }
                            }
                        } catch {}
                    }

                    # Ensure PDQ entries are present for any remaining computers not shown
                    try {
                        if (Get-Command Get-PDQComputersForUser -ErrorAction SilentlyContinue) {
                            # Build a fast lookup of existing items
                            $existing = @{}
                            foreach ($it in $locationListView.Items) { $existing[$it.Text.ToUpperInvariant()] = $true }
                            $pdqComputersAll = Get-PDQComputersForUser -Username $itemName
                            foreach ($pc in $pdqComputersAll) {
                                if (-not [string]::IsNullOrWhiteSpace($pc)) {
                                    $key = $pc.ToUpperInvariant()
                                    if (-not $existing.ContainsKey($key)) {
                                        $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$pc)
                                        [void]$lvItem.SubItems.Add("From PDQ Inventory")
                                        $locationListView.Items.Add($lvItem) | Out-Null
                                    }
                                }
                            }
                        }
                    } catch {}

                    # Kick off asynchronous QUser live-session lookups so offline machines don't block the UI.
                    try {
                        try {
                            $lc = 0
                            try { if ($locationListView) { $lc = [int]$locationListView.Items.Count } } catch { $lc = 0 }
                            Write-Log -Message "Async QUser kickoff reached for '$itemName' (location items=$lc)" -Level "Info"
                        } catch {}

                        $maxProbe = 10
                        try {
                            if ($global:Settings -and $global:Settings.QUser -and $global:Settings.QUser.MaxComputersPerQuery) {
                                $maxProbe = [Math]::Max(1, [int]$global:Settings.QUser.MaxComputersPerQuery)
                            }
                        } catch { $maxProbe = 10 }

                        # Probe the computers already shown in the Location list first (guarantees we check the "Historical" ones).
                        $candidates = New-Object 'System.Collections.Generic.List[string]'
                        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
                        foreach ($it in $locationListView.Items) {
                            try {
                                if (-not $it) { continue }
                                $c = [string]$it.Text
                                if ([string]::IsNullOrWhiteSpace($c) -or $c -like "No computers*") { continue }
                                $k = $c.Trim().ToUpperInvariant()
                                if ($seen.Add($k)) { [void]$candidates.Add($c.Trim()) }
                            } catch {}
                        }

                        $targets = @($candidates | Select-Object -First $maxProbe)
                        try { Write-Log -Message "Async QUser kickoff targets computed for '$itemName': targets=$($targets.Count), maxProbe=$maxProbe" -Level "Info" } catch {}
                        if ($targets.Count -gt 0) {
                            try {
                                $preview = @($targets | Select-Object -First 5) -join ", "
                                Write-Log -Message "Starting live-session QUser scan for '$itemName' on $($targets.Count) computers (maxProbe=$maxProbe): $preview" -Level "Info"
                            } catch {}
                            Start-QUserAutoQueryForUser -Username $itemName -ComputerNames $targets
                        }
                    } catch {
                        try { Write-Log -Message "ADapp: Failed to start async QUser lookups for user $itemName`: $_" -Level "Warning" } catch {}
                    }
                } else {
                    # Fallback to PDQ only if combined function not available
                    if (Get-Command Get-PDQComputersForUser -ErrorAction SilentlyContinue) {
                        $pdqComputers = Get-PDQComputersForUser -Username $itemName
                        if ($pdqComputers -and $pdqComputers.Count -gt 0) {
                            foreach ($pc in $pdqComputers) {
                                if (-not [string]::IsNullOrWhiteSpace($pc)) {
                                    $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$pc)
                                    [void]$lvItem.SubItems.Add("From PDQ Inventory")
                                    $locationListView.Items.Add($lvItem) | Out-Null
                                }
                            }
                        }
                    }
                    
                    # Also try QUser data separately if available
                    try {
                        if (Get-Command Get-QUserComputersForUser -ErrorAction SilentlyContinue) {
                            $qUserComputers = Get-QUserComputersForUser -Username $itemName
                            foreach ($computer in $qUserComputers) {
                                if (-not [string]::IsNullOrWhiteSpace($computer)) {
                                    $sessions = Get-QUserSessionsForComputer -ComputerName $computer
                                    $userSessions = $sessions | Where-Object { $_.Username.ToUpperInvariant() -eq $itemName.ToUpperInvariant() }
                                    
                                    foreach ($session in $userSessions) {
                                        $lvItem = New-Object System.Windows.Forms.ListViewItem($computer)
                                        $details = "Live Session (QUser) ($($session.State)) - $($session.SessionName) (ID: $($session.SessionId))"
                                        [void]$lvItem.SubItems.Add($details)
                                        $lvItem.BackColor = [System.Drawing.Color]::LightGreen
                                        $locationListView.Items.Add($lvItem) | Out-Null
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Log -Message "Error getting QUser fallback data for user ${itemName}: $_" -Level "Warning"
                    }
                }
            } catch {
                Write-Log -Message "Error getting combined location data for user ${itemName}: $_" -Level "Warning"
            }
            
            if ($locationListView.Items.Count -eq 0) {
                $lvItem = New-Object System.Windows.Forms.ListViewItem("No computers found")
                [void]$lvItem.SubItems.Add("No data available")
                $locationListView.Items.Add($lvItem) | Out-Null
            }
        }
        elseif ($itemType -eq 'Computer') {
            # Show users on this computer via PDQ and QUser
            try {
                if (Get-Command Get-CombinedComputerUserData -ErrorAction SilentlyContinue) {
                    # Best-effort PDQ cache refresh to ensure PDQ data is available
                    try { if (Get-Command Update-PDQCache -ErrorAction SilentlyContinue) { if (-not $global:PDQInventoryCache) { Update-PDQCache | Out-Null } } } catch {}

                    # Check if computer is online (from cached status or test)
                    $isComputerOnline = $false
                    if ($itemDetails -and $null -ne $itemDetails.IsOnline) {
                        $isComputerOnline = $itemDetails.IsOnline
                        Write-Log -Message "ADapp: Computer $itemName online status from cache: $isComputerOnline" -Level "Info"
                    } else {
                        try {
                            if (Get-Command Test-ComputerOnline -ErrorAction SilentlyContinue) {
                                $isComputerOnline = Test-ComputerOnline -ComputerName $itemName
                                Write-Log -Message "ADapp: Computer $itemName online status from test: $isComputerOnline" -Level "Info"
                            }
                        } catch {
                            Write-Log -Message "ADapp: Error testing if computer $itemName is online: $_" -Level "Warning"
                        }
                    }

                    try {
                        # Only query QUser if computer is online
                        $includeQUser = $isComputerOnline
                        $combinedData = Get-CombinedComputerUserData -ComputerName $itemName -IncludeQUser:$includeQUser -IncludePDQ -IncludeHistorical
                        $resultCount = if ($combinedData) { $combinedData.Count } else { 0 }
                        Write-Log -Message "ADapp: Get-CombinedComputerUserData returned $resultCount results for computer $itemName (QUser=$includeQUser)" -Level "Info"
                    } catch {
                        Write-Log -Message "ADapp: ERROR calling Get-CombinedComputerUserData for computer $itemName`: $_" -Level "Error"
                        $combinedData = $null
                    }
                    $hasLiveSessionForUser = {
                        param([string]$username)
                        foreach ($it in $locationListView.Items) {
                            if (-not $it) { continue }
                            if ($it.Text -eq $username -and $it.SubItems.Count -ge 2 -and $it.SubItems[1].Text -like "*Live Session (QUser)*") {
                                return $true
                            }
                        }
                        return $false
                    }
                    $removeNonLiveForUser = {
                        param([string]$username)
                        for ($x = $locationListView.Items.Count - 1; $x -ge 0; $x--) {
                            $it = $locationListView.Items[$x]
                            if (-not $it) { continue }
                            if ($it.Text -eq $username) {
                                $d = ""
                                try { if ($it.SubItems.Count -ge 2) { $d = [string]$it.SubItems[1].Text } } catch { $d = "" }
                                if ($d -notlike "*Live Session (QUser)*") {
                                    $locationListView.Items.RemoveAt($x)
                                }
                            }
                        }
                    }

                    if ($combinedData -and $combinedData.Count -gt 0) {
                        foreach ($userInfo in $combinedData) {
                            Write-Log -Message "ADapp: Adding user - Username: $($userInfo.Username), Source: $($userInfo.Source), Status: $($userInfo.Status)" -Level "Info"
                            $isLive = ($userInfo.Source -like "*Live Session*")
                            if (-not $isLive -and (& $hasLiveSessionForUser $userInfo.Username)) {
                                continue
                            }
                            if ($isLive) {
                                & $removeNonLiveForUser $userInfo.Username
                            }
                            $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$userInfo.Username)
                            $details = $userInfo.Source
                            if ($userInfo.Status -and $userInfo.Status -ne "Offline/Cached") {
                                $details += " ($($userInfo.Status))"
                            }
                            if ($userInfo.SessionDetails) {
                                $details += " - $($userInfo.SessionDetails)"
                            }
                            if ($userInfo.IdleTime -and $userInfo.IdleTime -ne "none") {
                                $details += " [Idle: $($userInfo.IdleTime)]"
                            }
                            [void]$lvItem.SubItems.Add($details)
                            
                            # Color code different data sources
                            if ($userInfo.Source -like "*Live Session*") {
                                $lvItem.BackColor = [System.Drawing.Color]::LightGreen
                            } elseif ($userInfo.Source -like "*Recent Sessions*") {
                                $lvItem.BackColor = [System.Drawing.Color]::LightBlue
                            }
                            
                            $locationListView.Items.Add($lvItem) | Out-Null
                        }
                    } else {
                        # Fallback: manually populate from PDQ and (optionally) QUser when combined call returns nothing
                        try {
                            if (Get-Command Get-PDQUsersForComputer -ErrorAction SilentlyContinue) {
                                $pdqUsers = Get-PDQUsersForComputer -ComputerName $itemName
                                if ($pdqUsers -and $pdqUsers.Count -gt 0) {
                                    foreach ($user in $pdqUsers) {
                                        if (-not [string]::IsNullOrWhiteSpace($user)) {
                                            if (& $hasLiveSessionForUser $user) { continue }
                                            $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$user)
                                            [void]$lvItem.SubItems.Add("From PDQ Inventory")
                                            $locationListView.Items.Add($lvItem) | Out-Null
                                        }
                                    }
                                }
                            }
                        } catch {}
                        try {
                            $canQueryQUser = [bool]$isComputerOnline
                            try {
                                if ($global:Settings -and $global:Settings.QUser -and ($null -ne $global:Settings.QUser.Enabled)) {
                                    $canQueryQUser = $canQueryQUser -and [bool]$global:Settings.QUser.Enabled
                                }
                            } catch {}
                            if ($canQueryQUser) {
                                try {
                                    if (Get-Command Get-QUserSessionsForComputer -ErrorAction SilentlyContinue) {
                                        $sessions = Get-QUserSessionsForComputer -ComputerName $itemName
                                        foreach ($session in $sessions) {
                                            if ($session -and $session.Username) {
                                                & $removeNonLiveForUser $session.Username
                                                $lvItem = New-Object System.Windows.Forms.ListViewItem($session.Username)
                                                $details = "Live Session (QUser) ($($session.State)) - $($session.SessionName) (ID: $($session.SessionId))"
                                                [void]$lvItem.SubItems.Add($details)
                                                $lvItem.BackColor = [System.Drawing.Color]::LightGreen
                                                $locationListView.Items.Add($lvItem) | Out-Null
                                            }
                                        }
                                    }
                                } catch {
                                    Write-Log -Message "Error getting QUser data for computer ${itemName}: $_" -Level "Warning"
                                }
                            } else {
                                try { Write-Log -Message "ADapp: Skipping QUser fallback for $itemName (offline or QUser disabled)" -Level "Info" } catch {}
                            }
                        } catch {
                            Write-Log -Message "Error getting QUser fallback data for computer ${itemName}: $_" -Level "Warning"
                        }
                    }
                }
            } catch {
                Write-Log -Message "Error getting combined user data for computer ${itemName}: $_" -Level "Warning"
            }
            
            if ($locationListView.Items.Count -eq 0) {
                $lvItem = New-Object System.Windows.Forms.ListViewItem("No users found")
                [void]$lvItem.SubItems.Add("No data or current sessions available")
                $locationListView.Items.Add($lvItem) | Out-Null
            }
        }
        else {
            # For groups or other types, show a message
            $lvItem = New-Object System.Windows.Forms.ListViewItem("N/A")
            [void]$lvItem.SubItems.Add("Location info not applicable")
            $locationListView.Items.Add($lvItem) | Out-Null
        }
    } catch {
        Write-Log -Message "Error populating location info for ${itemName}: $_" -Level "Warning"
        $lvItem = New-Object System.Windows.Forms.ListViewItem("Error")
        [void]$lvItem.SubItems.Add("Could not load location data")
        $locationListView.Items.Add($lvItem) | Out-Null
    }
    
    # Enable/disable PDQ menu items and buttons based on selection
    try {
        Update-PDQMenuStateFromCurrentSelection
    } catch {
        Write-Log -Message "Error updating PDQ menu/button state: $_" -Level "Warning"
    }
}

# Add selection changed event for results
$resultsListView.Add_SelectedIndexChanged({
    # Track last selection for optional diagnostics / future enhancements
    if ($resultsListView.SelectedItems.Count -gt 0) {
        try { $script:lastResultsSelectionIndex = [int]$resultsListView.SelectedIndices[0] } catch { $script:lastResultsSelectionIndex = $null }
        try { Set-CurrentSelectionFromListViewItem -Item $resultsListView.SelectedItems[0] } catch {}
    } else {
        # If user clicks empty space and WinForms clears selection, keep the cached selection highlighted
        try { Apply-SelectionHighlightFromCache } catch {}
    }

    if ($resultsListView.SelectedItems.Count -gt 0) {
        Update-ResultsDetailsFromItem -SelectedItem $resultsListView.SelectedItems[0]
        return
        $selectedItem = $resultsListView.SelectedItems[0]
        $itemDetails = $selectedItem.Tag
        $itemType = $selectedItem.SubItems[0].Text # Get Type ("User", "Computer", etc.)
        $itemName = $selectedItem.SubItems[1].Text # Get Name (SAMAccountName or ComputerName)

        # Clear existing details
        $fieldListView.Items.Clear()
        $groupsListView.Items.Clear()
        $locationListView.Items.Clear()

        # Add field details in a structured way
        if ($null -ne $itemDetails -and ($itemDetails -is [hashtable] -or $itemDetails -is [pscustomobject])) {
            # Add specific fields based on item type
            if ($itemType -eq 'User') {
                # Add User fields in order
                $fieldListView.Items.Clear()
                
                # Define the fields to display for users
                $userFields = @(
                    @{ Label = "Username"; PropertyName = "Name" },
                    @{ Label = "Full Name"; PropertyName = "FullName" },
                    @{ Label = "Title"; PropertyName = "Title" },
                    @{ Label = "Department"; PropertyName = "Department" },
                    @{ Label = "Phone"; PropertyName = "Phone" },
                    @{ Label = "OU Path"; PropertyName = "OUPath" },
                    @{ Label = "Email"; PropertyName = "Email" },
                    @{ Label = "Account Status"; PropertyName = "Enabled"; },
                    @{ Label = "Locked Status"; PropertyName = "LockedOut" }
                )
                
                # Add each field with appropriate label
                foreach ($field in $userFields) {
                    $lvItem = New-Object System.Windows.Forms.ListViewItem($field.Label)
                    $propertyValue = $null
                    
                    if ($itemDetails.PSObject.Properties[$field.PropertyName]) {
                        $propertyValue = $itemDetails.$($field.PropertyName)
                    }
                    
                    $valueText = if ($null -eq $propertyValue -or [string]::IsNullOrEmpty($propertyValue)) { "N/A" } else { $propertyValue.ToString() }
                    $null = $lvItem.SubItems.Add($valueText)
                    $fieldListView.Items.Add($lvItem) | Out-Null
                }
            }
            elseif ($itemType -eq 'Computer') {
                # Add Computer fields in order
                $fieldListView.Items.Clear()
                
                # Define the fields to display for computers
                $computerFields = @(
                    @{ Label = "Computer Name"; PropertyName = "Name" },
                    @{ Label = "Operating System"; PropertyName = "OperatingSystem" },
                    @{ Label = "OS Version"; PropertyName = "OSVersion" },
                    @{ Label = "IP Address"; PropertyName = "IPv4Address" },
                    @{ Label = "Status"; PropertyName = "Enabled" },
                    @{ Label = "Last Logon"; PropertyName = "LastLogon" },
                    @{ Label = "Pwd Last Set"; PropertyName = "PasswordLastSet" },
                    @{ Label = "OU Path"; PropertyName = "OUPath" }
                )
                
                foreach ($field in $computerFields) {
                    $lvItem = New-Object System.Windows.Forms.ListViewItem($field.Label)
                    $propertyValue = $null
                    
                    if ($itemDetails.PSObject.Properties[$field.PropertyName]) {
                        $propertyValue = $itemDetails.$($field.PropertyName)
                    }
                    
                    $valueText = if ($null -eq $propertyValue -or [string]::IsNullOrEmpty($propertyValue)) { "N/A" } else { $propertyValue.ToString() }
                    $null = $lvItem.SubItems.Add($valueText)
                    $fieldListView.Items.Add($lvItem) | Out-Null
                }

                # Append PDQ Inventory info when available
                try {
                    if (Get-Command Get-PDQInfoForComputer -ErrorAction SilentlyContinue) {
                        $pdqRow = Get-PDQInfoForComputer -ComputerName $itemName
                        if ($pdqRow) {
                            $add = {
                                param($label, $candidates)
                                $val = $null
                                foreach ($c in $candidates) {
                                    if ($pdqRow.PSObject.Properties.Name -contains $c) { $val = $pdqRow.$c; if ($val) { break } }
                                }
                                if ($val) {
                                    $i = New-Object System.Windows.Forms.ListViewItem("PDQ: $label")
                                    $i.SubItems.Add([string]$val) | Out-Null
                                    $fieldListView.Items.Add($i) | Out-Null
                                }
                            }
                            & $add "Last Inventory" @('Last Scan','Last Inventory','Last Successful Inventory Scan','Scan Date','Last Scan Time')
                            & $add "Serial Number" @('Serial Number','Bios Serial Number','SerialNumber')
                            & $add "Manufacturer" @('Manufacturer','Make','Vendor')
                            & $add "Model" @('Model','Product')
                            & $add "Last Logged On User" @('Last Logged On User','Last LoggedOn User','User Logged On','Current Logged On User','Logged On User')
                            & $add "IP Address(es)" @('IP Addresses','IP Address','IPv4 Address','IPv4','IPv6 Address')
                            & $add "Uptime" @('Uptime','System Uptime')
                            & $add "Asset Tag" @('Asset Tag','AssetTag')
                            & $add "BIOS Version" @('BIOS Version','SMBIOS Version')
                            & $add "OS Build" @('OS Build','Build','OS Version')
                            & $add "Last Reboot" @('Last Reboot','Last Boot Time','Last Boot')
                            & $add "Free Space C:" @('Free Space (C:)','C: Free Space','C Drive Free Space','Free Space C')
                        }
                    }
                } catch {}
            }
            elseif ($itemType -eq 'Group') {
                # Add Group fields in order
                $fieldListView.Items.Clear()
                
                # Define the fields to display for groups
                $groupFields = @(
                    @{ Label = "Group Name"; PropertyName = "Name" },
                    @{ Label = "Description"; PropertyName = "Description" },
                    @{ Label = "Email"; PropertyName = "Email" },
                    @{ Label = "Group Scope"; PropertyName = "GroupScope" },
                    @{ Label = "Group Type"; PropertyName = "GroupType" },
                    @{ Label = "OU Path"; PropertyName = "OUPath" }
                )
                
                foreach ($field in $groupFields) {
                    $lvItem = New-Object System.Windows.Forms.ListViewItem($field.Label)
                    $propertyValue = $null
                    
                    if ($itemDetails.PSObject.Properties[$field.PropertyName]) {
                        $propertyValue = $itemDetails.$($field.PropertyName)
                    }
                    
                    $valueText = if ($null -eq $propertyValue -or [string]::IsNullOrEmpty($propertyValue)) { "N/A" } else { $propertyValue.ToString() }
                    $null = $lvItem.SubItems.Add($valueText)
                    $fieldListView.Items.Add($lvItem) | Out-Null
                }

                # Get and display group members
                try {
                    $groupIdentity = $null
                    if ($itemDetails -and $itemDetails.PSObject.Properties['DistinguishedName'] -and $itemDetails.DistinguishedName) {
                        $groupIdentity = $itemDetails.DistinguishedName
                    } elseif ($itemDetails -and $itemDetails.PSObject.Properties['SamAccountName'] -and $itemDetails.SamAccountName) {
                        $groupIdentity = $itemDetails.SamAccountName
                    } else {
                        $groupIdentity = $itemName
                    }
                    $groupMembers = Get-ADGroupMember -Identity $groupIdentity -Recursive | Get-ADObject -Properties Name, ObjectClass, DistinguishedName
                    $groupsListView.Items.Clear()
                    
                    if ($groupMembers) {
                        foreach ($member in $groupMembers) {
                            $lvItem = New-Object System.Windows.Forms.ListViewItem($member.Name)
                            [void]$lvItem.SubItems.Add($member.ObjectClass)
                            [void]$lvItem.SubItems.Add($member.DistinguishedName)
                            $groupsListView.Items.Add($lvItem) | Out-Null
                        }
                    } else {
                        $lvItem = New-Object System.Windows.Forms.ListViewItem("No members found")
                        $groupsListView.Items.Add($lvItem) | Out-Null
                    }
                } catch {
                    $lvItem = New-Object System.Windows.Forms.ListViewItem("Error retrieving group members")
                    [void]$lvItem.SubItems.Add($_.Exception.Message)
                    $groupsListView.Items.Add($lvItem) | Out-Null
                }
            }
            else {
                # For other types or fallback, show all properties
                Write-Log -Message "Showing generic properties for $itemType $itemName" -Level "Verbose"
                
                foreach ($property in $itemDetails.PSObject.Properties) {
                    # Skip complex objects and arrays
                    if ($property.Name -eq 'Groups') { continue }
                    
                    $lvItem = New-Object System.Windows.Forms.ListViewItem($property.Name)
                    $valueText = if ($null -eq $property.Value) { "N/A" } else { $property.Value.ToString() }
                    $null = $lvItem.SubItems.Add($valueText)
                    $fieldListView.Items.Add($lvItem) | Out-Null
                }
            }
        } else {
             Write-Log -Message "Item Tag is not a valid object type or is null" -Level "Warning"
             $lvItem = New-Object System.Windows.Forms.ListViewItem("Error")
             $null = $lvItem.SubItems.Add("Could not load details.")
             $fieldListView.Items.Add($lvItem) | Out-Null
        }

        # Add group memberships if available
        if ($itemType -ne 'Group' -and $itemDetails -and $itemDetails.PSObject.Properties['Groups']) {
            $groupsListView.Items.Clear()
            $groups = $itemDetails.Groups
            
            if ($groups -and $groups.Count -gt 0) {
                foreach ($group in $groups) {
                    if (-not [string]::IsNullOrWhiteSpace($group)) {
                        $lvItem = New-Object System.Windows.Forms.ListViewItem($group)
                        $groupsListView.Items.Add($lvItem) | Out-Null
                    }
                }
            } else {
                $lvItem = New-Object System.Windows.Forms.ListViewItem("No groups found")
                $groupsListView.Items.Add($lvItem) | Out-Null
            }
        }

        # Populate location info using combined PDQ and QUser data
        try {
            if ($itemType -eq 'User') {
                # Show computers where this user is found via PDQ and QUser
                try {
                    if (Get-Command Get-CombinedUserLocationData -ErrorAction SilentlyContinue) {
                        # Best-effort PDQ cache refresh to ensure PDQ data is available
                        try { if (Get-Command Update-PDQCache -ErrorAction SilentlyContinue) { if (-not $global:PDQInventoryCache) { Update-PDQCache | Out-Null } } } catch {}

                        try {
                            # Populate fast data first (PDQ + Historical). Live sessions (QUser) are streamed in asynchronously.
                            try { Stop-QUserAutoQueryJobs } catch {}
                            $combinedData = @(Get-CombinedUserLocationData -Username $itemName -IncludeQUser:$false -IncludePDQ -IncludeHistorical)
                            $resultCount = $combinedData.Count
                            Write-Log -Message "ADapp: Get-CombinedUserLocationData returned $resultCount results for user $itemName" -Level "Info"
                        } catch {
                            Write-Log -Message "ADapp: ERROR calling Get-CombinedUserLocationData for user $itemName`: $_" -Level "Error"
                            $combinedData = $null
                        }
                        if ($combinedData -and $combinedData.Count -gt 0) {
                            foreach ($location in $combinedData) {
                                Write-Log -Message "ADapp: Adding location - Computer: $($location.Computer), Source: $($location.Source), Status: $($location.Status)" -Level "Info"
                                $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$location.Computer)
                                $details = $location.Source
                                if ($location.Status -and $location.Status -ne "Offline/Cached") {
                                    $details += " ($($location.Status))"
                                }
                                if ($location.SessionDetails) {
                                    $details += " - $($location.SessionDetails)"
                                }
                                [void]$lvItem.SubItems.Add($details)
                                
                                # Color code different data sources
                                if ($location.Source -like "*Live Session*") {
                                    $lvItem.BackColor = [System.Drawing.Color]::LightGreen
                                } elseif ($location.Source -like "*Recent Sessions*") {
                                    $lvItem.BackColor = [System.Drawing.Color]::LightBlue
                                }
                                
                                $locationListView.Items.Add($lvItem) | Out-Null
                            }
                        } else {
                            # Fallback: manually populate from PDQ and QUser when combined call returns nothing
                            try {
                                if (Get-Command Get-PDQComputersForUser -ErrorAction SilentlyContinue) {
                                    $pdqComputers = Get-PDQComputersForUser -Username $itemName
                                    if ($pdqComputers -and $pdqComputers.Count -gt 0) {
                                        foreach ($pc in $pdqComputers) {
                                            if (-not [string]::IsNullOrWhiteSpace($pc)) {
                                                $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$pc)
                                                [void]$lvItem.SubItems.Add("From PDQ Inventory")
                                                $locationListView.Items.Add($lvItem) | Out-Null
                                            }
                                        }
                                    }
                                }
                            } catch {}
                        }

                        # Ensure PDQ entries are present for any remaining computers not shown
                        try {
                            if (Get-Command Get-PDQComputersForUser -ErrorAction SilentlyContinue) {
                                # Build a fast lookup of existing items
                                $existing = @{}
                                foreach ($it in $locationListView.Items) { $existing[$it.Text.ToUpperInvariant()] = $true }
                                $pdqComputersAll = Get-PDQComputersForUser -Username $itemName
                                foreach ($pc in $pdqComputersAll) {
                                    if (-not [string]::IsNullOrWhiteSpace($pc)) {
                                        $key = $pc.ToUpperInvariant()
                                        if (-not $existing.ContainsKey($key)) {
                                            $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$pc)
                                            [void]$lvItem.SubItems.Add("From PDQ Inventory")
                                            $locationListView.Items.Add($lvItem) | Out-Null
                                        }
                                    }
                                }
                            }
                        } catch {}

                        # Kick off asynchronous QUser live-session lookups so offline machines don't block the UI.
                        try {
                            try {
                                $lc = 0
                                try { if ($locationListView) { $lc = [int]$locationListView.Items.Count } } catch { $lc = 0 }
                                Write-Log -Message "Async QUser kickoff reached for '$itemName' (location items=$lc)" -Level "Info"
                            } catch {}

                            $maxProbe = 10
                            try {
                                if ($global:Settings -and $global:Settings.QUser -and $global:Settings.QUser.MaxComputersPerQuery) {
                                    $maxProbe = [Math]::Max(1, [int]$global:Settings.QUser.MaxComputersPerQuery)
                                }
                            } catch { $maxProbe = 10 }

                            # Probe the computers already shown in the Location list first (guarantees we check the "Historical" ones).
                            $candidates = New-Object 'System.Collections.Generic.List[string]'
                            $seen = New-Object 'System.Collections.Generic.HashSet[string]'
                            foreach ($it in $locationListView.Items) {
                                try {
                                    if (-not $it) { continue }
                                    $c = [string]$it.Text
                                    if ([string]::IsNullOrWhiteSpace($c) -or $c -like "No computers*") { continue }
                                    $k = $c.Trim().ToUpperInvariant()
                                    if ($seen.Add($k)) { [void]$candidates.Add($c.Trim()) }
                                } catch {}
                            }

                            $targets = @($candidates | Select-Object -First $maxProbe)
                            try { Write-Log -Message "Async QUser kickoff targets computed for '$itemName': targets=$($targets.Count), maxProbe=$maxProbe" -Level "Info" } catch {}
                            if ($targets.Count -gt 0) {
                                try {
                                    $preview = @($targets | Select-Object -First 5) -join ", "
                                    Write-Log -Message "Starting live-session QUser scan for '$itemName' on $($targets.Count) computers (maxProbe=$maxProbe): $preview" -Level "Info"
                                } catch {}
                                Start-QUserAutoQueryForUser -Username $itemName -ComputerNames $targets
                            }
                        } catch {
                            try { Write-Log -Message "ADapp: Failed to start async QUser lookups for user $itemName`: $_" -Level "Warning" } catch {}
                        }
                    } else {
                        # Fallback to PDQ only if combined function not available
                        if (Get-Command Get-PDQComputersForUser -ErrorAction SilentlyContinue) {
                            $pdqComputers = Get-PDQComputersForUser -Username $itemName
                            if ($pdqComputers -and $pdqComputers.Count -gt 0) {
                                foreach ($pc in $pdqComputers) {
                                    if (-not [string]::IsNullOrWhiteSpace($pc)) {
                                        $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$pc)
                                        [void]$lvItem.SubItems.Add("From PDQ Inventory")
                                        $locationListView.Items.Add($lvItem) | Out-Null
                                    }
                                }
                            }
                        }
                        
                        # Also try QUser data separately if available
                        try {
                            if (Get-Command Get-QUserComputersForUser -ErrorAction SilentlyContinue) {
                                $qUserComputers = Get-QUserComputersForUser -Username $itemName
                                foreach ($computer in $qUserComputers) {
                                    if (-not [string]::IsNullOrWhiteSpace($computer)) {
                                        $sessions = Get-QUserSessionsForComputer -ComputerName $computer
                                        $userSessions = $sessions | Where-Object { $_.Username.ToUpperInvariant() -eq $itemName.ToUpperInvariant() }
                                        
                                        foreach ($session in $userSessions) {
                                            $lvItem = New-Object System.Windows.Forms.ListViewItem($computer)
                                            $details = "Live Session (QUser) ($($session.State)) - $($session.SessionName) (ID: $($session.SessionId))"
                                            [void]$lvItem.SubItems.Add($details)
                                            $lvItem.BackColor = [System.Drawing.Color]::LightGreen
                                            $locationListView.Items.Add($lvItem) | Out-Null
                                        }
                                    }
                                }
                            }
                        } catch {
                            Write-Log -Message "Error getting QUser fallback data for user ${itemName}: $_" -Level "Warning"
                        }
                    }
                } catch {
                    Write-Log -Message "Error getting combined location data for user ${itemName}: $_" -Level "Warning"
                }
                
                if ($locationListView.Items.Count -eq 0) {
                    $lvItem = New-Object System.Windows.Forms.ListViewItem("No computers found")
                    [void]$lvItem.SubItems.Add("No data available")
                    $locationListView.Items.Add($lvItem) | Out-Null
                }
            }
            elseif ($itemType -eq 'Computer') {
                # Show users on this computer via PDQ and QUser
                try {
                    if (Get-Command Get-CombinedComputerUserData -ErrorAction SilentlyContinue) {
                        # Best-effort PDQ cache refresh to ensure PDQ data is available
                        try { if (Get-Command Update-PDQCache -ErrorAction SilentlyContinue) { if (-not $global:PDQInventoryCache) { Update-PDQCache | Out-Null } } } catch {}

                        # Check if computer is online (from cached status or test)
                        $isComputerOnline = $false
                        if ($itemDetails -and $null -ne $itemDetails.IsOnline) {
                            $isComputerOnline = $itemDetails.IsOnline
                            Write-Log -Message "ADapp: Computer $itemName online status from cache: $isComputerOnline" -Level "Info"
                        } else {
                            try {
                                if (Get-Command Test-ComputerOnline -ErrorAction SilentlyContinue) {
                                    $isComputerOnline = Test-ComputerOnline -ComputerName $itemName
                                    Write-Log -Message "ADapp: Computer $itemName online status from test: $isComputerOnline" -Level "Info"
                                }
                            } catch {
                                Write-Log -Message "ADapp: Error testing if computer $itemName is online: $_" -Level "Warning"
                            }
                        }

                        try {
                            # Only query QUser if computer is online
                            $includeQUser = $isComputerOnline
                            $combinedData = Get-CombinedComputerUserData -ComputerName $itemName -IncludeQUser:$includeQUser -IncludePDQ -IncludeHistorical
                            $resultCount = if ($combinedData) { $combinedData.Count } else { 0 }
                            Write-Log -Message "ADapp: Get-CombinedComputerUserData returned $resultCount results for computer $itemName (QUser=$includeQUser)" -Level "Info"
                        } catch {
                            Write-Log -Message "ADapp: ERROR calling Get-CombinedComputerUserData for computer $itemName`: $_" -Level "Error"
                            $combinedData = $null
                        }
                        if ($combinedData -and $combinedData.Count -gt 0) {
                            foreach ($userInfo in $combinedData) {
                                Write-Log -Message "ADapp: Adding user - Username: $($userInfo.Username), Source: $($userInfo.Source), Status: $($userInfo.Status)" -Level "Info"
                                $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$userInfo.Username)
                                $details = $userInfo.Source
                                if ($userInfo.Status -and $userInfo.Status -ne "Offline/Cached") {
                                    $details += " ($($userInfo.Status))"
                                }
                                if ($userInfo.SessionDetails) {
                                    $details += " - $($userInfo.SessionDetails)"
                                }
                                if ($userInfo.IdleTime -and $userInfo.IdleTime -ne "none") {
                                    $details += " [Idle: $($userInfo.IdleTime)]"
                                }
                                [void]$lvItem.SubItems.Add($details)
                                
                                # Color code different data sources
                                if ($userInfo.Source -like "*Live Session*") {
                                    $lvItem.BackColor = [System.Drawing.Color]::LightGreen
                                } elseif ($userInfo.Source -like "*Recent Sessions*") {
                                    $lvItem.BackColor = [System.Drawing.Color]::LightBlue
                                }
                                
                                $locationListView.Items.Add($lvItem) | Out-Null
                            }
                        } else {
                            # Fallback: manually populate from PDQ and (optionally) QUser when combined call returns nothing
                            try {
                                if (Get-Command Get-PDQUsersForComputer -ErrorAction SilentlyContinue) {
                                    $pdqUsers = Get-PDQUsersForComputer -ComputerName $itemName
                                    if ($pdqUsers -and $pdqUsers.Count -gt 0) {
                                        foreach ($user in $pdqUsers) {
                                            if (-not [string]::IsNullOrWhiteSpace($user)) {
                                                $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$user)
                                                [void]$lvItem.SubItems.Add("From PDQ Inventory")
                                                $locationListView.Items.Add($lvItem) | Out-Null
                                            }
                                        }
                                    }
                                }
                            } catch {}
                            try {
                                $canQueryQUser = [bool]$isComputerOnline
                                try {
                                    if ($global:Settings -and $global:Settings.QUser -and ($null -ne $global:Settings.QUser.Enabled)) {
                                        $canQueryQUser = $canQueryQUser -and [bool]$global:Settings.QUser.Enabled
                                    }
                                } catch {}

                                if ($canQueryQUser -and (Get-Command Get-QUserSessionsForComputer -ErrorAction SilentlyContinue)) {
                                    $sessions = Get-QUserSessionsForComputer -ComputerName $itemName
                                    foreach ($session in $sessions) {
                                        # Remove any PDQ-only entry for this user
                                        for ($i = $locationListView.Items.Count - 1; $i -ge 0; $i--) {
                                            if ($locationListView.Items[$i].Text -eq $session.Username -and $locationListView.Items[$i].SubItems[1].Text -like "*PDQ*") {
                                                $locationListView.Items.RemoveAt($i)
                                            }
                                        }
                                        $lvItem = New-Object System.Windows.Forms.ListViewItem($session.Username)
                                        $details = "Live Session (QUser) ($($session.State)) - $($session.SessionName) (ID: $($session.SessionId))"
                                        if ($session.IdleTime -and $session.IdleTime -ne "none") { $details += " [Idle: $($session.IdleTime)]" }
                                        [void]$lvItem.SubItems.Add($details)
                                        $lvItem.BackColor = [System.Drawing.Color]::LightGreen
                                        $locationListView.Items.Add($lvItem) | Out-Null
                                    }
                                } else {
                                    try { Write-Log -Message "ADapp: Skipping QUser session query for $itemName (offline or QUser disabled)" -Level "Info" } catch {}
                                }
                            } catch {}
                        }

                        # Ensure PDQ entries are present for any remaining users not shown
                        try {
                            if (Get-Command Get-PDQUsersForComputer -ErrorAction SilentlyContinue) {
                                # Build a fast lookup of existing usernames
                                $existingUsers = @{}
                                foreach ($it in $locationListView.Items) { $existingUsers[$it.Text.ToUpperInvariant()] = $true }
                                $pdqUsersAll = Get-PDQUsersForComputer -ComputerName $itemName
                                foreach ($u in $pdqUsersAll) {
                                    if (-not [string]::IsNullOrWhiteSpace($u)) {
                                        $k = $u.ToUpperInvariant()
                                        if (-not $existingUsers.ContainsKey($k)) {
                                            $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$u)
                                            [void]$lvItem.SubItems.Add("From PDQ Inventory")
                                            $locationListView.Items.Add($lvItem) | Out-Null
                                        }
                                    }
                                }
                            }
                        } catch {}
                    } else {
                        # Fallback to separate PDQ and QUser calls if combined function not available
                        # Show users found on this computer via PDQ
                        if (Get-Command Get-PDQUsersForComputer -ErrorAction SilentlyContinue) {
                            $pdqUsers = Get-PDQUsersForComputer -ComputerName $itemName
                            if ($pdqUsers -and $pdqUsers.Count -gt 0) {
                                foreach ($user in $pdqUsers) {
                                    if (-not [string]::IsNullOrWhiteSpace($user)) {
                                        $lvItem = New-Object System.Windows.Forms.ListViewItem([string]$user)
                                        [void]$lvItem.SubItems.Add("From PDQ Inventory")
                                        $locationListView.Items.Add($lvItem) | Out-Null
                                    }
                                }
                            }
                        }
                        
                        # Also try QUser data separately if available (only when computer is online)
                        try {
                            $canQueryQUser = [bool]$isComputerOnline
                            try {
                                if ($global:Settings -and $global:Settings.QUser -and ($null -ne $global:Settings.QUser.Enabled)) {
                                    $canQueryQUser = $canQueryQUser -and [bool]$global:Settings.QUser.Enabled
                                }
                            } catch {}

                            if ($canQueryQUser -and (Get-Command Get-QUserSessionsForComputer -ErrorAction SilentlyContinue)) {
                                $sessions = Get-QUserSessionsForComputer -ComputerName $itemName
                                foreach ($session in $sessions) {
                                    $lvItem = New-Object System.Windows.Forms.ListViewItem($session.Username)
                                    $details = "Live Session (QUser) ($($session.State)) - $($session.SessionName) (ID: $($session.SessionId))"
                                    if ($session.IdleTime -and $session.IdleTime -ne "none") {
                                        $details += " [Idle: $($session.IdleTime)]"
                                    }
                                    [void]$lvItem.SubItems.Add($details)
                                    $lvItem.BackColor = [System.Drawing.Color]::LightGreen
                                    $locationListView.Items.Add($lvItem) | Out-Null
                                }
                            } else {
                                try { Write-Log -Message "ADapp: Skipping QUser fallback for $itemName (offline or QUser disabled)" -Level "Info" } catch {}
                            }
                        } catch {
                            Write-Log -Message "Error getting QUser fallback data for computer ${itemName}: $_" -Level "Warning"
                        }
                    }
                } catch {
                    Write-Log -Message "Error getting combined user data for computer ${itemName}: $_" -Level "Warning"
                }
                
                if ($locationListView.Items.Count -eq 0) {
                    $lvItem = New-Object System.Windows.Forms.ListViewItem("No users found")
                    [void]$lvItem.SubItems.Add("No data or current sessions available")
                    $locationListView.Items.Add($lvItem) | Out-Null
                }
            }
            else {
                # For groups or other types, show a message
                $lvItem = New-Object System.Windows.Forms.ListViewItem("N/A")
                [void]$lvItem.SubItems.Add("Location info not applicable")
                $locationListView.Items.Add($lvItem) | Out-Null
            }
        } catch {
            Write-Log -Message "Error populating location info for ${itemName}: $_" -Level "Warning"
            $lvItem = New-Object System.Windows.Forms.ListViewItem("Error")
            [void]$lvItem.SubItems.Add("Could not load location data")
            $locationListView.Items.Add($lvItem) | Out-Null
        }
        
        # Enable/disable PDQ menu items and buttons based on selection
        try {
            Update-PDQMenuStateFromCurrentSelection
        } catch {
            Write-Log -Message "Error updating PDQ menu/button state: $_" -Level "Warning"
        }
    }
})

# Menus are already initialized by the functions above

# Custom event handlers
$mainForm.Add_Shown({
    Write-Log -Message "Main form shown" -Level "Info"
    $statusLabel.Text = "Ready"
    try { Refresh-FavoritesMenu } catch { try { Write-Log -Message "Error refreshing favorites on Shown: $_" -Level "Warning" } catch {} }
})

# Replace the FormClosing event handler
$mainForm.Add_FormClosing({
    param($sender, $e)
    
    # Safely log application closing
    try {
        Write-Log -Message "Application closing" -Level "Info"
    }
    catch {
        # Suppress errors during shutdown
    }
})

# Define function to create a basic info list view
<#
.SYNOPSIS
Brief description of CreateBasicInfoListView.
.DESCRIPTION
Extended description of CreateBasicInfoListView.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
CreateBasicInfoListView
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

<#
.SYNOPSIS
Brief description of CreateBasicInfoListView.
.DESCRIPTION
Extended description of CreateBasicInfoListView.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
CreateBasicInfoListView
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function CreateBasicInfoListView {
    $listView = New-Object System.Windows.Forms.ListView
    $listView.Dock = [System.Windows.Forms.DockStyle]::Fill
    $listView.View = [System.Windows.Forms.View]::Details
    $listView.FullRowSelect = $true
    $listView.GridLines = $true
    
    # Add columns
    [void]$listView.Columns.Add("Property", 200)
    [void]$listView.Columns.Add("Value", 500)
    
    return $listView
}
# Show the progress dialog
try {
    # Initialize the progress bar
    if ($global:progressBar -and $global:progressBar.PSObject.Properties.Name -contains "Visible") {
        $global:progressBar.Value = 0
        $global:progressBar.Visible = $true
    }
    
    # First check if there is a current (cached) computer selection
    $sel = $null
    try { $sel = Get-CurrentSelection } catch {}
    if ($sel -and $sel.Type -eq "Computer" -and -not [string]::IsNullOrWhiteSpace($sel.Name)) {
        $computerName = $sel.Name
        
        # Before calling Get-ADComputer, add a check
        if (-not [string]::IsNullOrWhiteSpace($computerName)) {
            # Get the computer properties
            $computerProperties = Get-ADComputer -Identity $computerName -Properties *
            
            # Update the basic info panel
            Update-BasicInfoPanel -ItemProperties $computerProperties -ItemType "Computer"
        } else {
            if ($global:statusLabel -and $global:statusLabel.PSObject.Properties.Name -contains "Text") {
                $global:statusLabel.Text = "Error: Computer name is missing"
            }
            [System.Windows.Forms.MessageBox]::Show(
                "Cannot retrieve computer information because the computer name is missing or invalid.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
    
    # Hide the progress bar
    if ($global:progressBar -and $global:progressBar.PSObject.Properties.Name -contains "Visible") {
        $global:progressBar.Visible = $false
    }
}
catch {
    if ($global:progressBar -and $global:progressBar.PSObject.Properties.Name -contains "Visible") {
        $global:progressBar.Visible = $false
    }
    if ($global:statusLabel -and $global:statusLabel.PSObject.Properties.Name -contains "Text") {
        $global:statusLabel.Text = "Error retrieving computer information"
    }
    [System.Windows.Forms.MessageBox]::Show(
        "Error retrieving computer information: $_",
        "Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
}

# Add a function to refresh group data
<#
.SYNOPSIS
Brief description of Update-GroupMembershipDisplay.
.DESCRIPTION
Extended description of Update-GroupMembershipDisplay.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Update-GroupMembershipDisplay
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

<#
.SYNOPSIS
Brief description of Update-GroupMembershipDisplay.
.DESCRIPTION
Extended description of Update-GroupMembershipDisplay.

.INPUTS
None
.OUTPUTS
None
.EXAMPLE
Update-GroupMembershipDisplay
.NOTES
Auto-generated by tools/Add-HelpStubs.ps1. Please refine as needed.
#>

function Update-GroupMembershipDisplay {
    param (
        [string]$ItemName,
        [bool]$IsComputer
    )
    
    try {
        # Get updated groups
        if ($IsComputer) {
            $updatedGroups = Get-WorkstationSecurityGroups -ComputerName $ItemName
            if ($updatedGroups) {
                $currentGroups = $updatedGroups | Where-Object { $_ -ne $null }
            } else {
                $currentGroups = @()
            }
        } else {
            $updatedGroups = Get-UserSecurityGroups -Username $ItemName
            if ($updatedGroups) {
                $currentGroups = $updatedGroups | Where-Object { $_ -ne $null }
            } else {
                $currentGroups = @()
            }
        }
        
        # Update the Tag property for the matching item (do NOT rely on UI selection)
        try {
            $targetType = if ($IsComputer) { "Computer" } else { "User" }
            $targetItem = $null
            try {
                foreach ($it in $resultsListView.Items) {
                    if (-not $it) { continue }
                    $t = $null; $n = $null
                    try { $t = [string]$it.SubItems[0].Text } catch {}
                    try { $n = [string]$it.SubItems[1].Text } catch {}
                    if ($t -eq $targetType -and $n -eq $ItemName) { $targetItem = $it; break }
                }
            } catch {}

            if ($targetItem -and $targetItem.Tag -and $targetItem.Tag.PSObject.Properties['Groups']) {
                $targetItem.Tag.Groups = $currentGroups | Select-Object -ExpandProperty Name
            }

            # Keep cached selection in sync if it's the same item
            try {
                $sel = Get-CurrentSelection
                if ($sel -and $sel.Type -eq $targetType -and $sel.Name -eq $ItemName -and $sel.Tag -and $sel.Tag.PSObject.Properties['Groups']) {
                    $sel.Tag.Groups = $currentGroups | Select-Object -ExpandProperty Name
                }
            } catch {}
        } catch {}
        
        # Clear and update the groups list view
        $groupsListView.Items.Clear()
        
        if ($currentGroups -and $currentGroups.Count -gt 0) {
            foreach ($group in $currentGroups) {
                if (-not [string]::IsNullOrWhiteSpace($group.Name)) {
                    $lvItem = New-Object System.Windows.Forms.ListViewItem($group.Name)
                    [void]$lvItem.SubItems.Add($group.GroupCategory.ToString())
                    $groupsListView.Items.Add($lvItem) | Out-Null
                }
            }
        } else {
            $lvItem = New-Object System.Windows.Forms.ListViewItem("No groups found")
            $groupsListView.Items.Add($lvItem) | Out-Null
        }
    }
    catch {
        Write-Log -Message "Error refreshing group membership display: $_" -Level "Error"
        $lvItem = New-Object System.Windows.Forms.ListViewItem("Error")
        $null = $lvItem.SubItems.Add("Could not refresh groups.")
        $groupsListView.Items.Add($lvItem) | Out-Null
    }
}



# === Keyboard shortcut dispatcher wiring ===
try {
    $ShortcutDispatch = @{}
    if ($Settings.Shortcuts) {
        try { if ($newSearchMenuItem -and $Settings.Shortcuts.NewSearch) { $newSearchMenuItem.ShortcutKeys = (Parse-ShortcutStringToKeys -Shortcut $Settings.Shortcuts.NewSearch) } } catch {}
        try { if ($rdpMenuItem -and $Settings.Shortcuts.ConnectRDP) { $rdpMenuItem.ShortcutKeys = (Parse-ShortcutStringToKeys -Shortcut $Settings.Shortcuts.ConnectRDP) } } catch {}
        try { if ($vncMenuItem -and $Settings.Shortcuts.ConnectVNC) { $vncMenuItem.ShortcutKeys = (Parse-ShortcutStringToKeys -Shortcut $Settings.Shortcuts.ConnectVNC) } } catch {}
        try { if ($pingMenuItem -and $Settings.Shortcuts.ConnectPing) { $pingMenuItem.ShortcutKeys = (Parse-ShortcutStringToKeys -Shortcut $Settings.Shortcuts.ConnectPing) } } catch {}
        if ($Settings.Shortcuts.FocusSearch) { $ShortcutDispatch[$Settings.Shortcuts.FocusSearch] = { try { $searchTextBox.Focus(); $searchTextBox.SelectAll() } catch {} } }
        if ($Settings.Shortcuts.NewSearch)   { $ShortcutDispatch[$Settings.Shortcuts.NewSearch]   = { try { Invoke-NewSearch } catch {} } }
        if ($Settings.Shortcuts.ClearFilters){ $ShortcutDispatch[$Settings.Shortcuts.ClearFilters]= { try { Clear-SearchFilters } catch {} } }
        if ($Settings.Shortcuts.ConnectRDP)  { $ShortcutDispatch[$Settings.Shortcuts.ConnectRDP]  = { try { if ($rdpMenuItem) { $rdpMenuItem.PerformClick() } } catch {} } }
        if ($Settings.Shortcuts.ConnectVNC)  { $ShortcutDispatch[$Settings.Shortcuts.ConnectVNC]  = { try { if ($vncMenuItem) { $vncMenuItem.PerformClick() } } catch {} } }
        if ($Settings.Shortcuts.ConnectPing)  { $ShortcutDispatch[$Settings.Shortcuts.ConnectPing]  = { try { if ($pingMenuItem) { $pingMenuItem.PerformClick() } } catch {} } }
    }

    $mainForm.KeyPreview = $true
    $mainForm.Add_KeyDown({ param($sender,$e)
        try {
            $combo = Convert-KeyEventToShortcutString -KeyEvent $e
            if ([string]::IsNullOrWhiteSpace($combo)) { return }
            if ($ShortcutDispatch.ContainsKey($combo) -and $ShortcutDispatch[$combo]) {
                & $ShortcutDispatch[$combo]
                $e.SuppressKeyPress = $true
            }
        } catch {}
    })
} catch {}

# Start IPC poller + UI-thread timer to process incoming commands (openUser/activate)
try {
    Initialize-ADappIpcSpoolPermissions
    Write-ADappIpcTrace -Message ("ipc poller started spool={0}" -f $script:ADappIpcSpoolDir)
    $script:ADappIpcTimer = New-Object System.Windows.Forms.Timer
    $script:ADappIpcTimer.Interval = 250
    $script:ADappIpcTimer.Add_Tick({ Process-ADappIpcQueue })
    $script:ADappIpcTimer.Start()
} catch {}

# Show the form
$mainForm.Add_Shown({
    try { $mainForm.Activate() } catch {}
    try {
        if (-not [string]::IsNullOrWhiteSpace($script:StartupOpenUser)) {
            Invoke-ADappOpenUser -Username $script:StartupOpenUser
            $script:StartupOpenUser = $null
        }
    } catch {}
})
try { Apply-Theme -Root $mainForm } catch {}
[void] $mainForm.ShowDialog()

# Release mutex on shutdown (best-effort)
try {
    if ($script:ADappMutex) {
        try { $script:ADappMutex.ReleaseMutex() } catch {}
        try { $script:ADappMutex.Dispose() } catch {}
    }
} catch {}

# Settings load duplicated below originally. Already loaded at top via Settings module; this block removed.

# Add Diagnostics under Tools menu
try {
    $toolsDiagnosticsMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $toolsDiagnosticsMenuItem.Text = "Diagnostics"
    $toolsDiagnosticsMenuItem.Add_Click({
        Invoke-Safe -Context 'Diagnostics' -ScriptBlock {
            $lines = @()
            # AD module
            try {
                if (Get-Command Get-ADUser -ErrorAction Stop) { $lines += "[OK] AD module available" } else { $lines += "[WARN] AD module not fully available" }
            } catch { $lines += "[WARN] AD module check failed: $_" }
            # DC connectivity
            try {
                $null = Get-ADDomainController -Discover -ErrorAction Stop
                $lines += "[OK] Domain Controller reachable"
            } catch { $lines += "[WARN] DC check failed: $_" }
            # LogPath permission
            try {
                $testLog = Join-Path -Path $global:AppConfig.LogPath -ChildPath "perm_test.txt"
                "test" | Out-File -FilePath $testLog -Force
                Remove-Item $testLog -Force
                $lines += "[OK] LogPath write access"
            } catch { $lines += "[WARN] LogPath write failed: $_" }
            # DataPath permission
            try {
                $testData = Join-Path -Path $global:AppConfig.DataPath -ChildPath "perm_test.txt"
                "test" | Out-File -FilePath $testData -Force
                Remove-Item $testData -Force
                $lines += "[OK] DataPath write access"
            } catch { $lines += "[WARN] DataPath write failed: $_" }
            # PDQ folder exists
            try {
                if ($global:Settings.PDQ.Enabled -and -not [string]::IsNullOrWhiteSpace($global:Settings.PDQ.ReportFolder)) {
                    if (Test-Path $global:Settings.PDQ.ReportFolder) { $lines += "[OK] PDQ ReportFolder exists" } else { $lines += "[WARN] PDQ ReportFolder missing" }
                } else { $lines += "[INFO] PDQ integration disabled or not configured" }
            } catch { $lines += "[WARN] PDQ check failed: $_" }
            # WinRM local check
            try {
                $null = Test-WSMan -ErrorAction Stop
                $lines += "[OK] WinRM available locally"
            } catch { $lines += "[WARN] WinRM not available locally: $_" }
            
            # Show results in a simple dialog
            $diagForm = New-Object System.Windows.Forms.Form
            $diagForm.Text = "Diagnostics"
            $diagForm.Size = New-Object System.Drawing.Size(700, 450)
            $diagForm.StartPosition = "CenterParent"
            $tb = New-Object System.Windows.Forms.TextBox
            $tb.Multiline = $true
            $tb.ReadOnly = $true
            $tb.ScrollBars = 'Vertical'
            $tb.Dock = 'Fill'
            $tb.Font = $mainForm.Font
            $tb.Text = ($lines -join [Environment]::NewLine)
            $diagForm.Controls.Add($tb)
            [void]$diagForm.ShowDialog($mainForm)
        }
    })
    if ($toolsMenu) { [void]$toolsMenu.DropDownItems.Add($toolsDiagnosticsMenuItem) }
} catch { Write-Log -Message "Failed to add Diagnostics menu: $_" -Level "Warning" }