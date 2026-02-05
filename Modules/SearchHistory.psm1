#Requires -Version 5.1
<#
.SYNOPSIS
    Search history management module for ADapp.
.DESCRIPTION
    Provides functions to read, save, and manage search history.
    History is persisted to a JSON file in the application data directory
    and surfaced as a dropdown menu in the UI.
.NOTES
    Module: SearchHistory
    Author: ADapp Team
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region Functions

function Read-SearchHistory {
    <#
    .SYNOPSIS
        Reads search history from the history file.
    .DESCRIPTION
        Loads the JSON search-history file referenced by $global:AppConfig.SearchHistoryFile.
        If the file is corrupt (e.g. duplicate-case JSON keys), attempts an
        automatic repair by renaming colliding keys and re-saving.
    .OUTPUTS
        System.Object[]
        An array of PSCustomObjects with SearchTerm and SearchType properties.
        Returns an empty array if no history exists or the file cannot be read.
    .EXAMPLE
        $history = Read-SearchHistory
    #>
    [CmdletBinding()]
    param ()

    $historyPath = $global:AppConfig.SearchHistoryFile
    if (Test-Path $historyPath) {
        try {
            $jsonText = Get-Content $historyPath -Raw
            $history = $jsonText | ConvertFrom-Json
            if ($null -eq $history) {
                return @()
            }
            elseif (-not ($history -is [array])) {
                return @($history)
            }
            else {
                return $history
            }
        }
        catch {
            Write-Warning "Error loading search history: $_"
            try {
                # Attempt repair for duplicate-case JSON keys ("Value" vs "value")
                $raw = Get-Content $historyPath -Raw
                $sanitized = [System.Text.RegularExpressions.Regex]::Replace($raw, '"Value"\s*:', '"Value_upper":')
                $repaired = $sanitized | ConvertFrom-Json
                if ($null -ne $repaired) {
                    if (-not ($repaired -is [array])) { $repaired = @($repaired) }
                    $clean = @()
                    foreach ($item in $repaired) {
                        if ($null -ne $item) {
                            $clean += [PSCustomObject]@{
                                SearchTerm = $item.SearchTerm
                                SearchType = $item.SearchType
                            }
                        }
                    }
                    if ($clean.Count -ge 0) { Save-SearchHistory -History $clean }
                    return $clean
                }
            } catch { }
            return @()
        }
    }
    return @()
}

function Save-SearchHistory {
    <#
    .SYNOPSIS
        Saves search history to the history file.
    .DESCRIPTION
        Serialises the supplied history array to JSON and writes it to the
        path specified in $global:AppConfig.SearchHistoryFile, creating the
        parent directory if it does not exist.
    .PARAMETER History
        Array of search history objects to persist.
    .OUTPUTS
        None
    .EXAMPLE
        Save-SearchHistory -History @($entry1, $entry2)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $History
    )

    $historyPath = $global:AppConfig.SearchHistoryFile
    try {
        $historyArray = @($History)

        # Ensure the parent directory exists
        $dir = Split-Path $historyPath -Parent
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        $historyArray | ConvertTo-Json -Depth 5 |
            Out-File -FilePath $historyPath -Encoding UTF8 -Force
    }
    catch {
        Write-Warning "Error saving search history: $_"
    }
}

function Update-SearchHistory {
    <#
    .SYNOPSIS
        Adds a search to the history.
    .DESCRIPTION
        Prepends a new entry to the search history, removing any prior entry
        with the same search term so the most recent use floats to the top.
        The list is trimmed to $global:AppConfig.MaxSearchHistory entries
        (default 20).
    .PARAMETER SearchTerm
        The search term to record.
    .PARAMETER SearchType
        The type of search performed (User, Computer, Group, All).
    .OUTPUTS
        None
    .EXAMPLE
        Update-SearchHistory -SearchTerm "jsmith" -SearchType "User"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SearchTerm,

        [Parameter(Mandatory = $true)]
        [string]$SearchType
    )

    if ([string]::IsNullOrWhiteSpace($SearchTerm)) { return }

    $history = Read-SearchHistory
    $maxHistory = if ($global:AppConfig.MaxSearchHistory) { $global:AppConfig.MaxSearchHistory } else { 20 }

    # Remove any existing entry with the same term so it moves to the top
    $history = @($history | Where-Object { $_.SearchTerm -ne $SearchTerm })

    # Prepend the new entry
    $newEntry = [PSCustomObject]@{
        SearchTerm = $SearchTerm
        SearchType = $SearchType
        Timestamp  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }

    $history = @($newEntry) + @($history)

    # Trim to the configured maximum
    if ($history.Count -gt $maxHistory) {
        $history = $history | Select-Object -First $maxHistory
    }

    Save-SearchHistory -History $history
}

function Update-SearchHistoryMenu {
    <#
    .SYNOPSIS
        Updates the history dropdown menu with recent searches.
    .DESCRIPTION
        Clears and rebuilds the supplied ToolStripMenuItem with the current
        search history entries. Each menu item triggers a search when clicked.
        Includes a "Clear History" option at the bottom.
    .PARAMETER HistoryMenu
        The ToolStripMenuItem to populate. Falls back to $global:historyMenu
        if not specified.
    .OUTPUTS
        None
    .EXAMPLE
        Update-SearchHistoryMenu -HistoryMenu $global:historyMenu
    #>
    [CmdletBinding()]
    param (
        [System.Windows.Forms.ToolStripMenuItem]$HistoryMenu
    )

    if (-not $HistoryMenu) { $HistoryMenu = $global:historyMenu }
    if (-not $HistoryMenu) { return }

    $history = Read-SearchHistory

    # Clear existing items
    $HistoryMenu.DropDownItems.Clear()

    #region Empty state
    if ($history.Count -eq 0) {
        $emptyItem = New-Object System.Windows.Forms.ToolStripMenuItem
        $emptyItem.Text = "(No recent searches)"
        $emptyItem.Enabled = $false
        [void]$HistoryMenu.DropDownItems.Add($emptyItem)
        return
    }
    #endregion Empty state

    #region History items
    foreach ($item in $history) {
        $menuItem = New-Object System.Windows.Forms.ToolStripMenuItem
        $menuItem.Text = "$($item.SearchTerm) ($($item.SearchType))"
        $menuItem.Tag = $item
        $menuItem.Add_Click({
            param($sender, $e)
            $historyItem = $sender.Tag
            $global:searchTextBox.Text = $historyItem.SearchTerm
            if ($global:searchTypeCombo.Items.Contains($historyItem.SearchType)) {
                $global:searchTypeCombo.SelectedItem = $historyItem.SearchType
            }
            $global:searchButton.PerformClick()
        })
        [void]$HistoryMenu.DropDownItems.Add($menuItem)
    }
    #endregion History items

    #region Clear option
    [void]$HistoryMenu.DropDownItems.Add("-")
    $clearItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $clearItem.Text = "Clear History"
    $clearItem.Add_Click({
        $result = [System.Windows.Forms.MessageBox]::Show(
            "Clear search history?",
            "Confirm",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
            Save-SearchHistory -History @()
            Update-SearchHistoryMenu -HistoryMenu $global:historyMenu
        }
    })
    [void]$HistoryMenu.DropDownItems.Add($clearItem)
    #endregion Clear option
}

#endregion Functions

# ── Module Exports ────────────────────────────────────────────────────────────
Export-ModuleMember -Function Read-SearchHistory, Save-SearchHistory, Update-SearchHistory, Update-SearchHistoryMenu
