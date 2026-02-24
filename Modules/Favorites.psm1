#Requires -Version 5.1
<#
.SYNOPSIS
    Favorites management module for ADapp.
.DESCRIPTION
    Provides functions to read, save, and manage user favorites (saved searches).
    Favorites are persisted to a JSON file in the application data directory
    and surfaced as a dropdown menu in the UI.
.NOTES
    Module: Favorites
    Author: ADapp Team
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region Functions

function Remove-DefaultAdvancedSearch {
    <#
    .SYNOPSIS
        Cleans up favorites by removing default-valued AdvancedSearch objects.
    .DESCRIPTION
        Iterates through the supplied favorites array and strips the
        AdvancedSearch property from any favourite where every field is still
        at its default value. This keeps the persisted JSON lean. Favourites
        with meaningful AdvancedSearch criteria are left untouched.
    .PARAMETER favorites
        Array of favorite objects to clean up.
    .OUTPUTS
        System.Object[]
        The cleaned array of favorites. Items are never removed — only the
        redundant AdvancedSearch property is stripped.
    .EXAMPLE
        $cleaned = Remove-DefaultAdvancedSearch -favorites $favorites
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $favorites
    )

    if ($null -eq $favorites -or $favorites.Count -eq 0) {
        return @()
    }

    $cleaned = @()
    $inputCount = @($favorites).Count

    foreach ($fav in @($favorites)) {
        if ($null -eq $fav) {
            continue
        }

        try {
            if ($fav.AdvancedSearch) {
                # Check whether any AdvancedSearch field has a non-default value
                $hasLocation       = $fav.AdvancedSearch.Location -and $fav.AdvancedSearch.Location -ne "All Locations"
                $hasStatus         = $fav.AdvancedSearch.Status -and $fav.AdvancedSearch.Status -ne "All"
                $hasDateRange      = $fav.AdvancedSearch.DateRange -and $fav.AdvancedSearch.DateRange -ne "Any time"
                $hasCustomDates    = $fav.AdvancedSearch.CustomDateStart -and $fav.AdvancedSearch.CustomDateEnd
                $hasExactMatch     = $fav.AdvancedSearch.ExactMatch -eq $true
                $hasIncludeInactive = $fav.AdvancedSearch.IncludeInactive -eq $true

                if (-not ($hasLocation -or $hasStatus -or $hasDateRange -or $hasCustomDates -or $hasExactMatch -or $hasIncludeInactive)) {
                    # All defaults — clone via JSON and strip the property
                    try {
                        $favJson  = $fav | ConvertTo-Json -Depth 10 -ErrorAction Stop
                        $favClone = $favJson | ConvertFrom-Json -ErrorAction Stop
                        if ($favClone.PSObject.Properties['AdvancedSearch']) {
                            $favClone.PSObject.Properties.Remove('AdvancedSearch')
                        }
                        $cleaned += $favClone
                    }
                    catch {
                        Write-Warning "Error cloning favorite '$($fav.Name)' during cleanup: $_"
                        $cleaned += $fav
                    }
                }
                else {
                    $cleaned += $fav
                }
            }
            else {
                $cleaned += $fav
            }
        }
        catch {
            Write-Warning "Error cleaning up favorite '$($fav.Name)': $_"
            $cleaned += $fav
        }
    }

    # Safety check: warn if any favourites were unexpectedly lost
    if ($cleaned.Count -lt $inputCount) {
        Write-Warning "Remove-DefaultAdvancedSearch: Lost $($inputCount - $cleaned.Count) favorites during cleanup (input: $inputCount, output: $($cleaned.Count))"
    }

    return $cleaned
}

function Repair-FavoritesJson {
    <#
    .SYNOPSIS
        Attempts to extract a valid JSON array from corrupted favorites content.
    .DESCRIPTION
        When two JSON arrays are concatenated (e.g. by a partial write followed
        by a full write), the file becomes invalid. This function scans for every
        '[' character after position 0 and tries to parse from there to the end.
        The last position that yields valid JSON wins (most complete data).
    .PARAMETER Content
        The raw (potentially corrupted) file content.
    .PARAMETER FilePath
        Optional path used only for diagnostic messages; not read or written.
    .OUTPUTS
        System.Object[] or $null — the parsed array on success, $null on failure.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Content,

        [string]$FilePath = ""
    )

    $bestResult = $null
    $searchFrom = 1
    while ($searchFrom -lt $Content.Length) {
        $idx = $Content.IndexOf('[', $searchFrom)
        if ($idx -lt 0) { break }
        $candidate = $Content.Substring($idx)
        try {
            $parsed = $candidate | ConvertFrom-Json -ErrorAction Stop
            if ($null -ne $parsed) {
                $arr = if ($parsed -is [Array]) { @($parsed) } else { @($parsed) }
                if ($null -eq $bestResult -or $arr.Count -gt $bestResult.Count) {
                    $bestResult = $arr
                }
            }
        } catch {}
        $searchFrom = $idx + 1
    }

    if ($null -ne $bestResult -and $bestResult.Count -gt 0) {
        return , $bestResult
    }
    return $null
}

function Read-FavoritesFromFile {
    <#
    .SYNOPSIS
        Reads and parses favorites from a single file path with auto-repair.
    .DESCRIPTION
        Tries ConvertFrom-Json first; on failure, attempts Repair-FavoritesJson
        to recover from concatenated/corrupted files. When repair succeeds the
        file is rewritten with clean JSON to prevent future failures.
    .PARAMETER Path
        Full path to the favorites JSON file.
    .OUTPUTS
        System.Object[] — the parsed favourites, or an empty array.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) { return , @() }

    try {
        $content = Get-Content -Path $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($content)) { return , @() }

        try {
            $parsed = $content | ConvertFrom-Json -ErrorAction Stop
            if ($null -ne $parsed) {
                return $(if ($parsed -is [Array]) { , @($parsed) } else { , @($parsed) })
            }
            return , @()
        }
        catch {
            $repaired = Repair-FavoritesJson -Content $content -FilePath $Path
            if ($null -ne $repaired -and $repaired.Count -gt 0) {
                try {
                    $json = $repaired | ConvertTo-Json -Depth 10 -Compress:$false
                    $json | Out-File -FilePath $Path -Encoding UTF8 -Force -ErrorAction Stop
                } catch {}
                return , $repaired
            }
            return , @()
        }
    }
    catch { return , @() }
}

function Read-Favorites {
    <#
    .SYNOPSIS
        Reads saved favorites from the favorites file.
    .DESCRIPTION
        Loads the JSON favorites file referenced by $global:AppConfig.FavoritesFile.
        Always returns an array, even for a single favourite. When the primary
        path fails or is corrupt, falls back to the local data path. Corrupted
        files (e.g. from concatenated writes) are auto-repaired.
    .OUTPUTS
        System.Object[]
        An array of favourite objects. Returns an empty array if no favourites
        exist or the file cannot be read.
    .EXAMPLE
        $favorites = Read-Favorites
    #>
    [CmdletBinding()]
    param ()

    $favoritesPath = $null
    try { $favoritesPath = $global:AppConfig.FavoritesFile } catch {}

    if ([string]::IsNullOrWhiteSpace($favoritesPath)) {
        $favoritesPath = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data\favorites.json"
    }

    $result = Read-FavoritesFromFile -Path $favoritesPath

    if ($result.Count -eq 0) {
        $localFallback = Join-Path -Path $env:ProgramData -ChildPath "ADapp\Data\favorites.json"
        if ($localFallback -ne $favoritesPath) {
            $result = Read-FavoritesFromFile -Path $localFallback
        }
    }

    return , $result
}

function Read-FavoritesFromPath {
    <#
    .SYNOPSIS
        Reads favorites from a specific file path.
    .DESCRIPTION
        Low-level helper that loads and parses a single favorites JSON file.
        Always returns an array (empty on failure).
    .PARAMETER Path
        Full path to the favorites JSON file.
    .OUTPUTS
        System.Object[]
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        try { Write-Log -Message "Read-FavoritesFromPath: file not found '$Path'" -Level "Warning" } catch {}
        return , @()
    }

    try {
        $content = Get-Content -Path $Path -Raw -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($content)) {
            try { Write-Log -Message "Read-FavoritesFromPath: file is empty '$Path'" -Level "Warning" } catch {}
            return , @()
        }

        $parsed = $content | ConvertFrom-Json -ErrorAction Stop

        if ($null -eq $parsed) {
            return , @()
        }

        $favorites = if ($parsed -is [Array]) { $parsed } else { @($parsed) }

        try { Write-Log -Message "Read-FavoritesFromPath: loaded $($favorites.Count) favorite(s) from '$Path'" -Level "Info" } catch {}
        return , $favorites
    }
    catch {
        try { Write-Log -Message "Read-FavoritesFromPath: error reading '$Path': $_" -Level "Warning" } catch {}
        return , @()
    }
}

function Save-Favorites {
    <#
    .SYNOPSIS
        Saves favorites to the favorites file.
    .DESCRIPTION
        Serialises the supplied favorites array to JSON and writes it atomically
        to the path specified in $global:AppConfig.FavoritesFile. A temporary
        file is written first and validated before replacing the original, to
        guard against partial writes corrupting the file.
    .PARAMETER favorites
        Array of favorite objects to persist.
    .OUTPUTS
        None
    .EXAMPLE
        Save-Favorites -favorites @($fav1, $fav2)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $favorites
    )

    $favoritesPath = $global:AppConfig.FavoritesFile
    try {
        $favoritesArray = @($favorites)
        $originalCount  = $favoritesArray.Count

        # Temporarily disabled: Remove-DefaultAdvancedSearch cleanup
        # TODO: Re-enable once confirmed cleanup is working correctly
        # $favoritesArray = Remove-DefaultAdvancedSearch -favorites $favoritesArray

        try { Write-Log -Message "Save-Favorites: path='$favoritesPath' count='$($favoritesArray.Count)' (original: $originalCount)" -Level "Info" } catch { }

        # Ensure the parent directory exists
        $dir = Split-Path $favoritesPath -Parent
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        $json = $favoritesArray | ConvertTo-Json -Depth 10 -Compress:$false

        # Validate the generated JSON before writing to disk
        try {
            $null = $json | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Warning "Generated JSON is invalid: $_"
            throw "Failed to generate valid JSON for favorites"
        }

        # Atomic write: temp file → validate → replace original
        $tempFile = $favoritesPath + ".tmp"
        $json | Out-File -FilePath $tempFile -Encoding UTF8 -Force -ErrorAction Stop

        try {
            $testContent = Get-Content -Path $tempFile -Raw -ErrorAction Stop
            $null = $testContent | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Warning "Written file validation failed: $_"
            if (Test-Path $tempFile) {
                Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
            }
            throw "Failed to validate written favorites file"
        }

        Move-Item -Path $tempFile -Destination $favoritesPath -Force -ErrorAction Stop
    }
    catch {
        Write-Warning "Error saving favorites: $_"
        $tempFile = $favoritesPath + ".tmp"
        if (Test-Path $tempFile) {
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Update-FavoritesMenu {
    <#
    .SYNOPSIS
        Updates the favorites dropdown menu with current favorites.
    .DESCRIPTION
        Clears and rebuilds the supplied ToolStripMenuItem with an "Add Current
        Search…" option, individual favourite items that trigger a search when
        clicked, and a "Clear All Favorites" option at the bottom.
    .PARAMETER FavoritesMenu
        The ToolStripMenuItem to populate.
    .OUTPUTS
        None
    .EXAMPLE
        Update-FavoritesMenu -FavoritesMenu $global:favoritesMenu
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ToolStripMenuItem]$FavoritesMenu
    )

    if (-not $FavoritesMenu) { return }

    $favorites = Read-Favorites

    $FavoritesMenu.DropDownItems.Clear()

    #region Add Current Search option
    $addItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $addItem.Text = "Add Current Search..."
    $addItem.Add_Click({
        $searchTerm = $global:searchTextBox.Text
        if ([string]::IsNullOrWhiteSpace($searchTerm)) {
            [System.Windows.Forms.MessageBox]::Show(
                "No search term to save.",
                "Add Favorite",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return
        }

        $favorites = Read-Favorites
        $newFavorite = [PSCustomObject]@{
            SearchTerm = $searchTerm
            SearchType = $global:searchTypeCombo.SelectedItem.ToString()
            DateAdded  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }

        # Prevent duplicate entries
        $existing = $favorites | Where-Object { $_.SearchTerm -eq $searchTerm }
        if ($existing) {
            [System.Windows.Forms.MessageBox]::Show(
                "'$searchTerm' is already in favorites.",
                "Add Favorite",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            return
        }

        $favorites = @($favorites) + @($newFavorite)
        Save-Favorites -favorites $favorites
        Update-FavoritesMenu -FavoritesMenu $global:favoritesMenu
        [System.Windows.Forms.MessageBox]::Show(
            "Added '$searchTerm' to favorites.",
            "Add Favorite",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    })
    [void]$FavoritesMenu.DropDownItems.Add($addItem)
    #endregion Add Current Search option

    #region Favorite items
    if ($favorites.Count -gt 0) {
        [void]$FavoritesMenu.DropDownItems.Add("-")

        foreach ($fav in $favorites) {
            $item = New-Object System.Windows.Forms.ToolStripMenuItem
            $item.Text = "$($fav.SearchTerm) ($($fav.SearchType))"
            $item.Tag = $fav
            $item.Add_Click({
                param($sender, $e)
                $favorite = $sender.Tag
                $global:searchTextBox.Text = $favorite.SearchTerm
                if ($global:searchTypeCombo.Items.Contains($favorite.SearchType)) {
                    $global:searchTypeCombo.SelectedItem = $favorite.SearchType
                }
                $global:searchButton.PerformClick()
            })
            [void]$FavoritesMenu.DropDownItems.Add($item)
        }

        # Separator and clear option
        [void]$FavoritesMenu.DropDownItems.Add("-")
        $clearItem = New-Object System.Windows.Forms.ToolStripMenuItem
        $clearItem.Text = "Clear All Favorites"
        $clearItem.Add_Click({
            $result = [System.Windows.Forms.MessageBox]::Show(
                "Clear all favorites?",
                "Confirm",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                Save-Favorites -favorites @()
                Update-FavoritesMenu -FavoritesMenu $global:favoritesMenu
            }
        })
        [void]$FavoritesMenu.DropDownItems.Add($clearItem)
    }
    #endregion Favorite items
}

#endregion Functions

# ── Module Exports ────────────────────────────────────────────────────────────
Export-ModuleMember -Function Read-Favorites, Save-Favorites, Update-FavoritesMenu
