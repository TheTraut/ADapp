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

function Read-Favorites {
    <#
    .SYNOPSIS
        Reads saved favorites from the favorites file.
    .DESCRIPTION
        Loads the JSON favorites file referenced by $global:AppConfig.FavoritesFile.
        Always returns an array, even for a single favourite.
    .OUTPUTS
        System.Object[]
        An array of favourite objects. Returns an empty array if no favourites
        exist or the file cannot be read.
    .EXAMPLE
        $favorites = Read-Favorites
    #>
    [CmdletBinding()]
    param ()

    $favoritesPath = $global:AppConfig.FavoritesFile
    if (Test-Path $favoritesPath) {
        try {
            $content   = Get-Content -Path $favoritesPath -Raw -ErrorAction Stop
            $favorites = $content | ConvertFrom-Json -ErrorAction Stop

            if ($null -eq $favorites) {
                return @()
            }
            elseif ($favorites -is [Array]) {
                $favorites = $favorites
            }
            else {
                $favorites = @($favorites)
            }

            return $favorites
        }
        catch {
            Write-Warning "Error loading favorites: $_"
            return @()
        }
    }
    return @()
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
