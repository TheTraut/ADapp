#Requires -Version 5.1

<#
.SYNOPSIS
    UI module for the ADapp application.
.DESCRIPTION
    Contains all Windows Forms UI construction, layout helpers, and display
    utilities used by ADapp. Provides the main form initialisation, ListView
    helpers, Markdown rendering, and the PDQ Deploy package picker dialog.
.NOTES
    Module : UI
    Author : ADapp Team
#>

# Load UI assemblies early so type references resolve during import
try { Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop | Out-Null } catch {}
try { Add-Type -AssemblyName System.Drawing -ErrorAction Stop | Out-Null } catch {}

# Script-scoped variables shared across functions
$script:form                    = $null
$script:progressBar             = $null
$script:statusLabel             = $null
$script:menuStrip               = $null
$script:searchBox               = $null
$script:typeCombo               = $null
$script:searchButton            = $null
$script:listView                = $null
$script:basicInfoPanel          = $null
$script:basicInfoListView       = $null
$script:usersListPanel          = $null
$script:loggedInUsersView       = $null
$script:favoritesMenu           = $null
$script:historyMenu             = $null
$script:PrimaryColor            = [System.Drawing.Color]::FromArgb(0, 99, 177)
$script:SecondaryColor          = [System.Drawing.ColorTranslator]::FromHtml("#f2f2f2")
$script:ListViewComparerTypeName = "ListViewItemComparer"

#region C# Embedded Types

# Add-Type for ListView sorting -- used by Add-ListViewSorting to sort columns.
# The type is only compiled once; a fallback with a unique name is tried on conflict.
try {
    if (-not ([System.Management.Automation.PSTypeName]"$script:ListViewComparerTypeName").Type) {
        Add-Type -TypeDefinition @"
using System;
using System.Windows.Forms;
using System.Collections;

public class $script:ListViewComparerTypeName : IComparer
{
    private int col;
    private bool ascending;

    public $script:ListViewComparerTypeName(int column, bool asc)
    {
        col = column;
        ascending = asc;
    }

    public int Compare(object x, object y)
    {
        ListViewItem itemX = (ListViewItem)x;
        ListViewItem itemY = (ListViewItem)y;

        // Get the values to compare
        string strX = itemX.SubItems[col].Text;
        string strY = itemY.SubItems[col].Text;

        // Try to parse as numbers for numeric columns
        double numX, numY;
        bool isNumX = double.TryParse(strX, out numX);
        bool isNumY = double.TryParse(strY, out numY);

        if (isNumX && isNumY)
        {
            return ascending ? numX.CompareTo(numY) : numY.CompareTo(numX);
        }
        else
        {
            return ascending ? String.Compare(strX, strY) : String.Compare(strY, strX);
        }
    }
}
"@ -ReferencedAssemblies System.Windows.Forms -ErrorAction Stop
    }
}
catch {
    # Assembly may be locked; fall back to a timestamped unique type name
    Write-Log -Message "Error adding ListView comparer type: $_" -Level "Warning"

    try {
        $uniqueTypeName = "$script:ListViewComparerTypeName$(Get-Date -Format 'yyyyMMddHHmmss')"
        $script:ListViewComparerTypeName = $uniqueTypeName

        Add-Type -TypeDefinition @"
using System;
using System.Windows.Forms;
using System.Collections;

public class $uniqueTypeName : IComparer
{
    private int col;
    private bool ascending;

    public $uniqueTypeName(int column, bool asc)
    {
        col = column;
        ascending = asc;
    }

    public int Compare(object x, object y)
    {
        ListViewItem itemX = (ListViewItem)x;
        ListViewItem itemY = (ListViewItem)y;

        // Basic string comparison for simplicity in fallback
        string strX = itemX.SubItems[col].Text;
        string strY = itemY.SubItems[col].Text;

        return ascending ? String.Compare(strX, strY) : String.Compare(strY, strX);
    }
}
"@ -ReferencedAssemblies System.Windows.Forms -ErrorAction Stop
    }
    catch {
        Write-Log -Message "Critical error adding ListView comparer type: $_" -Level "Error"
        # Continue without sorting capability
    }
}

#endregion C# Embedded Types

#region Functions

function Test-ComputerOnline {
    <#
    .SYNOPSIS
        Tests whether a computer is online using ICMP ping with retries and timeout.
    .DESCRIPTION
        Performs a lightweight ping check using .NET Ping with configurable timeout
        and retry attempts. Domain suffixes are stripped before pinging.
        Returns $true if any attempt succeeds, otherwise $false.
    .PARAMETER ComputerName
        The target computer NetBIOS or FQDN. Domain suffix, if present, is stripped.
    .PARAMETER TimeoutMilliseconds
        Timeout in milliseconds for each ping attempt. Defaults to 500ms.
    .PARAMETER Retries
        Number of retry attempts. Defaults to 1.
    .OUTPUTS
        System.Boolean. $true if reachable; otherwise $false.
    .EXAMPLE
        Test-ComputerOnline -ComputerName "WORKSTATION01"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [int]$TimeoutMilliseconds = 500,

        [int]$Retries = 1
    )

    try {
        # Strip domain suffix so the ping targets the short name only
        $ComputerName = $ComputerName.Split('.')[0].Trim()

        for ($i = 0; $i -lt $Retries; $i++) {
            try {
                $pingOptions = New-Object System.Net.NetworkInformation.PingOptions
                $ping = New-Object System.Net.NetworkInformation.Ping
                $reply = $ping.Send($ComputerName, $TimeoutMilliseconds, [byte[]]::new(32), $pingOptions)

                if ($reply.Status -eq 'Success') {
                    return $true
                }

                # Brief pause between retries to avoid flooding
                if ($i -lt $Retries - 1) {
                    Start-Sleep -Milliseconds 100
                }
            }
            catch {
                continue
            }
        }

        return $false
    }
    catch {
        Write-Log -Message "Error testing connection to $ComputerName`: $_" -Level "Warning"
        return $false
    }
}

function Set-ListViewItemColor {
    <#
    .SYNOPSIS
        Sets per-item foreground and/or background color for a ListViewItem.
    .DESCRIPTION
        Updates the foreground and background colors on a ListViewItem when the
        supplied color values are not Color.Empty. Useful for highlighting status
        conditions in list views.
    .PARAMETER Item
        The ListViewItem to update.
    .PARAMETER ForeColor
        Optional foreground color. Defaults to Color.Empty (no change).
    .PARAMETER BackColor
        Optional background color. Defaults to Color.Empty (no change).
    .OUTPUTS
        None.
    .EXAMPLE
        Set-ListViewItemColor -Item $lvItem -ForeColor ([System.Drawing.Color]::Red)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListViewItem]$Item,

        [Parameter(Mandatory = $false)]
        [System.Drawing.Color]$ForeColor = [System.Drawing.Color]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Drawing.Color]$BackColor = [System.Drawing.Color]::Empty
    )

    try {
        if ($ForeColor -ne [System.Drawing.Color]::Empty) {
            $Item.ForeColor = $ForeColor
        }

        if ($BackColor -ne [System.Drawing.Color]::Empty) {
            $Item.BackColor = $BackColor
        }
    }
    catch {
        Write-Log -Message "Error setting ListView item color: $_" -Level "Warning"
    }
}

function Add-ListViewSorting {
    <#
    .SYNOPSIS
        Adds click-to-sort behavior to a ListView with visual indicators.
    .DESCRIPTION
        Wires ColumnClick to toggle ascending/descending sort per column using a
        dynamic IComparer type. Updates column headers with ^ / v indicators and
        remembers last sort state. A third click on the same column restores the
        original unsorted order.
    .PARAMETER ListView
        The ListView control to enable sorting on.
    .OUTPUTS
        None.
    .EXAMPLE
        Add-ListViewSorting -ListView $myListView
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListView]$ListView
    )

    try {
        # Clickable headers let users discover sortability
        $ListView.HeaderStyle = [System.Windows.Forms.ColumnHeaderStyle]::Clickable

        if ([string]::IsNullOrEmpty($script:ListViewComparerTypeName)) {
            Write-Log -Message "ListView sorting unavailable: No comparer type defined" -Level "Warning"
            return
        }

        # Store sort state in the Tag property so it travels with the control
        $ListView.Tag = @{
            SortOrder      = @{}
            LastColumn     = $null
            OriginalItems  = $null
        }

        $ListView.Add_ColumnClick({
            param($sender, $e)

            try {
                $listView = $sender
                $column = $e.Column
                $tag = $listView.Tag

                if (-not $tag) {
                    $tag = @{
                        SortOrder     = @{}
                        LastColumn    = $null
                        OriginalItems = $null
                    }
                    $listView.Tag = $tag
                }

                # Cycle: ascending -> descending -> unsorted
                $hasExisting = $tag.SortOrder.ContainsKey($column)
                $ascending = $true
                $state = 'Ascending'

                if (-not $hasExisting -or $tag.LastColumn -ne $column) {
                    $ascending = $true
                    $state = 'Ascending'
                    $tag.SortOrder.Clear()
                    $tag.SortOrder[$column] = $true
                    $tag.LastColumn = $column
                }
                elseif ($tag.SortOrder[$column]) {
                    $ascending = $false
                    $state = 'Descending'
                    $tag.SortOrder[$column] = $false
                    $tag.LastColumn = $column
                }
                else {
                    $state = 'None'
                    $tag.SortOrder.Remove($column) | Out-Null
                    $tag.LastColumn = $null
                }

                $comparerType = [Type]::GetType($script:ListViewComparerTypeName)
                if ($null -eq $comparerType) {
                    # Fall back to scanning loaded assemblies
                    $comparerType = [AppDomain]::CurrentDomain.GetAssemblies() |
                        ForEach-Object { $_.GetTypes() } |
                        Where-Object { $_.Name -eq $script:ListViewComparerTypeName } |
                        Select-Object -First 1
                }

                if ($state -eq 'None') {
                    $listView.ListViewItemSorter = $null
                    if ($tag.OriginalItems -and $tag.OriginalItems.Count -gt 0) {
                        $listView.BeginUpdate()
                        $listView.Items.Clear()
                        [void]$listView.Items.AddRange($tag.OriginalItems)
                        $listView.EndUpdate()
                    }
                }
                elseif ($null -ne $comparerType) {
                    # Snapshot original order before the first sort
                    if (-not $tag.OriginalItems -or $tag.OriginalItems.Count -ne $listView.Items.Count) {
                        $tag.OriginalItems = @($listView.Items)
                    }

                    $comparer = New-Object -TypeName $comparerType.FullName -ArgumentList $column, $ascending
                    $listView.ListViewItemSorter = $comparer
                    $listView.Sort()
                }
                else {
                    Write-Log -Message "ListView sorting failed: Unable to create comparer type" -Level "Warning"
                }

                # Refresh header text with sort direction indicators
                for ($i = 0; $i -lt $listView.Columns.Count; $i++) {
                    $colHeader = $listView.Columns[$i]
                    $text = $colHeader.Text

                    $text = $text -replace ' [\^v]$', ''

                    if ($state -ne 'None' -and $i -eq $column) {
                        $indicator = if ($ascending) { '^' } else { 'v' }
                        $text += " $indicator"
                    }

                    $colHeader.Text = $text
                }
            }
            catch {
                Write-Log -Message "Error in ListView sorting: $_" -Level "Error"
            }
        })
    }
    catch {
        Write-Log -Message "Error adding ListView sorting: $_" -Level "Error"
    }
}

function CreateBasicInfoListView {
    <#
    .SYNOPSIS
        Creates and configures a two-column ListView for key/value details.
    .DESCRIPTION
        Returns a ListView configured for details view with grid lines and sorting
        support. The second column width is sized relative to the current basic info
        panel width.
    .OUTPUTS
        System.Windows.Forms.ListView.
    .EXAMPLE
        $lv = CreateBasicInfoListView
    #>
    [CmdletBinding()]
    param ()

    [void]($listView = [System.Windows.Forms.ListView]::new())
    $listView.View = [System.Windows.Forms.View]::Details
    $listView.FullRowSelect = $true
    $listView.GridLines = $true
    $listView.Dock = [System.Windows.Forms.DockStyle]::Fill
    $listView.HeaderStyle = [System.Windows.Forms.ColumnHeaderStyle]::Nonclickable
    $listView.BackColor = [System.Drawing.Color]::White
    $listView.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle

    [void]$listView.Columns.Add("Field", 130)
    [void]$listView.Columns.Add("Value", $basicInfoPanel.Width - 135)

    Add-ListViewSorting -ListView $listView

    return $listView
}

function AddDetailLabel {
    <#
    .SYNOPSIS
        Adds a labeled field/value pair to the basic info ListView.
    .DESCRIPTION
        Creates a ListViewItem with the field and value; applies contextual background
        color for common status values (e.g., LOCKED, DISABLED, Online/Offline) to
        improve readability at a glance.
    .PARAMETER field
        The label text for the field.
    .PARAMETER value
        The value text to display.
    .OUTPUTS
        None.
    .EXAMPLE
        AddDetailLabel -field "Status:" -value "ENABLED"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$field,

        [Parameter(Mandatory = $true)]
        [string]$value
    )

    $item = New-Object System.Windows.Forms.ListViewItem($field)
    $item.UseItemStyleForSubItems = $false
    [void]$item.SubItems.Add($value)

    # Colour-code status values so they stand out visually
    if ($field -match "Status:") {
        if ($value -match "LOCKED|DISABLED|Offline") {
            $item.SubItems[1].BackColor = [System.Drawing.Color]::LightPink
        }
        elseif ($value -match "ENABLED|Online") {
            $item.SubItems[1].BackColor = [System.Drawing.Color]::LightGreen
        }
    }

    [void]$script:basicInfoListView.Items.Add($item)
}

function ShowNoResults {
    <#
    .SYNOPSIS
        Displays a placeholder message in a ListView when no results are available.
    .DESCRIPTION
        Clears the ListView and inserts a single gray-colored item with the supplied
        message text, giving users clear feedback that no data was found.
    .PARAMETER listView
        The ListView control to update.
    .PARAMETER message
        The text to display.
    .OUTPUTS
        None.
    .EXAMPLE
        ShowNoResults -listView $lv -message "No matching records found."
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListView]$listView,

        [Parameter(Mandatory = $true)]
        [string]$message
    )

    $listView.Items.Clear()
    $item = New-Object System.Windows.Forms.ListViewItem($message)
    $item.ForeColor = [System.Drawing.Color]::Gray
    [void]$listView.Items.Add($item)
}

function Convert-MarkdownToHtml {
    <#
    .SYNOPSIS
        Converts a minimal subset of Markdown to styled HTML.
    .DESCRIPTION
        Supports headers (#, ##), unordered lists, and paragraphs. Intended for
        lightweight rendering in embedded WebBrowser controls rather than full
        Markdown fidelity.
    .PARAMETER markdown
        The markdown text to convert.
    .OUTPUTS
        System.String. Returns HTML markup.
    .EXAMPLE
        $html = Convert-MarkdownToHtml -markdown "# Hello`n- item one"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$markdown
    )

    $html = @"
<html>
<head>
<style>
body { font-family: Segoe UI, Tahoma, Geneva, Verdana, sans-serif; margin: 10px; }
h1 { font-size: 1.5em; }
h2 { font-size: 1.3em; }
ul { padding-left: 20px; }
li { margin-bottom: 5px; }
p { margin-bottom: 10px; }
</style>
</head>
<body>
"@

    $lines = $markdown -split "`n"
    $inList = $false
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed -match "^# (.*)") {
            $html += "<h1>" + $matches[1] + "</h1>`n"
        }
        elseif ($trimmed -match "^## (.*)") {
            $html += "<h2>" + $matches[1] + "</h2>`n"
        }
        elseif ($trimmed -match "^- (.*)") {
            if (-not $inList) {
                $html += "<ul>`n"
                $inList = $true
            }
            $html += "<li>" + $matches[1] + "</li>`n"
        }
        else {
            if ($inList) {
                $html += "</ul>`n"
                $inList = $false
            }
            if ($trimmed -ne "") {
                $html += "<p>" + $trimmed + "</p>`n"
            }
        }
    }
    if ($inList) {
        $html += "</ul>`n"
    }
    $html += "</body></html>"
    return $html
}

function Show-MarkdownWindow {
    <#
    .SYNOPSIS
        Shows a simple, resizable window rendering provided Markdown content.
    .DESCRIPTION
        Converts Markdown to HTML via Convert-MarkdownToHtml and displays it in a
        WebBrowser control within a modal dialog.
    .PARAMETER Title
        Window title text.
    .PARAMETER MarkdownText
        Markdown content to render inside the window.
    .OUTPUTS
        None.
    .EXAMPLE
        Show-MarkdownWindow -Title "Help" -MarkdownText "# Welcome"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$MarkdownText
    )

    $html = Convert-MarkdownToHtml -markdown $MarkdownText
    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = $Title
    $dialog.Size = New-Object System.Drawing.Size(600, 400)
    $dialog.StartPosition = "CenterParent"

    $webBrowser = New-Object System.Windows.Forms.WebBrowser
    $webBrowser.Dock = [System.Windows.Forms.DockStyle]::Fill
    $webBrowser.DocumentText = $html
    $dialog.Controls.Add($webBrowser)
    $dialog.ShowDialog()
}

function Show-MarkdownDialog {
    <#
    .SYNOPSIS
        Shows a modal dialog rendering Markdown with a Close button.
    .DESCRIPTION
        Renders Markdown to HTML, embeds it in a fixed-size dialog with a Close
        button, and disables navigation and the context menu for a controlled
        read-only view.
    .PARAMETER Title
        Dialog title text.
    .PARAMETER MarkdownContent
        Markdown content to display.
    .OUTPUTS
        None.
    .EXAMPLE
        Show-MarkdownDialog -Title "Release Notes" -MarkdownContent $md
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$MarkdownContent
    )

    try {
        $html = Convert-MarkdownToHtml -markdown $MarkdownContent

        $dialogForm = New-Object System.Windows.Forms.Form
        $dialogForm.Text = $Title
        $dialogForm.Size = New-Object System.Drawing.Size(600, 400)
        $dialogForm.StartPosition = "CenterScreen"
        $dialogForm.MinimizeBox = $false
        $dialogForm.MaximizeBox = $false
        $dialogForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog

        $webBrowser = New-Object System.Windows.Forms.WebBrowser
        $webBrowser.Dock = [System.Windows.Forms.DockStyle]::Fill
        $webBrowser.IsWebBrowserContextMenuEnabled = $false
        $webBrowser.AllowNavigation = $false
        $webBrowser.DocumentText = $html
        $dialogForm.Controls.Add($webBrowser)

        $closeButton = New-Object System.Windows.Forms.Button
        $closeButton.Text = "Close"
        $closeButton.Size = New-Object System.Drawing.Size(75, 23)
        $closeButton.Location = New-Object System.Drawing.Point(($dialogForm.ClientSize.Width - 85), ($dialogForm.ClientSize.Height - 35))
        $closeButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
        $closeButton.Add_Click({ $dialogForm.Close() })
        $dialogForm.Controls.Add($closeButton)

        $dialogForm.ActiveControl = $closeButton

        [void]$dialogForm.ShowDialog()
    }
    catch {
        Write-Log -Message "Error showing markdown dialog: $_" -Level "Error"
        [System.Windows.Forms.MessageBox]::Show("Could not display content: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Initialize-ADUI {
    <#
    .SYNOPSIS
        Initializes and lays out the main Windows Forms UI for the application.
    .DESCRIPTION
        Creates the main form, menus (File, Search, History, Favorites), status
        strip, search panel, results and details views, and wires up icons and
        menu handlers. Exports controls to $global: scope for use by other modules.
    .OUTPUTS
        None.
    .EXAMPLE
        Initialize-ADUI
    #>
    [CmdletBinding()]
    param ()

    [void][System.Windows.Forms.Application]::EnableVisualStyles()
    $script:form = [System.Windows.Forms.Form]::new()
    $script:form.Text = "AD Search Tool"
    $script:form.Size = New-Object System.Drawing.Size(960, 600)
    $script:form.StartPosition = "CenterScreen"
    $script:form.MinimumSize = New-Object System.Drawing.Size(960, 600)

    $iconPath = Join-Path $PSScriptRoot "..\assets\icons\adapp.ico"
    if (Test-Path $iconPath) {
        $script:form.Icon = [System.Drawing.Icon]::new($iconPath)
    }
    else {
        Write-Warning "Icon file not found at $iconPath - using default icon"
    }

    # ── Menu strip ──────────────────────────────────────────────────────
    $script:menuStrip = New-Object System.Windows.Forms.MenuStrip
    $script:menuStrip.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
    $script:form.MainMenuStrip = $script:menuStrip
    $script:form.Controls.Add($script:menuStrip)

    # File menu
    $fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $fileMenu.Text = "File"
    $script:menuStrip.Items.Add($fileMenu)

    $aboutMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $aboutMenuItem.Text = "About"
    $aboutMenuItem.Add_Click({
        try {
            $aboutPath = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath "ABOUT.md"
            if (Test-Path $aboutPath) {
                $aboutContent = Get-Content -Path $aboutPath -Raw
                Show-MarkdownDialog -Title "About AD Management Tool" -MarkdownContent $aboutContent
            }
            else {
                [System.Windows.Forms.MessageBox]::Show(
                    "About information file not found.",
                    "Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Error
                ) | Out-Null
            }
        }
        catch {
            Write-Log -Message "Error displaying About information: $_" -Level "Error"
        }
    })
    $fileMenu.DropDownItems.Add($aboutMenuItem)

    $changeLogMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $changeLogMenuItem.Text = "Change Log"
    $changeLogMenuItem.Add_Click({
        $md = @"
# Change Log 2/7/2025
- Added favorites and search history functionality
- Added About and Change Log menu items
- Added last password set date to user/computer details
- Fixed issue with last logon time not being the correct date
"@
        Show-MarkdownDialog -Title "Change Log" -MarkdownContent $md
    })
    $fileMenu.DropDownItems.Add($changeLogMenuItem)

    $fileMenu.DropDownItems.Add("-")

    $exitMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $exitMenuItem.Text = "Exit"
    $exitMenuItem.Add_Click({ $script:form.Close() })
    $fileMenu.DropDownItems.Add($exitMenuItem)

    # Search menu
    $searchMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $searchMenu.Text = "Search"
    $script:menuStrip.Items.Add($searchMenu)

    $script:historyMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $script:historyMenu.Text = "History"
    $searchMenu.DropDownItems.Add($script:historyMenu)

    $script:favoritesMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $script:favoritesMenu.Text = "Favorites"
    $searchMenu.DropDownItems.Add($script:favoritesMenu)

    # ── Status strip ────────────────────────────────────────────────────
    $statusStrip = New-Object System.Windows.Forms.StatusStrip
    $script:statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $script:statusLabel.Text = "Ready"
    $statusStrip.Items.Add($script:statusLabel)

    $script:progressBar = New-Object System.Windows.Forms.ToolStripProgressBar
    $script:progressBar.Visible = $false
    $statusStrip.Items.Add($script:progressBar)

    $script:form.Controls.Add($statusStrip)

    # ── Search panel ────────────────────────────────────────────────────
    $searchPanel = New-Object System.Windows.Forms.Panel
    $searchPanel.Dock = [System.Windows.Forms.DockStyle]::Top
    $searchPanel.Height = 50
    $searchPanel.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
    $searchPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $script:form.Controls.Add($searchPanel)

    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.Text = "Search:"
    $searchLabel.Location = New-Object System.Drawing.Point(10, 15)
    $searchLabel.Size = New-Object System.Drawing.Size(50, 20)
    $searchPanel.Controls.Add($searchLabel)

    $script:searchBox = New-Object System.Windows.Forms.TextBox
    $script:searchBox.Location = New-Object System.Drawing.Point(65, 12)
    $script:searchBox.Size = New-Object System.Drawing.Size(250, 20)
    $searchPanel.Controls.Add($script:searchBox)

    $typeLabel = New-Object System.Windows.Forms.Label
    $typeLabel.Text = "Type:"
    $typeLabel.Location = New-Object System.Drawing.Point(325, 15)
    $typeLabel.Size = New-Object System.Drawing.Size(40, 20)
    $searchPanel.Controls.Add($typeLabel)

    $script:typeCombo = New-Object System.Windows.Forms.ComboBox
    $script:typeCombo.Location = New-Object System.Drawing.Point(370, 12)
    $script:typeCombo.Size = New-Object System.Drawing.Size(120, 20)
    $script:typeCombo.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $script:typeCombo.Items.Add("All")
    $script:typeCombo.Items.Add("User")
    $script:typeCombo.Items.Add("Computer")
    $script:typeCombo.SelectedIndex = 0
    $searchPanel.Controls.Add($script:typeCombo)

    $script:searchButton = New-Object System.Windows.Forms.Button
    $script:searchButton.Text = "Search"
    $script:searchButton.Location = New-Object System.Drawing.Point(500, 11)
    $script:searchButton.Size = New-Object System.Drawing.Size(75, 23)
    $script:searchButton.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
    $script:searchButton.ForeColor = [System.Drawing.Color]::White
    $script:searchButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $searchPanel.Controls.Add($script:searchButton)

    # ── Main content area ───────────────────────────────────────────────
    $containerPanel = New-Object System.Windows.Forms.SplitContainer
    $containerPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $containerPanel.Orientation = [System.Windows.Forms.Orientation]::Horizontal
    $containerPanel.SplitterDistance = 250
    $script:form.Controls.Add($containerPanel)

    # Results list view
    $script:listView = New-Object System.Windows.Forms.ListView
    $script:listView.Name = "MainResultsListView"
    $script:listView.Dock = [System.Windows.Forms.DockStyle]::Fill
    $script:listView.View = [System.Windows.Forms.View]::Details
    $script:listView.FullRowSelect = $true
    $script:listView.GridLines = $true
    $script:listView.HideSelection = $false

    $script:listView.Columns.Add("Type", 80)
    $script:listView.Columns.Add("Name", 150)
    $script:listView.Columns.Add("Details", 250)
    $script:listView.Columns.Add("Status", 80)
    $script:listView.Columns.Add("Last Logon", 150)
    $script:listView.Columns.Add("Pwd Last Set", 150)

    Add-ListViewSorting -ListView $script:listView
    $script:listView.Tag.DebugSortClicks = $true

    $containerPanel.Panel1.Controls.Add($script:listView)

    # Details split container
    $detailsPanel = New-Object System.Windows.Forms.SplitContainer
    $detailsPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $detailsPanel.Orientation = [System.Windows.Forms.Orientation]::Horizontal
    $containerPanel.Panel2.Controls.Add($detailsPanel)

    # Basic info panel
    $script:basicInfoPanel = New-Object System.Windows.Forms.Panel
    $script:basicInfoPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $detailsPanel.Panel1.Controls.Add($script:basicInfoPanel)

    # Users list panel
    $script:usersListPanel = New-Object System.Windows.Forms.Panel
    $script:usersListPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $detailsPanel.Panel2.Controls.Add($script:usersListPanel)

    # Logged-in users list view
    $script:loggedInUsersView = New-Object System.Windows.Forms.ListView
    $script:loggedInUsersView.Name = "LoggedInUsersListView"
    $script:loggedInUsersView.Dock = [System.Windows.Forms.DockStyle]::Fill
    $script:loggedInUsersView.View = [System.Windows.Forms.View]::Details
    $script:loggedInUsersView.FullRowSelect = $true
    $script:loggedInUsersView.GridLines = $true
    $script:loggedInUsersView.HideSelection = $false

    $script:loggedInUsersView.Columns.Add("Username", 120)
    $script:loggedInUsersView.Columns.Add("Full Name", 150)
    $script:loggedInUsersView.Columns.Add("Session Type", 100)
    $script:loggedInUsersView.Columns.Add("ID", 50)
    $script:loggedInUsersView.Columns.Add("State", 80)
    $script:loggedInUsersView.Columns.Add("Idle Time", 80)
    $script:loggedInUsersView.Columns.Add("Logon Time", 150)

    Add-ListViewSorting -ListView $script:loggedInUsersView

    # Basic info list view
    $script:basicInfoListView = CreateBasicInfoListView
    $script:basicInfoListView.Name = "BasicInfoListView"
    $script:basicInfoPanel.Controls.Add($script:basicInfoListView)

    # Populate dynamic menus
    Update-SearchHistoryMenu -HistoryMenu $script:historyMenu
    Update-FavoritesMenu

    # Expose controls globally so other modules can reference them
    $global:form                = $script:form
    $global:progressBar         = $script:progressBar
    $global:statusLabel         = $script:statusLabel
    $global:menuStrip           = $script:menuStrip
    $global:searchBox           = $script:searchBox
    $global:typeCombo           = $script:typeCombo
    $global:searchButton        = $script:searchButton
    $global:listView            = $script:listView
    $global:basicInfoPanel      = $script:basicInfoPanel
    $global:basicInfoListView   = $script:basicInfoListView
    $global:usersListPanel      = $script:usersListPanel
    $global:loggedInUsersView   = $script:loggedInUsersView
    $global:favoritesMenu       = $script:favoritesMenu
    $global:historyMenu         = $script:historyMenu
}

function Show-PDQDeployPackagePickerDialog {
    <#
    .SYNOPSIS
        Shows a package picker dialog for PDQ Deploy packages.
    .DESCRIPTION
        Loads packages from PDQDeploy.exe GetPackageNames (cached) and presents a
        searchable checked list box allowing the user to toggle selections. Returns
        the selected package names on OK, or $null on Cancel.
    .PARAMETER SelectedPackages
        Initial package names to pre-select in the list.
    .PARAMETER ParentForm
        Optional parent WinForms form for centering the dialog.
    .OUTPUTS
        System.String[]. Selected package names, or $null if cancelled.
    .EXAMPLE
        $pkgs = Show-PDQDeployPackagePickerDialog -SelectedPackages @("Package1")
    #>
    [CmdletBinding()]
    param (
        [string[]]$SelectedPackages = @(),

        [System.Windows.Forms.Form]$ParentForm = $null
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        Add-Type -AssemblyName System.Drawing | Out-Null
    } catch {}

    $dialog = $null
    try {
        $dialog = New-Object System.Windows.Forms.Form
        $dialog.Text = "Select PDQ Deploy Packages"
        $dialog.Size = New-Object System.Drawing.Size(650, 600)
        $dialog.StartPosition = if ($ParentForm) { "CenterParent" } else { "CenterScreen" }
        $dialog.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
        $dialog.MaximizeBox = $true
        $dialog.MinimizeBox = $false
        $dialog.MinimumSize = New-Object System.Drawing.Size(520, 450)

        # Centralised state object so all event handlers share the same references
        $state = [PSCustomObject]@{
            Populating  = $false
            AllPackages = @()
            SelectedSet = (New-Object "System.Collections.Generic.HashSet[string]" ([System.StringComparer]::OrdinalIgnoreCase))
        }
        foreach ($p in @($SelectedPackages)) {
            if (-not [string]::IsNullOrWhiteSpace($p)) { [void]$state.SelectedSet.Add([string]$p) }
        }

        $lblSearch = New-Object System.Windows.Forms.Label
        $lblSearch.Text = "Search:"
        $lblSearch.Location = New-Object System.Drawing.Point(10, 12)
        $lblSearch.AutoSize = $true
        $dialog.Controls.Add($lblSearch)

        $txtSearch = New-Object System.Windows.Forms.TextBox
        $txtSearch.Location = New-Object System.Drawing.Point(65, 10)
        $txtSearch.Size = New-Object System.Drawing.Size(400, 22)
        $txtSearch.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $dialog.Controls.Add($txtSearch)

        $btnRefresh = New-Object System.Windows.Forms.Button
        $btnRefresh.Text = "Refresh"
        $btnRefresh.Size = New-Object System.Drawing.Size(80, 24)
        $btnRefresh.Location = New-Object System.Drawing.Point(475, 8)
        $btnRefresh.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
        $dialog.Controls.Add($btnRefresh)

        $btnSelectAll = New-Object System.Windows.Forms.Button
        $btnSelectAll.Text = "Select All"
        $btnSelectAll.Size = New-Object System.Drawing.Size(80, 24)
        $btnSelectAll.Location = New-Object System.Drawing.Point(560, 8)
        $btnSelectAll.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
        $dialog.Controls.Add($btnSelectAll)

        $checkedList = New-Object System.Windows.Forms.CheckedListBox
        $checkedList.Location = New-Object System.Drawing.Point(10, 45)
        $checkedList.Size = New-Object System.Drawing.Size(615, 440)
        $checkedList.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $checkedList.CheckOnClick = $true
        $dialog.Controls.Add($checkedList)

        $btnClear = New-Object System.Windows.Forms.Button
        $btnClear.Text = "Clear"
        $btnClear.Size = New-Object System.Drawing.Size(80, 28)
        $btnClear.Location = New-Object System.Drawing.Point(10, 495)
        $btnClear.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
        $dialog.Controls.Add($btnClear)

        $lblStatus = New-Object System.Windows.Forms.Label
        $lblStatus.Text = "Loading packages..."
        $lblStatus.Location = New-Object System.Drawing.Point(100, 502)
        $lblStatus.Size = New-Object System.Drawing.Size(350, 20)
        $lblStatus.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $lblStatus.ForeColor = [System.Drawing.Color]::Gray
        $dialog.Controls.Add($lblStatus)

        $lblSelected = New-Object System.Windows.Forms.Label
        $lblSelected.Text = "Selected: 0"
        $lblSelected.Location = New-Object System.Drawing.Point(460, 502)
        $lblSelected.Size = New-Object System.Drawing.Size(165, 20)
        $lblSelected.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
        $lblSelected.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
        $dialog.Controls.Add($lblSelected)

        $btnOk = New-Object System.Windows.Forms.Button
        $btnOk.Text = "OK"
        $btnOk.Size = New-Object System.Drawing.Size(90, 28)
        $btnOk.Location = New-Object System.Drawing.Point(445, 528)
        $btnOk.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
        $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $dialog.Controls.Add($btnOk)

        $btnCancel = New-Object System.Windows.Forms.Button
        $btnCancel.Text = "Cancel"
        $btnCancel.Size = New-Object System.Drawing.Size(90, 28)
        $btnCancel.Location = New-Object System.Drawing.Point(535, 528)
        $btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
        $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $dialog.Controls.Add($btnCancel)

        $dialog.AcceptButton = $btnOk
        $dialog.CancelButton = $btnCancel

        $updateSelectedLabel = {
            try { $lblSelected.Text = "Selected: $($state.SelectedSet.Count)" } catch { $lblSelected.Text = "Selected: 0" }
        }

        $populateList = {
            param([string]$filterText)
            $state.Populating = $true
            try {
                $checkedList.BeginUpdate()
                $checkedList.Items.Clear()

                $ft = ""
                if (-not [string]::IsNullOrWhiteSpace($filterText)) { $ft = $filterText.Trim() }

                $visible = @()
                if ([string]::IsNullOrWhiteSpace($ft)) {
                    $visible = @($state.AllPackages)
                }
                else {
                    # Substring match avoids wildcard surprises
                    $visible = @($state.AllPackages | Where-Object { $_.IndexOf($ft, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 })
                }

                foreach ($pkg in $visible) {
                    $idx = $checkedList.Items.Add($pkg)
                    if ($state.SelectedSet.Contains($pkg)) {
                        $checkedList.SetItemChecked($idx, $true)
                    }
                }
            }
            finally {
                try { $checkedList.EndUpdate() } catch {}
                $state.Populating = $false
                & $updateSelectedLabel
            }
        }

        $loadPackages = {
            param([bool]$force)
            try {
                $lblStatus.Text = if ($force) { "Refreshing from PDQ..." } else { "Loading from cache..." }
                $lblStatus.ForeColor = [System.Drawing.Color]::Gray
                $dialog.Refresh()

                $pkgs = @()
                if ($force) {
                    $pkgs = @(Get-PDQDeployPackagesCached -ForceRefresh)
                }
                else {
                    $pkgs = @(Get-PDQDeployPackagesCached)
                }

                $state.AllPackages = @($pkgs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

                if (-not $state.AllPackages -or $state.AllPackages.Count -eq 0) {
                    $lblStatus.Text = "No packages found (check PDQ Deploy path/settings)."
                    $lblStatus.ForeColor = [System.Drawing.Color]::DarkRed
                }
                else {
                    $lblStatus.Text = "Loaded $($state.AllPackages.Count) packages"
                    $lblStatus.ForeColor = [System.Drawing.Color]::Green
                }

                & $populateList $txtSearch.Text
            }
            catch {
                $lblStatus.Text = "Error loading packages."
                $lblStatus.ForeColor = [System.Drawing.Color]::DarkRed
                try { Write-Log -Message "Show-PDQDeployPackagePickerDialog load error: $_" -Level "Warning" } catch {}
            }
        }

        $checkedList.Add_ItemCheck({
            if ($state.Populating) { return }
            try {
                $pkg = [string]$checkedList.Items[$_.Index]
                if ([string]::IsNullOrWhiteSpace($pkg)) { return }
                if ($_.NewValue -eq [System.Windows.Forms.CheckState]::Checked) {
                    [void]$state.SelectedSet.Add($pkg)
                }
                else {
                    [void]$state.SelectedSet.Remove($pkg)
                }
            } catch {}
            & $updateSelectedLabel
        })

        $txtSearch.Add_TextChanged({
            try { & $populateList $txtSearch.Text } catch {}
        })

        $btnRefresh.Add_Click({
            try { & $loadPackages $true } catch {}
        })

        $btnSelectAll.Add_Click({
            try {
                $state.Populating = $true
                try {
                    $checkedList.BeginUpdate()
                    for ($i = 0; $i -lt $checkedList.Items.Count; $i++) {
                        $pkg = [string]$checkedList.Items[$i]
                        if (-not [string]::IsNullOrWhiteSpace($pkg)) {
                            [void]$state.SelectedSet.Add($pkg)
                            $checkedList.SetItemChecked($i, $true)
                        }
                    }
                }
                finally {
                    try { $checkedList.EndUpdate() } catch {}
                    $state.Populating = $false
                }
            } catch {}
            & $updateSelectedLabel
        })

        $btnClear.Add_Click({
            try {
                $state.Populating = $true
                try {
                    $checkedList.BeginUpdate()
                    for ($i = 0; $i -lt $checkedList.Items.Count; $i++) {
                        $pkg = [string]$checkedList.Items[$i]
                        if (-not [string]::IsNullOrWhiteSpace($pkg)) {
                            [void]$state.SelectedSet.Remove($pkg)
                        }
                        $checkedList.SetItemChecked($i, $false)
                    }
                }
                finally {
                    try { $checkedList.EndUpdate() } catch {}
                    $state.Populating = $false
                }
            } catch {}
            & $updateSelectedLabel
        })

        # Initial load uses cached data to avoid blocking the UI
        & $loadPackages $false
        & $updateSelectedLabel

        $result = if ($ParentForm) { $dialog.ShowDialog($ParentForm) } else { $dialog.ShowDialog() }
        if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
            return $null
        }

        # Collect final selection without relying on extension methods
        $final = @($state.SelectedSet | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        return @($final)
    }
    catch {
        try { Write-Log -Message "Show-PDQDeployPackagePickerDialog error: $_" -Level "Warning" } catch {}
        return $null
    }
    finally {
        try { if ($dialog) { $dialog.Dispose() } } catch {}
    }
}

#endregion Functions

# ── Module Exports ──────────────────────────────────────────────────────
Export-ModuleMember -Function @(
    'Test-ComputerOnline',
    'Set-ListViewItemColor',
    'Add-ListViewSorting',
    'CreateBasicInfoListView',
    'AddDetailLabel',
    'ShowNoResults',
    'Convert-MarkdownToHtml',
    'Show-MarkdownWindow',
    'Show-MarkdownDialog',
    'Initialize-ADUI',
    'Show-PDQDeployPackagePickerDialog'
)
