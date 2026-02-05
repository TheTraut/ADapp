#Requires -Version 5.1
<#
.SYNOPSIS
    BitLocker recovery key retrieval module for ADapp.
.DESCRIPTION
    Provides functions to retrieve BitLocker recovery passwords stored in
    Active Directory and display them in a user-friendly WinForms dialog.
    Requires appropriate AD permissions to read msFVE-RecoveryInformation
    objects beneath computer accounts.
.NOTES
    Module: BitLockerRecovery
    Author: ADapp Team
    Requires: ActiveDirectory module, appropriate AD permissions
#>

#region Functions

function Get-BitLockerRecoveryKeys {
    <#
    .SYNOPSIS
        Retrieves BitLocker recovery keys for a computer from Active Directory.
    .DESCRIPTION
        Queries Active Directory for msFVE-RecoveryInformation objects stored
        under the specified computer's AD account. Returns the recovery password
        and the date it was escrowed for each key found.
    .PARAMETER ComputerName
        The name of the computer to retrieve recovery keys for.
    .OUTPUTS
        System.Object[]
        An array of PSCustomObjects with DateAdded, RecoveryPassword, and
        ComputerName properties. Returns $null if no keys are found.
    .EXAMPLE
        Get-BitLockerRecoveryKeys -ComputerName "WORKSTATION01"
    .EXAMPLE
        $keys = Get-BitLockerRecoveryKeys -ComputerName "PC-1234"
        $keys | Format-Table -AutoSize
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    try {
        # Look up the computer object in AD to get its DistinguishedName
        $computer = Get-ADComputer -Identity $ComputerName
        if (-not $computer) {
            Write-Warning "Computer '$ComputerName' not found in Active Directory."
            return $null
        }

        # Search for BitLocker recovery objects stored beneath the computer
        $bitlockerRecovery = Get-ADObject `
            -Filter "objectClass -eq 'msFVE-RecoveryInformation'" `
            -SearchBase $computer.DistinguishedName `
            -Properties msFVE-RecoveryPassword, whenCreated

        if (-not $bitlockerRecovery -or $bitlockerRecovery.Count -eq 0) {
            Write-Warning "No BitLocker recovery information found for computer '$ComputerName'."
            return $null
        }

        # Format each recovery entry into a consistent output object
        $recoveryInfo = $bitlockerRecovery | ForEach-Object {
            [PSCustomObject]@{
                DateAdded        = $_.whenCreated
                RecoveryPassword = $_.'msFVE-RecoveryPassword'
                ComputerName     = $ComputerName
            }
        }

        return $recoveryInfo
    }
    catch {
        Write-Error "Error retrieving BitLocker recovery keys: $_"
        return $null
    }
}

function Show-BitLockerRecoveryDialog {
    <#
    .SYNOPSIS
        Displays a dialog showing BitLocker recovery keys for a computer.
    .DESCRIPTION
        Creates a WinForms dialog that lists all BitLocker recovery keys stored
        in Active Directory for the specified computer. Includes a Copy button
        to copy the selected recovery password to the clipboard.
    .PARAMETER ComputerName
        The name of the computer to display recovery keys for.
    .EXAMPLE
        Show-BitLockerRecoveryDialog -ComputerName "WORKSTATION01"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # Retrieve recovery keys from AD
    $recoveryKeys = Get-BitLockerRecoveryKeys -ComputerName $ComputerName

    #region Form Setup
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "BitLocker Recovery Keys - $ComputerName"
    $form.Size = New-Object System.Drawing.Size(600, 400)
    $form.StartPosition = "CenterParent"
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    #endregion Form Setup

    #region ListView
    $listView = New-Object System.Windows.Forms.ListView
    $listView.Location = New-Object System.Drawing.Point(10, 10)
    $listView.Size = New-Object System.Drawing.Size(565, 300)
    $listView.View = [System.Windows.Forms.View]::Details
    $listView.FullRowSelect = $true
    $listView.GridLines = $true

    [void]$listView.Columns.Add("Date Added", 150)
    [void]$listView.Columns.Add("Recovery Password", 400)

    # Populate the ListView with recovery keys or show a placeholder message
    if ($recoveryKeys) {
        foreach ($key in $recoveryKeys) {
            $item = New-Object System.Windows.Forms.ListViewItem($key.DateAdded.ToString("yyyy-MM-dd HH:mm:ss"))
            [void]$item.SubItems.Add($key.RecoveryPassword)
            [void]$listView.Items.Add($item)
        }
    }
    else {
        $item = New-Object System.Windows.Forms.ListViewItem("No recovery keys found")
        $item.ForeColor = [System.Drawing.Color]::Gray
        [void]$listView.Items.Add($item)
    }

    $form.Controls.Add($listView)
    #endregion ListView

    #region Buttons
    # Copy button — copies the selected recovery password to the clipboard
    $copyButton = New-Object System.Windows.Forms.Button
    $copyButton.Location = New-Object System.Drawing.Point(10, 320)
    $copyButton.Size = New-Object System.Drawing.Size(100, 30)
    $copyButton.Text = "Copy"
    $copyButton.Add_Click({
        if ($listView.SelectedItems.Count -gt 0) {
            $selectedItem = $listView.SelectedItems[0]
            if ($selectedItem.SubItems.Count -gt 1) {
                [System.Windows.Forms.Clipboard]::SetText($selectedItem.SubItems[1].Text)
                [System.Windows.Forms.MessageBox]::Show(
                    "Recovery password copied to clipboard.",
                    "Copied",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Information
                )
            }
        }
        else {
            [System.Windows.Forms.MessageBox]::Show(
                "Please select a recovery key to copy.",
                "Select Key",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    })
    $form.Controls.Add($copyButton)

    # Close button — dismisses the dialog
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Location = New-Object System.Drawing.Point(475, 320)
    $closeButton.Size = New-Object System.Drawing.Size(100, 30)
    $closeButton.Text = "Close"
    $closeButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($closeButton)
    $form.CancelButton = $closeButton
    #endregion Buttons

    # Display the dialog modally
    [void]$form.ShowDialog()
}

#endregion Functions

# ── Module Exports ────────────────────────────────────────────────────────────
Export-ModuleMember -Function Get-BitLockerRecoveryKeys, Show-BitLockerRecoveryDialog
