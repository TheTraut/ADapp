#Requires -Version 5.1
<#
.SYNOPSIS
    Filtered transcript helpers for ADapp.
.DESCRIPTION
    Provides Start-FilteredTranscript and Stop-FilteredTranscript to record
    PowerShell transcripts while suppressing noisy WinForms output and
    optionally redacting sensitive data. Wraps the built-in Out-Default
    cmdlet with a filtering proxy for the duration of the transcript.
.NOTES
    Module: Transcript
    Author: ADapp Team
#>

# Store the original Out-Default cmdlet reference so it can be restored later
$script:originalOutDefault = $null

#region Functions

function Start-FilteredTranscript {
    <#
    .SYNOPSIS
        Starts a PowerShell transcript with output filtering.
    .DESCRIPTION
        Replaces the default Out-Default cmdlet with a proxy that filters
        objects via Test-ShouldSuppressOutput (from the Logging module) and
        optionally redacts sensitive strings when Settings.Security.SanitizeOutputs
        is enabled. Then starts a standard transcript at the specified path.
    .PARAMETER Path
        The file path where the transcript will be saved.
    .PARAMETER Append
        When specified, appends to an existing transcript file instead of
        overwriting it.
    .OUTPUTS
        None
    .EXAMPLE
        Start-FilteredTranscript -Path "C:\Logs\session.txt"
    .EXAMPLE
        Start-FilteredTranscript -Path "C:\Logs\session.txt" -Append
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [switch]$Append
    )

    try {
        # Proxy function that wraps Out-Default with filtering logic
        $newOutDefault = {
            param(
                [switch]$Transcript,
                [Parameter(ValueFromPipeline = $true)]$InputObject
            )
            begin {
                $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Out-Default', [System.Management.Automation.CommandTypes]::Cmdlet)
                $scriptCmd = { & $wrappedCmd @PSBoundParameters }
                $steppablePipeline = $scriptCmd.GetSteppablePipeline()
                $steppablePipeline.Begin($true)
            }
            process {
                # Suppress noisy WinForms / internal objects from the transcript
                if (Test-ShouldSuppressOutput -InputObject $InputObject) {
                    $null = $InputObject
                }
                else {
                    # Redact sensitive content in strings when configured
                    try {
                        if ($global:Settings.Security.SanitizeOutputs -and ($InputObject -is [string])) {
                            $InputObject = Redact-SensitiveData -Text $InputObject
                        }
                    } catch { }
                    $steppablePipeline.Process($InputObject)
                }
            }
            end {
                $steppablePipeline.End()
            }
        }

        # Save original Out-Default reference once so we can restore it later
        if (-not $script:originalOutDefault) {
            $script:originalOutDefault = Get-Command Out-Default -CommandType Cmdlet
        }

        # Replace Out-Default with the filtered proxy
        $ExecutionContext.InvokeCommand.NewScriptBlock($newOutDefault.ToString()) | Out-Null

        # Start the built-in transcript
        if ($Append) {
            Microsoft.PowerShell.Host\Start-Transcript -Path $Path -Append
        }
        else {
            Microsoft.PowerShell.Host\Start-Transcript -Path $Path
        }
    }
    catch {
        Write-Warning "Failed to start filtered transcript: $_"
        throw
    }
}

function Stop-FilteredTranscript {
    <#
    .SYNOPSIS
        Stops the filtered transcript and restores Out-Default.
    .DESCRIPTION
        Replaces the filtering Out-Default proxy with the original cmdlet and
        then stops the running PowerShell transcript.
    .OUTPUTS
        None
    .EXAMPLE
        Stop-FilteredTranscript
    #>
    [CmdletBinding()]
    param ()

    try {
        # Restore original Out-Default if it was previously replaced
        if ($script:originalOutDefault) {
            $restoreOutDefault = {
                param(
                    [switch]$Transcript,
                    [Parameter(ValueFromPipeline = $true)]$InputObject
                )
                begin {
                    $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand(
                        'Microsoft.PowerShell.Core\Out-Default',
                        [System.Management.Automation.CommandTypes]::Cmdlet
                    )
                    $scriptCmd = { & $wrappedCmd @PSBoundParameters }
                    $steppablePipeline = $scriptCmd.GetSteppablePipeline()
                    $steppablePipeline.Begin($true)
                }
                process {
                    $steppablePipeline.Process($InputObject)
                }
                end {
                    $steppablePipeline.End()
                }
            }

            $ExecutionContext.InvokeCommand.NewScriptBlock($restoreOutDefault.ToString()) | Out-Null
        }

        # Stop the built-in transcript
        try {
            Microsoft.PowerShell.Host\Stop-Transcript
        }
        catch {
            Write-Warning "Error stopping transcript: $_"
        }
    }
    catch {
        Write-Warning "Failed to stop filtered transcript: $_"
    }
}

#endregion Functions

# ── Module Exports ────────────────────────────────────────────────────────────
Export-ModuleMember -Function Start-FilteredTranscript, Stop-FilteredTranscript
