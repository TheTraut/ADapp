#Requires -Version 5.1
<#
.SYNOPSIS
    Logging and diagnostic helpers for ADapp.
.DESCRIPTION
    Provides structured logging (Write-Log, Write-LogEvent), audit event
    recording (Write-AuditEvent), output suppression for WinForms types, a
    safe-execution wrapper (Invoke-Safe), and sensitive-data redaction.
    Log output is directed to the console and/or a rolling file under
    %ProgramData%\ADapp\Logs.
.NOTES
    Module: Logging
    Author: ADapp Team
#>

# Ensure WinForms types are available even if modules are imported out-of-order
try { Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop | Out-Null } catch { }

# .NET type names whose instances should be suppressed from pipeline output
# (kept as strings so import succeeds even when WinForms is unavailable)
$script:SuppressedOutputTypes = @(
    'System.Windows.Forms.ToolStripMenuItem',
    'System.Windows.Forms.ToolStripItem',
    'System.Windows.Forms.Control',
    'System.Windows.Forms.ToolStripDropDownItem',
    'System.Windows.Forms.ToolStripDropDown',
    'System.Windows.Forms.ToolStrip'
)

#region Functions

function Redact-SensitiveData {
    <#
    .SYNOPSIS
        Redacts common sensitive-data patterns from text.
    .DESCRIPTION
        Uses regex heuristics to replace passwords, tokens, API keys, bearer
        tokens, and e-mail addresses with placeholder values. Intended to be
        called before emitting user-controlled strings to logs or UI. This is
        not a full DLP solution.
    .PARAMETER Text
        The input string to sanitise.
    .OUTPUTS
        System.String
        The sanitised text. Returns the original text on error.
    .EXAMPLE
        Redact-SensitiveData -Text "password=supersecret"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    try {
        $redacted = $Text
        # key=value style secrets
        $redacted = [Regex]::Replace($redacted, '(?i)(password|pwd|passphrase|token|apikey|api_key|secret|client_secret)\s*[:=]\s*([^\r\n;]+)', '$1=[REDACTED]')
        # e-mail addresses
        $redacted = [Regex]::Replace($redacted, '(?i)([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})', '[REDACTED_EMAIL]')
        # bearer tokens
        $redacted = [Regex]::Replace($redacted, '(?i)(bearer\s+)[a-z0-9\._\-]+', '$1[REDACTED]')
        return $redacted
    }
    catch {
        return $Text
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a formatted log message to console and/or file.
    .DESCRIPTION
        Formats a message with a timestamp and severity level, optionally
        redacts sensitive content, writes to the console and to a rolling log
        file under the configured log directory. Respects settings for
        console/file logging, rotation size, and maximum archive count.
        Resilient to early startup before settings are available.
    .PARAMETER Message
        The message text to log.
    .PARAMETER Level
        Severity level. Typical values: Info, Warning, Error, Audit.
        Defaults to "Info".
    .PARAMETER Warning
        When specified, forces the console output to use Write-Warning.
    .OUTPUTS
        None
    .EXAMPLE
        Write-Log -Message "Search started" -Level Info
    .EXAMPLE
        Write-Log -Message "Something went wrong" -Level Error -Warning
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$Level = "Info",

        [switch]$Warning
    )

    try {
        # Resolve log directory, even before AppConfig is loaded
        try {
            if ($global:AppConfig -and $global:AppConfig.LogPath) {
                $logDir = $global:AppConfig.LogPath
            }
            else {
                $logDir = Join-Path -Path $env:ProgramData -ChildPath 'ADapp\Logs'
            }
        }
        catch {
            $logDir = Join-Path -Path $env:ProgramData -ChildPath 'ADapp\Logs'
        }
        if (-not (Test-Path $logDir)) {
            try { $null = New-Item -ItemType Directory -Path $logDir -Force } catch { }
        }
        $logFile = Join-Path -Path $logDir -ChildPath "ADapp.log"

        #region Read logging settings
        $enableConsole = $true
        $enableFile    = $true
        $maxSizeMb     = 10
        $maxFiles      = 5

        try {
            if ($global:Settings -and $global:Settings.Logging) {
                if ($null -ne $global:Settings.Logging.EnableConsoleLogging) { $enableConsole = [bool]$global:Settings.Logging.EnableConsoleLogging }
                if ($null -ne $global:Settings.Logging.EnableFileLogging)    { $enableFile    = [bool]$global:Settings.Logging.EnableFileLogging }
                if ($global:Settings.Logging.MaxLogFileSizeMB) { $maxSizeMb = [int]$global:Settings.Logging.MaxLogFileSizeMB }
                if ($global:Settings.Logging.MaxLogFiles)      { $maxFiles  = [int]$global:Settings.Logging.MaxLogFiles }
            }
        } catch { }
        #endregion Read logging settings

        # Format the log line
        $timestamp  = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
        $msg        = $Message
        try { if ($global:Settings.Security.SanitizeOutputs) { $msg = Redact-SensitiveData -Text $msg } } catch { }
        $logMessage = "[$timestamp] [$Level] $msg"

        #region Console output
        if ($enableConsole) {
            if ($Warning -or $Level -eq "Warning" -or $Level -eq "Error") {
                Write-Warning $logMessage
            }
            elseif ($Level -eq "Info" -and -not $Message.Contains("initialized") -and -not $Message.Contains("started")) {
                Write-Host $logMessage -ForegroundColor Gray
            }
        }
        #endregion Console output

        #region File output with rotation
        if ($enableFile -and $null -ne $logFile -and $logFile -ne '') {
            if (-not (Test-Path $logDir)) {
                $null = New-Item -ItemType Directory -Path $logDir -Force
            }

            # Rotate when size exceeds the configured limit
            try {
                if (Test-Path $logFile) {
                    $fileInfo = Get-Item -Path $logFile -ErrorAction SilentlyContinue
                    if ($fileInfo -and ($fileInfo.Length -gt ($maxSizeMb * 1MB))) {
                        $timestamp2 = (Get-Date).ToString('yyyyMMdd_HHmmss')
                        $archived   = Join-Path -Path $logDir -ChildPath ("ADapp_" + $timestamp2 + ".log")
                        Move-Item -Path $logFile -Destination $archived -Force -ErrorAction SilentlyContinue

                        # Prune old archives beyond the configured maximum
                        $archives = Get-ChildItem -Path $logDir -Filter 'ADapp_*.log' -File -ErrorAction SilentlyContinue |
                            Sort-Object LastWriteTime -Descending
                        if ($archives.Count -gt $maxFiles) {
                            $toRemove = $archives | Select-Object -Skip $maxFiles
                            foreach ($old in $toRemove) {
                                Remove-Item -Path $old.FullName -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
            } catch { }

            $null = $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8 -Force
        }
        #endregion File output with rotation
    }
    catch {
        Write-Warning "Failed to write to log: $_"
    }
}

function Write-LogEvent {
    <#
    .SYNOPSIS
        Writes a structured log event as compact JSON via Write-Log.
    .DESCRIPTION
        Creates a JSON payload including timestamp, level, eventId,
        correlationId, duration, and context, then forwards it to Write-Log.
        Useful for machine-parsable log entries.
    .PARAMETER Operation
        Operation or event verb (e.g. "Search", "Audit").
    .PARAMETER EventId
        Numeric event identifier. Defaults to 0.
    .PARAMETER CorrelationId
        Optional correlation ID to group related events.
    .PARAMETER Context
        Hashtable with contextual properties to include in the payload.
    .PARAMETER DurationMs
        Optional operation duration in milliseconds.
    .PARAMETER Level
        Log level. One of Info, Warning, Error, Audit. Defaults to Info.
    .OUTPUTS
        None
    .EXAMPLE
        Write-LogEvent -Operation 'Search' -EventId 200 -Context @{ query = 'smith' }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Operation,

        [int]$EventId = 0,
        [string]$CorrelationId,
        [hashtable]$Context,
        [int]$DurationMs,

        [ValidateSet('Info', 'Warning', 'Error', 'Audit')]
        [string]$Level = 'Info'
    )

    try {
        $payload = [PSCustomObject]@{
            timestamp     = (Get-Date).ToString('o')
            level         = $Level
            eventId       = $EventId
            operation     = $Operation
            correlationId = $CorrelationId
            durationMs    = $DurationMs
            context       = $Context
        }
        $json = $payload | ConvertTo-Json -Depth 6 -Compress
        Write-Log -Message $json -Level $Level
    }
    catch {
        Write-Log -Message "Failed to write structured log event: $_" -Level "Warning"
    }
}

function Ensure-EventLogSource {
    <#
    .SYNOPSIS
        Ensures a Windows Event Log source exists.
    .DESCRIPTION
        Checks for the presence of the specified event source and creates it
        if missing. Returns $true on success, $false on failure.
    .PARAMETER Source
        The event source name. Defaults to 'ADapp'.
    .PARAMETER LogName
        The event log name. Defaults to 'Application'.
    .OUTPUTS
        System.Boolean
        $true if the source exists or was created; $false otherwise.
    .EXAMPLE
        if (Ensure-EventLogSource) { Write-EventLog ... }
    #>
    [CmdletBinding()]
    param (
        [string]$Source = 'ADapp',
        [string]$LogName = 'Application'
    )

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
            [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
        }
        return $true
    }
    catch {
        return $false
    }
}

function Write-AuditEvent {
    <#
    .SYNOPSIS
        Emits an audit event to structured logs and optionally to the
        Windows Event Log.
    .DESCRIPTION
        Captures the current actor (Windows identity), the action performed,
        the target, and the result. Writes a structured audit log via
        Write-LogEvent and, when Settings.Security.EnableAuditLogging is
        enabled, also writes a Windows Event Log entry.
    .PARAMETER Action
        The action performed (e.g. "Unlock", "AddToGroup").
    .PARAMETER Target
        The target of the action (e.g. user or group name).
    .PARAMETER Result
        Result string. Defaults to 'Success'.
    .PARAMETER Metadata
        Optional hashtable of additional details.
    .OUTPUTS
        None
    .EXAMPLE
        Write-AuditEvent -Action 'Unlock' -Target 'jdoe'
    .EXAMPLE
        Write-AuditEvent -Action 'AddToGroup' -Target 'Domain Admins' -Metadata @{ user = 'jdoe' }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Target,

        [string]$Result = 'Success',
        [hashtable]$Metadata
    )

    try {
        $who = try { ([Security.Principal.WindowsIdentity]::GetCurrent()).Name } catch { $env:USERNAME }
        $ctx = @{ action = $Action; target = $Target; actor = $who; result = $Result; meta = $Metadata }
        Write-LogEvent -Operation 'Audit' -EventId 1001 -Level 'Audit' -Context $ctx

        # Optionally write to Windows Event Log when audit logging is enabled
        if ($global:Settings -and $global:Settings.Security -and $global:Settings.Security.EnableAuditLogging) {
            if (Ensure-EventLogSource) {
                $msg = "ADapp Audit: Action=$Action; Target=$Target; Actor=$who; Result=$Result"
                try {
                    [System.Diagnostics.EventLog]::WriteEntry(
                        'ADapp', $msg,
                        [System.Diagnostics.EventLogEntryType]::Information, 1001
                    )
                } catch { }
            }
        }
    }
    catch {
        Write-Log -Message "Failed to write audit event: $_" -Level "Warning"
    }
}

function Test-ShouldSuppressOutput {
    <#
    .SYNOPSIS
        Determines whether an object's type should be suppressed from output.
    .DESCRIPTION
        Returns $true when the object's .NET type is listed in the internal
        suppression list, preventing UI framework objects from leaking into
        the pipeline or transcript.
    .PARAMETER InputObject
        The object to evaluate.
    .OUTPUTS
        System.Boolean
        $true if output should be suppressed; $false otherwise.
    .EXAMPLE
        if (Test-ShouldSuppressOutput -InputObject $obj) { return }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        $InputObject
    )

    if ($InputObject -ne $null) {
        $objectType = $InputObject.GetType().FullName
        return $script:SuppressedOutputTypes -contains $objectType
    }

    return $false
}

function Invoke-SilentCommand {
    <#
    .SYNOPSIS
        Executes a script block with all informational streams suppressed.
    .DESCRIPTION
        Temporarily sets Error, Verbose, Debug, Warning, and Information
        preference variables to SilentlyContinue, executes the provided
        script block, then restores the original preferences.
    .PARAMETER ScriptBlock
        The script block to execute silently.
    .OUTPUTS
        System.Object
        Any output produced by the script block.
    .EXAMPLE
        Invoke-SilentCommand -ScriptBlock { Get-ADUser -Filter * }
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock
    )

    try {
        # Snapshot current preferences
        $oldErrorActionPreference  = $ErrorActionPreference
        $oldVerbosePreference      = $VerbosePreference
        $oldDebugPreference        = $DebugPreference
        $oldWarningPreference      = $WarningPreference
        $oldInformationPreference  = $InformationPreference

        # Suppress all streams
        $ErrorActionPreference  = 'SilentlyContinue'
        $VerbosePreference      = 'SilentlyContinue'
        $DebugPreference        = 'SilentlyContinue'
        $WarningPreference      = 'SilentlyContinue'
        $InformationPreference  = 'SilentlyContinue'

        $result = & $ScriptBlock
        return $result
    }
    finally {
        # Restore original preferences
        $ErrorActionPreference  = $oldErrorActionPreference
        $VerbosePreference      = $oldVerbosePreference
        $DebugPreference        = $oldDebugPreference
        $WarningPreference      = $oldWarningPreference
        $InformationPreference  = $oldInformationPreference
    }
}

function Invoke-Safe {
    <#
    .SYNOPSIS
        Executes a script block with error handling and user notification.
    .DESCRIPTION
        Invokes the provided script block and catches unhandled exceptions,
        logging the error and presenting a message box to the user. Returns
        $null on error.
    .PARAMETER ScriptBlock
        The script block to execute.
    .PARAMETER Context
        A short label for the operation, used in log and error messages.
        Defaults to 'Operation'.
    .OUTPUTS
        System.Object
        Any output produced by the script block, or $null on error.
    .EXAMPLE
        Invoke-Safe -ScriptBlock { Get-ADUser 'jdoe' } -Context 'User lookup'
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [string]$Context = 'Operation'
    )

    try {
        & $ScriptBlock
    }
    catch {
        Write-Log -Message "Unhandled error in $($Context): $_" -Level "Error"
        try {
            [System.Windows.Forms.MessageBox]::Show(
                "$Context failed: $_",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        } catch { }
        return $null
    }
}

function Add-SuppressedOutputType {
    <#
    .SYNOPSIS
        Adds a .NET type name to the output suppression list.
    .DESCRIPTION
        Extends the internal list of types whose instances should be
        suppressed from being written to the pipeline or transcript.
    .PARAMETER TypeName
        The full .NET type name to suppress (e.g.
        "System.Windows.Forms.Label").
    .OUTPUTS
        None
    .EXAMPLE
        Add-SuppressedOutputType -TypeName "System.Windows.Forms.Label"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TypeName
    )

    if (-not $script:SuppressedOutputTypes.Contains($TypeName)) {
        $script:SuppressedOutputTypes += $TypeName
    }
}

#endregion Functions

# ── Module Exports ────────────────────────────────────────────────────────────
Export-ModuleMember -Function Write-Log, Invoke-SilentCommand, Test-ShouldSuppressOutput,
    Add-SuppressedOutputType, Redact-SensitiveData, Write-LogEvent,
    Write-AuditEvent, Invoke-Safe
