@{
    IncludeRules = @(
        'PSAvoidGlobalAliases',
        'PSAvoidUsingWriteHost',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSUseConsistentIndentation',
        'PSProvideCommentHelp'
    )

    # Exclude tools/ scripts from Write-Host warnings (CLI tools need console output)
    ExcludeRules = @()

    Rules = @{
        PSAvoidUsingWriteHost = @{
            Enable = $true
        }
        PSProvideCommentHelp = @{
            ExportedOnly = $true
            Enable       = $true
            Severity     = 'Information'
        }
        PSUseConsistentIndentation = @{
            Kind             = 'space'
            IndentationSize  = 4
        }
    }
}
