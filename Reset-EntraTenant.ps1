<#
.SYNOPSIS
    Enterprise-grade Entra ID teardown with detailed logging, retries, two-pass cleanup,
    trusted named location handling, directory role cleanup, Exchange Online DL removal,
    and final CSV/JSON reporting.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true)][string]$TenantId,
    [Parameter(Mandatory = $true)][string]$ClientId,
    [Parameter(Mandatory = $true)][string]$ClientSecret,
    [Parameter(Mandatory = $false)][string]$CertificatePath,
    [Parameter(Mandatory = $true)][string]$ExpectedTenantDomain,
    [Parameter(Mandatory = $true)][string[]]$AdminAccounts,
    [Parameter(Mandatory = $true)][string[]]$BreakGlassAccounts,
    [Parameter(Mandatory = $false)][string[]]$ExcludeGroups = @(),
    [Parameter(Mandatory = $false)][string[]]$ExcludeApps = @(),
    [Parameter(Mandatory = $false)][string[]]$ExcludeCAPs = @(),
    [Parameter(Mandatory = $false)][string[]]$ExcludeNamedLocations = @(),
    [Parameter(Mandatory = $false)][int]$DirSyncWaitSeconds = 300,
    [Parameter(Mandatory = $false)][int]$RetryCount = 3,
    [Parameter(Mandatory = $false)][int]$RetryBaseDelaySeconds = 5,
    [Parameter(Mandatory = $false)][string]$LogFilePath = ".\TenantReset_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",
    [Parameter(Mandatory = $false)][string]$ReportCsvPath = ".\TenantReset_$(Get-Date -Format 'yyyyMMdd_HHmmss')_report.csv",
    [Parameter(Mandatory = $false)][string]$ReportJsonPath = ".\TenantReset_$(Get-Date -Format 'yyyyMMdd_HHmmss')_report.json"
)

$ErrorActionPreference = 'Stop'

Start-Transcript -Path $LogFilePath -Append | Out-Null

# ---------------------------
# Optional module import
# ---------------------------
$ModulesToImport = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Identity.SignIns',
    'Microsoft.Graph.Identity.Governance',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Applications'
)

foreach ($ModuleName in $ModulesToImport) {
    if (Get-Module -ListAvailable -Name $ModuleName) {
        Import-Module $ModuleName -Force -ErrorAction Stop
    }
}

# ---------------------------
# Normalize lists
# ---------------------------
$ProtectedUpns = @(
    $AdminAccounts
    $BreakGlassAccounts
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
    $_.ToLower().Trim()
}

$SafeExcludeGroups = $ExcludeGroups | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToLower().Trim() }
$SafeExcludeApps = $ExcludeApps | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToLower().Trim() }
$SafeExcludeCAPs = $ExcludeCAPs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToLower().Trim() }
$SafeExcludeNamedLocations = $ExcludeNamedLocations | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.ToLower().Trim() }

# ---------------------------
# Reporting
# ---------------------------
$script:Report = New-Object System.Collections.Generic.List[object]
$script:Summary = [ordered]@{
    SUCCESS = 0
    SKIPPED = 0
    FAILED  = 0
}

function Add-ReportEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$ResourceType,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Reason,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $Entry = [pscustomobject]@{
        Timestamp    = (Get-Date).ToString("o")
        Stage        = $Stage
        ResourceType = $ResourceType
        Name         = $Name
        Status       = $Status
        Reason       = $Reason
        Message      = $Message
    }

    $script:Report.Add($Entry) | Out-Null

    switch ($Status.ToUpperInvariant()) {
        'SUCCESS' { $script:Summary.SUCCESS++ }
        'SKIPPED' { $script:Summary.SKIPPED++ }
        default   { $script:Summary.FAILED++ }
    }

    return $Entry
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$ResourceType,
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss'Z'"
    Write-Host ("[{0}] [{1}] [{2}] [{3}] [{4}] {5}" -f $Timestamp, $Level, $Stage, $ResourceType, $Action, $Message)
}

function Get-ErrorReason {
    param([Parameter(Mandatory = $true)][string]$Message)

    if ($Message -match 'Too Many Requests' -or $Message -match '429') {
        return 'THROTTLED'
    }
    elseif ($Message -match 'Request_ResourceNotFound' -or $Message -match '404' -or $Message -match 'does not exist') {
        return 'ALREADY_DELETED'
    }
    elseif ($Message -match 'Authorization_RequestDenied' -or $Message -match 'Insufficient privileges') {
        return 'PERMISSION_DENIED'
    }
    elseif ($Message -match 'onPremisesSyncEnabled' -or $Message -match '\bsync\b' -or $Message -match 'synced') {
        return 'SYNCED_OR_LOCKED'
    }
    elseif ($Message -match 'Trusted location') {
        return 'TRUSTED_LOCATION'
    }
    else {
        return 'FAILED'
    }
}

function Test-IsProtectedUpn {
    param([Parameter(Mandatory = $true)][string]$Upn)
    return ($ProtectedUpns -contains $Upn.ToLower().Trim())
}

function Get-DisplayNameOrId {
    param($Item)

    if ($null -ne $Item.PSObject.Properties['DisplayName'] -and -not [string]::IsNullOrWhiteSpace($Item.DisplayName)) {
        return $Item.DisplayName
    }
    elseif ($null -ne $Item.PSObject.Properties['UserPrincipalName'] -and -not [string]::IsNullOrWhiteSpace($Item.UserPrincipalName)) {
        return $Item.UserPrincipalName
    }
    elseif ($null -ne $Item.PSObject.Properties['AppId'] -and -not [string]::IsNullOrWhiteSpace($Item.AppId)) {
        return $Item.AppId
    }
    elseif ($null -ne $Item.PSObject.Properties['Id'] -and -not [string]::IsNullOrWhiteSpace($Item.Id)) {
        return $Item.Id
    }

    return 'Unknown'
}

function Invoke-GraphAction {
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][string]$ResourceType,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $false)][switch]$Treat404AsSuccess
    )

    for ($Attempt = 1; $Attempt -le $RetryCount; $Attempt++) {
        Write-Log -Stage $Stage -ResourceType $ResourceType -Action "ATTEMPT $Attempt/$RetryCount" -Level 'DEBUG' -Message "Starting: $Name"

        try {
            & $Action
            Write-Log -Stage $Stage -ResourceType $ResourceType -Action 'DELETE' -Level 'INFO' -Message "Succeeded: $Name"
            Add-ReportEntry -Stage $Stage -ResourceType $ResourceType -Name $Name -Status 'SUCCESS' -Reason 'DELETED' -Message 'Deleted successfully.'
            return $true
        }
        catch {
            $Msg = $_.Exception.Message
            $Reason = Get-ErrorReason -Message $Msg

            if ($Reason -eq 'THROTTLED' -and $Attempt -lt $RetryCount) {
                $Delay = [Math]::Max(1, $RetryBaseDelaySeconds * $Attempt)
                Write-Log -Stage $Stage -ResourceType $ResourceType -Action 'RETRY' -Level 'WARNING' -Message "Throttled for $Name. Waiting $Delay seconds before retry."
                Start-Sleep -Seconds $Delay
                continue
            }

            if ($Reason -eq 'ALREADY_DELETED' -and $Treat404AsSuccess) {
                Write-Log -Stage $Stage -ResourceType $ResourceType -Action 'SKIP' -Level 'WARNING' -Message "Already deleted: $Name"
                Add-ReportEntry -Stage $Stage -ResourceType $ResourceType -Name $Name -Status 'SKIPPED' -Reason 'ALREADY_DELETED' -Message $Msg
                return $true
            }

            if ($Reason -eq 'SYNCED_OR_LOCKED') {
                Write-Log -Stage $Stage -ResourceType $ResourceType -Action 'FAILED' -Level 'ERROR' -Message "Synced/locked object: $Name. $Msg"
                Add-ReportEntry -Stage $Stage -ResourceType $ResourceType -Name $Name -Status 'FAILED' -Reason 'SYNCED_OR_LOCKED' -Message $Msg
                return $false
            }

            if ($Reason -eq 'PERMISSION_DENIED') {
                Write-Log -Stage $Stage -ResourceType $ResourceType -Action 'FAILED' -Level 'ERROR' -Message "Permission denied: $Name. $Msg"
                Add-ReportEntry -Stage $Stage -ResourceType $ResourceType -Name $Name -Status 'FAILED' -Reason 'PERMISSION_DENIED' -Message $Msg
                return $false
            }

            if ($Reason -eq 'TRUSTED_LOCATION') {
                Write-Log -Stage $Stage -ResourceType $ResourceType -Action 'FAILED' -Level 'ERROR' -Message "Trusted location issue: $Name. $Msg"
                Add-ReportEntry -Stage $Stage -ResourceType $ResourceType -Name $Name -Status 'FAILED' -Reason 'TRUSTED_LOCATION' -Message $Msg
                return $false
            }

            if ($Attempt -lt $RetryCount) {
                $Delay = [Math]::Max(1, $RetryBaseDelaySeconds * $Attempt)
                Write-Log -Stage $Stage -ResourceType $ResourceType -Action 'RETRY' -Level 'WARNING' -Message "Temporary failure for $Name. Waiting $Delay seconds before retry. Error: $Msg"
                Start-Sleep -Seconds $Delay
                continue
            }

            Write-Log -Stage $Stage -ResourceType $ResourceType -Action 'FAILED' -Level 'ERROR' -Message "Final failure for $Name. Error: $Msg"
            Add-ReportEntry -Stage $Stage -ResourceType $ResourceType -Name $Name -Status 'FAILED' -Reason $Reason -Message $Msg
            return $false
        }
    }

    return $false
}

# ---------------------------
# Authentication
# ---------------------------
Write-Log -Stage 'AUTH' -ResourceType 'GRAPH' -Action 'CONNECT' -Level 'INFO' -Message 'Authenticating to Microsoft Graph...'

if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId) -or [string]::IsNullOrWhiteSpace($ClientSecret)) {
    throw "Missing required authentication parameters (TenantId / ClientId / ClientSecret)."
}

Write-Log -Stage 'AUTH' -ResourceType 'GRAPH' -Action 'VALIDATE' -Level 'DEBUG' -Message "TenantId provided. ClientId provided. SecretLength=$($ClientSecret.Length)"

if ($ClientSecret.Length -lt 20) {
    throw "ClientSecret appears invalid or truncated."
}

$SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential ($ClientId, $SecureSecret)

try {
    Connect-MgGraph `
        -TenantId $TenantId `
        -ClientSecretCredential $Credential `
        -NoWelcome `
        -ContextScope Process

    $Ctx = Get-MgContext
    if (-not $Ctx -or [string]::IsNullOrWhiteSpace($Ctx.ClientId)) {
        throw "Graph authentication succeeded but context is invalid."
    }

    Write-Log -Stage 'AUTH' -ResourceType 'GRAPH' -Action 'CONNECT' -Level 'INFO' -Message "Authentication successful. Connected as AppId: $($Ctx.ClientId)"
}
catch {
    throw "AUTH FAILURE: $($_.Exception.Message)"
}

# ---------------------------
# Main execution
# ---------------------------
try {
    # Safety lock
    Write-Log -Stage 'SAFETY' -ResourceType 'TENANT' -Action 'VERIFY' -Level 'INFO' -Message 'Verifying tenant identity...'

    $Org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
    if ($Org.VerifiedDomains.Name -notcontains $ExpectedTenantDomain) {
        throw "SAFETY LOCK: Tenant domain '$ExpectedTenantDomain' not found. Aborting."
    }

    Write-Log -Stage 'SAFETY' -ResourceType 'TENANT' -Action 'VERIFY' -Level 'INFO' -Message "Tenant safety lock passed. TenantId=$($Org.Id)"

    # DirSync disable
    Write-Log -Stage 'DIRSYNC' -ResourceType 'ORGANIZATION' -Action 'CHECK' -Level 'INFO' -Message 'Checking directory sync status...'

    if ($Org.OnPremisesSyncEnabled) {
        Write-Log -Stage 'DIRSYNC' -ResourceType 'ORGANIZATION' -Action 'DISABLE' -Level 'WARNING' -Message 'Directory sync is enabled. Disabling it now.'

        Invoke-GraphAction -Stage 'DIRSYNC' -ResourceType 'ORGANIZATION' -Name $Org.Id -Action {
            Update-MgOrganization -OrganizationId $Org.Id -OnPremisesSyncEnabled:$false -ErrorAction Stop
        } | Out-Null

        $Elapsed = 0
        do {
            Start-Sleep -Seconds 10
            $Elapsed += 10
            $Org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
            Write-Log -Stage 'DIRSYNC' -ResourceType 'ORGANIZATION' -Action 'WAIT' -Level 'INFO' -Message "Waiting for DirSync propagation... $Elapsed/$DirSyncWaitSeconds seconds"
        } while ($Org.OnPremisesSyncEnabled -and $Elapsed -lt $DirSyncWaitSeconds)

        if ($Org.OnPremisesSyncEnabled) {
            Write-Log -Stage 'DIRSYNC' -ResourceType 'ORGANIZATION' -Action 'WAIT' -Level 'WARNING' -Message 'DirSync still enabled after timeout. Some users may remain blocked until propagation completes.'
        }
        else {
            Write-Log -Stage 'DIRSYNC' -ResourceType 'ORGANIZATION' -Action 'COMPLETE' -Level 'INFO' -Message 'Directory sync disabled and propagation wait completed.'
        }
    }
    else {
        Write-Log -Stage 'DIRSYNC' -ResourceType 'ORGANIZATION' -Action 'CHECK' -Level 'INFO' -Message 'Directory sync is not enabled. Proceeding.'
    }

    # Conditional Access policies
    Write-Log -Stage 'CA' -ResourceType 'POLICY' -Action 'LIST' -Level 'INFO' -Message 'Fetching Conditional Access policies...'
    $Policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

    foreach ($Policy in $Policies) {
        $Name = Get-DisplayNameOrId $Policy
        $PolicyKeys = @()

        if (-not [string]::IsNullOrWhiteSpace($Policy.DisplayName)) { $PolicyKeys += $Policy.DisplayName.ToLower().Trim() }
        if (-not [string]::IsNullOrWhiteSpace($Policy.Id)) { $PolicyKeys += $Policy.Id.ToLower().Trim() }

        if ($PolicyKeys | Where-Object { $SafeExcludeCAPs -contains $_ }) {
            Write-Log -Stage 'CA' -ResourceType 'POLICY' -Action 'SKIP' -Level 'WARNING' -Message "Protected CA policy skipped: $Name"
            Add-ReportEntry -Stage 'CA' -ResourceType 'POLICY' -Name $Name -Status 'SKIPPED' -Reason 'PROTECTED' -Message 'Excluded by configuration.'
            continue
        }

        if ($PSCmdlet.ShouldProcess("CA Policy: $Name", "Delete")) {
            Invoke-GraphAction -Stage 'CA' -ResourceType 'POLICY' -Name $Name -Treat404AsSuccess -Action {
                Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $Policy.Id -ErrorAction Stop
            } | Out-Null
        }
    }

    # Named Locations
    Write-Log -Stage 'CA' -ResourceType 'NAMED_LOCATION' -Action 'LIST' -Level 'INFO' -Message 'Fetching named locations...'
    $NamedLocations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop

    foreach ($Location in $NamedLocations) {
        $Name = Get-DisplayNameOrId $Location
        $LocationKeys = @()

        if (-not [string]::IsNullOrWhiteSpace($Location.DisplayName)) { $LocationKeys += $Location.DisplayName.ToLower().Trim() }
        if (-not [string]::IsNullOrWhiteSpace($Location.Id)) { $LocationKeys += $Location.Id.ToLower().Trim() }

        if ($LocationKeys | Where-Object { $SafeExcludeNamedLocations -contains $_ }) {
            Write-Log -Stage 'CA' -ResourceType 'NAMED_LOCATION' -Action 'SKIP' -Level 'WARNING' -Message "Protected named location skipped: $Name"
            Add-ReportEntry -Stage 'CA' -ResourceType 'NAMED_LOCATION' -Name $Name -Status 'SKIPPED' -Reason 'PROTECTED' -Message 'Excluded by configuration.'
            continue
        }

        if ($PSCmdlet.ShouldProcess("Named Location: $Name", "Untrust and Delete")) {
            $Untrusted = $true

            if ($Location.IsTrusted -eq $true) {
                Write-Log -Stage 'CA' -ResourceType 'NAMED_LOCATION' -Action 'UNTRUST' -Level 'WARNING' -Message "Trusted named location detected. Unmarking trust first: $Name"

                $Body = @{
                    'displayName' = $Location.DisplayName
                    'isTrusted'   = $false
                }

                if ($Location.PSObject.Properties.Name -contains 'AdditionalProperties' -and $null -ne $Location.AdditionalProperties) {
                    try {
                        if ($Location.AdditionalProperties.ContainsKey('@odata.type')) {
                            $Body['@odata.type'] = $Location.AdditionalProperties['@odata.type']
                        }
                    }
                    catch { }
                }

                $Untrusted = Invoke-GraphAction -Stage 'CA' -ResourceType 'NAMED_LOCATION' -Name "$Name (Untrust)" -Treat404AsSuccess -Action {
                    Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId $Location.Id -BodyParameter $Body -ErrorAction Stop
                }
            }

            if ($Untrusted) {
                Invoke-GraphAction -Stage 'CA' -ResourceType 'NAMED_LOCATION' -Name $Name -Treat404AsSuccess -Action {
                    Remove-MgIdentityConditionalAccessNamedLocation -NamedLocationId $Location.Id -ErrorAction Stop
                } | Out-Null
            }
            else {
                Write-Log -Stage 'CA' -ResourceType 'NAMED_LOCATION' -Action 'FAILED' -Level 'WARNING' -Message "Could not untrust named location, so deletion was not attempted: $Name"
            }
        }
    }

    # Access reviews
    Write-Log -Stage 'GOVERNANCE' -ResourceType 'ACCESS_REVIEW' -Action 'LIST' -Level 'INFO' -Message 'Fetching access review definitions...'
    $Reviews = Get-MgIdentityGovernanceAccessReviewDefinition -All -ErrorAction Stop

    foreach ($Review in $Reviews) {
        $Name = Get-DisplayNameOrId $Review

        if ($PSCmdlet.ShouldProcess("Access Review: $Name", "Delete")) {
            Invoke-GraphAction -Stage 'GOVERNANCE' -ResourceType 'ACCESS_REVIEW' -Name $Name -Treat404AsSuccess -Action {
                Remove-MgIdentityGovernanceAccessReviewDefinition -AccessReviewScheduleDefinitionId $Review.Id -ErrorAction Stop
            } | Out-Null
        }
    }

    # Groups
    Write-Log -Stage 'GROUPS' -ResourceType 'GROUP' -Action 'LIST' -Level 'INFO' -Message 'Fetching Entra ID groups...'
    $Groups = Get-MgGroup -All -ErrorAction Stop

    foreach ($Group in $Groups) {
        $Name = Get-DisplayNameOrId $Group
        $GroupKeys = @()

        if (-not [string]::IsNullOrWhiteSpace($Group.DisplayName)) { $GroupKeys += $Group.DisplayName.ToLower().Trim() }
        if (-not [string]::IsNullOrWhiteSpace($Group.Id)) { $GroupKeys += $Group.Id.ToLower().Trim() }

        if ($GroupKeys | Where-Object { $SafeExcludeGroups -contains $_ }) {
            Write-Log -Stage 'GROUPS' -ResourceType 'GROUP' -Action 'SKIP' -Level 'WARNING' -Message "Protected group skipped: $Name"
            Add-ReportEntry -Stage 'GROUPS' -ResourceType 'GROUP' -Name $Name -Status 'SKIPPED' -Reason 'PROTECTED' -Message 'Excluded by configuration.'
            continue
        }

        if ($PSCmdlet.ShouldProcess("Group: $Name", "Delete")) {
            Invoke-GraphAction -Stage 'GROUPS' -ResourceType 'GROUP' -Name $Name -Treat404AsSuccess -Action {
                Remove-MgGroup -GroupId $Group.Id -ErrorAction Stop
            } | Out-Null
        }
    }

    # Exchange Online legacy distribution lists
    if ([string]::IsNullOrWhiteSpace($CertificatePath)) {
        Write-Log -Stage 'EXO' -ResourceType 'DISTRIBUTION_GROUP' -Action 'SKIP' -Level 'WARNING' -Message 'No CertificatePath provided. Skipping Exchange Online legacy distribution group cleanup.'
        Add-ReportEntry -Stage 'EXO' -ResourceType 'DISTRIBUTION_GROUP' -Name 'ExchangeOnline' -Status 'SKIPPED' -Reason 'NO_CERTIFICATE' -Message 'CertificatePath not provided.'
    }
    else {
        try {
            Write-Log -Stage 'EXO' -ResourceType 'SESSION' -Action 'CONNECT' -Level 'INFO' -Message 'Authenticating to Exchange Online...'
            Connect-ExchangeOnline -AppId $ClientId -Organization $ExpectedTenantDomain -CertificateFilePath $CertificatePath -ShowProgress:$false -ErrorAction Stop

            try {
                Write-Log -Stage 'EXO' -ResourceType 'DISTRIBUTION_GROUP' -Action 'LIST' -Level 'INFO' -Message 'Fetching Exchange distribution groups...'
                $DistGroups = Get-DistributionGroup -ResultSize Unlimited -ErrorAction Stop

                foreach ($DL in $DistGroups) {
                    $Name = Get-DisplayNameOrId $DL
                    $DLKeys = @()

                    if (-not [string]::IsNullOrWhiteSpace($DL.DisplayName)) { $DLKeys += $DL.DisplayName.ToLower().Trim() }
                    if (-not [string]::IsNullOrWhiteSpace($DL.Identity)) { $DLKeys += $DL.Identity.ToLower().Trim() }

                    if ($DLKeys | Where-Object { $SafeExcludeGroups -contains $_ }) {
                        Write-Log -Stage 'EXO' -ResourceType 'DISTRIBUTION_GROUP' -Action 'SKIP' -Level 'WARNING' -Message "Protected distribution list skipped: $Name"
                        Add-ReportEntry -Stage 'EXO' -ResourceType 'DISTRIBUTION_GROUP' -Name $Name -Status 'SKIPPED' -Reason 'PROTECTED' -Message 'Excluded by configuration.'
                        continue
                    }

                    if ($PSCmdlet.ShouldProcess("Distribution Group: $Name", "Delete")) {
                        try {
                            Remove-DistributionGroup -Identity $DL.Identity -Confirm:$false -ErrorAction Stop
                            Write-Log -Stage 'EXO' -ResourceType 'DISTRIBUTION_GROUP' -Action 'DELETE' -Level 'INFO' -Message "Deleted distribution group: $Name"
                            Add-ReportEntry -Stage 'EXO' -ResourceType 'DISTRIBUTION_GROUP' -Name $Name -Status 'SUCCESS' -Reason 'DELETED' -Message 'Deleted successfully.'
                        }
                        catch {
                            $Msg = $_.Exception.Message
                            $Reason = Get-ErrorReason -Message $Msg
                            Write-Log -Stage 'EXO' -ResourceType 'DISTRIBUTION_GROUP' -Action 'FAILED' -Level 'ERROR' -Message "Failed to delete distribution group: $Name. $Msg"
                            Add-ReportEntry -Stage 'EXO' -ResourceType 'DISTRIBUTION_GROUP' -Name $Name -Status 'FAILED' -Reason $Reason -Message $Msg
                        }
                    }
                }
            }
            finally {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                }
                catch { }
            }
        }
        catch {
            $Msg = $_.Exception.Message
            Write-Log -Stage 'EXO' -ResourceType 'SESSION' -Action 'FAILED' -Level 'WARNING' -Message "Exchange Online cleanup could not be started. $Msg"
            Add-ReportEntry -Stage 'EXO' -ResourceType 'SESSION' -Name 'ExchangeOnline' -Status 'FAILED' -Reason 'SESSION_CONNECT_FAILED' -Message $Msg
        }
    }

    # Directory roles and role members
    Write-Log -Stage 'ROLES' -ResourceType 'DIRECTORY_ROLE' -Action 'LIST' -Level 'INFO' -Message 'Removing role assignments before user deletion...'
    $Roles = Get-MgDirectoryRole -ErrorAction Stop

    foreach ($Role in $Roles) {
        $RoleName = Get-DisplayNameOrId $Role
        Write-Log -Stage 'ROLES' -ResourceType 'DIRECTORY_ROLE' -Action 'ENUMERATE' -Level 'INFO' -Message "Processing role: $RoleName"

        $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All -ErrorAction Stop
        foreach ($Member in $Members) {
            $MemberName = $Member.Id

            try {
                $MaybeUser = Get-MgUser -UserId $Member.Id -Property Id,UserPrincipalName -ErrorAction SilentlyContinue
                if ($MaybeUser) {
                    $MemberName = $MaybeUser.UserPrincipalName
                    if (Test-IsProtectedUpn -Upn $MaybeUser.UserPrincipalName) {
                        Write-Log -Stage 'ROLES' -ResourceType 'DIRECTORY_ROLE_MEMBER' -Action 'SKIP' -Level 'WARNING' -Message "Protected account retained in role ${RoleName}: ${MemberName}"
                        Add-ReportEntry -Stage 'ROLES' -ResourceType 'DIRECTORY_ROLE_MEMBER' -Name "${RoleName} -> ${MemberName}" -Status 'SKIPPED' -Reason 'PROTECTED' -Message 'Protected account preserved.'
                        continue
                    }
                }

                if ($PSCmdlet.ShouldProcess("Directory role member: ${RoleName} -> ${MemberName}", "Remove role assignment")) {
                    Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $Role.Id -DirectoryObjectId $Member.Id -ErrorAction Stop
                    Write-Log -Stage 'ROLES' -ResourceType 'DIRECTORY_ROLE_MEMBER' -Action 'REMOVE' -Level 'INFO' -Message "Removed from role ${RoleName}: ${MemberName}"
                    Add-ReportEntry -Stage 'ROLES' -ResourceType 'DIRECTORY_ROLE_MEMBER' -Name "${RoleName} -> ${MemberName}" -Status 'SUCCESS' -Reason 'DELETED' -Message 'Role assignment removed.'
                }
            }
            catch {
                $Msg = $_.Exception.Message
                $Reason = Get-ErrorReason -Message $Msg
                Write-Log -Stage 'ROLES' -ResourceType 'DIRECTORY_ROLE_MEMBER' -Action 'FAILED' -Level 'WARNING' -Message "Could not remove role assignment from ${RoleName} for ${MemberName}. ${Msg}"
                Add-ReportEntry -Stage 'ROLES' -ResourceType 'DIRECTORY_ROLE_MEMBER' -Name "${RoleName} -> ${MemberName}" -Status 'FAILED' -Reason $Reason -Message $Msg
            }
        }
    }

    # Service principals
    Write-Log -Stage 'ENTERPRISE_APPS' -ResourceType 'SERVICE_PRINCIPAL' -Action 'LIST' -Level 'INFO' -Message 'Fetching service principals...'
    $ServicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop

    foreach ($SP in $ServicePrincipals) {
        $Name = Get-DisplayNameOrId $SP

        if ($SP.AppId -eq $ClientId) {
            Write-Log -Stage 'ENTERPRISE_APPS' -ResourceType 'SERVICE_PRINCIPAL' -Action 'SKIP' -Level 'WARNING' -Message "Skipping pipeline service principal: $Name"
            Add-ReportEntry -Stage 'ENTERPRISE_APPS' -ResourceType 'SERVICE_PRINCIPAL' -Name $Name -Status 'SKIPPED' -Reason 'PIPELINE_SP' -Message 'Skipping own service principal.'
            continue
        }

        if ($SP.AppOwnerOrganizationId -eq 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' -or $SP.Tags -contains 'WindowsAzureActiveDirectoryIntegratedApp') {
            Write-Log -Stage 'ENTERPRISE_APPS' -ResourceType 'SERVICE_PRINCIPAL' -Action 'SKIP' -Level 'WARNING' -Message "Skipping Microsoft/native or integrated app: $Name"
            Add-ReportEntry -Stage 'ENTERPRISE_APPS' -ResourceType 'SERVICE_PRINCIPAL' -Name $Name -Status 'SKIPPED' -Reason 'MICROSOFT_NATIVE' -Message 'Native/integrated app preserved.'
            continue
        }

        $SPKeys = @()
        if (-not [string]::IsNullOrWhiteSpace($SP.DisplayName)) { $SPKeys += $SP.DisplayName.ToLower().Trim() }
        if (-not [string]::IsNullOrWhiteSpace($SP.AppId)) { $SPKeys += $SP.AppId.ToLower().Trim() }

        if ($SPKeys | Where-Object { $SafeExcludeApps -contains $_ }) {
            Write-Log -Stage 'ENTERPRISE_APPS' -ResourceType 'SERVICE_PRINCIPAL' -Action 'SKIP' -Level 'WARNING' -Message "Protected enterprise app skipped: $Name"
            Add-ReportEntry -Stage 'ENTERPRISE_APPS' -ResourceType 'SERVICE_PRINCIPAL' -Name $Name -Status 'SKIPPED' -Reason 'PROTECTED' -Message 'Excluded by configuration.'
            continue
        }

        if ($PSCmdlet.ShouldProcess("Service Principal: $Name", "Delete")) {
            Invoke-GraphAction -Stage 'ENTERPRISE_APPS' -ResourceType 'SERVICE_PRINCIPAL' -Name $Name -Treat404AsSuccess -Action {
                Remove-MgServicePrincipal -ServicePrincipalId $SP.Id -ErrorAction Stop
            } | Out-Null
        }
    }

    # App registrations
    Write-Log -Stage 'APP_REGISTRATIONS' -ResourceType 'APPLICATION' -Action 'LIST' -Level 'INFO' -Message 'Fetching app registrations...'
    $Apps = Get-MgApplication -All -ErrorAction Stop

    foreach ($App in $Apps) {
        $Name = Get-DisplayNameOrId $App

        if ($App.AppId -eq $ClientId) {
            Write-Log -Stage 'APP_REGISTRATIONS' -ResourceType 'APPLICATION' -Action 'SKIP' -Level 'WARNING' -Message "Skipping pipeline app registration: $Name"
            Add-ReportEntry -Stage 'APP_REGISTRATIONS' -ResourceType 'APPLICATION' -Name $Name -Status 'SKIPPED' -Reason 'PIPELINE_APP' -Message 'Skipping own application registration.'
            continue
        }

        $AppKeys = @()
        if (-not [string]::IsNullOrWhiteSpace($App.DisplayName)) { $AppKeys += $App.DisplayName.ToLower().Trim() }
        if (-not [string]::IsNullOrWhiteSpace($App.AppId)) { $AppKeys += $App.AppId.ToLower().Trim() }

        if ($AppKeys | Where-Object { $SafeExcludeApps -contains $_ }) {
            Write-Log -Stage 'APP_REGISTRATIONS' -ResourceType 'APPLICATION' -Action 'SKIP' -Level 'WARNING' -Message "Protected app registration skipped: $Name"
            Add-ReportEntry -Stage 'APP_REGISTRATIONS' -ResourceType 'APPLICATION' -Name $Name -Status 'SKIPPED' -Reason 'PROTECTED' -Message 'Excluded by configuration.'
            continue
        }

        if ($PSCmdlet.ShouldProcess("App Registration: $Name", "Delete")) {
            Invoke-GraphAction -Stage 'APP_REGISTRATIONS' -ResourceType 'APPLICATION' -Name $Name -Treat404AsSuccess -Action {
                Remove-MgApplication -ApplicationId $App.Id -ErrorAction Stop
            } | Out-Null
        }
    }

    # Devices
    Write-Log -Stage 'DEVICES' -ResourceType 'DEVICE' -Action 'LIST' -Level 'INFO' -Message 'Fetching devices...'
    $Devices = Get-MgDevice -All -ErrorAction Stop

    foreach ($Device in $Devices) {
        $Name = Get-DisplayNameOrId $Device

        if ($PSCmdlet.ShouldProcess("Device: $Name", "Delete")) {
            Invoke-GraphAction -Stage 'DEVICES' -ResourceType 'DEVICE' -Name $Name -Treat404AsSuccess -Action {
                Remove-MgDevice -DeviceId $Device.Id -ErrorAction Stop
            } | Out-Null
        }
    }

    # Users - first pass
    Write-Log -Stage 'USERS' -ResourceType 'USER' -Action 'LIST' -Level 'INFO' -Message 'Fetching users for first cleanup pass...'
    $Users = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,OnPremisesSyncEnabled -ErrorAction Stop

    foreach ($User in $Users) {
        $Upn = $User.UserPrincipalName
        $Name = if (-not [string]::IsNullOrWhiteSpace($User.DisplayName)) { "$($User.DisplayName) <$Upn>" } else { $Upn }

        if ([string]::IsNullOrWhiteSpace($Upn)) {
            Write-Log -Stage 'USERS' -ResourceType 'USER' -Action 'SKIP' -Level 'WARNING' -Message "User without UPN skipped: $($User.Id)"
            Add-ReportEntry -Stage 'USERS' -ResourceType 'USER' -Name $User.Id -Status 'SKIPPED' -Reason 'NO_UPN' -Message 'No user principal name available.'
            continue
        }

        if (Test-IsProtectedUpn -Upn $Upn) {
            Write-Log -Stage 'USERS' -ResourceType 'USER' -Action 'SKIP' -Level 'WARNING' -Message "Protected account skipped: $Name"
            Add-ReportEntry -Stage 'USERS' -ResourceType 'USER' -Name $Upn -Status 'SKIPPED' -Reason 'PROTECTED' -Message 'Protected admin/breakglass account.'
            continue
        }

        if ($PSCmdlet.ShouldProcess("User: $Upn", "Delete")) {
            Invoke-GraphAction -Stage 'USERS' -ResourceType 'USER' -Name $Name -Treat404AsSuccess -Action {
                Remove-MgUser -UserId $User.Id -ErrorAction Stop
            } | Out-Null
        }
    }

    # Users - second pass
    Write-Log -Stage 'USERS' -ResourceType 'USER' -Action 'WAIT' -Level 'INFO' -Message 'Waiting briefly before second user cleanup pass...'
    Start-Sleep -Seconds 20

    Write-Log -Stage 'USERS' -ResourceType 'USER' -Action 'LIST' -Level 'INFO' -Message 'Fetching users for second cleanup pass...'
    $UsersSecondPass = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,OnPremisesSyncEnabled -ErrorAction Stop

    foreach ($User in $UsersSecondPass) {
        $Upn = $User.UserPrincipalName
        $Name = if (-not [string]::IsNullOrWhiteSpace($User.DisplayName)) { "$($User.DisplayName) <$Upn>" } else { $Upn }

        if ([string]::IsNullOrWhiteSpace($Upn)) {
            continue
        }

        if (Test-IsProtectedUpn -Upn $Upn) {
            continue
        }

        if ($PSCmdlet.ShouldProcess("User: $Upn", "Delete (second pass)")) {
            $Ok = Invoke-GraphAction -Stage 'USERS' -ResourceType 'USER' -Name "$Name (Second pass)" -Treat404AsSuccess -Action {
                Remove-MgUser -UserId $User.Id -ErrorAction Stop
            }

            if (-not $Ok) {
                Write-Log -Stage 'USERS' -ResourceType 'USER' -Action 'RETAINED' -Level 'WARNING' -Message "User still could not be deleted after second pass: $Name"
            }
        }
    }

    # Summary
    Write-Log -Stage 'SUMMARY' -ResourceType 'REPORT' -Action 'COUNTS' -Level 'INFO' -Message "SUCCESS=$($script:Summary.SUCCESS) SKIPPED=$($script:Summary.SKIPPED) FAILED=$($script:Summary.FAILED)"

    try {
        $script:Report | Export-Csv -Path $ReportCsvPath -NoTypeInformation -Force
        $script:Report | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportJsonPath -Encoding UTF8
        Write-Log -Stage 'SUMMARY' -ResourceType 'REPORT' -Action 'EXPORT' -Level 'INFO' -Message "Report exported to: $ReportCsvPath and $ReportJsonPath"
    }
    catch {
        Write-Log -Stage 'SUMMARY' -ResourceType 'REPORT' -Action 'EXPORT' -Level 'WARNING' -Message "Could not export report files: $($_.Exception.Message)"
    }

    Write-Log -Stage 'SUMMARY' -ResourceType 'REPORT' -Action 'DONE' -Level 'INFO' -Message 'Teardown execution completed.'
}
catch {
    Write-Log -Stage 'FATAL' -ResourceType 'SCRIPT' -Action 'ERROR' -Level 'ERROR' -Message "CRITICAL FAILURE: $($_.Exception.Message)"
    throw
}
finally {
    Write-Log -Stage 'CLEANUP' -ResourceType 'DIRECTORY_ROLE' -Action 'REMOVE_GA' -Level 'INFO' -Message 'Removing Global Administrator role from the service principal if assigned...'

    try {
        $Role = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq 'Global Administrator' }
        $Sp = Get-MgServicePrincipal -Filter "appId eq '$ClientId'" -ErrorAction SilentlyContinue

        if ($Role -and $Sp) {
            try {
                Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $Role.Id -DirectoryObjectId $Sp.Id -ErrorAction Stop
                Write-Log -Stage 'CLEANUP' -ResourceType 'DIRECTORY_ROLE' -Action 'REMOVE_GA' -Level 'INFO' -Message 'Global Administrator role removed from the service principal.'
            }
            catch {
                Write-Log -Stage 'CLEANUP' -ResourceType 'DIRECTORY_ROLE' -Action 'REMOVE_GA' -Level 'WARNING' -Message "Could not remove Global Administrator role: $($_.Exception.Message)"
            }
        }
        else {
            Write-Log -Stage 'CLEANUP' -ResourceType 'DIRECTORY_ROLE' -Action 'REMOVE_GA' -Level 'WARNING' -Message 'Global Administrator role or service principal not found during cleanup.'
        }
    }
    catch {
        Write-Log -Stage 'CLEANUP' -ResourceType 'DIRECTORY_ROLE' -Action 'REMOVE_GA' -Level 'WARNING' -Message "Role cleanup check failed: $($_.Exception.Message)"
    }

    Write-Log -Stage 'CLEANUP' -ResourceType 'SESSION' -Action 'DISCONNECT' -Level 'INFO' -Message 'Disconnecting sessions...'

    try {
        if (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }
    }
    catch { }

    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
    }
    catch { }

    try {
        Stop-Transcript | Out-Null
    }
    catch { }
}