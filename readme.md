# Entra ID Enterprise Teardown Pipeline

An automated, enterprise-grade CI/CD pipeline designed to cleanly and safely reset a Microsoft Entra ID tenant.

Built for Gitea Actions running on ARM64 infrastructure, this pipeline uses Microsoft Graph PowerShell to systematically purge Conditional Access policies, Named Locations, Access Reviews, Groups, Enterprise Applications, App Registrations, Devices, and Users. It preserves designated administrative accounts, break-glass accounts, and explicitly excluded infrastructure.

---

## Table of Contents

- [What this pipeline does](#what-this-pipeline-does)
- [Why this exists](#why-this-exists)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [One-time setup](#one-time-setup)
- [Secrets and variables](#secrets-and-variables)
- [Workflow usage](#workflow-usage)
- [QA / validation](#qa--validation)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Security and governance](#security-and-governance)
- [Operational checklist](#operational-checklist)

---

## What this pipeline does

The teardown process is dependency-aware and runs in a controlled order:

1. Authenticate to Microsoft Graph.
2. Verify the target tenant domain as a safety lock.
3. Disable Directory Synchronization if enabled.
4. Remove Conditional Access policies.
5. Untrust and remove Named Locations.
6. Remove Access Review definitions.
7. Delete Groups.
8. Optionally remove Exchange Online legacy Distribution Groups.
9. Remove Enterprise Applications (Service Principals).
10. Remove App Registrations.
11. Remove Devices.
12. Remove Users, while preserving protected accounts.
13. Remove the Global Administrator role from the teardown Service Principal during cleanup.
14. Export logs and a final report for auditability.

---

## Why this exists

Doing a full reset manually in the Entra admin center is slow, error-prone, and difficult to audit. This pipeline provides:

- **Consistency**: the same safe workflow every run
- **Auditability**: transcripts and reports for every execution
- **Safety controls**: tenant-domain safety lock, exclusions, and protected accounts
- **Repeatability**: dry-run first, live run only after validation
- **Scale**: handles large tenants far faster than manual cleanup

---

## Architecture

The solution has three parts:

1. **Setup script**  
   Creates the Entra application, service principal, client secret, and permissions.

2. **Teardown script**  
   `Reset-EntraTenant.ps1` performs the actual cleanup.

3. **CI/CD workflow**  
   Gitea Actions runs the script in:
   - **dry-run mode** for pull requests
   - **execute mode** for push to `main` or manual dispatch

---

## Prerequisites

### Azure / Entra requirements
- Microsoft Entra tenant
- A Global Administrator account for one-time setup
- Permission to create app registrations and assign directory roles

### Runtime requirements
- PowerShell 7.x on the runner
- Microsoft Graph PowerShell modules
- Exchange Online PowerShell module if you plan to delete legacy distribution groups
- A runner with network access to Microsoft Graph and Exchange Online endpoints

### Operational requirements
- A verified tenant domain to act as the safety lock
- A list of admin and break-glass accounts to preserve
- A list of groups, apps, CA policies, and named locations to exclude

---

## One-time setup

### Step 1: Create the teardown app and client secret

Use a Global Administrator account and run the setup script locally. This script creates the app registration, generates a client secret, and grants Microsoft Graph permissions.

```powershell
$ErrorActionPreference = "Stop"

$AppName = "Entra-ID-Environment-Teardown-SP"

$RequiredPermissions = @(
    "User.ReadWrite.All", "Group.ReadWrite.All", "Application.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess", "Policy.Read.All",
    "AccessReview.ReadWrite.All", "AccessReview.Read.All",
    "Device.ReadWrite.All", "Organization.ReadWrite.All", "Directory.ReadWrite.All"
)

Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Cyan

Connect-MgGraph `
    -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All","Directory.ReadWrite.All" `
    -UseDeviceAuthentication `
    -NoWelcome `
    -ContextScope Process `
    -Environment Global

try {
    $Context = Get-MgContext
    if (-not $Context.Account) {
        throw "Graph authentication failed. No account context found."
    }

    Write-Host "Creating App Registration..." -ForegroundColor Yellow
    $App = New-MgApplication -DisplayName $AppName

    if (-not $App.Id) {
        throw "Application creation failed."
    }

    Write-Host "Generating Client Secret..." -ForegroundColor Yellow
    $Secret = Add-MgApplicationPassword `
        -ApplicationId $App.Id `
        -PasswordCredential @{
            DisplayName = "Gitea Pipeline"
            EndDateTime = (Get-Date).AddYears(1)
        }

    Write-Host "Creating Service Principal..." -ForegroundColor Yellow
    $Sp = New-MgServicePrincipal -AppId $App.AppId

    Start-Sleep -Seconds 15

    $GraphSp = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"

    if (-not $GraphSp) {
        throw "Microsoft Graph SP not found."
    }

    Write-Host "Assigning Graph API Permissions..." -ForegroundColor Yellow

    foreach ($RoleName in $RequiredPermissions) {
        $AppRole = $GraphSp.AppRoles | Where-Object { $_.Value -eq $RoleName }

        if ($AppRole) {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $Sp.Id `
                -PrincipalId $Sp.Id `
                -ResourceId $GraphSp.Id `
                -AppRoleId $AppRole.Id | Out-Null

            Write-Host " -> Granted: $RoleName" -ForegroundColor Green
        }
        else {
            Write-Host " -> Skipped (not found): $RoleName" -ForegroundColor DarkYellow
        }
    }

    $TenantId = (Get-MgOrganization | Select-Object -First 1).Id

    Write-Host "`n=== COPY THESE TO YOUR GITEA SECRETS ===" -ForegroundColor Green
    Write-Host "ENTRA_TENANT_ID     : $TenantId"
    Write-Host "ENTRA_CLIENT_ID     : $($App.AppId)"
    Write-Host "ENTRA_CLIENT_SECRET : $($Secret.SecretText)"
    Write-Host "========================================`n" -ForegroundColor Green
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}
```

### Step 2: Assign Global Administrator to the service principal

This is required if the pipeline must delete privileged users.

```powershell
$ClientId = "PASTE_YOUR_CLIENT_ID_HERE"

Write-Host "Authenticating via Device Code..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All" -UseDeviceAuthentication -NoWelcome

try {
    $Sp = Get-MgServicePrincipal -Filter "AppId eq '$ClientId'"
    $GlobalAdminRole = Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq 'Global Administrator'"

    $ExistingAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "PrincipalId eq '$($Sp.Id)' and RoleDefinitionId eq '$($GlobalAdminRole.Id)'"

    if ($ExistingAssignments) {
        Write-Host "Service Principal is already a Global Administrator." -ForegroundColor DarkGray
    }
    else {
        $RoleAssignment = @{
            PrincipalId = $Sp.Id
            RoleDefinitionId = $GlobalAdminRole.Id
            DirectoryScopeId = "/"
        }
        New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $RoleAssignment | Out-Null
        Write-Host "SUCCESS! Global Admin role assigned." -ForegroundColor Green
    }
}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}
```

---

## Secrets and variables

### Repository secrets

Store these in your repository secrets:

| Secret name | Purpose | Example |
|---|---|---|
| `ENTRA_TENANT_ID` | Tenant GUID | `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee` |
| `ENTRA_CLIENT_ID` | Application (client) ID | `11111111-2222-3333-4444-555555555555` |
| `ENTRA_CLIENT_SECRET` | Client secret generated in setup | `long-random-secret-value` |

### Repository variables

Store these in repository variables:

| Variable name | Purpose | Example |
|---|---|---|
| `ENTRA_TARGET_DOMAIN` | Safety lock domain | `contoso.onmicrosoft.com` |
| `ADMIN_UPNS` | Protected admin UPNs | `admin@contoso.com,cto@contoso.com` |
| `BREAKGLASS_UPNS` | Protected break-glass accounts | `breakglass@contoso.com` |
| `EXCLUDE_GROUPS` | Groups to preserve | `Global Administrators,Security Baseline` |
| `EXCLUDE_APPS` | Apps/SPs to preserve | `Azure DevOps Sync App,entra-helpdesk` |
| `EXCLUDE_CAPS` | CA policies to preserve | `Require MFA for Admins,Block Legacy Auth` |
| `EXCLUDE_NAMED_LOCATIONS` | Named locations to preserve | `Corporate HQ,Developer VPN` |

### Example formatting guidance

Use comma-separated values without extra spaces where possible.

Good:
```text
admin@contoso.com,cto@contoso.com
```

Also accepted:
```text
admin@contoso.com, cto@contoso.com
```

The script trims whitespace automatically.

---

## Workflow usage

### Dry-run mode

Use dry-run in pull requests or manual validation. It produces a transcript but does not delete objects.

### Live mode

Use live execution only after the dry-run looks correct and the environment is approved.

### Manual dispatch inputs

The workflow accepts manual inputs for:
- run mode
- target domain
- admin accounts
- break-glass accounts
- exclusion lists

---

## QA / validation

Use the checklist below before every destructive run.

### Pre-run QA
- Confirm the tenant domain matches `ENTRA_TARGET_DOMAIN`
- Confirm the service principal has the required Graph permissions
- Confirm Global Administrator is assigned to the service principal if privileged users must be deleted
- Confirm the client secret is valid and not expired
- Confirm break-glass accounts are included in `BREAKGLASS_UPNS`
- Confirm any SCIM or external IdP provisioning is paused
- Confirm any critical groups, apps, and CA policies are listed in exclusions

### Dry-run QA
- Validate the script syntax locally with PSScriptAnalyzer
- Run the pipeline in dry-run mode
- Review the transcript for:
  - tenant mismatch warnings
  - permission errors
  - missing modules
  - excluded object lists
  - named location trust handling
  - role cleanup behavior

### Live-run QA
- Verify the workflow ran on the correct branch or manual approval path
- Review the transcript for:
  - all expected resource types processed
  - skipped protected accounts
  - remaining synced objects
  - any 404/429 handling
- Review the exported CSV/JSON report if enabled
- Confirm the tenant is in the expected post-reset state

### Post-run QA
- Check that protected accounts still exist
- Confirm excluded groups/apps/policies still exist
- Validate no accidental removal of named locations used by conditional access
- Review any failed entries in the report and rerun if needed

---

## Limitations

This pipeline is powerful, but it has important limits:

1. **Synced users and objects**  
   Objects mastered on-premises may not be deletable until synchronization is disabled and propagation completes, or they must be deleted from the source directory.

2. **Privileged identity protection**  
   Some users and role assignments may still require elevated directory permissions and may fail if the service principal does not have sufficient roles.

3. **Trusted named locations**  
   Trusted named locations must be untrusted before deletion.

4. **Exchange Online dependency**  
   Legacy distribution list cleanup requires a certificate-based Exchange Online connection. If no certificate is provided, that phase is skipped.

5. **Eventual consistency**  
   Microsoft Graph is eventually consistent. Some deletions may return 404 if the object already disappeared or if another operation removed it first.

6. **Throttling**  
   Large tenants can trigger 429 responses. Retry logic helps, but very large environments may still need multiple runs.

7. **External identity providers / SCIM**  
   If an external IdP is still provisioning users or groups, deleted objects may be recreated after the teardown unless provisioning is paused first.

8. **Destructive by design**  
   This is not a recovery workflow. It is intended for controlled reset scenarios only.

---

## Troubleshooting

### Problem: PowerShell parser error with `:`
Use `${variable}` when a variable is followed by a colon or other special character.

Bad:
```powershell
"Protected account retained in role $RoleName: $MemberName"
```

Good:
```powershell
"Protected account retained in role ${RoleName}: ${MemberName}"
```

### Problem: Client secret authentication fails
Check:
- secret value is correct
- secret is not expired
- `ENTRA_CLIENT_ID` matches the app registration
- `ENTRA_TENANT_ID` matches the correct tenant

### Problem: Named location cannot be deleted
The location is trusted. Unmark it as trusted before deletion.

### Problem: User deletion says insufficient privileges
The service principal needs the required directory role, and privileged users may require Global Administrator.

### Problem: Synced users fail to delete
Disable directory sync and wait for propagation, or delete the user from the authoritative source.

### Problem: Module installation happens every run
This is expected on ephemeral runners. Each job starts on a fresh machine, so modules are not retained unless you cache them or use a self-hosted runner.

---

## Security and governance

### Branch protection
Protect the `main` branch so destructive changes must go through pull requests and review.

### Manual approval
Use an environment gate such as `production-teardown` so live deletion requires approval.

### Break-glass accounts
Always maintain at least one break-glass account outside the deletion scope.

### Secret hygiene
Rotate the client secret on a schedule and immediately if there is any suspicion of exposure.

### Logging
Keep transcripts and exported reports for audit and incident review.

---

## Operational checklist

Before execution:

- [ ] Confirm the target tenant domain
- [ ] Confirm secrets are present
- [ ] Confirm variables are formatted correctly
- [ ] Confirm SCIM / external provisioning is paused
- [ ] Confirm break-glass admins are excluded
- [ ] Confirm any must-keep groups/apps/policies are excluded
- [ ] Confirm dry-run completed successfully
- [ ] Confirm live execution has approval

After execution:

- [ ] Review transcript
- [ ] Review CSV / JSON report
- [ ] Confirm protected accounts remain
- [ ] Confirm excluded objects remain
- [ ] Archive logs for audit

---

## Suggested repository structure

```text
.
├── Reset-EntraTenant.ps1
├── .gitea/
│   └── workflows/
│       └── entra-teardown.yaml
├── README.md
├── Setup-TeardownApp.ps1
├── Assign-GlobalAdmin.ps1
└── .gitignore
```

---

## Example `.gitignore`

```text
*.log
*.csv
*.json
.vscode/
.idea/
```

---

## Support notes

If you customize the script or workflow, re-run the dry-run first. For destructive automation, every change should be treated as a release candidate.

