<#
.SYNOPSIS
    Automated account lifecycle management system
.DESCRIPTION
    Script for intelligent deactivation and auditing of terminated employee accounts
    with risk assessment
.NOTES
    Version: 0.5
    Author: Security Automation Team
    Requires: Module ActiveDirectory
#>

#region Configuration
$Config = @{
    DomainController = "DC01.corp.domain.com"
    TerminationOU = "OU=Уволенные,OU=Пользователи,DC=corp,DC=domain,DC=com"
    RetentionPeriod = 90
    DatabasePath = "C:\ProgramData\IdentityManager\accounts.db"
    LogDirectory = "C:\Audit\IdentityLifecycle"
}
#endregion

#region Initialization
class AccountLifecycle {
    [string]$SamAccountName
    [datetime]$DeactivationDate
    [string]$Status
}

function Initialize-Environment {
    param($Config)
    
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        throw "ActiveDirectory module required"
    }
    
    Import-Module ActiveDirectory -Force
    
    # Create directory structure
    $directories = @($Config.LogDirectory, (Split-Path $Config.DatabasePath))
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
}
#endregion

#region Risk assessment
function Get-AccountRiskAssessment {
    param($User)
    
    $riskScore = 0
    $indicators = @()
    
    # Check last logon
    if ($User.LastLogonDate -gt (Get-Date).AddDays(-7)) {
        $riskScore += 30
        $indicators += "Recent login activity"
    }
    
    # Check privileged groups
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
    $userGroups = Get-ADPrincipalGroupMembership $User | Select-Object -ExpandProperty Name
    if ($userGroups | Where-Object { $_ -in $privilegedGroups }) {
        $riskScore += 50
        $indicators += "Privileged group member"
    }
    
    return @{
        RiskScore = $riskScore
        Indicators = $indicators
        RiskLevel = if ($riskScore -ge 70) { "High" } elseif ($riskScore -ge 30) { "Medium" } else { "Low" }
    }
}
#endregion

#region Enhanced logging
function Write-AuditLog {
    param($EventType, $Message, $Severity = "Info")
    
    $logEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        EventType = $EventType
        Message = $Message
        Severity = $Severity
        Hostname = $env:COMPUTERNAME
    }
    
    $logPath = Join-Path $Config.LogDirectory "audit_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logPath -Value ($logEntry | ConvertTo-Json -Compress)
}
#endregion

#region Main process
function Start-AccountLifecycleManagement {
    param($Config)
    
    Initialize-Environment -Config $Config
    Write-AuditLog -EventType "ProcessStart" -Message "Starting account lifecycle management"
    
    try {
        $users = Get-ADUser -Filter * -SearchBase $Config.TerminationOU -Properties *
        
        foreach ($user in $users) {
            if ($user.Enabled) {
                Write-AuditLog -EventType "Processing" -Message "Processing account: $($user.SamAccountName)"
                
                # Risk assessment
                $riskAssessment = Get-AccountRiskAssessment -User $user
                if ($riskAssessment.RiskLevel -eq "High") {
                    Write-AuditLog -EventType "HighRisk" -Message "High risk account detected: $($user.SamAccountName)" -Severity "Warning"
                }
                
                # Deactivate account
                Disable-ADAccount -Identity $User -Confirm:$false
                Set-ADUser -Identity $User -Description "Deactivated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                
                Write-AuditLog -EventType "Deactivation" -Message "Account $($user.SamAccountName) disabled"
            }
        }
        
    } catch {
        Write-AuditLog -EventType "Error" -Message "Process error: $($_.Exception.Message)" -Severity "Error"
    } finally {
        Write-AuditLog -EventType "ProcessEnd" -Message "Process completed"
    }
}

Start-AccountLifecycleManagement -Config $Config
#endregion