<#
.SYNOPSIS
    Automated account lifecycle management system
.DESCRIPTION
    Script for intelligent deactivation and auditing of terminated employee accounts
.NOTES
    Version: 0.1
    Author: Security Automation Team
    Requires: Module ActiveDirectory
#>

#region Configuration
$Config = @{
    DomainController = "DC01.corp.domain.com"
    TerminationOU = "OU=Уволенные,OU=Пользователи,DC=corp,DC=domain,DC=com"
    LogDirectory = "C:\Audit\IdentityLifecycle"
}
#endregion

#region Initialization
function Initialize-Environment {
    param($Config)
    
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        throw "ActiveDirectory module required"
    }
    
    Import-Module ActiveDirectory -Force
    
    # Create directory structure
    if (-not (Test-Path $Config.LogDirectory)) {
        New-Item -Path $Config.LogDirectory -ItemType Directory -Force | Out-Null
    }
}
#endregion

#region Basic logging
function Write-Log {
    param($Message)
    
    $logEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Message = $Message
        Hostname = $env:COMPUTERNAME
    }
    
    $logPath = Join-Path $Config.LogDirectory "audit_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logPath -Value ($logEntry | ConvertTo-Json -Compress)
}
#endregion

#region Main process
function Start-AccountDeactivation {
    param($Config)
    
    Initialize-Environment -Config $Config
    Write-Log -Message "Starting account deactivation process"
    
    try {
        # Find accounts to process
        $users = Get-ADUser -Filter * -SearchBase $Config.TerminationOU -Properties Enabled
        
        foreach ($user in $users) {
            if ($user.Enabled) {
                Write-Log -Message "Processing account: $($user.SamAccountName)"
                Disable-ADAccount -Identity $User -Confirm:$false
                Set-ADUser -Identity $User -Description "Deactivated: $(Get-Date -Format 'yyyy-MM-dd')"
                Write-Log -Message "Account $($user.SamAccountName) disabled"
            }
        }
        
    } catch {
        Write-Log -Message "Error: $($_.Exception.Message)"
    } finally {
        Write-Log -Message "Process completed"
    }
}

# Start process
Start-AccountDeactivation -Config $Config
#endregion