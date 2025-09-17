<#
.SYNOPSIS
    Автоматизированная система управления жизненным циклом учетных записей
.DESCRIPTION
    Скрипт для интеллектуального отключения и аудита учетных записей уволенных сотрудников
    с интеграцией с SIEM системой и многоуровневым логированием
.NOTES
    Version: 2.0
    Author: Security Automation Team
    Requires: Module ActiveDirectory, PSSQLite
#>

#region Конфигурация
$Config = @{
    DomainController = ""
    TerminationOU = "OU=Уволенные,OU=Пользователи,DC=corp,DC=domain,DC=com"
    RetentionPeriod = 90
    SIEMEndpoint = ""
    DatabasePath = "C:\ProgramData\IdentityManager\accounts.db"
    LogDirectory = "C:\Audit\IdentityLifecycle"
    NotificationEmail = "security-team@domain.com"
}
#endregion

#region Инициализация
class AccountLifecycle {
    [string]$SamAccountName
    [datetime]$DeactivationDate
    [string]$Manager
    [string]$Department
    [bool]$HasActiveSessions
    [string]$Status
}

function Initialize-Environment {
    param($Config)
    
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        throw "Требуется модуль ActiveDirectory"
    }
    
    Import-Module ActiveDirectory -Force
    
    # Создание структуры каталогов
    $directories = @($Config.LogDirectory, (Split-Path $Config.DatabasePath))
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
    
    # Инициализация базы данных
    Initialize-AccountDatabase -Path $Config.DatabasePath
}
#endregion

#region База данных
function Initialize-AccountDatabase {
    param($Path)
    
    $query = @"
    CREATE TABLE IF NOT EXISTS AccountHistory (
        Id INTEGER PRIMARY KEY AUTOINCREMENT,
        SamAccountName TEXT NOT NULL,
        DeactivationDate TEXT NOT NULL,
        Manager TEXT,
        Department TEXT,
        PreviousState TEXT,
        ActionPerformed TEXT,
        Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS AuditLog (
        Id INTEGER PRIMARY KEY AUTOINCREMENT,
        EventType TEXT NOT NULL,
        Message TEXT NOT NULL,
        Severity TEXT NOT NULL,
        Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
"@
    Invoke-SQLiteQuery -Query $query -DataSource $Path
}
#endregion

#region Мониторинг
function Get-AccountRiskAssessment {
    param($User)
    
    $riskScore = 0
    $indicators = @()
    
    # Проверка последнего входа
    if ($User.LastLogonDate -gt (Get-Date).AddDays(-7)) {
        $riskScore += 30
        $indicators += "Активный вход в последние 7 дней"
    }
    
    # Проверка членства в привилегированных группы
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
    $userGroups = Get-ADPrincipalGroupMembership $User | Select-Object -ExpandProperty Name
    if ($userGroups | Where-Object { $_ -in $privilegedGroups }) {
        $riskScore += 50
        $indicators += "Член привилегированной группы"
    }
    
    # Проверка активных сессий (псевдо-код, реализация зависит от среды)
    $activeSessions = Test-ActiveUserSessions -UserName $User.SamAccountName
    if ($activeSessions) {
        $riskScore += 70
        $indicators += "Обнаружены активные сессии"
    }
    
    return @{
        RiskScore = $riskScore
        Indicators = $indicators
        RiskLevel = if ($riskScore -ge 70) { "High" } elseif ($riskScore -ge 30) { "Medium" } else { "Low" }
    }
}

function Test-ActiveUserSessions {
    param($UserName)
    # Реализация проверки активных сессий через WinRM или мониторинг RDP
    # Возвращает $true если есть активные сессии
    return $false
}
#endregion

#region Действия
function Invoke-AccountDeactivation {
    param($User, $Config)
    
    $lifecycleData = [AccountLifecycle]@{
        SamAccountName = $User.SamAccountName
        DeactivationDate = Get-Date
        Manager = $User.Manager
        Department = $User.Department
        HasActiveSessions = Test-ActiveUserSessions -UserName $User.SamAccountName
        Status = "Pending"
    }
    
    # Оценка рисков
    $riskAssessment = Get-AccountRiskAssessment -User $User
    
    if ($riskAssessment.RiskLevel -eq "High") {
        # Срочное уведомление для высокого риска
        Send-ImmediateAlert -User $User -RiskAssessment $riskAssessment -Config $Config
    }
    
    try {
        # Дополнительные меры безопасности для привилегированных учетных записей
        if ($riskAssessment.RiskScore -gt 0) {
            Revoke-UserSessions -UserName $User.SamAccountName
            Reset-UserPassword -UserName $User.SamAccountName
        }
        
        # Отключение учетной записи
        Disable-ADAccount -Identity $User -Confirm:$false
        Set-ADUser -Identity $User -Description "Deactivated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        
        # Сброс атрибутов
        Clear-ADUserRiskAttributes -User $User
        
        $lifecycleData.Status = "Completed"
        Write-AuditLog -EventType "Deactivation" -Message "Учетная запись $($User.SamAccountName) отключена" -Severity "Info"
        
    } catch {
        $lifecycleData.Status = "Failed"
        Write-AuditLog -EventType "Error" -Message "Ошибка отключения $($User.SamAccountName): $($_.Exception.Message)" -Severity "Error"
    }
    
    # Сохранение в базу данных
    Save-AccountHistory -LifecycleData $lifecycleData -Config $Config
}
#endregion

#region Уведомления
function Send-ImmediateAlert {
    param($User, $RiskAssessment, $Config)
    
    $subject = "🚨 ВЫСОКИЙ РИСК: Требуется немедленное действие для учетной записи $($User.SamAccountName)"
    $body = @"
Критическое уведомление безопасности:
Учетная запись: $($User.SamAccountName)
Уровень риска: $($RiskAssessment.RiskLevel) ($($RiskAssessment.RiskScore) баллов)
Причины: $($RiskAssessment.Indicators -join ', ')
Время обнаружения: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Требуется немедленное вмешательство!
"@
    
    # Отправка через SMTP или API системы уведомлений
    Send-EmailNotification -To $Config.NotificationEmail -Subject $subject -Body $body
}
#endregion

#region Логирование
function Write-AuditLog {
    param($EventType, $Message, $Severity)
    
    $logEntry = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        EventType = $EventType
        Message = $Message
        Severity = $Severity
        Hostname = $env:COMPUTERNAME
    }
    
    # Локальное логирование
    $logPath = Join-Path $Config.LogDirectory "audit_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logPath -Value ($logEntry | ConvertTo-Json -Compress)
    
    # Отправка в SIEM систему
    try {
        Invoke-RestMethod -Uri $Config.SIEMEndpoint -Method Post -Body ($logEntry | ConvertTo-Json) -ContentType "application/json"
    } catch {
        Write-Warning "Не удалось отправить лог в SIEM: $($_.Exception.Message)"
    }
}
#endregion

#region Главный процесс
function Start-AccountLifecycleManagement {
    param($Config)
    
    Initialize-Environment -Config $Config
    Write-AuditLog -EventType "ProcessStart" -Message "Запуск управления жизненным циклом учетных записей" -Severity "Info"
    
    try {
        # Поиск учетных записей для обработки
        $users = Get-ADUser -Filter * -SearchBase $Config.TerminationOU -Properties *
        
        foreach ($user in $users) {
            if ($user.Enabled) {
                Write-AuditLog -EventType "Processing" -Message "Обработка учетной записи: $($user.SamAccountName)" -Severity "Info"
                Invoke-AccountDeactivation -User $user -Config $Config
            }
        }
        
    } catch {
        Write-AuditLog -EventType "Error" -Message "Критическая ошибка процесса: $($_.Exception.Message)" -Severity "Critical"
    } finally {
        Write-AuditLog -EventType "ProcessEnd" -Message "Завершение управления жизненным циклом учетных записей" -Severity "Info"
    }
}

# Запуск процесса
Start-AccountLifecycleManagement -Config $Config
#endregion