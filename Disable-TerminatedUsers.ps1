<#
.SYNOPSIS
    Автоматизированная система управления жизненным циклом учетных записей
.DESCRIPTION
    Скрипт для интеллектуального отключения и аудита учетных записей уволенных сотрудников
    с интеграцией с SIEM системой и многоуровневым логированием
.NOTES
    Version: 2.1
    Author: Security Automation Team
    Requires: Module ActiveDirectory, PSSQLite
#>

#region Конфигурация
$Config = @{
    DomainController = ""
    TerminationOU = "OU=Уволенные,OU=Пользователи,DC=corp,DC=domain, DC=com"
    RetentionPeriod = 90
    SIEMEndpoint = ""
    DatabasePath = "C:\ProgramData\IdentityManager\accounts.db"
    LogDirectory = "C:\Audit\IdentityLifecycle"
    NotificationEmail = "security-team@domain.com"
    LogRetentionDays = 30
    CriticalAccessGroups = @(
        "Finance_System_Admins",
        "SQL_DB_Owners", 
        "ERP_Superusers",
        "VPN_Privileged_Access",
        "SharePoint_Administrators"
    )
}
#endregion


function Get-CriticalAccessGroups {
    param($UserName)
    
    $criticalGroups = @()
    $allGroups = Get-ADPrincipalGroupMembership -Identity $UserName | Select-Object -ExpandProperty Name
    
    foreach ($group in $Config.CriticalAccessGroups) {
        if ($allGroups -contains $group) {
            $criticalGroups += $group
        }
    }
    
    return $criticalGroups
}

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
    
    CREATE INDEX IF NOT EXISTS idx_account_history_name ON AccountHistory(SamAccountName);
    CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON AuditLog(Timestamp);
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
    
    # Проверка членства в привилегированных группах
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
    $userGroups = Get-ADPrincipalGroupMembership $User | Select-Object -ExpandProperty Name
    if ($userGroups | Where-Object { $_ -in $privilegedGroups }) {
        $riskScore += 50
        $indicators += "Член привилегированной группы"
    }

    $criticalGroups = Get-CriticalAccessGroups -UserName $User.SamAccountName
    if ($criticalGroups.Count -gt 0) {
        $riskScore += 40
        $indicators += "Член критичных групп доступа: $($criticalGroups -join ', ')"
        # Сохраняем информацию о критичных группах для детального отчета
        $User | Add-Member -NotePropertyName CriticalAccessGroups -NotePropertyValue $criticalGroups -Force
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

function Send-CriticalAccessNotification {
    param($User, $CriticalGroups, $Config)
    
    $subject = "⚠️ КРИТИЧНЫЙ ДОСТУП: Учетная запись $($User.SamAccountName) имеет привилегированный доступ"
    $body = @"
Внимание! Отключаемая учетная запись имеет доступ к критичным системам:
Пользователь: $($User.SamAccountName)
Отображаемое имя: $($User.Name)
Отдел: $($User.Department)
Критичные группы: $($CriticalGroups -join ', ')
Время отключения: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Требуется дополнительная проверка:
1. Убедиться в отсутствии зависимостей
2. Проверить наличие резервных доступов
3. Уведомить владельцев систем

"@
    
    Send-EmailNotification -To $Config.NotificationEmail -Subject $subject -Body $body
}

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
    if ($criticalGroups -and $criticalGroups.Count -gt 0) {
        Write-AuditLog -EventType "CriticalAccess" -Message "Учетная запись $($User.SamAccountName) имеет доступ к критичным системам через группы: $($criticalGroups -join ', ')" -Severity "Warning" -Config $Config
        Send-CriticalAccessNotification -User $User -CriticalGroups $criticalGroups -Config $Config
    }
    $riskAssessment = Get-AccountRiskAssessment -User $User
    if ($riskAssessment.RiskLevel -eq "High") {
        Send-ImmediateAlert -User $User -RiskAssessment $riskAssessment -Config $Config
    }

    try {
        if ($riskAssessment.RiskScore -gt 0) {
            Revoke-UserSessions -UserName $User.SamAccountName
            Reset-UserPassword -UserName $User.SamAccountName
        }
        Disable-ADAccount -Identity $User -Confirm:$false
        Set-ADUser -Identity $User -Description "Deactivated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Clear-ADUserRiskAttributes -User $User

        $lifecycleData.Status = "Completed"
        Write-AuditLog -EventType "Deactivation" -Message "Учетная запись $($User.SamAccountName) отключена" -Severity "Info" -Config $Config

    } catch {
        $lifecycleData.Status = "Failed"
        Write-AuditLog -EventType "Error" -Message ("Ошибка отключения $($User.SamAccountName): $($_.Exception.Message)`nStackTrace: $($_.ScriptStackTrace)") -Severity "Error" -Config $Config
    }
    Save-AccountHistory -LifecycleData $lifecycleData -Config $Config
}


function Clear-ADUserRiskAttributes {
    param($User)
    
    try {
        # Очистка потенциально опасных атрибутов
        Set-ADUser -Identity $User -Clear "msTSInitialProgram", "msTSWorkDirectory", "msTSHomeDirectory"
    } catch {
        Write-Warning "Не удалось очистить атрибуты пользователя $($User.SamAccountName): $($_.Exception.Message)"
    }
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

function Send-EmailNotification {
    param($To, $Subject, $Body)
    
    # Заглушка для реализации отправки email
    Write-Host "Уведомление отправлено: $Subject" -ForegroundColor Yellow
}
#endregion

#region Логирование
function Write-AuditLog {
    param($EventType, $Message, $Severity, $Config)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        EventType = $EventType
        Message = $Message
        Severity = $Severity
        Hostname = $env:COMPUTERNAME
        ProcessId = $pid
    }
    $logPath = Join-Path $Config.LogDirectory "audit_$(Get-Date -Format 'yyyyMMdd').log"
    $logLine = "$timestamp [$Severity] [$EventType] $Message (Host: $env:COMPUTERNAME, PID: $pid)"
    
    try {
        Add-Content -Path $logPath -Value $logLine -Encoding UTF8
        if ((Get-Item $logPath -ErrorAction SilentlyContinue).Length -gt 50MB) {
            $archivePath = $logPath -replace '\.log$', "_$(Get-Date -Format 'HHmmss').log"
            Move-Item $logPath $archivePath -Force
            Compress-Archive -Path $archivePath -DestinationPath "$archivePath.zip" -Force
            Remove-Item $archivePath -Force
        }
    } catch {
        Write-Warning "Не удалось записать локальный лог: $($_.Exception.Message)"
    }
    if (-not [string]::IsNullOrEmpty($Config.SIEMEndpoint)) {
        $maxRetries = 3
        $retryDelay = 1
        
        for ($i = 1; $i -le $maxRetries; $i++) {
            try {
                Invoke-RestMethod -Uri $Config.SIEMEndpoint -Method Post -Body ($logEntry | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 5
                break
            } catch {
                if ($i -eq $maxRetries) {
                    Write-Warning "Не удалось отправить лог в SIEM после $maxRetries попыток: $($_.Exception.Message)"
                    $failedLogPath = Join-Path $Config.LogDirectory "failed_siem_logs.json"
                    $logEntry | ConvertTo-Json | Out-File -FilePath $failedLogPath -Append
                } else {
                    Start-Sleep -Seconds $retryDelay
                    $retryDelay *= 2
                }
            }
        }
    }
}

function Invoke-LogMaintenance {
    param($Config)
    
    try {
        $cutoffDate = (Get-Date).AddDays(-$Config.LogRetentionDays)
        
        Get-ChildItem $Config.LogDirectory -Filter "audit_*.log" | 
            Where-Object { $_.LastWriteTime -lt $cutoffDate } |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem $Config.LogDirectory -Filter "*.zip" |
            Where-Object { $_.LastWriteTime -lt $cutoffDate } |
            Remove-Item -Force -ErrorAction SilentlyContinue
            
        Write-Host "Очистка логов завершена. Удалено файлов старше $($Config.LogRetentionDays) дней" -ForegroundColor Green
    } catch {
        Write-Warning "Ошибка очистки логов: $($_.Exception.Message)"
    }
}
#endregion

#region Вспомогательные функции
function Revoke-UserSessions {
    param($UserName)
    # Заглушка для реализации принудительного разрыва сессий
    Write-Host "Сессии пользователя $UserName будут разорваны" -ForegroundColor Cyan
}

function Reset-UserPassword {
    param($UserName)
    # Заглушка для реализации сброса пароля
    Write-Host "Пароль пользователя $UserName будет сброшен" -ForegroundColor Cyan
}

function Save-AccountHistory {
    param($LifecycleData, $Config)
    # Заглушка для сохранения в базу данных
    Write-Host "Данные сохранены для $($LifecycleData.SamAccountName)" -ForegroundColor Green
}
#endregion

#region Главный процесс
function Start-AccountLifecycleManagement {
    param($Config)
    
    Initialize-Environment -Config $Config
    Write-AuditLog -EventType "ProcessStart" -Message "Запуск управления жизненным циклом учетных записей" -Severity "Info" -Config $Config
    
    try {
        # Очистка старых логов
        Invoke-LogMaintenance -Config $Config
        
        # Поиск учетных записей для обработки
        $users = Get-ADUser -Filter * -SearchBase $Config.TerminationOU -Properties *
        
        foreach ($user in $users) {
            if ($user.Enabled) {
                Write-AuditLog -EventType "Processing" -Message "Обработка учетной записи: $($user.SamAccountName)" -Severity "Info" -Config $Config
                Invoke-AccountDeactivation -User $user -Config $Config
            }
        }
        
    } catch {
        Write-AuditLog -EventType "Error" -Message "Критическая ошибка процесса: $($_.Exception.Message)" -Severity "Critical" -Config $Config
    } finally {
        Write-AuditLog -EventType "ProcessEnd" -Message "Завершение управления жизненным циклом учетных записей" -Severity "Info" -Config $Config
    }
}

# Запуск процесса
Start-AccountLifecycleManagement -Config $Config
#endregion