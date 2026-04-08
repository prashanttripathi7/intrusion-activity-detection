Write-Host "Sending safe demo events to Windows Event Viewer..." -ForegroundColor Cyan
Write-Host "Run this after clicking 'Start Monitoring' in the dashboard." -ForegroundColor Yellow

$events = @(
    @{
        Type = "WARNING"
        Id = 1
        Description = "TLSv1.0 insecure protocol negotiated with remote host 192.0.2.200"
    },
    @{
        Type = "ERROR"
        Id = 2
        Description = "Possible SQL injection attempt from 203.0.113.50 using UNION SELECT on /product?id=1"
    },
    @{
        Type = "WARNING"
        Id = 3
        Description = "Suspicious command execution request: cmd.exe /c whoami from 203.0.113.50"
    },
    @{
        Type = "WARNING"
        Id = 4
        Description = "Access denied for admin path /admin from 185.220.101.45 status 403"
    }
)

foreach ($event in $events) {
    eventcreate /T $event.Type /ID $event.Id /L APPLICATION /SO IDS-DEMO /D $event.Description
    Start-Sleep -Seconds 1
}

Write-Host "Demo events written. Check the dashboard alerts and timeline." -ForegroundColor Green
