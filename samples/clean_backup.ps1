# Automated Daily Backup Script
$SourceDir = "C:\Users\Documents"
$BackupDir = "D:\Backups\Daily"
$LogFile = "D:\Backups\backup_log.txt"

Write-Output "Starting routine daily file archiving..." | Out-File -FilePath $LogFile -Append

if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force
}

Get-ChildItem -Path $SourceDir -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } | Copy-Item -Destination $BackupDir

Write-Output "Daily archiving finished successfully at $(Get-Date)" | Out-File -FilePath $LogFile -Append
