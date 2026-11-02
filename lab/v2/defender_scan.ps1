param(
    [Parameter(Mandatory = $true)][string]$ScanPath,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = "Stop"

$resolvedPath = (Resolve-Path -LiteralPath $ScanPath).Path
$status = Get-MpComputerStatus
if (-not $status.AntivirusEnabled -or -not $status.RealTimeProtectionEnabled) {
    throw "Microsoft Defender is not enabled with real-time protection."
}

Start-MpScan -ScanType CustomScan -ScanPath $resolvedPath
$detections = @(
    Get-MpThreatDetection | Where-Object {
        (($_.Resources -join " ") -like "*$resolvedPath*")
    }
)
if ($detections.Count -gt 0) {
    throw "Defender detected $($detections.Count) item(s) under $resolvedPath."
}

$lines = @(
    "scan_path=$resolvedPath"
    "scan_completed_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC'))"
    "antivirus_enabled=True"
    "real_time_protection_enabled=True"
    "detections=0"
)
[System.IO.File]::WriteAllText(
    $OutputPath, (($lines -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false)
)
$lines
