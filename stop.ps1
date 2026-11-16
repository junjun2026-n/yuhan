$ErrorActionPreference = 'Stop'
$wafRoot = $PSScriptRoot
$wafPython = Join-Path $wafRoot '.venv\Scripts\python.exe'
$wafProcesses = @(Get-CimInstance Win32_Process | Where-Object {
    $_.ExecutablePath -eq $wafPython -and
    ($_.CommandLine -match '-m\s+waf\.cli\s+serve' -or $_.CommandLine -match '-m\s+uvicorn\s+waf\.main:create_(proxy|admin)')
})
foreach ($wafProcess in $wafProcesses) {
    Stop-Process -Id $wafProcess.ProcessId -ErrorAction SilentlyContinue
}
Write-Output "Stopped WAF processes: $($wafProcesses.Count)"
