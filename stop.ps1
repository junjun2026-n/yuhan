# ============================================================
# 文件名称：stop.ps1
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：执行 stop 对应的启动、构建或运维任务。
#           文件用途：供WAF的 yuhan/stop.ps1 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
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
