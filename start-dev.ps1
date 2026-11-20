# ============================================================
# 文件名称：start-dev.ps1
# 生成日期：2026-10-27
# 修改日期：2026-11-20
# 版本信息：v0.261115
# 作    者：JUN
# 备    注：本程序由AI辅助完成。
#           文件功能：执行 start-dev 对应的启动、构建或运维任务。
#           文件用途：供WAF的 yuhan/start-dev.ps1 模块使用。
#           注意事项：运行前检查依赖与配置；涉及数据或服务变更时先备份并验证。
# ============================================================
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
& "$PSScriptRoot\.venv\Scripts\python.exe" -m tools.dev
exit $LASTEXITCODE
