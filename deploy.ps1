param([switch]$PrepareOnly)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$deployArgs = @('-m', 'tools.deploy')
if ($PrepareOnly) { $deployArgs += '--prepare-only' }
& "$PSScriptRoot\.venv\Scripts\python.exe" @deployArgs
exit $LASTEXITCODE
