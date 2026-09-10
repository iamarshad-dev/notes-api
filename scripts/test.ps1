param([switch]$UseLocalDatabase)
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot)
$previous = @{}
try {
    if ($UseLocalDatabase) {
        # Read only database settings, never echo credentials or dot-source .env as code.
        foreach ($line in Get-Content -LiteralPath '.env') {
            if ($line -match '^\s*(DB_URL|DB_USERNAME|DB_PASSWORD)=(.*)$') {
                $name = 'TEST_' + $Matches[1]
                $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
                [Environment]::SetEnvironmentVariable($name, $Matches[2].Trim().Trim('"').Trim("'"), 'Process')
            }
        }
        if (-not $env:TEST_DB_URL) { throw 'DB_URL must be configured in .env' }
    }
    & ./gradlew.bat test --console=plain
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed; see build/reports/tests/test/index.html' }
} finally {
    foreach ($name in $previous.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
    Pop-Location
}
