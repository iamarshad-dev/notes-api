$ErrorActionPreference = 'Stop'
Push-Location (Split-Path $PSScriptRoot)
$previous = @{}
try {
    foreach ($line in Get-Content -LiteralPath '.env') {
        if ($line -match '^\s*(DB_URL|DB_USERNAME|DB_PASSWORD|JWT_SECRET|JWT_ACCESS_TOKEN_TTL|CORS_ALLOWED_ORIGINS)=(.*)$') {
            $name = $Matches[1]
            $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
            [Environment]::SetEnvironmentVariable($name, $Matches[2].Trim().Trim('"').Trim("'"), 'Process')
        }
    }
    & ./gradlew.bat bootRun --console=plain
    if ($LASTEXITCODE -ne 0) { throw 'Application stopped with an error' }
} finally {
    foreach ($name in $previous.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
    }
    Pop-Location
}
