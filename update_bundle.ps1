# update_bundle.ps1
#
# Rebuilds the given service image(s) at a new version tag, bumps that tag in
# both docker-compose.yml and docker-compose.customer.yml, then exports a
# fresh customer bundle tar containing all 4 built images (at their current,
# possibly-mixed tags) plus the stock redis image.
#
# Usage:
#   .\update_bundle.ps1 -Version 1.1                     (rebuilds app only -- the common case)
#   .\update_bundle.ps1 -Version 1.1 -Services app,llm   (rebuilds app + llm)
#   .\update_bundle.ps1 -Version 1.1 -Services shakthidb (rebuilds only the DB image)
#
# Valid service names: app, llm, llm-embed, shakthidb

param(
    [Parameter(Mandatory=$true)][string]$Version,
    [string[]]$Services = @("app")
)

$ErrorActionPreference = "Stop"

$dockerfileMap = @{
    "app"       = "Dockerfile.app"
    "llm"       = "Dockerfile.llm"
    "llm-embed" = "Dockerfile.llm"
    "shakthidb" = "Dockerfile"
}

foreach ($svc in $Services) {
    if (-not $dockerfileMap.ContainsKey($svc)) {
        Write-Error "Unknown service '$svc'. Valid: app, llm, llm-embed, shakthidb"
        exit 1
    }
}

foreach ($svc in $Services) {
    $df    = $dockerfileMap[$svc]
    $image = "aicyberauditbox-${svc}:${Version}"

    Write-Host "=== Building $image from $df ===" -ForegroundColor Cyan
    docker build -f $df -t $image .
    if ($LASTEXITCODE -ne 0) { Write-Error "Build failed for $svc"; exit 1 }

    foreach ($composeFile in @("docker-compose.yml", "docker-compose.customer.yml")) {
        if (Test-Path $composeFile) {
            (Get-Content $composeFile) -replace "aicyberauditbox-${svc}:\S+", "aicyberauditbox-${svc}:${Version}" |
                Set-Content $composeFile -Encoding utf8
        }
    }
    Write-Host "Bumped $svc to :$Version in compose files." -ForegroundColor Green
}

# Pull the CURRENT effective tag for every built service from the compose file
$targetCompose = if (Test-Path "docker-compose.customer.yml") { "docker-compose.customer.yml" } else { "docker-compose.yml" }
$composeContent = Get-Content $targetCompose -Raw

function Get-ImageRef([string]$svc) {
    if ($composeContent -match "aicyberauditbox-${svc}:\S+") {
        return $matches[0]
    }
    Write-Error "Could not find image tag for $svc in $targetCompose"
    exit 1

}

$images = @(
    (Get-ImageRef "shakthidb"),
    (Get-ImageRef "llm"),
    (Get-ImageRef "llm-embed"),
    (Get-ImageRef "app"),
    "redis:7-alpine"
)

$tarName = "aicyberauditbox_bundle_v${Version}.tar"
Write-Host ""
Write-Host "=== Exporting bundle: $tarName ===" -ForegroundColor Cyan
Write-Host "Images: $($images -join ', ')"
docker save $images -o $tarName
if ($LASTEXITCODE -ne 0) { Write-Error "docker save failed"; exit 1 }

Write-Host ""
Write-Host "Done. New bundle: $tarName" -ForegroundColor Green
Write-Host "Ship this file + the updated docker-compose.customer.yml to the customer."
