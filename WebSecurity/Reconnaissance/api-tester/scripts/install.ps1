param(
    [string]$Version = "latest",
    [string]$Repo = "leedale1981/infosec",
    [string]$InstallDir = "$env:LOCALAPPDATA\\Programs\\api-tester"
)

$ErrorActionPreference = "Stop"

function Get-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE.ToLowerInvariant()) {
        "amd64" { return "amd64" }
        "arm64" { return "arm64" }
        default { throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
}

function Get-Version {
    param([string]$RequestedVersion, [string]$Repository)

    if ($RequestedVersion -ne "latest") {
        return $RequestedVersion
    }

    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/latest"
    return $release.tag_name.TrimStart("v")
}

$arch = Get-Arch
$resolvedVersion = Get-Version -RequestedVersion $Version -Repository $Repo
$zipName = "api-tester_${resolvedVersion}_windows_${arch}.zip"
$url = "https://github.com/$Repo/releases/download/v$resolvedVersion/$zipName"
$tempDir = Join-Path $env:TEMP ("api-tester-" + [guid]::NewGuid().ToString())
$zipPath = Join-Path $tempDir $zipName

New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zipPath

Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force
Copy-Item -Path (Join-Path $tempDir "api-tester.exe") -Destination (Join-Path $InstallDir "api-tester.exe") -Force

$currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = $currentUserPath -split ";"
if ($pathEntries -notcontains $InstallDir) {
    $newPath = if ([string]::IsNullOrWhiteSpace($currentUserPath)) { $InstallDir } else { "$currentUserPath;$InstallDir" }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "Added $InstallDir to user PATH. Restart terminal to use api-tester."
}

Write-Host "Installed api-tester $resolvedVersion to $InstallDir"
Remove-Item -Path $tempDir -Recurse -Force
