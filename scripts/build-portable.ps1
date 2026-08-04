$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$PortableRoot = Join-Path $Root "portable\NetMap-Portable"
$RuntimeSource = Join-Path $Root "src-tauri\WebView2.FixedVersionRuntime"
$ReleaseExe = Join-Path $Root "src-tauri\target\release\netmap-portable.exe"

if (-not (Test-Path $RuntimeSource)) {
    throw "Missing fixed WebView2 runtime at $RuntimeSource. See README.md."
}

Push-Location $Root
try {
    npm run test
    if ($LASTEXITCODE -ne 0) { throw "Frontend tests failed." }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "Frontend build failed." }
    npm run desktop:build -- --no-bundle
    if ($LASTEXITCODE -ne 0) { throw "Desktop release build failed." }

    if (Test-Path $PortableRoot) {
        Remove-Item $PortableRoot -Recurse -Force
    }

    New-Item -ItemType Directory -Path $PortableRoot | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $PortableRoot "data\projects") | Out-Null

    Copy-Item $ReleaseExe (Join-Path $PortableRoot "NetMap Portable.exe")
    $runtimeDestination = Join-Path $PortableRoot "WebView2.FixedVersionRuntime"
    Copy-Item $RuntimeSource $runtimeDestination -Recurse
    Copy-Item (Join-Path $Root "README.md") $PortableRoot

    # Fixed WebView2 v120+ uses an AppContainer renderer on Windows 10.
    # Grant its standard package identities read/execute access while the
    # artifact is still on NTFS. On filesystems without ACLs the installed
    # Evergreen runtime remains the fallback.
    & icacls.exe $runtimeDestination /grant "*S-1-15-2-2:(OI)(CI)(RX)" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not set ALL APPLICATION PACKAGES runtime permissions."
    }
    & icacls.exe $runtimeDestination /grant "*S-1-15-2-1:(OI)(CI)(RX)" /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Could not set ALL RESTRICTED APPLICATION PACKAGES runtime permissions."
    }

    $checksums = Get-ChildItem $PortableRoot -File -Recurse |
        Get-FileHash -Algorithm SHA256 |
        ForEach-Object {
            $relative = $_.Path.Substring($PortableRoot.Length + 1)
            "$($_.Hash.ToLowerInvariant())  $relative"
        }
    $checksums | Set-Content (Join-Path $PortableRoot "SHA256SUMS.txt") -Encoding ascii

    Write-Host "Portable build created at $PortableRoot"
}
finally {
    Pop-Location
}
