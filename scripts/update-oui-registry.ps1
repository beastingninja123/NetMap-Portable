$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Destination = Join-Path $Root "src-tauri\assets\oui.tsv"
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("netmap-oui-" + [guid]::NewGuid())

$registries = @(
    @{ Url = "https://standards-oui.ieee.org/oui/oui.csv"; Bits = 24 },
    @{ Url = "https://standards-oui.ieee.org/oui28/mam.csv"; Bits = 28 },
    @{ Url = "https://standards-oui.ieee.org/oui36/oui36.csv"; Bits = 36 }
)

New-Item -ItemType Directory -Path $TempRoot | Out-Null
New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
try {
    try {
        $entries = foreach ($registry in $registries) {
            $source = Join-Path $TempRoot ("oui-{0}.csv" -f $registry.Bits)
            Invoke-WebRequest -Uri $registry.Url -OutFile $source
            Import-Csv $source | ForEach-Object {
                $assignment = ($_.Assignment -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
                $organization = ($_."Organization Name" -replace "[\t\r\n]+", " ").Trim()
                if ($assignment -and $organization) {
                    "{0}`t{1}`t{2}" -f $registry.Bits, $assignment, $organization
                }
            }
        }
    }
    catch {
        Write-Warning "IEEE download was unavailable; using Wireshark's generated IEEE registry snapshot."
        $source = Join-Path $TempRoot "manuf"
        Invoke-WebRequest -Uri "https://www.wireshark.org/download/automated/data/manuf" -OutFile $source
        $entries = Get-Content $source | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object {
            $fields = $_ -split "`t+", 3
            $prefixField = if ($fields.Count) { $fields[0].Trim() } else { '' }
            if ($fields.Count -ge 3 -and $prefixField -match '^([0-9A-Fa-f:]+)(?:/([0-9]+))?$') {
                $bits = if ($Matches[2]) { [int]$Matches[2] } else { 24 }
                if ($bits -in 24, 28, 36) {
                    $assignment = ($Matches[1] -replace ':', '').ToUpperInvariant()
                    $organization = ($fields[2] -replace "[\t\r\n]+", " ").Trim()
                    if ($organization) { "{0}`t{1}`t{2}" -f $bits, $assignment, $organization }
                }
            }
        }
    }
    @(
        "# IEEE Registration Authority public MA-L, MA-M, and MA-S snapshot"
        "# Generated: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd'))"
        "# prefix_bits<TAB>assignment_hex<TAB>organization"
        $entries | Sort-Object -Unique
    ) | Set-Content -LiteralPath $Destination -Encoding utf8
    Write-Host "Wrote $Destination"
}
finally {
    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
