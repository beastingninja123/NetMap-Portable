$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$Destination = Join-Path $Root "test-pcaps"
New-Item -ItemType Directory -Path $Destination -Force | Out-Null

$Captures = @(
    @{
        Name = "wireshark-modbus-tcp-float.pcap"
        Url = "https://gitlab.com/wireshark/wireshark/uploads/02a5c8e333b4f8d9029ed3fce7fc897a/Modbus_TCP_FLOAT.pcap"
    },
    @{
        Name = "wireshark-s7comm-plc-status.pcap"
        Url = "https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/s7comm_reading_plc_status.pcap"
    },
    @{
        Name = "wireshark-dnp3-select-operate.pcap"
        Url = "https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/dnp3_select_operate.pcap"
    },
    @{
        Name = "wireshark-iec104.pcap"
        Url = "https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/iec104.pcap"
    },
    @{
        Name = "wireshark-hart-ip.pcap"
        Url = "https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/hart_ip.pcap"
    },
    @{
        Name = "netresec-4sics-geek-lounge-2015-10-20.pcap"
        Url = "https://share.netresec.com/s/xYj2qCNbsLEAd6M/download/4SICS-GeekLounge-151020.pcap"
    },
    @{
        Name = "netresec-s4x15-bacnet-fiu.pcap"
        Url = "https://share.netresec.com/s/At9EfzR6SKP8E8j/download/BACnet_FIU.pcap"
    }
)

foreach ($Capture in $Captures) {
    $Output = Join-Path $Destination $Capture.Name
    $Temporary = "$Output.download"
    try {
        Invoke-WebRequest -Uri $Capture.Url -OutFile $Temporary -UseBasicParsing -TimeoutSec 60 -Headers @{ "User-Agent" = "NetMap-Portable fixture fetcher" }
        $Bytes = [System.IO.File]::ReadAllBytes($Temporary)
        if ($Bytes.Length -lt 24) {
            throw "Downloaded capture is too short: $($Capture.Name)"
        }
        $Magic = [BitConverter]::ToString($Bytes[0..3])
        if ($Magic -notin @("A1-B2-C3-D4", "D4-C3-B2-A1", "0A-0D-0D-0A", "4D-3C-B2-A1", "A1-B2-3C-4D")) {
            throw "Downloaded file is not PCAP/PCAPNG: $($Capture.Name) ($Magic)"
        }
        Move-Item -LiteralPath $Temporary -Destination $Output -Force
    }
    finally {
        if (Test-Path -LiteralPath $Temporary) {
            Remove-Item -LiteralPath $Temporary -Force
        }
    }
}

Get-ChildItem -LiteralPath $Destination -File -Filter *.pcap* |
    Get-FileHash -Algorithm SHA256 |
    Select-Object Hash, Path
