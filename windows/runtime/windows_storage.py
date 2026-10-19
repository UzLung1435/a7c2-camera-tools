"""Identify the camera's photo card and PMHOME volumes on Windows."""

import hashlib
import json
from pathlib import Path
import re
import subprocess


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def volume_identity(serial):
    require(re.fullmatch(r"[A-Fa-f0-9]{12}", serial),
            "12 hex digit camera USB serial required")
    script = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$pnp=@(Get-CimInstance Win32_PnPEntity | Where-Object {
    $_.PNPDeviceID -eq ('USB\VID_054C&PID_0E8A\'+$serialNumber) -and
    $_.Status -eq 'OK' -and $_.Service -eq 'USBSTOR'
})
$disks=@(Get-Disk | Where-Object {
    $_.BusType -eq 'USB' -and $_.SerialNumber -eq $serialNumber -and
    $_.OperationalStatus -eq 'Online'
})
$rows=@(foreach($disk in $disks){
    foreach($part in @(Get-Partition -DiskNumber $disk.Number)){
        $vol=$part | Get-Volume -ErrorAction SilentlyContinue
        if($vol){[pscustomobject]@{
            disk=$disk.Number; disk_size=$disk.Size; read_only=$disk.IsReadOnly;
            partition=$part.PartitionNumber; drive=[string]$part.DriveLetter;
            filesystem=[string]$vol.FileSystem; label=[string]$vol.FileSystemLabel;
            volume_size=$vol.Size; free=$vol.SizeRemaining;
            volume_id=[string]$vol.UniqueId
        }}
    }
})
[pscustomobject]@{pnp_count=$pnp.Count; volumes=$rows} | ConvertTo-Json -Depth 4 -Compress
'''
    script = "$serialNumber='" + serial.upper() + "'\n" + script
    code = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                           "-Command", script], capture_output=True, timeout=40)
    require(code.returncode == 0,
            "Windows camera disk inventory failed: " +
            code.stderr.decode("utf-8", "replace")[:200])
    data = json.loads(code.stdout.decode("utf-8"))
    require(data["pnp_count"] == 1, "target camera is not USBSTOR mounted")
    volumes = data["volumes"]
    card = [item for item in volumes if item["filesystem"].lower() == "exfat"
            and not item["read_only"] and item["volume_size"] > 32 * 1024**3]
    home = [item for item in volumes if item["label"] == "PMHOME" and
            item["read_only"] and item["volume_size"] < 128 * 1024**2]
    require(len(card) == len(home) == 1 and
            card[0]["disk"] != home[0]["disk"] and
            re.fullmatch(r"[A-Z]", card[0]["drive"]),
            "one camera photo card and PMHOME volume required")
    return card[0], home[0]
