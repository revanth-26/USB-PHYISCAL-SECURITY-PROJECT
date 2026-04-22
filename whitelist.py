from __future__ import annotations

import re
from dataclasses import dataclass


VID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})")
PID_RE = re.compile(r"PID_([0-9A-Fa-f]{4})")


@dataclass(frozen=True)
class UsbIdentity:
    device_name: str | None
    pnp_device_id: str | None
    vid: str | None
    pid: str | None
    serial: str | None


def parse_identity(device_name: str | None, pnp_device_id: str | None) -> UsbIdentity:
    vid = None
    pid = None
    serial = None

    if pnp_device_id:
        m1 = VID_RE.search(pnp_device_id)
        m2 = PID_RE.search(pnp_device_id)
        if m1:
            vid = m1.group(1).upper()
        if m2:
            pid = m2.group(1).upper()

        # Many Windows PNPDeviceIDs look like: USBSTOR\DISK&VEN_...\... \SERIAL&0
        # We store the trailing part as a best-effort serial discriminator.
        if "\\" in pnp_device_id:
            serial = pnp_device_id.split("\\")[-1].strip() or None

    return UsbIdentity(
        device_name=device_name,
        pnp_device_id=pnp_device_id,
        vid=vid,
        pid=pid,
        serial=serial,
    )
