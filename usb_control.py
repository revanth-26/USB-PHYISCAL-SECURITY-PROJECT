from __future__ import annotations

import ctypes
import subprocess
import winreg


USBSTOR_KEY = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
USBSTOR_VALUE = "Start"
REMOVABLE_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
REMOVABLE_POLICY_VALUE = "Deny_All"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_usb_storage_enabled() -> bool:
    """
    USBSTOR Start values (common):
    - 3: manual (enabled)
    - 4: disabled
    """
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, USBSTOR_KEY, 0, winreg.KEY_READ) as k:
            val, _ = winreg.QueryValueEx(k, USBSTOR_VALUE)
            return int(val) != 4
    except FileNotFoundError:
        # If key doesn't exist, assume enabled (some systems differ).
        return True
    except Exception:
        return True


def set_usb_storage_enabled(enabled: bool) -> None:
    if not is_admin():
        raise PermissionError("Administrator privileges are required to change USB storage policy.")
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, USBSTOR_KEY) as k:
        winreg.SetValueEx(k, USBSTOR_VALUE, 0, winreg.REG_DWORD, 3 if enabled else 4)
    if enabled:
        _set_removable_policy_block(False)
        _set_automount(True)
        _set_usb_disks_online()
    else:
        _set_removable_policy_block(True)
        _stop_usbstor_service()
        _remove_usb_drive_letters()
        _set_automount(False)
        _set_usb_disks_offline()


def _run_ps(script: str) -> None:
    # Best-effort helper. We do not fail the whole flow for partial hardening steps.
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def _stop_usbstor_service() -> None:
    subprocess.run(
        ["sc.exe", "stop", "USBSTOR"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def _set_usb_disks_offline() -> None:
    # If a pendrive was already mounted, take it offline to block file access immediately.
    _run_ps(
        "Get-Disk | Where-Object {$_.BusType -eq 'USB' -and $_.OperationalStatus -ne 'Offline'} "
        "| Set-Disk -IsOffline $true -ErrorAction SilentlyContinue"
    )


def _set_usb_disks_online() -> None:
    _run_ps(
        "Get-Disk | Where-Object {$_.BusType -eq 'USB' -and $_.OperationalStatus -eq 'Offline'} "
        "| Set-Disk -IsOffline $false -ErrorAction SilentlyContinue"
    )


def _set_removable_policy_block(block: bool) -> None:
    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REMOVABLE_POLICY_KEY) as k:
        winreg.SetValueEx(k, REMOVABLE_POLICY_VALUE, 0, winreg.REG_DWORD, 1 if block else 0)


def _set_automount(enabled: bool) -> None:
    subprocess.run(
        ["mountvol", "/E" if enabled else "/N"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def _remove_usb_drive_letters() -> None:
    # Remove current access paths so USB volumes disappear from Explorer immediately.
    _run_ps(
        "$parts = Get-Partition | Where-Object {$_.DriveLetter}; "
        "foreach ($p in $parts) { "
        "  $d = Get-Disk -Number $p.DiskNumber -ErrorAction SilentlyContinue; "
        "  if ($d -and $d.BusType -eq 'USB') { "
        "    Remove-PartitionAccessPath -DiskNumber $p.DiskNumber -PartitionNumber $p.PartitionNumber "
        "      -AccessPath ($p.DriveLetter + ':\\') -ErrorAction SilentlyContinue "
        "  } "
        "}"
    )
