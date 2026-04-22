from __future__ import annotations

import threading
import time
from dataclasses import dataclass

import wmi
import pythoncom

import db
from usb_control import get_usb_storage_enabled, set_usb_storage_enabled
from whitelist import UsbIdentity, parse_identity


@dataclass(frozen=True)
class UsbEvent:
    event_type: str  # "insert" | "remove" | "scan"
    identity: UsbIdentity | None


def _list_usb_storage_devices(c: wmi.WMI) -> list[UsbIdentity]:
    """
    Best-effort enumeration of USB storage devices.
    Uses Win32_DiskDrive where InterfaceType='USB'.
    """
    out: list[UsbIdentity] = []
    for d in c.Win32_DiskDrive(InterfaceType="USB"):
        name = getattr(d, "Model", None) or getattr(d, "Caption", None)
        pnp = getattr(d, "PNPDeviceID", None)
        out.append(parse_identity(device_name=name, pnp_device_id=pnp))
    return out


class UsbMonitor:
    """
    Background thread that polls connected USB storage devices and logs insert/remove events.
    If whitelist enforcement is enabled, it will auto-block unknown devices (global USBSTOR disable).
    """

    def __init__(self, poll_seconds: float = 2.0):
        self._poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._last_by_pnp: dict[str, UsbIdentity] = {}
        self._callbacks: list[callable[[UsbEvent], None]] = []

    def add_callback(self, cb: callable[[UsbEvent], None]) -> None:
        self._callbacks.append(cb)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="UsbMonitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def current_devices(self) -> list[UsbIdentity]:
        with self._lock:
            return list(self._last_by_pnp.values())

    def _emit(self, ev: UsbEvent) -> None:
        for cb in list(self._callbacks):
            try:
                cb(ev)
            except Exception:
                pass

    def _run(self) -> None:
        # WMI uses COM; background threads must init COM explicitly.
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            while not self._stop.is_set():
                try:
                    devices = _list_usb_storage_devices(c)
                    current: dict[str, UsbIdentity] = {}
                    for dev in devices:
                        key = dev.pnp_device_id or f"{dev.vid}:{dev.pid}:{dev.serial}:{dev.device_name}"
                        if key:
                            current[key] = dev

                    with self._lock:
                        prev = dict(self._last_by_pnp)
                        self._last_by_pnp = current

                    inserted = [current[k] for k in current.keys() - prev.keys()]
                    removed = [prev[k] for k in prev.keys() - current.keys()]

                    for dev in inserted:
                        allowed = db.whitelist_is_allowed(dev.pnp_device_id, dev.vid, dev.pid, dev.serial)
                        action = None

                        enforce = db.setting_get("enforce_whitelist") == "1"
                        if enforce and not allowed:
                            # Coarse but reliable enforcement: disable USB storage globally.
                            if get_usb_storage_enabled():
                                try:
                                    set_usb_storage_enabled(False)
                                    action = "disabled_usbstor"
                                except Exception:
                                    action = "failed_disable_usbstor"
                            else:
                                action = "usbstor_already_disabled"

                        db.log_usb_event(
                            event_type="insert",
                            device_name=dev.device_name,
                            pnp_device_id=dev.pnp_device_id,
                            vid=dev.vid,
                            pid=dev.pid,
                            serial=dev.serial,
                            allowed=allowed,
                            action_taken=action,
                        )
                        self._emit(UsbEvent(event_type="insert", identity=dev))

                    for dev in removed:
                        db.log_usb_event(
                            event_type="remove",
                            device_name=dev.device_name,
                            pnp_device_id=dev.pnp_device_id,
                            vid=dev.vid,
                            pid=dev.pid,
                            serial=dev.serial,
                            allowed=None,
                            action_taken=None,
                        )
                        self._emit(UsbEvent(event_type="remove", identity=dev))

                except Exception:
                    # Keep monitoring even if a WMI call fails temporarily.
                    pass

                time.sleep(self._poll_seconds)
        finally:
            pythoncom.CoUninitialize()


def set_whitelist_enforcement(enabled: bool) -> None:
    db.setting_set("enforce_whitelist", "1" if enabled else "0")


def get_whitelist_enforcement() -> bool:
    return db.setting_get("enforce_whitelist") == "1"

