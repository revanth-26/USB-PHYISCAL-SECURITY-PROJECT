from __future__ import annotations

from datetime import datetime
from pathlib import Path

import cv2

from config import INTRUDER_DIR, ensure_dirs


def capture_intruder_snapshot(prefix: str = "intruder") -> str:
    """
    Captures a single frame from the default webcam and saves it to `intruders/`.
    Returns the saved file path as string.
    """
    ensure_dirs()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = INTRUDER_DIR / f"{prefix}_{ts}.jpg"

    cap = cv2.VideoCapture(0)
    try:
        if not cap.isOpened():
            raise RuntimeError("Webcam not available.")
        ok, frame = cap.read()
        if not ok or frame is None:
            raise RuntimeError("Failed to capture image from webcam.")
        cv2.imwrite(str(out_path), frame)
    finally:
        cap.release()

    return str(Path(out_path).resolve())
