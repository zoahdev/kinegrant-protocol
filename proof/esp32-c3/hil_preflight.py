from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from kinegrant.experimental.esp32c3_serial import PySerialTransport, read_device_challenge


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture one ESP32-C3 challenge without authorizing actuator movement"
    )
    parser.add_argument("--port", required=True, help="explicit serial port, for example COM7")
    parser.add_argument("--baudrate", type=int, default=115_200)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--confirm-low-risk-paper-barrier",
        action="store_true",
        help="confirm the device is attached only to the documented low-risk fixture",
    )
    args = parser.parse_args(argv)
    if not args.confirm_low_risk_paper_barrier:
        print("REFUSED: explicit low-risk fixture confirmation is required", file=sys.stderr)
        return 2
    if args.output.exists():
        print("REFUSED: output already exists", file=sys.stderr)
        return 2
    try:
        with PySerialTransport(args.port, baudrate=args.baudrate) as transport:
            challenge = read_device_challenge(transport)
        record = {
            "type": "kinegrant:ESP32C3PreflightRecord",
            "status": "PREFLIGHT_ONLY_NOT_PHYSICAL_PROOF",
            "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "port": args.port,
            "baudrate": args.baudrate,
            "challenge": challenge.to_dict(),
            "actuator_command_sent": False,
            "physical_evidence_result": "NOT_RUN",
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    except (OSError, RuntimeError, TimeoutError, PermissionError, ValueError) as exc:
        print(f"FAILED CLOSED: {exc}", file=sys.stderr)
        return 2
    print(f"PREFLIGHT_ONLY_NOT_PHYSICAL_PROOF: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
