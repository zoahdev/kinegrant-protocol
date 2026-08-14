from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kinegrant.crypto import key_id, public_key_from_id


_DEVICE_ID = re.compile(r"^[A-Za-z0-9:._-]{1,96}$")


def generate_provisioning(device_id: str, executor_kid: str, output_dir: Path) -> dict[str, str]:
    if _DEVICE_ID.fullmatch(device_id) is None:
        raise ValueError("device_id must use 1-96 safe ASCII identifier characters")
    public_key_from_id(executor_kid)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError("output directory is not empty")
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    device_kid = key_id(private_key.public_key())
    csv_path = output_dir / "provisioning-secret.csv"
    with csv_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("key", "type", "encoding", "value"))
        writer.writerow(("kgp_config", "namespace", "", ""))
        writer.writerow(("device_id", "data", "string", device_id))
        writer.writerow(("executor_kid", "data", "string", executor_kid))
        writer.writerow(("device_seed", "data", "hex2bin", seed.hex()))
    try:
        os.chmod(csv_path, 0o600)
    except OSError:
        pass

    record = {
        "type": "kinegrant:ESP32C3ProvisioningRecord",
        "profile": "kgp-esp32c3-paper-barrier/0.1",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "device_id": device_id,
        "device_kid": device_kid,
        "trusted_executor_kid": executor_kid,
        "secret_material_included": False,
        "physical_evidence_result": "NOT_RUN",
    }
    record_path = output_dir / "provisioning-public-record.json"
    with record_path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate one ESP32-C3 NVS provisioning CSV and public key record"
    )
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--executor-kid", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        record = generate_provisioning(args.device_id, args.executor_kid, args.output_dir)
    except (OSError, TypeError, ValueError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(record, sort_keys=True))
    print(
        "SECRET: provisioning-secret.csv must be converted, flashed, then removed; "
        "never commit or publish it.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
