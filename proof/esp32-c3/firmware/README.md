# ESP32-C3 paper-barrier firmware

Status: **buildable experimental firmware; physical result remains `NOT_RUN`**.

This ESP-IDF project implements the device-local boundary for
`kgp-esp32c3-paper-barrier/0.1`. It is deliberately locked when provisioning is
missing or state cannot be committed. It is only for the lightweight paper
fixture described in [`../HARDWARE.md`](../HARDWARE.md).

## Security boundary

- boots with GPIO4 inactive;
- requires `device_id`, `executor_kid`, and a 32-byte device seed in NVS;
- increments and commits a persistent boot counter before issuing a challenge;
- generates an 18-byte nonce with the ESP-IDF entropy source;
- accepts one canonical, bounded JSON command for the active 10-second challenge;
- verifies Ed25519, exact fields, trusted executor, device/action/parameter,
  sequence, challenge, and content-derived command ID;
- commits sequence, command ID, and actuator count before invoking LEDC;
- exposes only compiled `open` and `closed` pulse widths on GPIO4;
- signs a canonical acknowledgement and wipes key material on fatal exit.

Malformed input consumes the live challenge and produces no authorization. A new
challenge is emitted afterward. Bootloader and application logs are disabled on
the protocol serial channel so non-JSON diagnostics cannot be mistaken for
authorized protocol frames.

## Reproducible dependency

The build downloads Monocypher 4.0.3 from its official site and verifies the
publisher's SHA-512 checksum before compiling the core and optional Ed25519
sources. Monocypher 4.0.3 contains the 2026 signature timing-leak fix and is
available under CC0 or BSD-2-Clause. The dependency is not part of KGP-001 and
does not change the repository's Apache-2.0 licensing.

- <https://monocypher.org/download/>
- <https://monocypher.org/quality-assurance/disclosures>
- <https://monocypher.org/manual/ed25519>

## Build

Use ESP-IDF 5.5.3, the version pinned in GitHub Actions:

```bash
cd proof/esp32-c3/firmware
idf.py set-target esp32c3
idf.py build
```

The build alone is not physical proof. Flashing and provisioning must wait until
the exact board pinout and power plan have passed `HARDWARE.md`.

## Required NVS provisioning

Namespace `kgp_config` must contain:

| Key | NVS type | Requirement |
| --- | --- | --- |
| `device_id` | string | 1–96 characters from `A-Z a-z 0-9 : . _ -` |
| `executor_kid` | string | exact trusted `kinegrant:key:ed25519:...` identifier |
| `device_seed` | blob | exactly 32 random bytes; never commit it |

The derived device public key ID is printed only in the signed acknowledgement.
The seed lives in ordinary flash in this experiment and is not hardware-backed.
Production use would require a separate provisioning, secure-boot, flash-
encryption, extraction-resistance, and key-rotation design.

Generate a secret NVS CSV and a separate public record:

```bash
python proof/provision_esp32c3.py \
  --device-id device:esp32c3:paper-barrier:01 \
  --executor-kid kinegrant:key:ed25519:REPLACE_WITH_43_BASE64URL_CHARS \
  --output-dir ./local-provisioning
```

Inside an exported ESP-IDF environment, convert and flash the NVS partition:

```bash
python "$IDF_PATH/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py" \
  generate local-provisioning/provisioning-secret.csv \
  local-provisioning/provisioning-secret.bin 0x6000

parttool.py --port COM7 write_partition \
  --partition-name nvs \
  --input local-provisioning/provisioning-secret.bin
```

The CSV and binary contain the device secret. Keep the public JSON record, but
securely remove both secret files after flashing. Do not use shell history or
screenshots that expose their contents.

## Fixed local actuator configuration

- GPIO4, 50 Hz LEDC;
- `closed`: 1100 microseconds;
- `open`: 1900 microseconds;
- signal detached after 600 milliseconds.

These are cautious initial values, not a claim that an unidentified SG90 clone
or SuperMini board has been calibrated. Reduce travel if the physical fixture
approaches a stop or chatters.
