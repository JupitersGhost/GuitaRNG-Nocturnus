"""Capture Spectra-compatible TRNG lines from Nocturnus native USB serial."""

from __future__ import annotations

import argparse
import base64
import binascii
import sys

try:
    import serial
except ImportError as exc:  # pragma: no cover - depends on host setup
    raise SystemExit("pyserial is required: py -m pip install pyserial") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Decode TRNG:<base64> lines and append their 32-byte payloads."
    )
    parser.add_argument("port", help="serial device, for example COM7 or /dev/ttyACM0")
    parser.add_argument("output", help="binary output file")
    parser.add_argument("--baud", type=int, default=115200, help="nominal CDC baud")
    parser.add_argument(
        "--blocks", type=int, default=0, help="stop after this many blocks (0 = forever)"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    blocks = 0
    byte_count = 0

    with serial.Serial(args.port, args.baud, timeout=1) as device, open(
        args.output, "ab", buffering=0
    ) as output:
        print(f"Listening on {args.port}; appending conditioned bytes to {args.output}")
        while not args.blocks or blocks < args.blocks:
            raw_line = device.readline()
            if not raw_line:
                continue
            line = raw_line.strip()
            if not line.startswith(b"TRNG:"):
                print(line.decode("utf-8", errors="replace"))
                continue
            try:
                payload = base64.b64decode(line[5:], validate=True)
            except (binascii.Error, ValueError) as exc:
                print(f"discarding malformed TRNG line: {exc}", file=sys.stderr)
                continue
            if len(payload) != 32:
                print(
                    f"discarding TRNG payload of {len(payload)} bytes (expected 32)",
                    file=sys.stderr,
                )
                continue
            output.write(payload)
            blocks += 1
            byte_count += len(payload)
            print(f"blocks={blocks} bytes={byte_count}", end="\r", flush=True)

    print(f"\nCaptured {blocks} blocks / {byte_count} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
