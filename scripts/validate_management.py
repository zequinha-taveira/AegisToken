#!/usr/bin/env python3
"""AegisToken — Phase 10 Management HID hardware validation.

Run with an AegisToken device connected. Requires ``hidapi`` (``pip install
hidapi``); ``cbor2`` enables decoding of responses.

    python scripts/validate_management.py

Exit code is 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import sys

try:
    import hid
except ImportError as exc:  # pragma: no cover - tooling dependency
    print("hidapi is required: pip install hidapi")
    print(exc)
    sys.exit(2)

try:
    import cbor2
except ImportError:  # pragma: no cover - optional
    cbor2 = None

REPORT_SIZE = 64
HEADER_LEN = 5
PAYLOAD_PER_REPORT = REPORT_SIZE - HEADER_LEN
PROTOCOL_VERSION = 1
RESPONSE_FLAG = 0x80
MANAGEMENT_USAGE_PAGE = 0xFF00

GET_DEVICE_INFO = 0x01
GET_CAPABILITIES = 0x02
GET_CONFIGURATION = 0x03
SET_CONFIGURATION = 0x04
VALIDATE_CONFIGURATION = 0x05
COMMIT_CONFIGURATION = 0x06
GET_LIFECYCLE = 0x07
GET_STATUS = 0x09
GET_DIAGNOSTICS = 0x0A
GET_LAST_FIDO_STATUS = 0x14

CTAP_STATUS_NAMES = {
    0x00: "CTAP2_OK",
    0x01: "ERR_INVALID_COMMAND",
    0x02: "ERR_INVALID_PARAMETER",
    0x03: "ERR_INVALID_LENGTH",
    0x0A: "ERR_TIMEOUT",
    0x2E: "CTAP2_ERR_NO_CREDENTIALS",
    0x33: "CTAP2_ERR_PIN_AUTH_INVALID",
    0x34: "CTAP2_ERR_PIN_AUTH_BLOCKED",
    0x36: "CTAP2_ERR_PIN_REQUIRED",
    0x39: "CTAP2_ERR_OPERATION_DENIED",
    0x3B: "CTAP2_ERR_UP_REQUIRED",
    0x3D: "CTAP2_ERR_PIN_AUTH_REQUIRED",
}

RESULTS: list[tuple[str, bool, str]] = []


def record(ac: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((ac, passed, detail))
    flag = "PASS" if passed else "FAIL"
    print(f"[{flag}] {ac}" + (f" — {detail}" if detail else ""))


def frames(command: int, payload: bytes) -> list[bytes]:
    out: list[bytes] = []
    first = payload[:PAYLOAD_PER_REPORT]
    report = (
        bytes([PROTOCOL_VERSION, command])
        + len(payload).to_bytes(2, "little")
        + bytes([0])
        + first
    )
    out.append(report.ljust(REPORT_SIZE, b"\x00"))
    offset = len(first)
    sequence = 0
    while offset < len(payload):
        chunk = payload[offset : offset + PAYLOAD_PER_REPORT]
        report = (
            bytes([PROTOCOL_VERSION, command])
            + sequence.to_bytes(2, "little")
            + bytes([1])
            + chunk
        )
        out.append(report.ljust(REPORT_SIZE, b"\x00"))
        offset += len(chunk)
        sequence += 1
    return out


def open_hid(path):
    """Open a HID path across both the modern and legacy hidapi bindings."""
    if hasattr(hid, "Device"):
        return hid.Device(path=path)
    device = hid.device()
    device.open_path(path)
    return device


def open_management_device():
    for entry in hid.enumerate():
        if entry.get("usage_page") != MANAGEMENT_USAGE_PAGE:
            continue
        try:
            device = open_hid(entry["path"])
        except Exception:  # noqa: BLE001
            continue
        return device, entry
    return None, None


class ManagementDevice:
    def __init__(self, device) -> None:
        self.device = device

    def _read(self) -> bytes:
        data = self.device.read(REPORT_SIZE, 2000)
        if not data:
            return b""
        return bytes(data).ljust(REPORT_SIZE, b"\x00")

    def request(self, command: int, payload: bytes = b"") -> tuple[int, bytes]:
        for report in frames(command, payload):
            # hidapi expects the first byte to be the Report ID; these reports
            # are unnumbered, so prepend 0x00.
            self.device.write(b"\x00" + report)
        first = self._read()
        if not first:
            raise TimeoutError("no response from Management HID")
        total = int.from_bytes(first[2:4], "little")
        data = bytearray(first[HEADER_LEN:])
        sequence = 0
        while len(data) < total:
            cont = self._read()
            if not cont:
                raise TimeoutError("truncated response")
            if int.from_bytes(cont[2:4], "little") != sequence:
                raise RuntimeError("bad continuation sequence")
            data.extend(cont[HEADER_LEN:])
            sequence += 1
        body = bytes(data[:total])
        if not body:
            raise RuntimeError("empty response body")
        return body[0], body[1:]


def decode(body: bytes):
    if cbor2 is None:
        return None
    try:
        return cbor2.loads(body)
    except Exception:  # noqa: BLE001
        return None


def main() -> int:
    device, entry = open_management_device()
    record("AC-003 Management HID enumeration", device is not None)
    if device is None:
        return summarize()

    product = entry.get("product_string") if entry else None
    print(f"interface: {product}")
    management = ManagementDevice(device)

    try:
        status, body = management.request(GET_DEVICE_INFO)
        info = decode(body)
        record("AC-004 GET_DEVICE_INFO", status == 0 and len(body) > 0, f"status={status}")
        if info is not None:
            print(f"    device info: {info}")
    except Exception as exc:  # noqa: BLE001
        record("AC-004 GET_DEVICE_INFO", False, str(exc))

    try:
        status, body = management.request(GET_CAPABILITIES)
        capabilities = decode(body)
        ok = status == 0 and capabilities is not None
        record("AC-005 GET_CAPABILITIES", ok, f"status={status}")
        if capabilities is not None:
            # AC-009: the Desktop Manager discovers the hardware from the device.
            record(
                "AC-009 automatic discovery",
                capabilities.get(2) in (30, 48),
                f"gpio_count={capabilities.get(2)}",
            )
            record(
                "capabilities advertise both HID interfaces",
                capabilities.get(7) is True and capabilities.get(8) is True,
            )
    except Exception as exc:  # noqa: BLE001
        record("AC-005 GET_CAPABILITIES", False, str(exc))

    config = None
    try:
        status, body = management.request(GET_CONFIGURATION)
        record("AC-006a GET_CONFIGURATION", status == 0 and len(body) > 0, f"status={status}")
        if cbor2 is not None and status == 0:
            config = cbor2.loads(body)
    except Exception as exc:  # noqa: BLE001
        record("AC-006a GET_CONFIGURATION", False, str(exc))

    if cbor2 is not None and config is not None:
        try:
            original = config[2][4]
            config[2][4] = 1 if original != 1 else 2
            set_status, _ = management.request(SET_CONFIGURATION, cbor2.dumps(config))
            commit_status, _ = management.request(COMMIT_CONFIGURATION, b"")
            status, body = management.request(GET_CONFIGURATION)
            applied = cbor2.loads(body)[2][4] if status == 0 else None
            record(
                "AC-006 valid configuration applied",
                set_status == 0 and commit_status == 0 and applied == config[2][4],
                f"set={set_status} commit={commit_status}",
            )
            # restore the original value
            config[2][4] = original
            management.request(SET_CONFIGURATION, cbor2.dumps(config))
            management.request(COMMIT_CONFIGURATION, b"")
        except Exception as exc:  # noqa: BLE001
            record("AC-006 valid configuration applied", False, str(exc))

        try:
            invalid = dict(config)
            invalid[2] = dict(config[2])
            invalid[2][1] = 99
            status, _ = management.request(SET_CONFIGURATION, cbor2.dumps(invalid))
            record("AC-007 reject out-of-range GPIO", status != 0, f"status={status}")
        except Exception as exc:  # noqa: BLE001
            record("AC-007 reject out-of-range GPIO", False, str(exc))

        try:
            invalid = dict(config)
            invalid[1] = dict(config[1])
            invalid[1][0] = "Evil Key"
            status, _ = management.request(SET_CONFIGURATION, cbor2.dumps(invalid))
            record("AC-007 reject bad USB identity", status != 0, f"status={status}")
        except Exception as exc:  # noqa: BLE001
            record("AC-007 reject bad USB identity", False, str(exc))
    else:
        try:
            status, _ = management.request(SET_CONFIGURATION, b"\xff\xff")
            record("AC-007 reject invalid CBOR", status != 0, f"status={status}")
        except Exception as exc:  # noqa: BLE001
            record("AC-007 reject invalid CBOR", False, str(exc))

    for name, command in [
        ("GET_LIFECYCLE", GET_LIFECYCLE),
        ("GET_STATUS", GET_STATUS),
        ("GET_DIAGNOSTICS", GET_DIAGNOSTICS),
    ]:
        try:
            status, body = management.request(command)
            record(name, status == 0 and len(body) > 0, f"status={status}")
        except Exception as exc:  # noqa: BLE001
            record(name, False, str(exc))

    try:
        status, body = management.request(GET_LAST_FIDO_STATUS)
        if status == 0 and len(body) >= 2:
            command, ctap_status = body[0], body[1]
            name = CTAP_STATUS_NAMES.get(ctap_status, "unknown")
            print(
                "    last FIDO command=0x"
                f"{command:02x} status=0x{ctap_status:02x} ({name})"
            )
    except Exception as exc:  # noqa: BLE001
        print(f"    last FIDO status unavailable: {exc}")

    return summarize()


def summarize() -> int:
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
