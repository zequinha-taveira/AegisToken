#!/usr/bin/env python3
# Copyright (c) 2026 AegisToken Project
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Native, lightweight PC/SC smartcard transport for Python (Windows, Linux, macOS).

Implements the subset of PC/SC (WinSCard / PCSC-Lite) required by the AegisToken
hardware validation scripts, with zero third-party dependencies (ctypes only).

Exposes the same high-level duck-typed interface as ``pyscard`` (``smartcard.System.readers``):
- ``readers() -> list[SmartCardReader]``
- ``reader.createConnection() -> SmartCardConnection``
- ``connection.connect()``
- ``connection.getATR() -> list[int]``
- ``connection.transmit(apdu: list[int] | bytes) -> tuple[list[int], int, int]``
- ``connection.disconnect()``

Licensed under MIT OR Apache-2.0 to eliminate LGPL dependencies from AegisToken.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys

# PC/SC Constants
SCARD_SCOPE_USER = 0
SCARD_SCOPE_TERMINAL = 1
SCARD_SCOPE_SYSTEM = 2

SCARD_SHARE_EXCLUSIVE = 1
SCARD_SHARE_SHARED = 2
SCARD_SHARE_DIRECT = 3

SCARD_PROTOCOL_UNDEFINED = 0x00000000
SCARD_PROTOCOL_T0 = 0x00000001
SCARD_PROTOCOL_T1 = 0x00000002
SCARD_PROTOCOL_RAW = 0x00000004
SCARD_PROTOCOL_Tx = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1

SCARD_LEAVE_CARD = 0
SCARD_RESET_CARD = 1
SCARD_UNPOWER_CARD = 2
SCARD_EJECT_CARD = 3

SCARD_S_SUCCESS = 0
SCARD_E_NO_READERS_AVAILABLE = 0x8010002E
SCARD_E_NO_SMARTCARD = 0x8010000C
SCARD_E_UNKNOWN_READER = 0x80100009


class SCARD_IO_REQUEST(ctypes.Structure):
    _fields_ = [
        ("dwProtocol", ctypes.c_ulong),
        ("cbPciLength", ctypes.c_ulong),
    ]


class PCSCError(RuntimeError):
    """Exception raised on PC/SC operation failures."""

    def __init__(self, message: str, return_code: int = 0):
        super().__init__(f"{message} (return code: 0x{return_code & 0xFFFFFFFF:08X})")
        self.return_code = return_code


def _load_pcsc_library():
    """Load the platform PC/SC shared library."""
    if sys.platform == "win32":
        try:
            return ctypes.windll.winscard
        except Exception as exc:
            raise PCSCError(f"Failed to load winscard.dll: {exc}") from exc
    elif sys.platform == "darwin":
        path = "/System/Library/Frameworks/PCSC.framework/PCSC"
        if os.path.exists(path):
            return ctypes.CDLL(path)
        lib_name = ctypes.util.find_library("PCSC")
        if lib_name:
            return ctypes.CDLL(lib_name)
    else:
        # Linux / BSD
        for name in ("libpcsclite.so.1", "libpcsclite.so"):
            try:
                return ctypes.CDLL(name)
            except OSError:
                continue
        lib_name = ctypes.util.find_library("pcsclite")
        if lib_name:
            return ctypes.CDLL(lib_name)
    raise PCSCError("PCSC-Lite library (libpcsclite) not found. Install pcscd / pcsc-lite.")


_LIB = None


def get_lib():
    global _LIB
    if _LIB is None:
        _LIB = _load_pcsc_library()
    return _LIB


def _get_pci_struct(lib, protocol: int) -> SCARD_IO_REQUEST:
    """Return the SCARD_IO_REQUEST struct for T=0 or T=1."""
    sym_name = "g_rgSCardT0Pci" if protocol == SCARD_PROTOCOL_T0 else "g_rgSCardT1Pci"
    try:
        return SCARD_IO_REQUEST.in_dll(lib, sym_name)
    except Exception:
        # Construct directly if symbol lookup in DLL fails
        req = SCARD_IO_REQUEST()
        req.dwProtocol = protocol
        req.cbPciLength = ctypes.sizeof(SCARD_IO_REQUEST)
        return req


class SmartCardConnection:
    """Manages an active connection to a card in a PC/SC reader."""

    def __init__(self, reader_name: str, context: int):
        self.reader_name = reader_name
        self._context = context
        self._card_handle = ctypes.c_size_t(0)
        self._active_protocol = ctypes.c_ulong(0)
        self._connected = False

    def connect(self, protocol: int = SCARD_PROTOCOL_Tx, share_mode: int = SCARD_SHARE_SHARED):
        lib = get_lib()
        c_reader = self.reader_name.encode("utf-8")
        h_card = ctypes.c_size_t(0)
        active_proto = ctypes.c_ulong(0)

        connect_fn = getattr(lib, "SCardConnectA", getattr(lib, "SCardConnect", None))
        if not connect_fn:
            raise PCSCError("SCardConnect not found in PC/SC library")

        rc = connect_fn(
            ctypes.c_size_t(self._context),
            c_reader,
            ctypes.c_ulong(share_mode),
            ctypes.c_ulong(protocol),
            ctypes.byref(h_card),
            ctypes.byref(active_proto),
        )
        if rc != SCARD_S_SUCCESS:
            raise PCSCError(f"SCardConnect failed on '{self.reader_name}'", rc)

        self._card_handle = h_card
        self._active_protocol = active_proto
        self._connected = True

    def disconnect(self, disposition: int = SCARD_LEAVE_CARD):
        if not self._connected:
            return
        lib = get_lib()
        disconnect_fn = getattr(lib, "SCardDisconnect", None)
        if disconnect_fn and self._card_handle.value:
            disconnect_fn(self._card_handle, ctypes.c_ulong(disposition))
        self._connected = False
        self._card_handle = ctypes.c_size_t(0)

    def getATR(self) -> list[int]:
        """Query and return the card ATR bytes."""
        if not self._connected:
            raise PCSCError("Card is not connected")
        lib = get_lib()
        status_fn = getattr(lib, "SCardStatusA", getattr(lib, "SCardStatus", None))
        if not status_fn:
            raise PCSCError("SCardStatus not found in PC/SC library")

        reader_len = ctypes.c_ulong(256)
        reader_buf = ctypes.create_string_buffer(256)
        state = ctypes.c_ulong(0)
        proto = ctypes.c_ulong(0)
        atr_buf = ctypes.create_string_buffer(64)
        atr_len = ctypes.c_ulong(64)

        rc = status_fn(
            self._card_handle,
            reader_buf,
            ctypes.byref(reader_len),
            ctypes.byref(state),
            ctypes.byref(proto),
            atr_buf,
            ctypes.byref(atr_len),
        )
        if rc != SCARD_S_SUCCESS:
            raise PCSCError("SCardStatus failed", rc)

        return [atr_buf.raw[i] for i in range(atr_len.value)]

    def transmit(self, apdu: list[int] | bytes) -> tuple[list[int], int, int]:
        """Transmit an APDU and return (data_bytes, sw1, sw2)."""
        if not self._connected:
            raise PCSCError("Card is not connected")
        lib = get_lib()
        transmit_fn = getattr(lib, "SCardTransmit", None)
        if not transmit_fn:
            raise PCSCError("SCardTransmit not found in PC/SC library")

        raw_apdu = bytes(apdu)
        send_buf = ctypes.create_string_buffer(raw_apdu, len(raw_apdu))
        recv_buf = ctypes.create_string_buffer(65538)
        recv_len = ctypes.c_ulong(len(recv_buf))

        pio_send = _get_pci_struct(lib, self._active_protocol.value)

        rc = transmit_fn(
            self._card_handle,
            ctypes.byref(pio_send),
            send_buf,
            ctypes.c_ulong(len(raw_apdu)),
            None,
            recv_buf,
            ctypes.byref(recv_len),
        )
        if rc != SCARD_S_SUCCESS:
            raise PCSCError("SCardTransmit failed", rc)

        length = recv_len.value
        if length < 2:
            raise PCSCError(f"Invalid APDU response length: {length}")

        resp_bytes = [recv_buf.raw[i] for i in range(length)]
        sw1 = resp_bytes[-2]
        sw2 = resp_bytes[-1]
        data = resp_bytes[:-2]
        return data, sw1, sw2

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


class SmartCardReader:
    """Represents an enumerated smartcard reader."""

    def __init__(self, name: str, context: int):
        self.name = name
        self._context = context

    def createConnection(self) -> SmartCardConnection:
        return SmartCardConnection(self.name, self._context)

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"<SmartCardReader: {self.name}>"


def readers() -> list[SmartCardReader]:
    """Enumerate and return all available PC/SC smartcard readers.

    Matches the signature and behavior of ``smartcard.System.readers()`` from pyscard.
    """
    try:
        lib = get_lib()
    except Exception:
        # Fall back to pyscard if native ctypes fails to load library
        try:
            from smartcard.System import readers as pyscard_readers
            return list(pyscard_readers())
        except ImportError:
            return []

    ctx = ctypes.c_size_t(0)
    establish_fn = getattr(lib, "SCardEstablishContext", None)
    if not establish_fn:
        return []

    rc = establish_fn(
        ctypes.c_ulong(SCARD_SCOPE_USER),
        None,
        None,
        ctypes.byref(ctx),
    )
    if rc != SCARD_S_SUCCESS:
        return []

    list_fn = getattr(lib, "SCardListReadersA", getattr(lib, "SCardListReaders", None))
    if not list_fn:
        return []

    cch = ctypes.c_ulong(0)
    rc = list_fn(ctx, None, None, ctypes.byref(cch))
    if rc != SCARD_S_SUCCESS or cch.value == 0:
        return []

    buf = ctypes.create_string_buffer(cch.value)
    rc = list_fn(ctx, None, buf, ctypes.byref(cch))
    if rc != SCARD_S_SUCCESS:
        return []

    raw = buf.raw[: cch.value]
    names = [s.decode("utf-8", errors="replace") for s in raw.split(b"\x00") if s]
    return [SmartCardReader(name, ctx.value) for name in names]


if __name__ == "__main__":
    print("Testing pcsc_transport.py...")
    available = readers()
    print(f"Readers found: {len(available)}")
    for r in available:
        print(f" - {r}")
