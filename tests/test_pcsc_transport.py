#!/usr/bin/env python3
# Copyright (c) 2026 AegisToken Project
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Unit tests for the native permissive pcsc_transport module."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

import pcsc_transport


class TestPCSCTransport(unittest.TestCase):
    def test_constants_defined(self):
        self.assertEqual(pcsc_transport.SCARD_S_SUCCESS, 0)
        self.assertEqual(pcsc_transport.SCARD_SHARE_SHARED, 2)
        self.assertEqual(pcsc_transport.SCARD_PROTOCOL_T0, 1)
        self.assertEqual(pcsc_transport.SCARD_PROTOCOL_T1, 2)

    def test_readers_call_succeeds(self):
        # readers() must always return a list (empty or populated), never crash
        readers = pcsc_transport.readers()
        self.assertIsInstance(readers, list)

    def test_mock_reader_interface(self):
        # Verify reader and connection duck-typing matching pyscard
        reader = pcsc_transport.SmartCardReader("AegisToken Reader 0", context=123)
        self.assertEqual(str(reader), "AegisToken Reader 0")
        conn = reader.createConnection()
        self.assertIsInstance(conn, pcsc_transport.SmartCardConnection)
        self.assertEqual(conn.reader_name, "AegisToken Reader 0")
        self.assertFalse(conn._connected)

    def test_unconnected_connection_raises(self):
        reader = pcsc_transport.SmartCardReader("Test Reader", context=0)
        conn = reader.createConnection()
        with self.assertRaises(pcsc_transport.PCSCError):
            conn.getATR()
        with self.assertRaises(pcsc_transport.PCSCError):
            conn.transmit([0x00, 0xA4, 0x04, 0x00])


if __name__ == "__main__":
    unittest.main()
