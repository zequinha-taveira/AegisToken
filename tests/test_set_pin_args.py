#!/usr/bin/env python3
# Copyright (c) 2026 AegisToken Project
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Unit tests for `scripts/set_pin.py`: argument parsing and secret channels.

The module is imported without `python-fido2`: the dependency is loaded only
when a real operation runs, so the parser stays testable on a bare host.
"""

import io
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

import set_pin


SENTINEL = "S3NT1NEL-pin-value"


class TestParseArgs(unittest.TestCase):
    def test_defaults_to_set_with_prompts(self):
        self.assertEqual(set_pin.parse_args([]), ("--set", False, False))

    def test_accepts_stdin_sources(self):
        self.assertEqual(
            set_pin.parse_args(["--change", "--old-pin-stdin", "--pin-stdin"]),
            ("--change", True, True),
        )

    def test_rejects_pin_in_argv(self):
        for argv in (
            ["--set", "--pin", SENTINEL],
            ["--set", f"--pin={SENTINEL}"],
            ["--change", "--old-pin", SENTINEL],
            ["--change", f"--old-pin={SENTINEL}"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(set_pin.UsageError) as raised:
                    set_pin.parse_args(argv)
                self.assertNotIn(SENTINEL, str(raised.exception))

    def test_unknown_option_reports_only_the_name(self):
        for token in (f"--key={SENTINEL}", f"-key={SENTINEL}"):
            with self.subTest(token=token):
                with self.assertRaises(set_pin.UsageError) as raised:
                    set_pin.parse_args([token])
                self.assertIn("key", str(raised.exception))
                self.assertNotIn(SENTINEL, str(raised.exception))

    def test_single_dash_secret_option_is_rejected_without_echo(self):
        for token in (f"-pin={SENTINEL}", f"-old-pin={SENTINEL}"):
            with self.subTest(token=token):
                with self.assertRaises(set_pin.UsageError) as raised:
                    set_pin.parse_args([token])
                self.assertNotIn(SENTINEL, str(raised.exception))

    def test_positional_is_rejected_without_echo(self):
        with self.assertRaises(set_pin.UsageError) as raised:
            set_pin.parse_args([SENTINEL])
        self.assertNotIn(SENTINEL, str(raised.exception))


class TestSecretChannels(unittest.TestCase):
    def test_reads_one_line_without_the_line_ending(self):
        with mock.patch("sys.stdin", io.StringIO("123456\r\n654321\n")):
            self.assertEqual(set_pin.read_stdin_secret("current PIN"), "123456")
            self.assertEqual(set_pin.read_stdin_secret("new PIN"), "654321")

    def test_empty_or_closed_stdin_is_an_error(self):
        for stream in (io.StringIO("\n"), io.StringIO("\r\n"), io.StringIO("")):
            with self.subTest(stream=stream):
                with mock.patch("sys.stdin", stream):
                    with self.assertRaises(set_pin.UsageError):
                        set_pin.read_stdin_secret("new PIN")

    def test_change_requires_both_stdin_flags(self):
        with self.assertRaises(set_pin.UsageError):
            set_pin._acquire("--change", True, False)
        with self.assertRaises(set_pin.UsageError):
            set_pin._acquire("--change", False, True)

    def test_set_rejects_old_pin_stdin(self):
        with self.assertRaises(set_pin.UsageError):
            set_pin._acquire("--set", False, True)

    def test_retries_rejects_secret_flags(self):
        with self.assertRaises(set_pin.UsageError):
            set_pin._acquire("--retries", True, False)

    def test_stdin_change_reads_current_then_new(self):
        with mock.patch("sys.stdin", io.StringIO("111111\n222222\n")):
            old, new = set_pin._acquire("--change", True, True)
        self.assertEqual((old, new), ("111111", "222222"))

    def test_no_tty_and_no_flags_is_a_usage_error(self):
        with mock.patch("sys.stdin", io.StringIO("")):
            with self.assertRaises(set_pin.UsageError):
                set_pin._acquire("--set", False, False)

    def test_stdin_flags_refuse_a_terminal(self):
        class FakeTty(io.StringIO):
            def isatty(self):
                return True

        for pin_stdin, old_pin_stdin in ((True, False), (True, True)):
            with self.subTest(pin_stdin=pin_stdin, old_pin_stdin=old_pin_stdin):
                with mock.patch("sys.stdin", FakeTty("")):
                    with self.assertRaises(set_pin.UsageError):
                        set_pin._acquire("--change", pin_stdin, old_pin_stdin)

    def test_tty_without_flags_keeps_the_hidden_prompt(self):
        class FakeTty(io.StringIO):
            def isatty(self):
                return True

        with mock.patch("sys.stdin", FakeTty("")):
            with mock.patch("set_pin.getpass.getpass", return_value="123456") as prompt:
                self.assertEqual(set_pin._acquire("--set", False, False), (None, "123456"))
                prompt.assert_called_once()

        with mock.patch("sys.stdin", FakeTty("")):
            with mock.patch(
                "set_pin.getpass.getpass", side_effect=["111111", "222222"]
            ) as prompt:
                self.assertEqual(
                    set_pin._acquire("--change", False, False), ("111111", "222222")
                )
                self.assertEqual(prompt.call_count, 2)


class TestMainSafety(unittest.TestCase):
    def test_help_wins_over_a_secret_flag_without_echo(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = set_pin.main(["--help", "--pin", SENTINEL])
        self.assertEqual(code, 0)
        self.assertNotIn(SENTINEL, stdout.getvalue() + stderr.getvalue())
        self.assertIn("USAGE", stdout.getvalue())

    def test_argv_secret_fails_before_any_device_or_echo(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = set_pin.main(["--set", f"--pin={SENTINEL}"])
        self.assertEqual(code, 2)
        self.assertNotIn(SENTINEL, stdout.getvalue() + stderr.getvalue())
        self.assertIn("--pin", stderr.getvalue())

    def test_redact_removes_every_acquired_secret(self):
        text = f"failed with {SENTINEL} and 222222"
        self.assertEqual(
            set_pin.redact(text, [SENTINEL, "222222", None]),
            "failed with <redacted> and <redacted>",
        )


class TestSubprocess(unittest.TestCase):
    """Exercise the real entry point: exit code and streams, not just `main()`."""

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        script = os.path.join(os.path.dirname(__file__), "..", "scripts", "set_pin.py")
        return subprocess.run(
            [sys.executable, script, *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_help_exits_zero_without_echoing_a_secret(self):
        result = self._run("--help", "--pin", SENTINEL)
        self.assertEqual(result.returncode, 0)
        self.assertIn("USAGE", result.stdout)
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)

    def test_argv_secret_exits_two_without_echoing_it(self):
        result = self._run("--set", f"--pin={SENTINEL}")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--pin", result.stderr)
        self.assertNotIn(SENTINEL, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
