#!/usr/bin/env python3
# Copyright (c) 2026 AegisToken Project
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Unit tests for `scripts/validate_fido.py`: argument parsing and PIN channels.

The module is imported without `python-fido2` (the CI does not install it):
the dependency is guarded and reported only when `main()` runs.
"""

import io
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

import validate_fido


SENTINEL = "S3NT1NEL-pin-value"


class FakeTty(io.StringIO):
    def isatty(self):
        return True


class TestParseArgs(unittest.TestCase):
    def test_defaults_to_presence_only(self):
        self.assertEqual(validate_fido.parse_args([]), (False, False))

    def test_accepts_each_pin_source(self):
        self.assertEqual(validate_fido.parse_args(["--pin-stdin"]), (True, False))
        self.assertEqual(validate_fido.parse_args(["--pin-prompt"]), (False, True))

    def test_pin_sources_are_mutually_exclusive(self):
        with self.assertRaises(validate_fido.UsageError):
            validate_fido.parse_args(["--pin-stdin", "--pin-prompt"])

    def test_pin_flags_reject_an_inline_value(self):
        for token in ("--pin-stdin=x", "--pin-prompt=x"):
            with self.subTest(token=token):
                with self.assertRaises(validate_fido.UsageError) as raised:
                    validate_fido.parse_args([token])
                self.assertIn("takes no value", str(raised.exception))

    def test_rejects_pin_in_argv(self):
        for argv in (
            ["--pin", SENTINEL],
            [f"--pin={SENTINEL}"],
            ["--old-pin", SENTINEL],
            [f"--old-pin={SENTINEL}"],
            [f"-pin={SENTINEL}"],
            [f"-old-pin={SENTINEL}"],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(validate_fido.UsageError) as raised:
                    validate_fido.parse_args(argv)
                self.assertNotIn(SENTINEL, str(raised.exception))
                self.assertIn("pin", str(raised.exception))

    def test_unknown_option_reports_only_the_name(self):
        for token in (f"--key={SENTINEL}", f"-key={SENTINEL}"):
            with self.subTest(token=token):
                with self.assertRaises(validate_fido.UsageError) as raised:
                    validate_fido.parse_args([token])
                self.assertIn("key", str(raised.exception))
                self.assertNotIn(SENTINEL, str(raised.exception))

    def test_positional_is_rejected_without_echo(self):
        with self.assertRaises(validate_fido.UsageError) as raised:
            validate_fido.parse_args([SENTINEL])
        self.assertNotIn(SENTINEL, str(raised.exception))

    def test_help_is_ignored_by_the_parser(self):
        self.assertEqual(validate_fido.parse_args(["--help"]), (False, False))


class TestSecretChannels(unittest.TestCase):
    def test_reads_one_line_without_the_line_ending(self):
        with mock.patch("sys.stdin", io.StringIO("123456\r\n654321\n")):
            self.assertEqual(validate_fido.read_stdin_secret("PIN"), "123456")
            self.assertEqual(validate_fido.read_stdin_secret("PIN"), "654321")

    def test_empty_or_closed_stdin_is_an_error(self):
        for stream in (io.StringIO("\n"), io.StringIO("\r\n"), io.StringIO("")):
            with self.subTest(stream=stream):
                with mock.patch("sys.stdin", stream):
                    with self.assertRaises(validate_fido.UsageError):
                        validate_fido.read_stdin_secret("PIN")

    def test_pin_stdin_reads_from_a_pipe(self):
        with mock.patch("sys.stdin", io.StringIO("123456\n")):
            self.assertEqual(validate_fido._acquire_pin(True, False), "123456")

    def test_pin_stdin_refuses_a_terminal(self):
        with mock.patch("sys.stdin", FakeTty("")):
            with self.assertRaises(validate_fido.UsageError) as raised:
                validate_fido._acquire_pin(True, False)
            self.assertIn("pipe", str(raised.exception))

    def test_pin_prompt_requires_a_terminal(self):
        with mock.patch("sys.stdin", io.StringIO("")):
            with self.assertRaises(validate_fido.UsageError) as raised:
                validate_fido._acquire_pin(False, True)
            self.assertIn("--pin-stdin", str(raised.exception))

    def test_pin_prompt_uses_a_hidden_prompt(self):
        with mock.patch("sys.stdin", FakeTty("")):
            with mock.patch(
                "validate_fido.getpass.getpass", return_value="123456"
            ) as prompt:
                self.assertEqual(validate_fido._acquire_pin(False, True), "123456")
                prompt.assert_called_once()

    def test_empty_prompt_is_an_error(self):
        with mock.patch("sys.stdin", FakeTty("")):
            with mock.patch("validate_fido.getpass.getpass", return_value=""):
                with self.assertRaises(validate_fido.UsageError):
                    validate_fido._acquire_pin(False, True)

    def test_no_flags_means_no_pin(self):
        self.assertIsNone(validate_fido._acquire_pin(False, False))


class TestRedaction(unittest.TestCase):
    def setUp(self):
        validate_fido.RESULTS.clear()
        validate_fido.SECRETS.clear()

    def tearDown(self):
        validate_fido.RESULTS.clear()
        validate_fido.SECRETS.clear()

    def test_redact_removes_every_acquired_secret(self):
        validate_fido.SECRETS.extend([SENTINEL, "222222"])
        self.assertEqual(
            validate_fido.redact(f"failed with {SENTINEL} and 222222"),
            "failed with <redacted> and <redacted>",
        )

    def test_record_redacts_the_pin(self):
        validate_fido.SECRETS.append(SENTINEL)
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            validate_fido.record("check", False, f"boom {SENTINEL}")
        self.assertNotIn(SENTINEL, stdout.getvalue())
        self.assertNotIn(SENTINEL, validate_fido.RESULTS[0][2])
        self.assertIn("<redacted>", validate_fido.RESULTS[0][2])


class TestMainSafety(unittest.TestCase):
    def setUp(self):
        validate_fido.RESULTS.clear()
        validate_fido.SECRETS.clear()

    def tearDown(self):
        validate_fido.RESULTS.clear()
        validate_fido.SECRETS.clear()

    def test_help_wins_over_a_secret_flag_without_echo(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = validate_fido.main(["--help", "--pin", SENTINEL])
        self.assertEqual(code, 0)
        self.assertIn("USAGE", stdout.getvalue())
        self.assertNotIn(SENTINEL, stdout.getvalue() + stderr.getvalue())

    def test_argv_secret_fails_before_any_device_or_echo(self):
        for argv in (["--pin", SENTINEL], [f"--pin={SENTINEL}"], [f"--old-pin={SENTINEL}"]):
            with self.subTest(argv=argv):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    code = validate_fido.main(argv)
                self.assertEqual(code, 2)
                self.assertNotIn(SENTINEL, stdout.getvalue() + stderr.getvalue())
                self.assertIn("--pin", stderr.getvalue())

    def test_conflicting_sources_fail_without_reading_stdin(self):
        stream = io.StringIO(SENTINEL)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdin", stream):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = validate_fido.main(["--pin-stdin", "--pin-prompt"])
        self.assertEqual(code, 2)
        self.assertNotIn(SENTINEL, stdout.getvalue() + stderr.getvalue())

    @unittest.skipIf(
        validate_fido._FIDO_IMPORT_ERROR is None,
        "python-fido2 is installed; the dependency guard is not exercised",
    )
    def test_missing_fido2_exits_two_without_reading_the_pin(self):
        stream = io.StringIO(SENTINEL)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdin", stream):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = validate_fido.main(["--pin-stdin"])
        self.assertEqual(code, 2)
        self.assertIn("python-fido2", stderr.getvalue())
        self.assertNotIn(SENTINEL, stdout.getvalue() + stderr.getvalue())
        self.assertEqual(stream.tell(), 0)


class TestSubprocess(unittest.TestCase):
    """Exercise the real entry point: exit code and streams, not just `main()`."""

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        script = os.path.join(
            os.path.dirname(__file__), "..", "scripts", "validate_fido.py"
        )
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
        for args in (("--pin", SENTINEL), (f"--pin={SENTINEL}",)):
            with self.subTest(args=args):
                result = self._run(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--pin", result.stderr)
                self.assertNotIn(SENTINEL, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
