import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from firmware.firmware_audit import (  # noqa: E402
    DANGEROUS_FUNCTIONS,
    FirmwareImage,
    build_fixture,
    main,
    score_image,
    sniff_format,
)


class FormatTest(unittest.TestCase):
    def test_sniff_elf(self):
        self.assertEqual(sniff_format(b"\x7fELF\x02\x01\x01", "x"), "elf")

    def test_sniff_pe(self):
        self.assertEqual(sniff_format(b"MZ\x90\x00", "x.exe"), "pe")

    def test_sniff_png(self):
        self.assertEqual(
            sniff_format(b"\x89PNG\r\n\x1a\n....", "x.png"), "png")

    def test_sniff_raw(self):
        self.assertEqual(sniff_format(b"UA\x00P5\x00" + bytes(32), "x.bin"), "raw")


class ImageTest(unittest.TestCase):
    def setUp(self):
        self.img = build_fixture()

    def test_strings_extract(self):
        strs = self.img.strings()
        joined = b"\n".join(strs).decode("latin-1")
        self.assertIn("router.example.com", joined)
        self.assertIn("config", joined)

    def test_sha256(self):
        self.assertEqual(len(self.img.sha256()), 64)

    def test_fixture_format(self):
        self.assertEqual(self.img.fmt, "raw")


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.rel = score_image(build_fixture())

    def test_secrets_found(self):
        kinds = {f["kind"] for f in self.rel["findings"]}
        self.assertTrue(kinds & {"embedded-credential", "embedded-password"})

    def test_backdoor_found(self):
        kinds = {f["kind"] for f in self.rel["findings"]}
        self.assertIn("alternate-shell-port", kinds)
        self.assertIn("netcat-exec", kinds)
        self.assertIn("temp-payload-path", kinds)

    def test_dangerous_functions_found(self):
        kinds = {f["kind"] for f in self.rel["findings"]}
        self.assertIn("memory-unsafe", kinds)
        self.assertIn("process-exec", kinds)

    def test_aws_key_example_found(self):
        kinds = {f["kind"] for f in self.rel["findings"]}
        self.assertIn("aws-access-key", kinds)

    def test_risk_score_positive(self):
        self.assertGreater(self.rel["risk_score"], 0)

    def test_config_paths_include_example(self):
        paths = self.rel["config_paths"]
        self.assertTrue(any("log" in p for p in paths))

    def test_clean_image_zero_risk(self):
        clean = score_image(FirmwareImage(b"hello world safe " * 10,
                                          name="clean.bin", fmt="raw"))
        self.assertEqual(clean["risk_score"], 0)


class CliTest(unittest.TestCase):
    def test_demo_exit_zero_report_written(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.md")
            code = main(["--report", rp])
            self.assertEqual(code, 0)  # demo run exits 0 by contract
            self.assertIn("FIRMWARE", open(rp).read())

    def test_strict_exits_one_when_risk(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.md")
            code = main(["--report", rp, "--strict"])
            self.assertEqual(code, 1)

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.json")
            code = main(["--report", rp])
            self.assertEqual(code, 0)
            data = json.loads(open(rp).read())
            self.assertTrue(data[0]["findings"])

    def test_image_file_input(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "evil.bin")
            open(p, "wb").write(b"api_key = XyZqWeRtYy aaa bbb\n/usr/sbin/sshd -p 2222\n")
            rp = os.path.join(td, "out.md")
            code = main(["--image", p, "--report", rp])
            self.assertEqual(code, 0)
            self.assertIn("evil.bin", open(rp).read())


if __name__ == "__main__":
    unittest.main()