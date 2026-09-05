#!/usr/bin/env python3
"""
F6 — Firmware audit pipeline (post-LogoFAIL discipline)
A pure-Python UEFI/firmware audit pipeline: parses an embedded UEFI-volume-ish
byte dump (volume headers + DXE module list), checks DXE module signatures,
validates a dbx revocation list, builds a CycloneDX-style SBOM JSON of the
modules, cross-references an embedded CISA-KEV-like list for known-vulnerable
module names, and emits an audit report. CHIPSEC/flashrom dump scripts are
stubbed as documented integration points.

Educational / authorized use only. See README legal section.

Usage:
    python3 firmware_audit.py     # run the offline self-test demo (exit 0)
"""

import hashlib
import json
import os
import struct
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# UEFI volume / DXE parsing helpers (byte-level, struct-based)
# ---------------------------------------------------------------------------
#
# We build a synthetic "UEFI-volume-ish" byte dump at runtime so the pipeline
# is fully offline. It models: volume header, file header, a handful of DXE
# core / protocol modules, each with a GUID and a trailing signature block.

EFI_FV_SIGNATURE = b"_FVH"


def build_dump(modules):
    """Serialize a synthetic UEFI-volume-ish dump as bytes.

    modules: list of dicts with guid, name, data (bytes), signature (bytes).
    Format:  [EfiFvHeader][ per module: Guid(16) NameLen(2) DataLen(2) Type(2)
                            Name Sig(16) Data ].
    """
    out = bytearray()
    out += EFI_FV_SIGNATURE                       # 4 bytes "volume signature"
    out += struct.pack("<I", 0xFEFF0001)          # fv revision / attributes
    out += struct.pack("<I", 1)                   # number of files
    out += struct.pack("<HHHH", 0, 0, 0, 0)       # checksum/reserved
    for m in modules:
        guid = m["guid"].encode("ascii")          # 16-byte GUID (padded)
        guid = guid[:16].ljust(16, b"\x00")
        name = m["name"].encode("ascii")
        out += guid
        out += struct.pack("<HH", len(name), len(m["data"]))
        out += struct.pack("<H", 0x14)            # EFI_FV_FILETYPE (driver)
        out += name
        out += m["signature"]
        out += m["data"]
    return bytes(out)


class FvParser:
    """Parse an EFI-volume-ish dump into a list of module records."""

    def __init__(self, data):
        self.data = data
        self.offset = 0
        self.modules = []

    def parse(self):
        if not self.data.startswith(EFI_FV_SIGNATURE):
            raise ValueError("not an UEFI volume-ish dump (missing _FVH signature)")
        self.offset = 4
        # (revision attrs, file_count, checksum x4)
        self.offset += 4 + 4 + 8
        while self.offset < len(self.data):
            guid = self.data[self.offset:self.offset + 16].rstrip(b"\x00").decode("ascii", "replace")
            self.offset += 16
            name_len, data_len = struct.unpack("<HH", self.data[self.offset:self.offset + 4])
            self.offset += 4
            ftype = struct.unpack("<H", self.data[self.offset:self.offset + 2])[0]
            self.offset += 2
            name = self.data[self.offset:self.offset + name_len].decode("ascii", "replace")
            self.offset += name_len
            sig = self.data[self.offset:self.offset + 16].hex()
            self.offset += 16
            data = self.data[self.offset:self.offset + data_len]
            self.offset += data_len
            payload = name.encode("ascii") + data + bytes.fromhex(sig)
            self.modules.append({
                "guid": guid,
                "name": name,
                "file_type": ftype,
                "size": len(payload),
                "signature": sig,
                "sha256": hashlib.sha256(payload).hexdigest()[:16],
            })
        return self.modules


# ---------------------------------------------------------------------------
# Signature / checksum verification table (embedded, simple)
# ---------------------------------------------------------------------------

# known-good -> digest of each module's expected signature (first 8 hex chars)
SIGNATURE_TABLE = {
    "DxeCore.efi":             "a1b2c3d4",
    "PcdDxe.efi":              "55aa0001",
    "SmbiosDxe.efi":           "0badf00d",
    "AcpiTableDxe.efi":        "deadbeef",
    "CapsuleRuntimeDxe.efi":   "c0ffee00",
    "GraphicsConsoleDxe.efi":  "12345678",
}

# dbx (revocation list) — GUIDs / names of revoked-but-allowed external modules
DBX_NAMES = {
    "CapsuleRuntimeDxe.efi",
    "AfuEfiGuard.efi",
}

# CISA-KEV-like known-vulnerable module names
KEV_MODULES = {
    "SmbiosDxe.efi",     # known LogoFAIL-family vulnerable parser
    "GraphicsConsoleDxe.efi",  # BMP parsing history of CVEs
}


def check_signatures(modules):
    """Return list of (module, ok_bool, reason)."""
    result = []
    for m in modules:
        expected = SIGNATURE_TABLE.get(m["name"])
        actual = m["signature"][:8]
        if expected is None:
            result.append((m, False, "unknown-signature (not in table)"))
        elif actual == expected:
            result.append((m, True, "signature-ok"))
        else:
            result.append((m, False, "signature-mismatch"))
    return result


def validate_dbx(modules):
    """Given the dbx revocation list, flag revoked-but-present modules."""
    revocations = []
    for m in modules:
        if m["name"] in DBX_NAMES:
            revocations.append({
                "module": m["name"],
                "guid": m["guid"],
                "present_in_image": True,
                "action": "revoked-but-present — block/update required",
            })
    return revocations


def cross_reference_kev(modules):
    """Flag module names that appear in the embedded KEV-like list."""
    hits = []
    for m in modules:
        if m["name"] in KEV_MODULES:
            hits.append({
                "module": m["name"],
                "guid": m["guid"],
                "kev": True,
                "recommend": "apply vendor advisory / revoke in dbx",
            })
    return hits


# ---------------------------------------------------------------------------
# SBOM JSON (CycloneDX-ish)
# ---------------------------------------------------------------------------

def build_sbom(modules, sig_results, dbx, kev):
    components = []
    for m in modules:
        sig = next((s for s in sig_results if s[0]["name"] == m["name"]), None)
        components.append({
            "type": "firmware",
            "name": m["name"],
            "bom-ref": f"module-{m['sha256']}",
            "guid": m["guid"],
            "size": m["size"],
            "hashes": [{"alg": "SHA-256", "content": m["sha256"]}],
            "signature": {"valid": sig[1] if sig else False, "reason": sig[2] if sig else "unknown"},
            "revoked": m["name"] in {d["module"] for d in dbx},
            "known_vulnerable": m["name"] in {k["module"] for k in kev},
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:f6-firmware-" + hashlib.sha1(str(len(modules)).encode()).hexdigest()[:8],
        "metadata": {"component": {"type": "firmware", "name": "f6-firmware-audit"}},
        "components": components,
    }


# ---------------------------------------------------------------------------
# Integration points (documented stubs: CHIPSEC / flashrom)
# ---------------------------------------------------------------------------

def chipsed_dump_driver(note="Integration point: pipe `chipsec_util uefi` output here as bytes."):
    """Documented integration point for a CHIPSEC UEFI dump."""
    return note


def flashrom_dump_driver(note="Integration point: feed `flashrom -p internal -r bios.bin` bytes to FvParser."):
    """Documented integration point for a flashrom SPI dump."""
    return note


# ---------------------------------------------------------------------------
# Report + offline demo
# ---------------------------------------------------------------------------

def _make_sample_modules():
    return [
        {"guid": "0E1A-2B3C-DXE0-0001", "name": "DxeCore.efi", "data": b"\x90" * 64, "signature": bytes.fromhex("a1b2c3d4000000000000000000000000")},
        {"guid": "0E1A-2B3C-DXE0-0002", "name": "PcdDxe.efi", "data": b"\x90" * 64, "signature": bytes.fromhex("55aa0001000000000000000000000000")},
        {"guid": "0E1A-2B3C-DXE0-0003", "name": "SmbiosDxe.efi", "data": b"\x90" * 64, "signature": bytes.fromhex("0badf00d000000000000000000000000")},
        {"guid": "0E1A-2B3C-DXE0-0004", "name": "AcpiTableDxe.efi", "data": b"\x90" * 64, "signature": bytes.fromhex("deadbeef000000000000000000000000")},
        {"guid": "0E1A-2B3C-DXE0-0005", "name": "CapsuleRuntimeDxe.efi", "data": b"\x90" * 64, "signature": bytes.fromhex("feedface000000000000000000000000")},
        {"guid": "0E1A-2B3C-DXE0-0006", "name": "GraphicsConsoleDxe.efi", "data": b"\x90" * 64, "signature": bytes.fromhex("deadbeef000000000000000000000000")},
    ]


def main(argv=None):
    print("=" * 60)
    print("  F6 — Firmware audit pipeline (post-LogoFAIL discipline)")
    print("=" * 60)

    modules = _make_sample_modules()
    dump = build_dump(modules)

    print("\n[1/5] Parse UEFI-volume-ish byte dump ...")
    parser = FvParser(dump)
    parsed = parser.parse()
    print(f"  modules parsed: {len(parsed)}")
    for m in parsed:
        print(f"    - {m['name']:<28} GUID={m['guid']:<22} SHA={m['sha256']}")

    print("\n[2/5] Check DXE module signatures ...")
    sig_results = check_signatures(parsed)
    sig_ok = sum(1 for _, ok, _ in sig_results if ok)
    print(f"  valid: {sig_ok}/{len(sig_results)}")
    for m, ok, reason in sig_results:
        print(f"    - {m['name']:<28} {'OK' if ok else 'BAD'}  ({reason})")

    print("\n[3/5] Validate dbx (revocation list) ...")
    dbx = validate_dbx(parsed)
    print(f"  revoked-but-present entries: {len(dbx)}")
    for d in dbx:
        print(f"    ! {d['module']}  ({d['action']})")

    print("\n[4/5] Cross-reference CISA-KEV-like list ...")
    kev = cross_reference_kev(parsed)
    print(f"  known-vulnerable modules: {len(kev)}")
    for k in kev:
        print(f"    ! {k['module']}  -> {k['recommend']}")

    print("\n[5/5] Build SBOM JSON + audit report ...")
    sbom = build_sbom(parsed, sig_results, dbx, kev)
    print(f"  SBOM components: {len(sbom['components'])}")

    print("\n--- Audit Report ---")
    print(f"  total modules        : {len(parsed)}")
    print(f"  valid signatures     : {sig_ok}")
    print(f"  invalid/unknown sigs : {len(sig_results) - sig_ok}")
    print(f"  revoked-but-present  : {len(dbx)}")
    print(f"  known-vulnerable     : {len(kev)}")
    vuln_blocks = len(dbx) + len(kev)
    verdict = "PASS" if (sig_ok == len(parsed) and vuln_blocks == 0) else "ACTION REQUIRED"
    print(f"  verdict              : {verdict}")

    print("\nIntegration points available:")
    print(f"    - {chipsed_dump_driver()}")
    print(f"    - {flashrom_dump_driver()}")

    print("\nDemo complete (exit 0).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
