# F6 — Firmware audit pipeline (post-LogoFAIL discipline)

A pure-Python UEFI/firmware audit pipeline that parses volume dumps, checks DXE module signatures, validates revocation lists, builds an SBOM, and cross-references known-vulnerable modules.

## Overview

- **UEFI-volume-ish parser**: Parses embedded byte dumps (volume headers + DXE module list with GUID/name)
- **Module signature checking**: Verifies DXE module signatures against a simple signature/checksum table
- **dbx revocation validation**: Validates a revocation list and flags revoked-but-present entries
- **SBOM (CycloneDX-ish)**: Builds a software bill of materials for the parsed modules
- **CISA-KEV-like cross-reference**: Flags module names matching an embedded known-vulnerable list
- **Post-LogoFAIL discipline**: Explicitly treats image-parsing drivers (fonts/BMP/PNG) as high-risk audit surfaces
- **Integration points**: CHIPSEC/flashrom dump scripts are stubbed as documented integration points

## Features

- **`FvParser`**: struct-based parsing of volume headers and DXE modules
- **Signature table**: known-good digest table with mismatch + unknown detection
- **dbx validation**: flags revoked modules still present in the image
- **SBOM generation**: CycloneDX 1.5 with per-module hashes, signature validity, revocation, and KEV status
- **Audit report**: pass/action-required verdict rollup
- **Fully offline**: synthetic byte dump generated at runtime

## Installation

```bash
# No third-party dependencies. Python 3.8+ standard library only.
```

## Usage

```python
from firmware_audit import FvParser, check_signatures, validate_dbx, cross_reference_kev, build_sbom

parsed = FvParser(dump_bytes).parse()          # feed real flashrom/chipsec bytes here
sig_results = check_signatures(parsed)
dbx = validate_dbx(parsed)
kev = cross_reference_kev(parsed)
sbom = build_sbom(parsed, sig_results, dbx, kev)
```

### Integration points

- **CHIPSEC**: pipe `chipsec_util uefi` output bytes into `FvParser`
- **flashrom**: feed `flashrom -p internal -r bios.bin` bytes into `FvParser`

### Running the Demo

```bash
python3 firmware/firmware_audit.py
```

## Example Output

```
============================================================
  F6 — Firmware audit pipeline (post-LogoFAIL discipline)
============================================================

[1/5] Parse UEFI-volume-ish byte dump ...
  modules parsed: 6
[2/5] Check DXE module signatures ...
  valid: 5/6
[3/5] Validate dbx (revocation list) ...
  revoked-but-present entries: 1
[4/5] Cross-reference CISA-KEV-like list ...
  ! SmbiosDxe.efi  -> apply vendor advisory / revoke in dbx
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission before dumping or auditing a device's firmware
- Dumping firmware from hardware you do not own may violate computer fraud laws and hardware warranties
- This tool should ONLY be used on devices you own or have written authorization to assess

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **DMCA / Anti-circumvention**: Bypassing access controls on firmware may be prohibited
- **Warranty / Terms of Service**: Dumping firmware may void warranties or breach device terms
- **International Law**: Firmware and hardware tampering laws differ across jurisdictions

### Acceptable Use
- Auditing your own devices and platforms
- Authorized supply-chain and firmware security assessments
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Dumping or modifying firmware you do not own without authorization
- Bypassing license or DRM protections
- Using firmware dumps to extract secrets or keys for unauthorized purposes
- Any activity that violates applicable laws or regulations

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover firmware vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
