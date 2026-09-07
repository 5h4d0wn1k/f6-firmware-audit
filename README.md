# F6 — Firmware / Image Audit

A deterministic, offline, standard-library-only auditor that extracts ASCII
strings, config artifacts, file paths, and dangerous-function references from
firmware-image byte buffers, flags embedded secrets, backdoored paths, and
dangerous functions, and rolls everything into a risk score and report.

## Overview

- **Format sniffing** — identifies `ELF`, `PE`, `PNG`, `U-Boot`, and raw
  `.bin/.img/.fw` blobs; scanning is format-agnostic (string extraction over the
  byte buffer).
- **String extraction** — printable-ASCII runs with min length (configurable).
- **Secrets** — API keys, passwords, AWS access keys (documented example only),
  private-key blocks, DB credentials.
- **Backdoor paths** — alternate-shell ports (`sshd -p`, `netcat -e`),
  temp-planted payload paths (`/tmp/.r.sh`), trojan services, `eval(base64)`,
  iptables rule flushes.
- **Dangerous functions** — `strcpy`/`strcat`/`sprintf`/`gets`,
  `system`/`popen`/`exec*`/`dlopen`.
- **Config-path extraction** — `/etc`-style paths and `.conf/.cfg/.json`
  artifacts surfaced as evidence.
- **Risk score** — weighted per-kind severity rollup (0 = clean).
- Exit codes: `0` successful run, `1` findings with `--strict` (gate mode),
  `2` config error. The default demo run always exits `0`. Reports to `reports/`
  (Markdown or JSON), gitignored.

## CLI

```bash
python3 firmware/firmware_audit.py --help
python3 firmware/firmware_audit.py
python3 firmware/firmware_audit.py --image bios.bin boot0.img --report reports/r.md
python3 firmware/firmware_audit.py --image router.dump --report reports/r.json
```

Config lives in `config.json` (`min_string_len`). Scans synthetic fixture bytes
or files you supply; nothing is fetched or decompressed externally.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## IMPORTANT: Read before use.

Provided **exclusively** for authorized security research, academic study, and
audit of firmware you own or are authorized to assess. Use without explicit
written authorization is illegal and unethical.

### Authorization Requirements

You MUST have explicit written permission before dumping or auditing a device's
firmware. Dumping firmware from hardware you do not own may violate computer
fraud laws and void hardware warranties. Use only on devices you own or have
written authorization to assess.

### Legal Framework

Unauthorized access to or interference with computer systems is governed by the
**Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive
on Attacks Against Information Systems** (2013/40/EU), and equivalent
legislation in other jurisdictions. **DMCA anti-circumvention** rules may also
restrict firmware extraction, and dumping firmware may void warranties.

### Acceptable Use

- Auditing your own devices and platforms
- Authorized supply-chain and firmware security assessments
- Academic research in controlled lab environments
- Security education and training (fixtures use doc.example.com and RFC 5737
  addresses only)

### Prohibited Use

- Dumping or modifying firmware you do not own without authorization
- Bypassing license or DRM protections
- Using recovered secrets from firmware for unauthorized purposes
- Any activity that violates applicable laws or regulations

### No Warranty

This software is provided "as is" without warranty of any kind. The authors
assume no liability for damages arising from use or misuse of this tool.

### Responsible Disclosure

If you discover firmware vulnerabilities using this tool, follow coordinated
disclosure: report to the vendor/owner privately, allow reasonable time for
remediation, and do not exploit beyond proof of concept.

## Live Lab Test Plan

1. **Demo run** — `python3 firmware/firmware_audit.py` scans the synthetic
   `router.bin` fixture, prints findings, writes the report, and exits `0`.
2. **Gate mode** — `--strict` exits `1` because the fixture carries risk.
2. **Secret coverage** — `test_secrets_found` asserts credential + password
   findings; `test_aws_key_example_found` covers the documented example key.
3. **Backdoor coverage** — `test_backdoor_found` asserts
   `alternate-shell-port`, `netcat-exec`, `temp-payload-path`.
4. **Dangerous-function coverage** — `test_dangerous_functions_found` asserts
   `memory-unsafe` and `process-exec`.
5. **Clean-image base case** — `test_clean_image_zero_risk` asserts a benign
   buffer scores 0 (no false positives).
6. **Real file input** — `--image evil.bin` (a temp file) is audited
   end-to-end (`test_image_file_input`).
7. **Offline guarantee** — stdlib only, no network, deterministic fixtures.

## Metrics

| Metric | Definition |
|--------|-----------|
| Image format | sniffed `elf`/`pe`/`png`/`uboot`/`raw`/`unknown` |
| Extracted strings | printable runs ≥ `min_string_len` |
| Findings | classified per kind (secret / backdoor / dangerous-fn) |
| Config paths | `/`-rooted paths with config-ish names |
| Risk score | weighted per-kind rollup (0 = clean) |
| Exit codes | 0 successful demo, 1 findings in --strict mode, 2 config error |

Verified offline: fixture `router.bin` → 9 classified findings, risk score 32,
5 config paths surfaced; a benign buffer scores 0.

## License

MIT License