> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# F6 — Firmware Security Auditor

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/f6-firmware-audit)
![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/f6-firmware-audit)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/f6-firmware-audit)

Deterministic, offline **embedded firmware security auditor** — extracts strings, config paths, embedded secrets, and dangerous-function references from firmware-image byte buffers, flags backdoor indicators, and rolls everything into a weighted risk score and report.

## Why

IoT and embedded devices ship with firmware image files that are rarely reviewed for **unsafe components**: hardcoded credentials, alternate-shell backdoors, and memory-unsafe C functions. F6 automates the triage pass — format sniffing (`ELF`, `PE`, `PNG`, `U-Boot`, raw `.bin/.img/.fw`), printable-ASCII string extraction, secret detection (API keys, passwords, private-key blocks, DB credentials), backdoor-path hunting (`sshd -p`, `netcat -e`, `/tmp` payloads, `iptables` flushes), and dangerous-function flags (`strcpy`/`system`/`popen`/`dlopen`). Built for **authorized firmware security assessment, supply-chain review, and academic study** on devices you own — fully offline, standard-library-only, deterministic.

## Features

- **Format sniffing** — identifies `ELF`, `PE`, `PNG`, `U-Boot`, raw blobs; scanning is format-agnostic.
- **String extraction** — printable-ASCII runs with configurable minimum length.
- **Secret detection** — API keys, passwords, AWS access-key examples, private-key blocks, DB credentials.
- **Backdoor paths** — alternate-shell ports, temp-planted payload paths, trojan services, `eval(base64)`, iptables rule flushes.
- **Dangerous functions** — `strcpy`/`strcat`/`sprintf`/`gets`, `system`/`popen`/`exec*`/`dlopen`.
- **Config-path extraction** — `/etc`-style paths and `.conf/.cfg/.json` artifacts surfaced as evidence.
- **Risk score & gate mode** — weighted per-kind severity rollup; `--strict` exits `1` when risk is present.

## Quickstart

```bash
# Help
python3 firmware/firmware_audit.py --help

# Default demo run (scans the synthetic router.bin fixture, writes report)
python3 firmware/firmware_audit.py

# Audit files you supply, JSON report
python3 firmware/firmware_audit.py --image bios.bin boot0.img --report reports/r.json

# Gate mode
python3 firmware/firmware_audit.py --image router.dump --strict
```

Config lives in [`config.json`](config.json) (`min_string_len`). Reports go to `reports/` (Markdown or JSON, gitignored).

```bash
# Run the offline test suite (18 tests)
python3 -m unittest discover -s tests -v
```

## Project structure

```
f6-firmware-audit/
├── firmware/              # firmware_audit.py — the auditor (stdlib only)
├── tests/                 # unittest suite (18 tests)
├── config.json            # min_string_len etc.
└── ETHICS.md, SCOPE.md    # authorized-use rules
```

## Documentation

- [ETHICS.md](ETHICS.md) — authorized-use policy
- [SCOPE.md](SCOPE.md) — assessment scope
- [SECURITY.md](SECURITY.md) — security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Audit only firmware you own or hold written authorization for.

## License

MIT. See [LICENSE](LICENSE).