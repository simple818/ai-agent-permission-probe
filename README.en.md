# ai-agent-permission-probe

**AI Agent Permission Boundary Probe (read-only audit)** — probes what an AI agent can actually access on the current machine and produces an evidence-backed permission matrix with risk ratings, hardening recommendations, and an optional fix center.

This repository is one iteration of an information-security open-source contribution program, focused on **AI agent security**: a read-only, compliant, traceable way to answer "what is this agent's blast radius on this machine?" It ships as a bilingual Skill (loadable English `SKILL.md` + Chinese `SKILL.zh-CN.md`) plus two scripts.

## Features

- **Read-only by design**: never modifies system state, never escalates privileges, sends no network payloads. The only writes are the report directory and one disposable tempfile (created and removed immediately).
- **8 permission surfaces**: identity & sudo, filesystem R/W/X, shell & tools, network egress, credential reachability (existence only), system information, GUI/browser resources, macOS security posture (SIP / Gatekeeper / FileVault).
- **Three-format reports**: JSON (structured, machine-readable) + Markdown (permission matrix, human-readable) + HTML (self-contained visual audit report, EN/中文 switchable, risk filter, keyword search).
- **Clickable term explanations**: a `?` button next to each check expands "what it is / why it matters / how to fix" — built for non-experts.
- **Optional fix center**: the HTML report lists 8 hardening items with commands you can copy, or hand to an agent; the separate `apply_fixes.py` is preview-first, backs up configs before changing them, and never applies admin actions without sudo.
- **Truthful writability checks**: a tempfile test instead of relying on permission bits alone, avoiding TCC/ACL false positives.
- **Risk ratings & hardening advice**: every finding carries a high / medium / low / info rating and a matching recommendation.
- **Zero third-party dependencies**: Python standard library only, Python 3.9+.

## Layout

```
ai-agent-permission-probe/
├── SKILL.md                  # Skill (English, loadable)
├── SKILL.zh-CN.md            # Skill (Chinese)
├── scripts/
│   ├── probe_permissions.py  # read-only probe (macOS-first, degrades cross-platform)
│   └── apply_fixes.py        # optional hardening script (preview-first, --apply to change, backups configs)
├── docs/
│   ├── features.md           # feature description (Chinese)
│   ├── requirements.md       # environment requirements (Chinese)
│   ├── tutorial.md           # run tutorial (Chinese)
│   ├── pitfalls.md           # pitfalls write-up (Chinese)
│   └── disclaimer.md         # risk statement & disclaimer (Chinese)
├── index.html                # bilingual project intro page
├── README.md                 # readme (Chinese)
├── README.en.md              # this file (English)
├── LICENSE                   # MIT
└── .gitignore
```

## Quick start

```bash
# 1. enter the project
cd ai-agent-permission-probe

# 2. run directly — no dependencies to install
python3 scripts/probe_permissions.py --output-dir ./probe-report

# 3. read the reports
open probe-report/probe_report.html   # visual report (EN/中文, filter, search, fix center)
open probe-report/probe_report.md     # permission matrix
```

Options:

| Option | Description |
| --- | --- |
| `--output-dir DIR` | report directory (default `./probe-report`) |
| `--json` / `--md` / `--html` | single output format (default: all three) |
| `--no-network` | skip outbound TCP and DNS checks (air-gapped networks) |

## Optional fixes

```bash
python3 scripts/apply_fixes.py --list                 # list the 8 available fixes
python3 scripts/apply_fixes.py --fix fix-path          # preview what would change (no changes made)
python3 scripts/apply_fixes.py --fix fix-path --apply  # apply for real (configs are backed up first)
```

Fixes are optional and preview-first. Admin-required fixes (e.g. `/Applications`, `/usr/local`) are detected and skipped for normal users, with a `sudo` hint. The HTML report's fix center gives every item a 〔copy command〕/〔hand to agent〕action, so you can fix from the report without touching the CLI.

## Output

- `probe_report.json`: `meta` (environment & timestamp), `risk_summary` (risk counts), `checks[]` (68 checks with status / evidence / risk / recommendation), `recommendations[]`, `fixes[]` (8 optional fix items).
- `probe_report.md`: risk summary table + permission matrix + high/medium findings + hardening recommendations.
- `probe_report.html`: self-contained visual audit report — EN/中文 switchable, risk filter, keyword search, clickable `?` term explanations, and the fix center at the bottom.
- Reports contain local hostname and username — **do not commit them** to a public repo (`probe-report/` is gitignored).
- **Each run produces a fresh report (UTC timestamped)** — archive multiple runs by date for before/after hardening comparison and audit trails.

## Compliance & positioning

- Defensive security only: audit, detection, assessment. No attack, exploitation, or brute-force content.
- The probe is a read-only audit: it never reads secret contents, never escalates, never modifies; output is used solely for permission assessment and hardening.
- Read [docs/disclaimer.md](docs/disclaimer.md) before use.

## References

Background alignment: OWASP AI Security & Governance Guide, OWASP Top 10 for LLM Applications, NIST AI RMF, MITRE ATLAS, Apple Platform Security. This implementation is original and shares no code with those references.

## License

[MIT](LICENSE) © 2026
