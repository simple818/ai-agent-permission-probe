---
name: ai-agent-permission-probe
description: Read-only permission boundary audit for AI agents and their runtime environments. Use when the user asks to probe or audit what an AI agent can access on this machine — filesystem read/write/execute, shell execution, network egress, environment-variable presence, credential-file presence (existence only), system information, GUI/browser resources, and macOS security posture; when assessing agent sandbox or least-privilege boundaries before deploying agents; or when producing a permission matrix / security audit report for review or compliance. Never modifies system state and never reads secret contents.
---

# AI Agent Permission Probe

Audit what an AI agent running as the current user can actually do on this host, and turn the findings into a permission matrix with risk ratings and hardening recommendations.

## 1. Purpose

This skill answers one question: **what is the blast radius of an AI agent on this machine?** It probes the runtime environment (filesystem access, shell capability, network egress, credentials reachability, system information, GUI/browser resources, security posture) and produces a structured, evidence-backed report. It is a defensive security-assessment tool: it does not exploit, escalate, or modify anything.

## 2. Safety contract (non-negotiable)

- **Read-only.** The probe never writes outside its own report directory, except for a disposable tempfile used to truthfully verify writability (created and removed immediately).
- **No secret contents.** Environment variable *values*, private key bodies, and credential file *contents* are never read, printed, or written to the report. Only existence and names are reported.
- **No privilege escalation.** `sudo` is only queried with `-n -l` (list, never prompts, never executes anything as root).
- **No exploitation.** Network checks are plain TCP connect attempts with short timeouts; no payloads are sent.
- The probe runs as the *current user* — it reports the permissions of the account the agent runs under, nothing more.

## 3. When to use / when not to use

**Use when:**
- The user asks to probe/audit what an AI agent can access on this computer (files, shell, network, credentials, GUI).
- Assessing agent sandbox or least-privilege boundaries before deploying an agent.
- Producing a permission matrix / security posture report for review, compliance, or GTV-style contribution documentation.
- Investigating a "what could a compromised agent do here?" question.

**Do NOT use when:**
- The user wants to *break out* of a sandbox, escalate privileges, or bypass security controls — that is out of scope and will be refused.
- The user asks to read actual secrets (passwords, keys, tokens) — refuse; the audit only reports existence.

## 4. Workflow

### Step 1 — Verify the environment

- Confirm Python 3.9+ is available: `python3 --version`.
- macOS is the primary target (macOS 12+ recommended). Linux works for the core checks; GUI/security checks degrade gracefully.

### Step 2 — Run the probe

```bash
python3 scripts/probe_permissions.py --output-dir ./probe-report
```

Flags:
- `--output-dir DIR` — where `probe_report.json` / `probe_report.md` / `probe_report.html` are written (default `./probe-report`).
- `--json` / `--md` / `--html` — select a single output format (default: all three).
- `--no-network` — skip outbound TCP and DNS checks (use on air-gapped or sensitive networks).

Run it in a directory where the agent is allowed to write the report. Never point the output into a system directory.

### Step 3 — Read the reports

- `probe_report.json` — structured findings: `meta`, `risk_summary`, `checks[]`, `recommendations[]`, `fixes[]`.
- `probe_report.md` — human-readable permission matrix + findings + hardening recommendations.
- `probe_report.html` — self-contained visual report: EN/中文 switchable, risk filter, keyword search, clickable `?` term explanations (what / risk / how to fix), and a fix center where each hardening item can be copied or handed to an agent.

### Step 4 — Synthesize

Produce a summary for the user covering:
1. **Permission matrix** — the categories the probe covers and the headline status of each.
2. **High/medium findings** — each with evidence and why it matters.
3. **Hardening recommendations** — prioritized, mapped to the findings.
4. **Open questions / limits** — what could not be checked and why.

Present the full matrix in the Markdown report; in the chat, give the top findings and recommendations, not all 68 rows.

### Step 5 — Never act on findings without approval

The probe is diagnostic. Do **not** chmod, delete, install, reconfigure, or change the system based on findings unless the user explicitly asks — and then only with their confirmation.

**Optional fixes (only if the user asks to harden the machine):** `scripts/apply_fixes.py` applies fixes non-destructively — it never changes anything unless `--apply` is passed (`--fix <id>` previews the planned changes), backs up any modified config file (`<file>.bak.<timestamp>`), and skips admin-required actions for normal users with a `sudo` hint. If the user does not ask for fixes, stop after Step 4.

## 5. Probe dimensions

| # | Category | What is checked |
|---|----------|-----------------|
| 1 | Identity | user/uid/gid, groups, HOME/shell, sudo (`-n -l`, never prompts), umask |
| 2 | Filesystem | R/W/X access to user, system, project and sensitive dirs; other users' home dirs; verified write tests; sticky-bit awareness |
| 3 | Shell | shell execution, available tools, PATH hygiene (user-writable / current-dir entries), homebrew |
| 4 | Network | proxy env vars, DNS resolution, outbound TCP egress, local listening sockets, default route |
| 5 | Credentials | sensitive env var *presence*, credential file *presence* (paths and entry names only) |
| 6 | System | platform, macOS version, CPU/memory, uptime, disk, installed apps, process visibility |
| 7 | GUI (macOS) | clipboard (`pbpaste`), browser profile existence (Chrome/Safari/Firefox) |
| 8 | Security posture (macOS) | SIP, Gatekeeper, FileVault |

## 6. Output schema (JSON)

```json
{
  "meta": { "tool": "...", "version": "...", "generated_at": "...", "host": "...",
            "platform": "...", "user": "...", "python": "...", "network_checks": "..." },
  "risk_summary": { "high": 0, "medium": 0, "low": 0, "info": 0 },
  "checks": [
    { "category": "filesystem", "check": "access::tmp (/tmp)", "status": "granted",
      "evidence": "exists=True R=True W=True X=True", "risk": "low",
      "recommendation": "..." }
  ],
  "recommendations": ["..."],
  "fixes": [
    { "id": "fix-path", "title_zh": "...", "title_en": "...", "detail_zh": "...",
      "detail_en": "...", "commands": ["..."], "needs_sudo": false }
  ]
}
```

`status` ∈ `granted | denied | partial | unknown | na`. `risk` ∈ `high | medium | low | info`.

## 7. Risk rubric

- **high** — writable non-sticky system directories, passwordless sudo, user-writable PATH entries, SIP disabled.
- **medium** — sensitive dirs (`.ssh`, `.aws`, …) reachable, other users' home dirs readable, listening sockets, secret env vars present, credential files present, browser profiles present, clipboard readable, FileVault/Gatekeeper off.
- **low** — sticky world-writable dirs (e.g. `/tmp`), clean PATH, no sudo.
- **info** — identity, versions, resource counts, context rows.

## 8. Hardening recommendations (map from findings)

1. Run agents under a dedicated least-privilege account; never grant passwordless sudo.
2. Restrict filesystem scope to the agent's own workspace.
3. Keep secrets out of reach: no credential files, no secret env vars, no browser/keychain access.
4. Allowlist outbound destinations; disable unneeded egress.
5. Keep SIP, Gatekeeper, FileVault enabled and the OS patched.
6. Set a restrictive umask; keep PATH free of user-writable/current-dir entries.
7. Review local listening services; close unneeded ports.
8. Re-run the probe after environment changes; keep reports as part of the security review.

## 9. Troubleshooting & pitfalls

- `os.access` can return `True` even when macOS TCC denies real access; the script's tempfile write-test is the more truthful signal. When the two disagree, report the discrepancy.
- `sudo -n -l` exit codes: `0` = listed (check for `NOPASSWD`), `1` = not permitted, other = password required/unavailable. `-n` guarantees it never prompts.
- `pbpaste` returning empty may mean an empty clipboard *or* a TCC denial — treat "empty" as inconclusive.
- Corporate proxies / firewalls cause TCP timeouts; use `--no-network` and note the limitation.
- `lsof` may be restricted; the script falls back to `netstat -an`.
- `csrutil`/`spctl`/`fdesetup` live outside a standard user PATH (`/usr/bin`, `/usr/sbin`); the script calls them by absolute path.
- Reports contain local host/user info — keep `probe-report/` out of version control (it is gitignored in this repo).

See [`docs/pitfalls.md`](docs/pitfalls.md) for the full pitfall write-up.

## 10. Related work & references

- OWASP — LLM AI Security & Governance Guide (agent security): https://owasp.org/www-project-ai-security-and-governance-guide/
- OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework
- MITRE ATLAS (adversarial threat landscape for AI systems): https://atlas.mitre.org/
- Apple Platform Security (TCC, SIP): https://support.apple.com/guide/security/welcome/web

These are referenced for context and best-practice alignment; this skill is an original implementation and shares no code with them.
