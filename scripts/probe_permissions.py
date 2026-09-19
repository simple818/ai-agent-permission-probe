#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_permissions.py — AI Agent Permission Probe (read-only)

Audits what an AI agent running as the current user can access on this host:
filesystem read/write/execute, shell and command availability, network egress,
environment-variable presence, credential-file presence (names only), system
information, GUI/browser resource reachability, and macOS security posture.

SAFETY CONTRACT (non-negotiable)
- Strictly read-only. The only writes are the report files under --output-dir and
  a disposable tempfile used to truthfully verify writability (removed at once).
- Never reads or prints the CONTENT of secrets (env var values, private keys,
  credentials). Only existence and names are reported.
- No privilege escalation. `sudo -n -l` is invoked with -n so it can never prompt.
- Network checks are plain TCP connect attempts with a short timeout; no payload
  is sent and nothing is exfiltrated.

Usage:
    python3 probe_permissions.py [--output-dir DIR] [--json] [--md] [--html] [--no-network]

Exit code: 0 on success (even when findings exist); non-zero on fatal errors.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

TOOL_NAME = "ai-agent-permission-probe"
TOOL_VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def run(cmd: list[str], timeout: int = 5) -> tuple[int, str, str]:
    """Run a read-only command. Returns (returncode, stdout, stderr). Never hangs."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return -1, "", "command not found"
    except subprocess.TimeoutExpired:
        return -2, "", "timeout"
    except Exception as exc:  # noqa: BLE001 - audit tool must not crash
        return -3, "", f"{type(exc).__name__}: {exc}"


def is_available(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def access_matrix(path: str) -> dict:
    """Permission bits for a path (may be unreliable under TCC/ACL; see pitfalls)."""
    p = os.path.expanduser(path)
    return {
        "path": p,
        "exists": os.path.exists(p),
        "read": os.access(p, os.R_OK),
        "write": os.access(p, os.W_OK),
        "execute": os.access(p, os.X_OK),
    }


def write_test(directory: str) -> tuple[bool, str]:
    """Truthfully verify writability with a disposable tempfile (removed at once)."""
    try:
        fd, tmp = tempfile.mkstemp(prefix=".probe_", dir=directory)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write("probe")
            return True, "tempfile created and removed"
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def tcp_test(host: str, port: int, timeout: int = 3) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except socket.timeout:
        return "timeout"
    except OSError as exc:
        return f"blocked/failed ({exc.errno})"
    except Exception as exc:  # noqa: BLE001
        return f"blocked/failed ({type(exc).__name__})"


def finding(category: str, check: str, status: str, evidence: str,
            risk: str, recommendation: str) -> dict:
    return {
        "category": category,
        "check": check,
        "status": status,          # granted | denied | partial | unknown | na
        "evidence": evidence,
        "risk": risk,              # high | medium | low | info
        "recommendation": recommendation,
    }


# --------------------------------------------------------------------------- #
# Check groups
# --------------------------------------------------------------------------- #

def check_identity() -> list[dict]:
    out = []
    user = os.environ.get("USER") or (os.environ.get("USERNAME") or "unknown")
    uid, gid = os.getuid(), os.getgid()
    try:
        groups = os.getgroups()
        groups_txt = ", ".join(str(g) for g in groups)
    except Exception as exc:  # noqa: BLE001
        groups_txt = f"unavailable ({type(exc).__name__})"
    out.append(finding(
        "identity", "current user", "granted", f"user={user} uid={uid} gid={gid}",
        "info", "Reported for context; least-privilege accounts are preferred for agents."))
    out.append(finding(
        "identity", "group membership", "granted", f"groups=[{groups_txt}]",
        "info", "Review group memberships; membership in admin/wheel raises impact."))
    out.append(finding(
        "identity", "HOME / shell", "granted",
        f"HOME={os.environ.get('HOME')} SHELL={os.environ.get('SHELL')}",
        "info", "Context only."))

    # sudo -n never prompts; -l only lists what is allowed.
    rc, sudo_out, sudo_err = run(["sudo", "-n", "-l"], timeout=5)
    if rc == 0 and "NOPASSWD" in sudo_out:
        status, ev, risk = "granted", "passwordless sudo appears configured", "high"
    elif rc == 0:
        status, ev, risk = "granted", "sudo usable (password may be required)", "medium"
    elif rc == 1:
        status, ev, risk = "denied", "sudo not permitted for this user", "low"
    else:
        status, ev, risk = "unknown", f"sudo unavailable or needs password (rc={rc})", "low"
    out.append(finding(
        "identity", "sudo (passwordless check)", status, ev, risk,
        "Remove NOPASSWD entries; agents must not run with privilege escalation."))

    rc, umask_out, _ = run(["sh", "-c", "umask"], timeout=5)
    out.append(finding(
        "identity", "umask", "granted" if rc == 0 else "unknown",
        umask_out or f"rc={rc}", "info",
        "Prefer a restrictive umask (e.g. 077) so new files are not world-readable."))
    return out


def check_filesystem() -> list[dict]:
    out = []
    targets = [
        ("home", os.path.expanduser("~"), "user"),
        ("Desktop", os.path.expanduser("~/Desktop"), "user"),
        ("Documents", os.path.expanduser("~/Documents"), "user"),
        ("Downloads", os.path.expanduser("~/Downloads"), "user"),
        ("Library", os.path.expanduser("~/Library"), "user"),
        ("AppSupport", os.path.expanduser("~/Library/Application Support"), "user"),
        ("config", os.path.expanduser("~/.config"), "user"),
        ("ssh-dir", os.path.expanduser("~/.ssh"), "secret"),
        ("aws-dir", os.path.expanduser("~/.aws"), "secret"),
        ("gnupg-dir", os.path.expanduser("~/.gnupg"), "secret"),
        ("etc", "/etc", "system"),
        ("usr-local", "/usr/local", "system"),
        ("homebrew", "/opt/homebrew", "system"),
        ("applications", "/Applications", "system"),
        ("system-library", "/System/Library", "system"),
        ("private-etc", "/private/etc", "system"),
        ("tmp", "/tmp", "system"),
        ("var", "/var", "system"),
        ("cwd", os.getcwd(), "project"),
        ("script-dir", str(Path(__file__).resolve().parent), "project"),
    ]
    for label, path, kind in targets:
        m = access_matrix(path)
        status = "na"
        if m["exists"]:
            status = "granted" if (m["read"] or m["write"] or m["execute"]) else "denied"
        risk = "info"
        rec = "Context only."
        sticky = False
        if m["exists"]:
            try:
                sticky = bool(os.stat(path).st_mode & stat.S_ISVTX)
            except Exception:  # noqa: BLE001
                sticky = False
        if kind == "system" and m["exists"] and m["write"]:
            if sticky:
                risk, rec = "low", "World-writable with sticky bit (standard for /tmp); normal, but still inspectable by all users."
            else:
                risk, rec = "high", "User-writable system directory: a compromised agent could tamper with system-wide files."
        elif kind == "secret" and m["exists"]:
            risk, rec = "medium", "Sensitive directory is reachable; audit must report existence only, never contents."
        m["label"] = label
        m["kind"] = kind
        m["status"] = status
        m["risk"] = risk
        m["recommendation"] = rec
        out.append(finding(
            "filesystem", f"access::{label} ({path})", status,
            f"exists={m['exists']} R={m['read']} W={m['write']} X={m['execute']}",
            risk, rec))

    # Other users' home directories (reachability only).
    try:
        users_dir = "/Users"
        others = []
        for entry in sorted(os.listdir(users_dir)):
            if entry == os.environ.get("USER"):
                continue
            p = os.path.join(users_dir, entry)
            if os.path.isdir(p):
                others.append(f"{entry}:R={os.access(p, os.R_OK)}")
        out.append(finding(
            "filesystem", "other users' home dirs", "granted" if others else "na",
            "; ".join(others) if others else "none found", "medium",
            "Reading other users' home directories can leak personal data; restrict scope."))
    except Exception as exc:  # noqa: BLE001
        out.append(finding(
            "filesystem", "other users' home dirs", "unknown", f"{type(exc).__name__}: {exc}",
            "info", "Could not enumerate /Users."))

    # Verifiable write tests on key writable-looking targets.
    for label in ["tmp", "home", "cwd"]:
        entry = next((t for t in targets if t[0] == label), None)
        if not entry:
            continue
        path = entry[1]
        if os.path.isdir(path):
            ok, ev = write_test(path)
            out.append(finding(
                "filesystem", f"write-test::{label}", "granted" if ok else "denied",
                ev, "low" if ok else "info",
                "Verified writability (tempfile test); matches os.access where no ACL/TCC is in play."))
    return out


def check_shell() -> list[dict]:
    out = []
    rc, out_txt, err = run(["sh", "-c", "echo probe-ok"], timeout=5)
    out.append(finding(
        "shell", "shell execution", "granted" if (rc == 0 and "probe-ok" in out_txt) else "denied",
        out_txt or err, "high" if rc != 0 else "info",
        "Shell execution is a core agent capability; scope the agent's shell use by policy."))

    tools = ["python3", "pip3", "git", "curl", "brew", "docker", "node", "npm",
             "ruby", "osascript", "netstat", "lsof", "sysctl", "launchctl",
             "ps", "pbpaste", "sqlite3"]
    present = [t for t in tools if is_available(t)]
    missing = [t for t in tools if not is_available(t)]
    out.append(finding(
        "shell", "available tools", "granted", ", ".join(present) or "none",
        "info", f"Not found: {', '.join(missing) or 'none'}. Tool availability widens the agent's capability surface."))

    # PATH hygiene: empty/'.' entries or user-writable PATH dirs are tampering vectors.
    path_entries = [e for e in os.environ.get("PATH", "").split(":") if e]
    risky = []
    for entry in path_entries:
        if entry in ("", "."):
            risky.append(f"{entry or '<empty>'} (current dir in PATH)")
            continue
        if os.path.isdir(entry) and os.access(entry, os.W_OK):
            risky.append(f"{entry} (user-writable)")
    if risky:
        out.append(finding(
            "shell", "PATH hygiene", "partial", "; ".join(risky), "high",
            "A user-writable or current-dir PATH entry lets a compromised agent inject executables."))
    else:
        out.append(finding(
            "shell", "PATH hygiene", "granted", f"{len(path_entries)} entries, none user-writable",
            "low", "Keep PATH free of user-writable and current-directory entries."))

    # Homebrew is a powerful install vector; report its presence.
    if is_available("brew"):
        out.append(finding(
            "shell", "homebrew", "granted", "brew in PATH", "medium",
            "brew can install software and services; restrict or monitor its use."))
    return out


def check_network(no_network: bool) -> list[dict]:
    out = []
    proxy_names = [k for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy") if k in os.environ]
    out.append(finding(
        "network", "proxy env vars", "granted" if proxy_names else "na",
        ", ".join(proxy_names) if proxy_names else "none set", "info",
        "Proxies route agent traffic; verify the proxy is the intended one."))

    rc, dns_out, _ = run(["python3", "-c", "import socket;print(socket.getaddrinfo('github.com',443,proto=socket.IPPROTO_TCP)[0][4][0])"], timeout=5)
    out.append(finding(
        "network", "DNS resolution", "granted" if rc == 0 else "denied",
        dns_out if rc == 0 else f"rc={rc}", "low",
        "DNS egress enables external lookups."))

    if not no_network:
        for host, port in [("1.1.1.1", 443), ("8.8.8.8", 53), ("github.com", 443), ("example.com", 443)]:
            result = tcp_test(host, port)
            out.append(finding(
                "network", f"egress tcp::{host}:{port}", "granted" if result == "open" else "denied",
                result, "info",
                "Outbound connectivity expands exfiltration / update channels; document expected egress."))

    # Local listeners.
    listeners = []
    rc, lsof_out, _ = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=8)
    if rc == 0:
        for line in lsof_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 9:
                listeners.append(parts[8])
    if not listeners:
        rc2, net_out, _ = run(["netstat", "-an"], timeout=8)
        if rc2 == 0:
            listeners = [l.split()[3] for l in net_out.splitlines() if "LISTEN" in l]
    if listeners:
        sample = ", ".join(sorted(set(listeners))[:10])
        out.append(finding(
            "network", "local listening sockets", "granted",
            f"count={len(listeners)} sample=[{sample}]", "medium",
            "Local services may be reachable by the agent; review exposed ports."))
    else:
        out.append(finding(
            "network", "local listening sockets", "unknown",
            "lsof/netstat unavailable or no listeners found", "info",
            "Could not enumerate (may need different privileges)."))

    rc, route_out, _ = run(["netstat", "-rn"], timeout=8)
    has_default = any("default" in line for line in route_out.splitlines())
    out.append(finding(
        "network", "default route", "granted" if has_default else "denied",
        "default route present" if has_default else "no default route", "info",
        "Context for egress analysis."))
    return out


def check_credentials() -> list[dict]:
    out = []
    # Environment variable PRESENCE only — never values.
    sensitive_prefixes = [
        "AWS_", "AZURE_", "GOOGLE_", "GCP_", "GITHUB_", "GITLAB_", "OPENAI_",
        "ANTHROPIC_", "HF_", "MISTRAL_", "DEEPSEEK_", "DATABASE_URL", "REDIS_URL",
        "MONGO_", "PG", "MYSQL", "JWT_", "API_KEY", "TOKEN", "SECRET", "PASSWORD",
        "SSH_AUTH_SOCK",
    ]
    found = [k for k in os.environ if any(k.startswith(p) for p in sensitive_prefixes)]
    out.append(finding(
        "credentials", "sensitive env vars (presence)", "granted" if found else "na",
        ", ".join(sorted(found)) if found else "none found", "medium",
        "Names are reported, never values. Rotate secrets that the agent does not need."))

    # Credential file PRESENCE — names and paths only.
    cred_paths = {
        "ssh": "~/.ssh",
        "aws-credentials": "~/.aws/credentials",
        "aws-config": "~/.aws/config",
        "netrc": "~/.netrc",
        "gitconfig": "~/.gitconfig",
        "gh-hosts": "~/.config/gh/hosts.yml",
        "docker-config": "~/.docker/config.json",
        "gnupg": "~/.gnupg",
        "kube-config": "~/.kube/config",
    }
    for label, path in cred_paths.items():
        p = os.path.expanduser(path)
        exists = os.path.exists(p)
        if exists and label == "ssh":
            try:
                names = [f for f in os.listdir(p) if not f.startswith(".")]
                ev = f"exists; entries=[{', '.join(sorted(names)) or 'none'}]"
            except Exception as exc:  # noqa: BLE001
                ev = f"exists; listing failed ({type(exc).__name__})"
        else:
            ev = "exists" if exists else "not present"
        out.append(finding(
            "credentials", f"file::{label}", "granted" if exists else "na",
            ev, "medium" if exists else "info",
            "Existence only — never read contents. Restrict agent access to needed credentials."))
    return out


def check_system() -> list[dict]:
    out = []
    out.append(finding(
        "system", "platform", "granted",
        f"{platform.system()} {platform.release()} ({platform.machine()})", "info", "Context."))
    try:
        mac_ver = platform.mac_ver()[0]
        if mac_ver:
            out.append(finding("system", "macOS version", "granted", mac_ver, "info", "Context."))
    except Exception:  # noqa: BLE001
        pass
    out.append(finding(
        "system", "python runtime", "granted", f"Python {platform.python_version()}", "info", "Context."))
    out.append(finding(
        "system", "cpu count", "granted", str(os.cpu_count() or "unknown"), "info", "Context."))

    mem = None
    rc, mem_out, _ = run(["sysctl", "-n", "hw.memsize"], timeout=5)
    if rc == 0 and mem_out.isdigit():
        mem = f"{int(mem_out) / (1024**3):.1f} GB"
    out.append(finding(
        "system", "memory", "granted" if mem else "unknown", mem or "unavailable", "info", "Context."))

    boot = None
    rc, boot_out, _ = run(["sysctl", "-n", "kern.boottime"], timeout=5)
    m = re.search(r"sec\s*=\s*(\d+)", boot_out) if rc == 0 else None
    if m:
        uptime_h = (time.time() - int(m.group(1))) / 3600
        boot = f"{uptime_h:.1f} hours"
    out.append(finding(
        "system", "uptime", "granted" if boot else "unknown", boot or "unavailable", "info", "Context."))

    try:
        usage = shutil.disk_usage(str(Path.home()))
        out.append(finding(
            "system", "home disk usage", "granted",
            f"total={usage.total / 1024**3:.0f}GB free={usage.free / 1024**3:.0f}GB",
            "info", "Context."))
    except Exception as exc:  # noqa: BLE001
        out.append(finding("system", "home disk usage", "unknown", str(exc), "info", "Context."))

    for app_dir in ["/Applications", os.path.expanduser("~/Applications")]:
        try:
            apps = [e for e in os.listdir(app_dir) if e.endswith(".app")]
            out.append(finding(
                "system", f"installed apps::{app_dir}", "granted", f"count={len(apps)}",
                "info", "Context."))
        except Exception as exc:  # noqa: BLE001
            out.append(finding(
                "system", f"installed apps::{app_dir}", "denied", f"{type(exc).__name__}",
                "info", "Not readable — itself a permission finding."))

    rc, ps_out, _ = run(["ps", "-axo", "comm="], timeout=8)
    if rc == 0:
        procs = [l.strip() for l in ps_out.splitlines() if l.strip()]
        uniq = sorted({os.path.basename(p) for p in procs})
        out.append(finding(
            "system", "process visibility", "granted",
            f"count={len(procs)} unique_binaries={len(uniq)}", "info",
            "Process listing reveals activity; consider scoping for agents."))
    else:
        out.append(finding("system", "process visibility", "denied", f"rc={rc}", "info", "Context."))
    return out


def check_gui() -> list[dict]:
    out = []
    if platform.system() != "Darwin":
        out.append(finding("gui", "macOS GUI checks", "na", "not macOS", "info", "Skipped."))
        return out

    rc, clip, _ = run(["pbpaste"], timeout=5)
    if rc == 0:
        status = "granted" if clip else "partial"
        ev = "clipboard readable" if clip else "clipboard empty (may still be permission-denied; see pitfalls)"
        out.append(finding("gui", "clipboard (pbpaste)", status, ev, "medium",
                           "Clipboard may hold secrets; agents should not read it without reason."))
    else:
        out.append(finding("gui", "clipboard (pbpaste)", "denied", f"rc={rc}", "low",
                           "Clipboard not readable — TCC may be blocking."))

    browsers = {
        "chrome": "~/Library/Application Support/Google/Chrome",
        "safari": "~/Library/Safari",
        "firefox": "~/Library/Application Support/Firefox",
    }
    for name, path in browsers.items():
        p = os.path.expanduser(path)
        exists = os.path.isdir(p)
        out.append(finding(
            "gui", f"browser profile::{name}", "granted" if exists else "na",
            "present" if exists else "not present", "medium" if exists else "info",
            "Browser profiles can contain sessions/cookies; restrict agent access."))
    return out


def check_security_posture() -> list[dict]:
    out = []
    rc, sip_out, _ = run(["/usr/bin/csrutil", "status"], timeout=8)
    if rc == 0:
        enabled = "enabled" in sip_out.lower()
        out.append(finding(
            "security", "SIP (System Integrity Protection)", "granted" if enabled else "denied",
            sip_out, "low" if enabled else "high",
            "SIP disabled weakens macOS integrity protections."))
    else:
        out.append(finding("security", "SIP", "unknown", f"csrutil unavailable (rc={rc})", "info", "Context."))

    rc, gk_out, _ = run(["/usr/sbin/spctl", "--status"], timeout=8)
    if rc == 0:
        enabled = "assessments enabled" in gk_out.lower()
        out.append(finding(
            "security", "Gatekeeper", "granted" if enabled else "denied",
            gk_out, "low" if enabled else "medium",
            "Gatekeeper disabled allows unsigned software to run."))
    else:
        out.append(finding("security", "Gatekeeper", "unknown", f"rc={rc}", "info", "Context."))

    rc, fv_out, _ = run(["/usr/bin/fdesetup", "status"], timeout=8)
    if rc == 0:
        on = "On" in fv_out
        out.append(finding(
            "security", "FileVault", "granted" if on else "denied",
            fv_out, "low" if on else "medium",
            "FileVault off means data at rest is unprotected."))
    else:
        out.append(finding("security", "FileVault", "unknown", f"rc={rc}", "info", "Context."))
    return out


# --------------------------------------------------------------------------- #
# Risk aggregation & recommendations
# --------------------------------------------------------------------------- #

def aggregate(checks: list[dict]) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for c in checks:
        counts[c["risk"]] = counts.get(c["risk"], 0) + 1
    return counts


def build_recommendations(checks: list[dict]) -> list[str]:
    recs = [
        "Run agents under a dedicated, least-privilege account; never grant passwordless sudo.",
        "Restrict agent filesystem scope to its own workspace and explicitly needed paths.",
        "Keep secret material out of the agent's reach: no credential files, no secret env vars, no browser/keychain access.",
        "Allowlist outbound network destinations; disable egress that the task does not require.",
        "Keep SIP, Gatekeeper and FileVault enabled; keep the OS patched.",
        "Set a restrictive umask and keep PATH free of user-writable or current-directory entries.",
        "Review local listening services and close ports the agent does not need.",
        "Re-run this probe after any environment change and treat the report as part of your security review.",
    ]
    found = [c for c in checks if c["risk"] in ("high", "medium")]
    if not found:
        recs.insert(0, "No high/medium findings — the environment is in good shape; keep monitoring.")
    return recs


def build_fixes() -> list[dict]:
    """Structured, optional fixes shown in the report's fix center.

    Each fix carries a bilingual title/detail and one or more commands.
    `needs_sudo=True` items require administrator rights and are NOT auto-applied
    by apply_fixes.py without --apply; they are always shown to the user first.
    """
    return [
        {
            "id": "fix-path",
            "category": "shell",
            "needs_sudo": False,
            "title_zh": "清理 PATH 中的用户可写目录",
            "title_en": "Clean user-writable directories from PATH",
            "detail_zh": "把 ~/.zshrc 与 ~/.zprofile 中指向用户可写目录的 PATH 条目移除，防止命令被替换（PATH 劫持）。修改前自动备份。",
            "detail_en": "Removes user-writable directories from PATH entries in ~/.zshrc and ~/.zprofile to prevent command hijacking. A backup is created first.",
            "commands": ["python3 scripts/apply_fixes.py --fix fix-path --apply"],
        },
        {
            "id": "fix-umask",
            "category": "identity",
            "needs_sudo": False,
            "title_zh": "收紧默认文件权限（umask 077）",
            "title_en": "Tighten default file permissions (umask 077)",
            "detail_zh": "在 ~/.zshrc 写入 umask 077，让新建文件默认只有你能读写，避免密钥与私人文件被他人读取。",
            "detail_en": "Writes umask 077 into ~/.zshrc so new files default to owner-only, keeping keys and private files safe.",
            "commands": ["python3 scripts/apply_fixes.py --fix fix-umask --apply"],
        },
        {
            "id": "fix-ssh-perm",
            "category": "credentials",
            "needs_sudo": False,
            "title_zh": "收紧 SSH 密钥目录权限",
            "title_en": "Tighten SSH key directory permissions",
            "detail_zh": "把 ~/.ssh 设为 700、内部文件设为 600，防止其他用户读取你的 SSH 密钥。",
            "detail_en": "Sets ~/.ssh to 700 and its files to 600 so other users cannot read your SSH keys.",
            "commands": ["python3 scripts/apply_fixes.py --fix fix-ssh-perm --apply"],
        },
        {
            "id": "fix-local-bin",
            "category": "shell",
            "needs_sudo": False,
            "title_zh": "收紧 ~/.local/bin 目录权限",
            "title_en": "Tighten ~/.local/bin permissions",
            "detail_zh": "该目录当前用户可写且位于 PATH 中；收紧为 755（仅所有者可写），降低被植入伪命令的风险。",
            "detail_en": "This PATH directory is user-writable; tightening it to 755 (owner-writable only) lowers the risk of planted fake commands.",
            "commands": ["python3 scripts/apply_fixes.py --fix fix-local-bin --apply"],
        },
        {
            "id": "fix-apps-perm",
            "category": "filesystem",
            "needs_sudo": True,
            "title_zh": "收紧 /Applications 写权限（需管理员）",
            "title_en": "Tighten /Applications write permission (admin)",
            "detail_zh": "当前用户可写 /Applications，等于可以篡改系统级应用。需要管理员权限执行 chmod 755。",
            "detail_en": "The current user can write into /Applications, enabling app-level tampering. Requires admin (chmod 755).",
            "commands": ["sudo chmod 755 /Applications"],
        },
        {
            "id": "fix-usr-local",
            "category": "filesystem",
            "needs_sudo": True,
            "title_zh": "收紧 /usr/local 写权限（需管理员）",
            "title_en": "Tighten /usr/local write permission (admin)",
            "detail_zh": "/usr/local（含 bin）当前用户可写；收紧为仅管理员可写，需要管理员权限。",
            "detail_en": "/usr/local (incl. bin) is user-writable; restricting it to admin-only requires admin rights.",
            "commands": ["sudo chmod 755 /usr/local", "sudo chmod 755 /usr/local/bin"],
        },
        {
            "id": "fix-py-framework",
            "category": "filesystem",
            "needs_sudo": True,
            "title_zh": "收紧 Python 框架 bin 目录（需管理员）",
            "title_en": "Tighten Python framework bin (admin)",
            "detail_zh": "/Library/Frameworks/Python.framework/.../bin 当前用户可写；改为 root 所有并收紧权限。",
            "detail_en": "The Python framework bin is user-writable; change ownership to root and tighten permissions.",
            "commands": [
                "sudo chown -R root:wheel /Library/Frameworks/Python.framework/Versions/3.12/bin",
                "sudo chmod 755 /Library/Frameworks/Python.framework/Versions/3.12/bin",
            ],
        },
        {
            "id": "fix-filevault",
            "category": "security",
            "needs_sudo": True,
            "title_zh": "开启 FileVault 全盘加密",
            "title_en": "Enable FileVault full-disk encryption",
            "detail_zh": "当前 FileVault 关闭，硬盘数据未加密。可在「系统设置 → 隐私与安全性 → FileVault」开启，或执行 fdesetup。",
            "detail_en": "FileVault is off, so disk data is unencrypted. Enable it in System Settings → Privacy & Security → FileVault, or run fdesetup.",
            "commands": ["sudo fdesetup enable"],
        },
    ]


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def build_report(checks: list[dict], no_network: bool) -> dict:
    counts = aggregate(checks)
    report = {
        "meta": {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "host": platform.node(),
            "platform": f"{platform.system()} {platform.release()}",
            "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
            "python": platform.python_version(),
            "network_checks": "disabled" if no_network else "enabled",
        },
        "risk_summary": counts,
        "checks": checks,
        "recommendations": build_recommendations(checks),
        "fixes": build_fixes(),
    }
    return report


def render_markdown(report: dict) -> str:
    lines = []
    lines.append("# AI Agent Permission Probe Report")
    lines.append("")
    meta = report["meta"]
    lines.append(f"- Tool: {meta['tool']} v{meta['version']}")
    lines.append(f"- Generated (UTC): {meta['generated_at']}")
    lines.append(f"- Host: {meta['host']}")
    lines.append(f"- Platform: {meta['platform']}")
    lines.append(f"- User: {meta['user']}")
    lines.append(f"- Python: {meta['python']}")
    lines.append(f"- Network checks: {meta['network_checks']}")
    lines.append("")
    lines.append("## Risk summary")
    lines.append("")
    lines.append("| Risk | Count |")
    lines.append("| --- | --- |")
    for k in ("high", "medium", "low", "info"):
        lines.append(f"| {k} | {report['risk_summary'].get(k, 0)} |")
    lines.append("")
    lines.append("## Permission matrix")
    lines.append("")
    lines.append("| # | Category | Check | Status | Risk | Evidence |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for i, c in enumerate(report["checks"], start=1):
        ev = c["evidence"].replace("|", "\\|")[:200]
        lines.append(f"| {i} | {c['category']} | {c['check']} | {c['status']} | {c['risk']} | {ev} |")
    lines.append("")
    lines.append("## High / medium findings")
    lines.append("")
    for c in report["checks"]:
        if c["risk"] in ("high", "medium"):
            lines.append(f"- **[{c['risk'].upper()}] {c['category']} / {c['check']}** — {c['evidence']}")
            lines.append(f"  - Recommendation: {c['recommendation']}")
    lines.append("")
    lines.append("## Recommendations")
    lines.append("")
    for r in report["recommendations"]:
        lines.append(f"- {r}")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by ai-agent-permission-probe. Read-only audit — no system state was modified.*")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HTML report rendering (single self-contained file, i18n UI + JS filters)
# --------------------------------------------------------------------------- #

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Agent Permission Probe Report</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='13' fill='none' stroke='%232f9e8f' stroke-width='3'/%3E%3Ccircle cx='16' cy='16' r='6' fill='%232f9e8f'/%3E%3Cpath d='M16 3v6M16 23v6M3 16h6M23 16h6' stroke='%23e0a458' stroke-width='2'/%3E%3C/svg%3E">
<link href="https://miaoda.feishu.cn/fonts/css2?family=Noto+Sans+SC:wght@400;500;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#0f1626;--bg-soft:#151e31;--line:#25304a;--line-soft:#1c2540;--ink:#e8ecf4;--ink-dim:#9aa7c0;--ink-faint:#6b7a97;--teal:#2f9e8f;--teal-bright:#5cc4b5;--amber:#e0a458;--red:#d96a5f;--yellow:#d9b45f;--mono:"JetBrains Mono",ui-monospace,"SF Mono",Menlo,monospace;--sans:"Noto Sans SC",-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:15px;line-height:1.65;-webkit-font-smoothing:antialiased}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px}
.topbar{position:sticky;top:0;z-index:20;background:rgba(15,22,38,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--line-soft)}
.topbar .wrap{display:flex;align-items:center;justify-content:space-between;height:54px}
.brand{font-family:var(--mono);font-size:13px;color:var(--ink-dim)}.brand b{color:var(--teal-bright);font-weight:600}
.lang-switch{display:flex;border:1px solid var(--line);border-radius:6px;overflow:hidden}
.lang-switch button{font-family:var(--mono);font-size:12px;padding:6px 14px;background:transparent;border:0;color:var(--ink-dim);cursor:pointer;min-height:40px}
.lang-switch button.active{background:var(--teal);color:#0b121d;font-weight:600}
.lang-switch button:focus-visible{outline:2px solid var(--teal-bright);outline-offset:-2px}
header{padding:44px 0 26px;border-bottom:1px solid var(--line-soft)}
h1{font-family:var(--mono);font-size:30px;font-weight:600;letter-spacing:-.01em}
h1 .dot{color:var(--amber)}
.sub{margin-top:6px;color:var(--ink-dim);font-size:14px}
.meta-grid{margin-top:22px;display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.meta-item{border:1px solid var(--line);border-radius:6px;background:var(--bg-soft);padding:10px 12px}
.meta-item .k{font-family:var(--mono);font-size:10px;letter-spacing:.1em;color:var(--ink-faint)}
.meta-item .v{font-size:13px;color:var(--ink);margin-top:3px;word-break:break-all}
section{padding:34px 0;border-bottom:1px solid var(--line-soft)}
h2{font-size:20px;font-weight:700;margin-bottom:18px}
.kicker{font-family:var(--mono);font-size:11px;color:var(--amber);letter-spacing:.14em;margin-bottom:6px}
.sum-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.sum-card{border:1px solid var(--line);border-radius:8px;background:var(--bg-soft);padding:16px}
.sum-card .n{font-family:var(--mono);font-size:34px;font-weight:600;line-height:1.1}
.sum-card .r{font-family:var(--mono);font-size:12px;margin-top:6px;display:flex;align-items:center;gap:7px}
.sum-card .d{font-size:12px;color:var(--ink-faint);margin-top:5px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%}
.dot-high{background:var(--red)}.dot-medium{background:var(--yellow)}.dot-low{background:var(--teal)}.dot-info{background:var(--ink-faint)}
.dot-granted{background:var(--teal)}.dot-denied{background:var(--red)}.dot-partial{background:var(--yellow)}.dot-unknown{background:var(--ink-faint)}.dot-na{background:#3a4560}
.controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:14px}
.filters{display:flex;flex-wrap:wrap;gap:6px}
.filters button{font-family:var(--mono);font-size:12px;padding:7px 14px;background:transparent;border:1px solid var(--line);border-radius:5px;color:var(--ink-dim);cursor:pointer;min-height:36px}
.filters button.active{background:var(--teal);border-color:var(--teal);color:#0b121d;font-weight:600}
.filters button:focus-visible{outline:2px solid var(--teal-bright);outline-offset:-2px}
.search{flex:1 1 220px;min-width:180px}
.search input{width:100%;background:#0b1120;border:1px solid var(--line);border-radius:5px;color:var(--ink);font-family:var(--mono);font-size:13px;padding:9px 12px;min-height:38px}
.search input:focus{outline:2px solid var(--teal-bright);outline-offset:-2px}
.count{font-family:var(--mono);font-size:12px;color:var(--ink-faint)}
.tbl-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:13px;min-width:760px}
th{font-family:var(--mono);font-size:11px;color:var(--ink-faint);letter-spacing:.06em;font-weight:600;text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);background:var(--bg-soft)}
td{padding:9px 12px;border-bottom:1px solid var(--line-soft);color:var(--ink-dim);vertical-align:top;word-break:break-word}
tbody tr:last-child td{border-bottom:0}
tr.row-hidden{display:none}
td.num{font-family:var(--mono);color:var(--amber);font-size:12px}
td.check{font-family:var(--mono);font-size:12px;color:var(--ink)}
.risk{font-family:var(--mono);font-size:11px;padding:2px 8px;border-radius:3px;display:inline-block}
.risk-high{color:var(--red);border:1px solid var(--red)}
.risk-medium{color:var(--yellow);border:1px solid var(--yellow)}
.risk-low{color:var(--teal-bright);border:1px solid var(--teal)}
.risk-info{color:var(--ink-faint);border:1px solid var(--line)}
.st{font-size:12px;margin-left:6px}
.term-btn{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;margin-left:7px;border-radius:50%;border:1px solid var(--line);background:transparent;color:var(--ink-faint);font-family:var(--mono);font-size:11px;line-height:1;cursor:pointer;vertical-align:middle;padding:0}
.term-btn:hover{border-color:var(--teal-bright);color:var(--teal-bright)}
.term-btn:focus-visible{outline:2px solid var(--teal-bright);outline-offset:-2px}
.term-row td{background:#121a2c;padding:0!important;border-bottom:1px solid var(--line-soft)}
.term-card{border-left:3px solid var(--amber);background:#1a2236;margin:6px 12px 12px;padding:10px 14px;border-radius:0 6px 6px 0}
.term-card .t{font-size:13px;font-weight:700;color:var(--amber);margin-bottom:4px}
.term-card .d{font-size:12.5px;color:var(--ink-dim);line-height:1.65}
.term-card .h{font-size:12.5px;color:var(--red);margin-top:5px}
.term-card .h b,.term-card .f b{color:var(--ink)}
.term-card .f{font-size:12.5px;color:var(--teal-bright);margin-top:3px}
.finding{border:1px solid var(--line);border-radius:8px;background:var(--bg-soft);padding:14px 16px;margin-bottom:10px}
.finding .fh{display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:13.5px}
.finding .fh .check{font-family:var(--mono);font-size:12px;color:var(--ink)}
.finding .ev{font-size:13px;color:var(--ink-dim);margin-top:7px;word-break:break-word}
.finding .rec{font-size:13px;color:var(--teal-bright);margin-top:5px}
.finding .rec::before{content:"→ ";color:var(--ink-faint)}
.fix-list{list-style:none;margin:0;padding:0}
.fix-item{border:1px solid var(--line);border-radius:8px;background:var(--bg-soft);padding:14px 16px;margin-bottom:10px}
.fix-head{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.fix-id{font-family:var(--mono);font-size:11px;color:var(--ink-faint)}
.fix-badge{font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:3px}
.fix-badge.ok{color:var(--teal-bright);border:1px solid var(--teal)}
.fix-badge.sudo{color:var(--amber);border:1px solid var(--amber)}
.fix-title{font-size:13.5px;font-weight:600;color:var(--ink)}
.fix-detail{font-size:12.5px;color:var(--ink-dim);margin-top:7px;line-height:1.65}
.fix-cmd{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px;align-items:center}
.fix-cmd-label{font-family:var(--mono);font-size:11px;color:var(--ink-faint)}
.fix-cmd code{font-family:var(--mono);font-size:11.5px;background:#0b1120;border:1px solid var(--line);border-radius:4px;padding:4px 8px;color:var(--teal-bright);word-break:break-all}
.fix-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.fix-btn{font-family:var(--mono);font-size:12px;padding:7px 14px;background:transparent;border:1px solid var(--line);border-radius:5px;color:var(--ink-dim);cursor:pointer;min-height:36px}
.fix-btn.copy:hover{border-color:var(--teal-bright);color:var(--teal-bright)}
.fix-btn.agent{background:var(--teal);border-color:var(--teal);color:#0b121d;font-weight:600}
.fix-btn.agent:hover{background:var(--teal-bright)}
.fix-btn:focus-visible{outline:2px solid var(--teal-bright);outline-offset:-2px}
.fix-btn.mini{padding:5px 10px;min-height:30px}
.fix-ask{margin-top:10px;border-top:1px dashed var(--line);padding-top:10px}
.fix-ask.hidden{display:none}
.fix-ask-txt{font-size:12px;color:var(--ink-faint);margin-bottom:5px}
.fix-ask-msg{font-family:var(--mono);font-size:12.5px;color:var(--amber);background:#0b1120;border:1px solid var(--line);border-radius:5px;padding:8px 10px;word-break:break-all;margin-bottom:8px}
.recs-note{margin-top:14px;font-size:12px;color:var(--ink-faint);line-height:1.7}
.empty{padding:22px;color:var(--ink-faint);font-size:14px;border:1px dashed var(--line);border-radius:8px}
footer{padding:26px 0 40px;color:var(--ink-faint);font-size:12px}
footer .mono{font-family:var(--mono)}
@media (max-width:760px){
  .wrap{padding:0 16px}
  h1{font-size:24px}
  .meta-grid{grid-template-columns:repeat(2,1fr)}
  .sum-grid{grid-template-columns:repeat(2,1fr)}
  .lang-switch button{min-height:44px;padding:6px 16px}
  .filters button{min-height:44px}
  .search input{min-height:44px}
  .term-btn{width:24px;height:24px;min-height:24px;font-size:13px}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style>
</head>
<body>

<div class="topbar"><div class="wrap">
  <div class="brand"><b>probe</b>_permissions</div>
  <div class="lang-switch" role="group" aria-label="language">
    <button id="btn-zh" class="active" data-lang="zh">中文</button>
    <button id="btn-en" data-lang="en">EN</button>
  </div>
</div></div>

<header><div class="wrap">
  <h1>probe_report<span class="dot">/</span></h1>
  <p class="sub" data-i18n="subtitle">AI Agent 权限审计报告 · 只读探测结果</p>
  <div class="meta-grid" id="metaGrid"></div>
</div></header>

<section id="summary"><div class="wrap">
  <p class="kicker" data-i18n="kSummary">RISK SUMMARY</p>
  <h2 data-i18n="hSummary">风险摘要</h2>
  <div class="sum-grid" id="sumGrid"></div>
</div></section>

<section id="matrix"><div class="wrap">
  <p class="kicker" data-i18n="kMatrix">PERMISSION MATRIX</p>
  <h2 data-i18n="hMatrix">权限矩阵</h2>
  <div class="controls">
    <div class="filters" id="filters">
      <button data-risk="all" class="active" data-i18n="fAll">全部</button>
      <button data-risk="high" data-i18n="fHigh">high</button>
      <button data-risk="medium" data-i18n="fMedium">medium</button>
      <button data-risk="low" data-i18n="fLow">low</button>
      <button data-risk="info" data-i18n="fInfo">info</button>
    </div>
    <div class="search"><input id="q" type="search" data-i18n-ph="ph" placeholder="搜索 check / 类别 / 证据"></div>
    <span class="count" id="count"></span>
  </div>
  <div class="tbl-wrap">
    <table>
      <colgroup><col style="width:4%"><col style="width:11%"><col style="width:30%"><col style="width:10%"><col style="width:8%"><col style="width:37%"></colgroup>
      <thead><tr>
        <th>#</th><th data-i18n="tCat">类别</th><th data-i18n="tCheck">检查项</th><th data-i18n="tStatus">状态</th><th data-i18n="tRisk">风险</th><th data-i18n="tEvidence">证据</th>
      </tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</div></section>

<section id="findings"><div class="wrap">
  <p class="kicker" data-i18n="kFindings">HIGH / MEDIUM FINDINGS</p>
  <h2 data-i18n="hFindings">高 / 中风险发现</h2>
  <div id="findingsList"></div>
</div></section>

<section id="recommendations"><div class="wrap">
  <p class="kicker" data-i18n="kRecs">处置建议</p>
  <h2 data-i18n="hRecs">加固建议</h2>
  <ul class="fix-list" id="recs"></ul>
  <p class="recs-note" data-i18n="recsNote">加固是可选的：可以〔复制命令〕自己粘贴执行，也可以〔交给 Agent 修复〕让它自动处理；不需要的项跳过即可，不影响报告。</p>
</div></section>

<footer><div class="wrap" style="display:flex;flex-wrap:wrap;gap:6px 20px;justify-content:space-between;width:100%">
  <span class="mono" id="footMeta"></span>
  <span data-i18n="footNote">只读审计 · 未修改任何系统状态</span>
</div></footer>

<script>
var REPORT_DATA = __DATA__;
(function(){
"use strict";
var LANG = "zh";
var I18N = {
  zh:{
    subtitle:"AI Agent 权限审计报告 · 只读探测结果",
    kSummary:"风险概览", hSummary:"风险摘要",
    sumHigh:"高 · 需立即处置", sumMedium:"中 · 建议整改", sumLow:"低 · 常规", sumInfo:"信息 · 上下文",
    kMatrix:"68 项检查", hMatrix:"权限矩阵",
    fAll:"全部", fHigh:"高", fMedium:"中", fLow:"低", fInfo:"信息",
    ph:"搜索检查项 / 类别 / 证据",
    tCat:"类别", tCheck:"检查项", tStatus:"状态", tRisk:"风险", tEvidence:"证据",
    showing:"显示 {a} / {b} 项",
    kFindings:"风险发现", hFindings:"高 / 中风险发现",
    noFindings:"未发现高 / 中风险项",
    kRecs:"处置建议", hRecs:"加固建议",
    recsNote:"加固是可选的：可以〔复制命令〕自己粘贴执行，也可以〔交给 Agent 修复〕让它自动处理；不需要的项跳过即可，不影响报告。",
    copyCmd:"复制命令", fixAgent:"交给 Agent 修复", copied:"已复制", needSudo:"需管理员", autoFix:"可自动修复",
    tellAi:"直接对 AI 说：", copyAsk:"复制这句话", fixPrefix:"帮我执行修复 #",
    footNote:"只读审计 · 未修改任何系统状态"
  },
  en:{
    subtitle:"AI Agent Permission Audit · Read-only probe results",
    kSummary:"RISK SUMMARY", hSummary:"Risk summary",
    sumHigh:"High · act now", sumMedium:"Medium · plan to fix", sumLow:"Low · routine", sumInfo:"Info · context",
    kMatrix:"PERMISSION MATRIX", hMatrix:"Permission matrix",
    fAll:"All", fHigh:"high", fMedium:"medium", fLow:"low", fInfo:"info",
    ph:"search check / category / evidence",
    tCat:"Category", tCheck:"Check", tStatus:"Status", tRisk:"Risk", tEvidence:"Evidence",
    showing:"Showing {a} / {b}",
    kFindings:"HIGH / MEDIUM FINDINGS", hFindings:"High / medium findings",
    noFindings:"No high / medium findings",
    kRecs:"RECOMMENDATIONS", hRecs:"Hardening fixes",
    recsNote:"Fixes are optional: copy the commands to run them yourself, or ask your agent to apply them. Skip any item you don't need.",
    copyCmd:"Copy", fixAgent:"Fix with agent", copied:"Copied", needSudo:"admin", autoFix:"auto",
    tellAi:"Tell your AI assistant: ", copyAsk:"Copy this", fixPrefix:"Please run fix #",
    footNote:"Read-only audit · no system state was modified"
  }
};
var STATUS_ZH = {granted:"已授予", denied:"已拒绝", partial:"部分", unknown:"未知", na:"不适用"};
var CAT_ZH = {identity:"身份", filesystem:"文件系统", shell:"Shell", network:"网络", credentials:"凭据", system:"系统", gui:"GUI", security:"安全基线"};
var RISK_ZH = {high:"高", medium:"中", low:"低", info:"信息"};
var CHECK_RULES = [
  ["sudo (passwordless check)", "sudo（免密检查）"],
  ["current user", "当前用户"],
  ["group membership", "所属组"],
  ["HOME / shell", "HOME / Shell"],
  ["shell execution", "Shell 执行"],
  ["available tools", "可用工具"],
  ["PATH hygiene", "PATH 卫生"],
  ["proxy env vars", "代理环境变量"],
  ["DNS resolution", "DNS 解析"],
  ["egress tcp::", "出站 TCP::"],
  ["local listening sockets", "本地监听端口"],
  ["default route", "默认路由"],
  ["sensitive env vars (presence)", "敏感环境变量（存在性）"],
  ["other users' home dirs", "其他用户家目录"],
  ["macOS version", "macOS 版本"],
  ["python runtime", "Python 运行时"],
  ["cpu count", "CPU 数量"],
  ["home disk usage", "家目录磁盘占用"],
  ["process visibility", "进程可见性"],
  ["clipboard (pbpaste)", "剪贴板（pbpaste）"],
  ["SIP (System Integrity Protection)", "SIP（系统完整性保护）"],
  ["browser profile::", "浏览器配置::"],
  ["write-test::", "写入测试::"],
  ["access::", "访问::"],
  ["file::", "文件::"],
  ["installed apps::", "已装应用::"],
  ["platform", "平台"],
  ["memory", "内存"],
  ["uptime", "运行时长"]
];
var EVIDENCE_RULES = [
  ["System Integrity Protection status: enabled.", "系统完整性保护：已启用。"],
  ["assessments enabled", "已启用评估"],
  ["FileVault is Off.", "FileVault 已关闭。"],
  ["tempfile created and removed", "临时文件已创建并删除"],
  ["sudo not permitted for this user", "当前用户无 sudo 权限"],
  ["passwordless sudo appears configured", "检测到免密 sudo 配置"],
  ["sudo usable (password may be required)", "sudo 可用（可能需要密码）"],
  ["clipboard readable", "剪贴板可读"],
  ["clipboard empty (may still be permission-denied; see pitfalls)", "剪贴板为空（也可能是权限被拒，见踩坑文档）"],
  ["brew in PATH", "brew 在 PATH 中"],
  ["default route present", "存在默认路由"],
  ["no default route", "无默认路由"],
  ["none set", "未设置"],
  ["none found", "未发现"],
  ["not present", "不存在"],
  ["exists=True", "存在=是"],
  ["exists=False", "存在=否"],
  ["exists; ", "存在；"],
  ["exists", "存在"],
  ["R=True", "读=是"],
  ["R=False", "读=否"],
  ["W=True", "写=是"],
  ["W=False", "写=否"],
  ["X=True", "执行=是"],
  ["X=False", "执行=否"],
  ["count=", "数量="],
  ["sample=[", "样例=["],
  ["entries=[", "条目=["],
  ["unique_binaries=", "独立二进制数="],
  ["groups=[", "所属组=["],
  ["user=", "用户="],
  ["(user-writable)", "（用户可写）"],
  ["(current dir in PATH)", "（PATH 中的当前目录）"],
  ["total=", "总="],
  ["free=", "可用="],
  ["not macOS", "非 macOS"],
  ["present", "存在"],
  ["open", "开放"],
  ["timeout", "超时"],
  ["blocked/failed", "被阻止/失败"]
];
var REC_ZH = {
  "Reported for context; least-privilege accounts are preferred for agents.": "仅为上下文报告；Agent 建议使用最小权限账号。",
  "Review group memberships; membership in admin/wheel raises impact.": "复查所属组；admin/wheel 组成员会放大影响。",
  "Context only.": "仅上下文。",
  "Remove NOPASSWD entries; agents must not run with privilege escalation.": "移除 NOPASSWD 配置；Agent 不得提权运行。",
  "Prefer a restrictive umask (e.g. 077) so new files are not world-readable.": "建议收紧 umask（如 077），避免新文件全局可读。",
  "User-writable system directory: a compromised agent could tamper with system-wide files.": "用户可写的系统目录：Agent 被攻破后可篡改系统级文件。",
  "World-writable with sticky bit (standard for /tmp); normal, but still inspectable by all users.": "全局可写且带 sticky 位（/tmp 标准配置）；正常，但所有用户仍可查看。",
  "Sensitive directory is reachable; audit must report existence only, never contents.": "敏感目录可达；审计仅报告存在性，绝不读取内容。",
  "Reading other users' home directories can leak personal data; restrict scope.": "读取其他用户家目录可能泄露个人数据；请限制范围。",
  "Could not enumerate /Users.": "无法枚举 /Users。",
  "Verified writability (tempfile test); matches os.access where no ACL/TCC is in play.": "已用临时文件验证可写性；无 ACL/TCC 时与 os.access 一致。",
  "Shell execution is a core agent capability; scope the agent's shell use by policy.": "Shell 执行是 Agent 核心能力；请按策略限定使用范围。",
  "A user-writable or current-dir PATH entry lets a compromised agent inject executables.": "PATH 中用户可写或当前目录条目可让被攻破的 Agent 注入可执行文件。",
  "Keep PATH free of user-writable and current-directory entries.": "保持 PATH 不含用户可写或当前目录条目。",
  "brew can install software and services; restrict or monitor its use.": "brew 可安装软件与服务；请限制或监控其使用。",
  "Proxies route agent traffic; verify the proxy is the intended one.": "代理会转发 Agent 流量；请确认代理为预期配置。",
  "DNS egress enables external lookups.": "DNS 出网允许外部解析。",
  "Outbound connectivity expands exfiltration / update channels; document expected egress.": "出网能力扩大外传/更新通道；请记录预期出网。",
  "Local services may be reachable by the agent; review exposed ports.": "本地服务可能被 Agent 访问；请复查暴露端口。",
  "Could not enumerate (may need different privileges).": "无法枚举（可能需要更高权限）。",
  "Context for egress analysis.": "出网分析上下文。",
  "Names are reported, never values. Rotate secrets that the agent does not need.": "仅报告名称，绝不读取值；请轮换 Agent 不需要的密钥。",
  "Existence only — never read contents. Restrict agent access to needed credentials.": "仅存在性——绝不读取内容；限制 Agent 访问所需凭据。",
  "Not readable — itself a permission finding.": "不可读——这本身就是一条权限发现。",
  "Process listing reveals activity; consider scoping for agents.": "进程列表可揭示活动；建议对 Agent 限定范围。",
  "Skipped.": "已跳过。",
  "Clipboard may hold secrets; agents should not read it without reason.": "剪贴板可能含密钥；Agent 不应无故读取。",
  "Clipboard not readable — TCC may be blocking.": "剪贴板不可读——可能被 TCC 拦截。",
  "Browser profiles can contain sessions/cookies; restrict agent access.": "浏览器配置可能含会话/Cookie；请限制 Agent 访问。",
  "SIP disabled weakens macOS integrity protections.": "SIP 关闭会削弱 macOS 完整性保护。",
  "Gatekeeper disabled allows unsigned software to run.": "Gatekeeper 关闭允许未签名软件运行。",
  "FileVault off means data at rest is unprotected.": "FileVault 关闭意味着静态数据无保护。",
  "Run agents under a dedicated, least-privilege account; never grant passwordless sudo.": "使用专用最小权限账号运行 Agent；绝不授予免密 sudo。",
  "Restrict agent filesystem scope to its own workspace and explicitly needed paths.": "将 Agent 文件系统范围限制在工作区与明确需要的路径。",
  "Keep secret material out of the agent's reach: no credential files, no secret env vars, no browser/keychain access.": "让密钥远离 Agent：无凭据文件、无敏感环境变量、无浏览器/钥匙串访问。",
  "Allowlist outbound network destinations; disable egress that the task does not require.": "出站目标白名单化；关闭任务不需要的出口。",
  "Keep SIP, Gatekeeper and FileVault enabled; keep the OS patched.": "保持 SIP、Gatekeeper、FileVault 开启，系统及时打补丁。",
  "Set a restrictive umask and keep PATH free of user-writable or current-directory entries.": "设置收紧的 umask；PATH 不含用户可写或当前目录条目。",
  "Review local listening services and close ports the agent does not need.": "复查本地监听服务，关闭 Agent 不需要的端口。",
  "Re-run this probe after any environment change and treat the report as part of your security review.": "环境变更后重跑本探测，报告纳入安全评审。",
  "No high/medium findings — the environment is in good shape; keep monitoring.": "未发现高/中风险项——环境状态良好，请持续监控。"
};
var REC_RULES = [
  ["Not found:", "未找到:"],
  ["Tool availability widens the agent's capability surface.", "工具可用性会扩大 Agent 的能力面。"]
];
function lzCat(s){ return (LANG==="zh" && CAT_ZH[s]) ? CAT_ZH[s] : s; }
function lzRisk(s){ return (LANG==="zh" && RISK_ZH[s]) ? RISK_ZH[s] : s; }
function lzCheck(s){ if(LANG!=="zh") return s; var o=s; CHECK_RULES.forEach(function(p){o=o.split(p[0]).join(p[1]);}); return o; }
function lzEv(s){ if(LANG!=="zh") return s; var o=String(s); EVIDENCE_RULES.forEach(function(p){o=o.split(p[0]).join(p[1]);}); return o; }
function lzRec(s){ if(LANG!=="zh") return s; if(REC_ZH[s]!==undefined) return REC_ZH[s]; var o=s; REC_RULES.forEach(function(p){o=o.split(p[0]).join(p[1]);}); return o; }

var GLOSSARY = {
  "path-hygiene":{name:"PATH 卫生",
    zh:{d:"PATH 是终端找命令时的“目录清单”。所谓“卫生”，就是检查这个清单里有没有用户可写目录、当前目录这类危险条目。",h:"只要有一个用户可写目录在清单里，攻击者就能往里面放一个和常用命令同名的伪命令，你下次敲命令时执行的是它。",f:"把这些目录从 PATH 里移除，或收紧目录权限，只保留可信目录。"},
    en:{d:"PATH is the directory list the shell searches when you type a command. “Hygiene” means checking the list for risky entries such as user-writable directories or the current directory.",h:"If any user-writable directory is on the list, an attacker can drop a fake executable with a common command name there, and your next command silently runs the fake.",f:"Remove such directories from PATH, or tighten their permissions so only trusted entries remain."}},
  "path-hijack":{name:"PATH 劫持",
    zh:{d:"攻击者在 PATH 中某个用户可写目录里放一个与常用命令同名的恶意文件，让 shell 先找到它并执行——这就是“劫持”了你的命令。",h:"你以为在运行真正的 python3、git，实际执行的是攻击者给的代码，等于命令注入。",f:"保持 PATH 干净、不用当前目录、重要命令用绝对路径。"},
    en:{d:"An attacker plants a malicious file with the same name as a common command inside a user-writable PATH directory, so the shell finds and runs it first — your command is “hijacked”.",h:"You think you are running the real python3 or git, but the attacker's code executes instead — command injection.",f:"Keep PATH clean, never include the current directory, and use absolute paths for critical commands."}},
  "user-writable":{name:"用户可写目录",
    zh:{d:"当前用户有权限往里新增、修改、删除文件的目录。正常是你自己的文件夹，但如果出现在 PATH、系统目录等关键位置就危险了。",h:"攻击者（或被攻破的 Agent）可以往里面写文件：放伪命令、篡改脚本、替换配置文件。",f:"关键位置的目录收紧为仅管理员可写；普通目录别放进 PATH。"},
    en:{d:"A directory where the current user can create, modify or delete files. Normal for your own folders, but dangerous when it appears in PATH or in system locations.",h:"An attacker (or a compromised agent) can drop files there: fake commands, tampered scripts, replaced configs.",f:"Restrict key directories to admin-only writes; keep ordinary directories out of PATH."}},
  "system-dir":{name:"系统目录",
    zh:{d:"影响整台电脑的目录，如 /Applications（应用）、/etc 和 /usr/local（系统配置与程序）、/System/Library（系统库）。",h:"如果用户能写系统目录，就能篡改影响所有用户的文件——等于半个管理员权限。",f:"系统目录应只有管理员可写；发现可写立即收紧权限。"},
    en:{d:"Directories that affect the whole machine: /Applications (apps), /etc and /usr/local (config and programs), /System/Library (system libraries).",h:"If a user can write into a system directory, they can tamper with files that affect every user — nearly admin power.",f:"System directories should be admin-writable only; tighten them immediately if found writable."}},
  "sudo":{name:"sudo（管理员执行）",
    zh:{d:"在 macOS/Linux 上用管理员身份执行命令的工具。普通命令前面加 sudo，一般会要求输密码。",h:"谁能用 sudo，谁就能绕过大部分权限限制；Agent 拿到 sudo 等于拿到整台机器。",f:"Agent 一律不给 sudo；管理员操作只留给真人手动做。"},
    en:{d:"The tool that runs a command as administrator on macOS/Linux. Plain commands prefixed with sudo normally ask for your password.",h:"Whoever can use sudo can bypass most permission checks; an agent with sudo effectively owns the machine.",f:"Never grant sudo to agents; keep admin actions for a human to run manually."}},
  "passwordless-sudo":{name:"免密 sudo",
    zh:{d:"配置成不需要输入密码就能用 sudo（通常是 NOPASSWD 规则）。",h:"等于把管理员钥匙挂在门口：任何拿到你终端的进程都能直接提权到管理员。",f:"移除 NOPASSWD 规则；即使保留 sudo 也必须每次要密码。"},
    en:{d:"sudo configured to run without asking for a password (usually a NOPASSWD rule).",h:"It is like leaving the admin key at the door: any process that reaches your terminal can escalate to administrator immediately.",f:"Remove NOPASSWD rules; even where sudo stays, require the password every time."}},
  "umask":{name:"umask（文件默认权限掩码）",
    zh:{d:"决定“新建的文件默认给谁什么权限”的数字。0022 表示新文件=所有者可读写、其他人只读；077 表示新文件只有自己能看。",h:"umask 太松（如 0000），新文件所有人可读可改，密钥和私人文件容易泄露。",f:"设为 077（或至少 022），让新文件默认只有你能访问。"},
    en:{d:"The number that decides default permissions on newly created files. 0022 = owner read/write, others read-only; 077 = only you can access.",h:"A loose umask (e.g. 0000) makes new files readable/writable by everyone, leaking keys and private files.",f:"Set it to 077 (or at least 022) so new files are private by default."}},
  "sticky":{name:"sticky 位（粘滞位）",
    zh:{d:"/tmp 这类共享目录上的特殊标记：目录人人可写，但只有文件所有者（或管理员）能删除/改名别人的文件。",h:"没有 sticky 位时，任何用户都能删掉别人放在共享目录里的临时文件，造成破坏。",f:"系统共享目录应保持 sticky 位；不要随意去掉。"},
    en:{d:"A special flag on shared directories like /tmp: anyone can write, but only the file's owner (or admin) can delete/rename others' files.",h:"Without the sticky bit, any user can delete other people's temporary files in shared directories.",f:"Keep the sticky bit on system shared directories; never remove it casually."}},
  "secret-dir":{name:"敏感目录",
    zh:{d:"存放密钥、证书、云凭据的目录，如 ~/.ssh（SSH 密钥）、~/.aws（云密钥）、~/.gnupg（加密密钥）。",h:"Agent 或恶意程序能进这些目录 = 有机会读走你的私钥和云凭据。",f:"收紧权限（如 700）；审计工具只报“存在”，不读内容。"},
    en:{d:"Directories that hold keys and credentials: ~/.ssh (SSH keys), ~/.aws (cloud keys), ~/.gnupg (encryption keys).",h:"If an agent or malware can reach these directories, it can read your private keys and cloud credentials.",f:"Tighten permissions (e.g. 700); audit tools report existence only, never contents."}},
  "write-test":{name:"写测试",
    zh:{d:"不只看权限位，而是真的创建一个临时文件再删掉，来验证“这个目录到底能不能写”。",h:"只看权限位可能被系统隐私保护（TCC）或特殊权限（ACL）骗到，测不准；写测试结果更可信。",f:"这是检测手段本身，无需处理。"},
    en:{d:"Instead of only reading permission bits, it actually creates a disposable temp file and removes it to verify whether the directory is really writable.",h:"Permission bits alone can be fooled by privacy guards (TCC) or ACLs; a real write test is more trustworthy.",f:"This is a detection method itself; nothing to fix."}},
  "shell":{name:"Shell 执行",
    zh:{d:"能否运行 shell 命令（在终端敲的那些指令）。对 Agent 来说就是它的“手”。",h:"能执行命令 = 能读写文件、联网、启动程序；能力越大，出事时破坏越大。",f:"按任务最小范围授权；用专用低权限账号运行 Agent。"},
    en:{d:"Whether shell commands can be executed — an agent's “hands”.",h:"Command execution means file access, networking and launching programs; more power means more blast radius.",f:"Authorize the minimum scope per task; run agents under a dedicated low-privilege account."}},
  "tools":{name:"可用工具",
    zh:{d:"系统里装了哪些命令行工具（git、curl、brew、node 等）。工具清单越全，Agent 能做的事越多。",h:"例如 curl 可外传数据，brew 可安装任意软件，osascript 可操控系统 UI。",f:"按任务需要裁剪可用工具；不需要的尽量不装或限制调用。"},
    en:{d:"Which command-line tools are installed (git, curl, brew, node, ...). The richer the toolset, the more an agent can do.",h:"curl can exfiltrate data, brew can install arbitrary software, osascript can drive the system UI.",f:"Trim the toolset to what tasks need; avoid or restrict tools you don't use."}},
  "proxy":{name:"代理环境变量",
    zh:{d:"HTTP_PROXY 这类环境变量，告诉程序“网络流量走哪个代理”。公司/科学上网环境常见。",h:"如果代理地址被替换成攻击者的，你的所有流量都会被它看光、改写。",f:"确认代理是你配置的那一个；不用的代理变量删掉。"},
    en:{d:"Environment variables like HTTP_PROXY that tell programs which proxy to route traffic through. Common in corporate or VPN setups.",h:"If the proxy address is swapped to an attacker's server, all your traffic can be watched and modified.",f:"Verify the proxy is the one you configured; delete proxy variables you don't use."}},
  "dns":{name:"DNS 解析",
    zh:{d:"把域名（如 github.com）翻译成 IP 地址的查询。能解析 = 能访问外部网络。",h:"DNS 可解析是出网的第一步，也是数据外传通道的一部分。",f:"在需要隔离的环境里限制 DNS 出口。"},
    en:{d:"The lookup that translates a domain (e.g. github.com) into an IP address. Being able to resolve means external network access.",h:"DNS resolution is the first step of egress and part of any exfiltration channel.",f:"Restrict DNS egress in isolated environments."}},
  "egress":{name:"出网（出站连接）",
    zh:{d:"本机主动向外发起网络连接的能力（例如连 github.com:443）。",h:"出网是数据外传的通道：你的文件、密钥一旦被读走，就可以被发到外部服务器。",f:"按白名单只允许任务需要的目标；隔离环境建议断开出网。"},
    en:{d:"The ability to initiate outbound network connections (e.g. to github.com:443).",h:"Egress is the channel for data exfiltration: files and keys, once read, can be sent to an external server.",f:"Allowlist only the destinations a task needs; consider disabling egress in isolated environments."}},
  "port":{name:"监听端口",
    zh:{d:"本机程序对外“开的门”——其他程序（或网络另一端）可以连进来。例如 8899、本地代理端口。",h:"暴露的端口可被本地恶意进程（甚至局域网/公网，视绑定地址）访问，扩大攻击面。",f:"关闭不需要的服务和端口；需要保留的确认只监听本机地址。"},
    en:{d:"A “door” opened by a local program that other programs (or remote peers) can connect to, e.g. port 8899 or local proxy ports.",h:"Exposed ports can be reached by malicious local processes (and possibly the network, depending on bind address), widening the attack surface.",f:"Close services and ports you don't need; keep the rest bound to localhost only."}},
  "route":{name:"默认路由",
    zh:{d:"本机连接外部网络的“默认出口”配置。没有它就连不出去。",h:"存在默认路由 = 具备出网条件；是数据外传的基础设施。",f:"隔离环境可考虑移除默认路由。"},
    en:{d:"The default gateway configuration for reaching external networks. Without it there is no way out.",h:"A default route means egress is possible — the infrastructure for exfiltration.",f:"Consider removing the default route in isolated environments."}},
  "env-secret":{name:"敏感环境变量",
    zh:{d:"存放密钥的变量，如 AWS_xxx、TOKEN、PASSWORD 等。报告只检查“存不存在”，绝不读取值。",h:"Agent 进程能看到这些变量 = 能读到里面的密钥，等于把云账号钥匙交给了它。",f:"Agent 不需要的密钥变量不要设置；需要的限制到最小范围。"},
    en:{d:"Environment variables that hold secrets, e.g. AWS_*, TOKEN, PASSWORD. The report checks existence only and never reads values.",h:"If an agent process can see these variables, it can read the secrets — handing it the keys to your accounts.",f:"Don't set secret variables the agent doesn't need; minimize what it can see."}},
  "credential":{name:"凭据文件",
    zh:{d:"存放密码、密钥、令牌的文件，如 ~/.ssh、~/.netrc、~/.gitconfig、~/.aws/credentials。",h:"Agent 能读这些文件 = 能直接拿到你的登录凭据，冒充你访问 GitHub、云服务等。",f:"Agent 运行账号不要有这些文件的读权限；审计只报存在，不读内容。"},
    en:{d:"Files holding passwords, keys and tokens, e.g. ~/.ssh, ~/.netrc, ~/.gitconfig, ~/.aws/credentials.",h:"If an agent can read these files, it obtains your login credentials and can impersonate you on GitHub, cloud services, etc.",f:"Keep the agent's account out of these files; audits report existence only."}},
  "clipboard":{name:"剪贴板",
    zh:{d:"你复制粘贴的内容（可能含密码、验证码、链接）。检测它是否可被读取。",h:"Agent 能读剪贴板 = 能拿到你刚粘贴过的任何敏感内容。",f:"粘贴敏感信息后尽快清空剪贴板；限制 Agent 读取权限。"},
    en:{d:"What you copy and paste — possibly passwords, codes, links. The probe checks whether it can be read.",h:"An agent that can read the clipboard obtains anything sensitive you just pasted.",f:"Clear the clipboard after pasting secrets; restrict agent read access."}},
  "tcc":{name:"TCC（隐私授权）",
    zh:{d:"macOS 的隐私授权系统：控制哪个 App 能读剪贴板、通讯录、屏幕等。首次用某权限时弹出的“允许访问吗”就是它在问。",h:"报告里很多“已拒绝/部分”其实是 TCC 在拦截，是保护机制在工作，不代表脚本出错。",f:"无需处理；反而是你想限制 Agent 时可以利用它。"},
    en:{d:"macOS's privacy permission system: it controls which apps can read the clipboard, contacts, screen, etc. The “allow access?” popup you see is TCC asking.",h:"Many “denied/partial” results are TCC blocking — a protection working, not a script error.",f:"Nothing to fix; it can even be used to restrict an agent."}},
  "browser":{name:"浏览器配置",
    zh:{d:"Chrome/Safari/Firefox 保存登录会话、Cookie、历史记录的配置文件。",h:"Agent 能读浏览器配置 = 能“借用”你的登录态，无需密码直接进你的账号。",f:"不要让 Agent 访问浏览器配置目录；审计只报存在。"},
    en:{d:"The profile folders where Chrome/Safari/Firefox keep sessions, cookies and history.",h:"An agent that can read browser profiles can borrow your logged-in sessions and enter your accounts without a password.",f:"Keep agents out of browser profile directories; audits report existence only."}},
  "sip":{name:"SIP（系统完整性保护）",
    zh:{d:"macOS 的底层防篡改机制，保护系统文件、系统进程不被修改。",h:"SIP 关闭 = 系统和恶意软件都能改系统文件，防病毒能力大幅下降。",f:"保持 SIP 开启（恢复模式里开启）。"},
    en:{d:"macOS's low-level tamper protection that prevents system files and processes from being modified.",h:"With SIP off, both you and malware can modify system files; defenses weaken significantly.",f:"Keep SIP enabled (enable it from Recovery mode if off)."}},
  "gatekeeper":{name:"Gatekeeper",
    zh:{d:"macOS 的安全开关：拦截“未签名/来源不明”的应用运行。",h:"关闭后任何来路不明的软件都能直接运行，恶意软件更容易混进来。",f:"保持开启；从 App Store 或签名开发者安装软件。"},
    en:{d:"macOS's safety switch that blocks unsigned or untrusted apps from running.",h:"When off, software from anywhere runs directly and malware slips in more easily.",f:"Keep it on; install apps from the App Store or signed developers."}},
  "filevault":{name:"FileVault（全盘加密）",
    zh:{d:"macOS 的整块硬盘加密。开启后即使硬盘被拆走，没有密码也读不出数据。",h:"关闭 = 硬盘丢了/被拿走，里面的所有文件直接裸奔。",f:"在“系统设置 → 隐私与安全性”里开启 FileVault。"},
    en:{d:"macOS full-disk encryption. When on, data on the disk is unreadable without the password even if the disk is removed.",h:"When off, a lost or stolen disk exposes all files directly.",f:"Turn it on in System Settings → Privacy & Security."}},
  "process":{name:"进程可见性",
    zh:{d:"能否列出系统里所有正在运行的程序。",h:"能列进程 = 能看出你在跑什么软件、用什么工具，为针对性攻击提供情报。",f:"对 Agent 可限制为只能看自己相关的进程。"},
    en:{d:"Whether all running programs on the system can be listed.",h:"Listing processes reveals what software and tools you run — reconnaissance for targeted attacks.",f:"Scope agents to see only their own processes if possible."}},
  "other-homes":{name:"其他用户家目录",
    zh:{d:"这台电脑上其他用户的个人文件夹（/Users/其他用户名）。",h:"能读 = 能接触别人的文档、配置和隐私数据。",f:"个人文件夹默认权限应仅所有者可读（700）。"}
    ,en:{d:"Other people's personal folders on this machine (/Users/other-username).",h:"Readable means their documents, configs and private data are exposed.",f:"Home folders should default to owner-only (700)."}}
};
var CHECK_TERMS = [
  ["PATH hygiene", ["path-hygiene","path-hijack","user-writable"]],
  ["sudo (passwordless check)", ["sudo","passwordless-sudo"]],
  ["umask", ["umask"]],
  ["write-test", ["write-test"]],
  ["other users' home dirs", ["other-homes"]],
  ["access::applications", ["user-writable","system-dir"]],
  ["access::etc", ["system-dir"]],
  ["access::usr-local", ["system-dir"]],
  ["access::homebrew", ["system-dir"]],
  ["access::system-library", ["system-dir"]],
  ["access::private-etc", ["system-dir"]],
  ["access::var", ["system-dir"]],
  ["access::tmp", ["sticky"]],
  ["access::ssh-dir", ["secret-dir"]],
  ["access::aws-dir", ["secret-dir"]],
  ["access::gnupg-dir", ["secret-dir"]],
  ["shell execution", ["shell"]],
  ["available tools", ["tools"]],
  ["proxy env vars", ["proxy"]],
  ["DNS resolution", ["dns"]],
  ["egress tcp", ["egress"]],
  ["local listening sockets", ["port"]],
  ["default route", ["route"]],
  ["sensitive env vars", ["env-secret"]],
  ["file::", ["credential"]],
  ["clipboard", ["clipboard","tcc"]],
  ["browser profile", ["browser"]],
  ["SIP (System Integrity Protection)", ["sip"]],
  ["Gatekeeper", ["gatekeeper"]],
  ["FileVault", ["filevault"]],
  ["process visibility", ["process"]]
];
function termsFor(check){
  var out = [];
  CHECK_TERMS.forEach(function(r){
    if(check.indexOf(r[0]) !== -1){
      r[1].forEach(function(t){ if(out.indexOf(t)===-1) out.push(t); });
    }
  });
  return out;
}
function toggleTerms(btn){
  var tr = btn.closest("tr");
  var next = tr.nextElementSibling;
  if(next && next.classList.contains("term-row")){ next.remove(); return; }
  var terms = btn.getAttribute("data-terms").split(",");
  var zh = (LANG==="zh");
  var h = "";
  terms.forEach(function(t){
    var g = GLOSSARY[t]; if(!g) return;
    var x = zh ? g.zh : g.en;
    h += '<div class="term-card"><div class="t">'+esc(g.name)+'</div>'
       + '<div class="d">'+esc(x.d)+'</div>'
       + '<div class="h"><b>'+(zh?"危害：":"Risk: ")+'</b>'+esc(x.h)+'</div>'
       + '<div class="f"><b>'+(zh?"加固：":"Fix: ")+'</b>'+esc(x.f)+'</div>'
       + '</div>';
  });
  if(!h) return;
  var trow = document.createElement("tr");
  trow.className = "term-row";
  trow.innerHTML = '<td colspan="6">'+h+'</td>';
  tr.parentNode.insertBefore(trow, tr.nextSibling);
}
var META_LABELS_ZH = {tool:"工具", generated_at:"生成时间 (UTC)", host:"主机", platform:"平台", user:"用户", python:"Python", network_checks:"网络检查", version:"版本"};
var META_LABELS_EN = {tool:"tool", generated_at:"generated (UTC)", host:"host", platform:"platform", user:"user", python:"python", network_checks:"network checks", version:"version"};

function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
function el(id){return document.getElementById(id);}

function friendlyTime(iso){
  var t = new Date(iso);
  if(isNaN(t)) return iso;
  function p(n){return (n<10?"0":"")+n;}
  return t.getUTCFullYear()+"-"+p(t.getUTCMonth()+1)+"-"+p(t.getUTCDate())+" "+p(t.getUTCHours())+":"+p(t.getUTCMinutes())+" UTC";
}
function renderMeta(){
  var m = REPORT_DATA.meta, h = "";
  var labels = (LANG === "zh") ? META_LABELS_ZH : META_LABELS_EN;
  var order = ["tool","version","generated_at","host","platform","user","python","network_checks"];
  order.forEach(function(k){
    var v = m[k];
    if(k==="network_checks") v = (LANG==="zh") ? ((v==="enabled")?"已启用":"已禁用") : v;
    if(k==="generated_at") v = (LANG==="zh") ? friendlyTime(v) : v;
    h += '<div class="meta-item"><div class="k">'+esc(labels[k]||k)+'</div><div class="v">'+esc(v)+'</div></div>';
  });
  el("metaGrid").innerHTML = h;
}

function renderSummary(){
  var s = REPORT_DATA.risk_summary, h = "";
  var items = [["high","dot-high","sumHigh","var(--red)"],["medium","dot-medium","sumMedium","var(--yellow)"],["low","dot-low","sumLow","var(--teal-bright)"],["info","dot-info","sumInfo","var(--ink-faint)"]];
  items.forEach(function(it){
    h += '<div class="sum-card"><div class="n" style="color:'+it[3]+'">'+(s[it[0]]||0)+'</div>'
      + '<div class="r"><span class="dot '+it[1]+'"></span><span>'+lzRisk(it[0])+'</span></div>'
      + '<div class="d" data-i18n="'+it[2]+'">'+I18N[LANG][it[2]]+'</div></div>';
  });
  el("sumGrid").innerHTML = h;
  applyI18n(el("sumGrid"));
}

function statusHtml(st){
  return '<span class="dot dot-'+st+'"></span><span class="st" data-status="'+st+'">'+st+'</span>';
}

function evShort(s){
  s = String(s);
  if(LANG==="zh"){
    var parts = s.split("; ");
    if(parts.length > 2 && s.length > 80){
      return parts.slice(0,2).join("; ") + " … 等 " + parts.length + " 项";
    }
  } else {
    var parts2 = s.split("; ");
    if(parts2.length > 2 && s.length > 120){
      return parts2.slice(0,2).join("; ") + " … and " + parts2.length + " more";
    }
  }
  if(s.length > 140) return s.slice(0,140)+"…";
  return s;
}

function renderRows(){
  var rows = REPORT_DATA.checks, h = "", i;
  for(i=0;i<rows.length;i++){
    var c = rows[i], ev = c.evidence || "";
    var short = evShort(ev);
    var terms = termsFor(c.check);
    var tbtn = terms.length ? ' <button class="term-btn" data-terms="'+terms.join(",")+'" aria-label="explain" title="'+((LANG==="zh")?"查看术语解释":"Explain")+'">?</button>' : '';
    h += '<tr data-risk="'+c.risk+'" data-cat="'+esc(c.category)+'" data-query="'+esc((c.check+" "+c.category+" "+ev).toLowerCase())+'">'
      + '<td class="num">'+String(i+1).padStart(2,"0")+'</td>'
      + '<td>'+esc(lzCat(c.category))+'</td>'
      + '<td class="check">'+esc(lzCheck(c.check))+tbtn+'</td>'
      + '<td>'+statusHtml(c.status)+'</td>'
      + '<td><span class="risk risk-'+c.risk+'">'+lzRisk(c.risk)+'</span></td>'
      + '<td title="'+esc(lzEv(ev))+'">'+esc(lzEv(short))+'</td>'
      + '</tr>';
  }
  el("rows").innerHTML = h;
  applyI18n(el("rows"));
}

function renderFindings(){
  var rows = REPORT_DATA.checks.filter(function(c){return c.risk==="high"||c.risk==="medium";});
  if(!rows.length){ el("findingsList").innerHTML = '<div class="empty" data-i18n="noFindings">'+I18N[LANG].noFindings+'</div>'; applyI18n(el("findingsList")); return; }
  var h = "";
  rows.forEach(function(c){
    h += '<div class="finding"><div class="fh"><span class="risk risk-'+c.risk+'">'+lzRisk(c.risk)+'</span><span>'+esc(lzCat(c.category))+'</span><span class="check">'+esc(lzCheck(c.check))+'</span></div>'
      + '<div class="ev">'+esc(evShort(lzEv(c.evidence)))+'</div>'
      + '<div class="rec">'+esc(lzRec(c.recommendation))+'</div></div>';
  });
  el("findingsList").innerHTML = h;
}

function copyText(txt, btn){
  function done(){ var o = btn.textContent; btn.textContent = (LANG==="zh")?I18N.zh.copied:I18N.en.copied; setTimeout(function(){btn.textContent=o;},1200); }
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(txt).then(done, function(){ legacyCopy(txt,btn,done); });
  } else { legacyCopy(txt,btn,done); }
}
function legacyCopy(txt,btn,done){
  var ta = document.createElement("textarea");
  ta.value = txt; ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.focus(); ta.select();
  try { document.execCommand("copy"); done(); } catch(e){ done(); }
  document.body.removeChild(ta);
}

function renderRecs(){
  var fixes = REPORT_DATA.fixes || [], h = "", zh = (LANG==="zh"), i;
  for(i=0;i<fixes.length;i++){
    var f = fixes[i];
    var title = zh ? f.title_zh : f.title_en;
    var detail = zh ? f.detail_zh : f.detail_en;
    var badge = f.needs_sudo
      ? '<span class="fix-badge sudo">'+(zh?I18N.zh.needSudo:I18N.en.needSudo)+'</span>'
      : '<span class="fix-badge ok">'+(zh?I18N.zh.autoFix:I18N.en.autoFix)+'</span>';
    var cmds = "";
    f.commands.forEach(function(c){ cmds += '<code>'+esc(c)+'</code>'; });
    var askMsg = (zh?I18N.zh.fixPrefix:I18N.en.fixPrefix) + (i+1) + " " + title;
    h += '<li class="fix-item">'
      + '<div class="fix-head"><span class="fix-id">#'+(i+1)+'</span>'+badge+'<span class="fix-title">'+esc(title)+'</span></div>'
      + '<div class="fix-detail">'+esc(detail)+'</div>'
      + '<div class="fix-cmd"><span class="fix-cmd-label">'+(zh?"修复命令：":"Commands: ")+'</span>'+cmds+'</div>'
      + '<div class="fix-actions">'
      + '<button class="fix-btn copy" data-copy="'+esc(f.commands.join("\n"))+'">'+(zh?I18N.zh.copyCmd:I18N.en.copyCmd)+'</button>'
      + '<button class="fix-btn agent" data-ask="'+esc(askMsg)+'">'+(zh?I18N.zh.fixAgent:I18N.en.fixAgent)+'</button>'
      + '</div>'
      + '<div class="fix-ask hidden"></div>'
      + '</li>';
  }
  el("recs").innerHTML = h;
  el("footMeta").textContent = REPORT_DATA.meta.tool + " v" + REPORT_DATA.meta.version + " · " + ((LANG==="zh") ? friendlyTime(REPORT_DATA.meta.generated_at) : REPORT_DATA.meta.generated_at);
}

var riskFilter = "all", query = "";
function applyFilters(){
  var rows = document.querySelectorAll("#rows tr"), shown = 0, i;
  for(i=0;i<rows.length;i++){
    var r = rows[i];
    if(r.classList.contains("term-row")){
      var prev = r.previousElementSibling;
      r.classList.toggle("row-hidden", prev ? prev.classList.contains("row-hidden") : true);
      continue;
    }
    var okRisk = (riskFilter==="all") || (r.getAttribute("data-risk")===riskFilter);
    var okQ = !query || (r.getAttribute("data-query").indexOf(query) !== -1);
    var show = okRisk && okQ;
    r.classList.toggle("row-hidden", !show);
    if(show) shown++;
  }
  el("count").textContent = I18N[LANG].showing.replace("{a}",shown).replace("{b}",REPORT_DATA.checks.length);
}

function applyI18n(root){
  if(!root) return;
  var nodes = root.querySelectorAll("[data-i18n]");
  for(var i=0;i<nodes.length;i++){
    var k = nodes[i].getAttribute("data-i18n");
    if(I18N[LANG][k] !== undefined) nodes[i].textContent = I18N[LANG][k];
  }
  var st = root.querySelectorAll("[data-status]");
  for(var j=0;j<st.length;j++){
    var s = st[j].getAttribute("data-status");
    st[j].textContent = (LANG==="zh" && STATUS_ZH[s]) ? STATUS_ZH[s] : s;
  }
  var ph = document.querySelectorAll("[data-i18n-ph]");
  for(var k2=0;k2<ph.length;k2++){ ph[k2].placeholder = I18N[LANG].ph; }
}

function setLang(lang){
  if(lang!==LANG){
    LANG = lang;
    document.documentElement.lang = (lang==="zh")?"zh-CN":"en";
    el("btn-zh").classList.toggle("active",lang==="zh");
    el("btn-en").classList.toggle("active",lang==="en");
    renderMeta(); renderSummary(); renderRows(); renderFindings(); renderRecs();
    applyI18n(document);
    applyFilters();
    try{ localStorage.setItem("probe-lang",lang); }catch(e){}
  }
}

var saved=null; try{ saved=localStorage.getItem("probe-lang"); }catch(e){}
LANG = (saved==="en"||saved==="zh") ? saved : "zh";
document.documentElement.lang = (LANG==="zh")?"zh-CN":"en";
el("btn-zh").classList.toggle("active",LANG==="zh");
el("btn-en").classList.toggle("active",LANG==="en");

el("btn-zh").addEventListener("click",function(){setLang("zh");});
el("btn-en").addEventListener("click",function(){setLang("en");});

var fBtns = document.querySelectorAll("#filters button");
for(var fi=0;fi<fBtns.length;fi++){
  fBtns[fi].addEventListener("click",function(){
    fBtns.forEach(function(b){b.classList.remove("active");});
    this.classList.add("active");
    riskFilter = this.getAttribute("data-risk");
    applyFilters();
  });
}
el("q").addEventListener("input",function(){ query = this.value.trim().toLowerCase(); applyFilters(); });
el("rows").addEventListener("click",function(e){
  var btn = e.target.closest ? e.target.closest(".term-btn") : null;
  if(btn) toggleTerms(btn);
});
el("recs").addEventListener("click",function(e){
  var t = e.target;
  var copy = t.closest ? t.closest(".fix-btn.copy") : null;
  if(copy){ copyText(copy.getAttribute("data-copy"), copy); return; }
  var ask = t.closest ? t.closest(".fix-btn.agent") : null;
  if(ask){
    var li = ask.closest(".fix-item");
    var box = li.querySelector(".fix-ask");
    if(box.classList.contains("hidden")){
      var msg = ask.getAttribute("data-ask");
      box.innerHTML = '<div class="fix-ask-txt">'+((LANG==="zh")?I18N.zh.tellAi:I18N.en.tellAi)+'</div>'
        + '<div class="fix-ask-msg">'+esc(msg)+'</div>'
        + '<button class="fix-btn copy mini" data-copy="'+esc(msg)+'">'+((LANG==="zh")?I18N.zh.copyAsk:I18N.en.copyAsk)+'</button>';
      box.classList.remove("hidden");
    } else {
      box.classList.add("hidden"); box.innerHTML = "";
    }
    return;
  }
});

renderMeta(); renderSummary(); renderRows(); renderFindings(); renderRecs(); applyFilters(); applyI18n(document);
})();
</script>
</body>
</html>
"""


def render_html(report: dict) -> str:
    return _HTML_TEMPLATE.replace("__DATA__", json.dumps(report, ensure_ascii=False))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only permission boundary audit for AI agents (macOS-first).")
    parser.add_argument("--output-dir", default="./probe-report",
                        help="Directory for report files (default: ./probe-report)")
    parser.add_argument("--json", action="store_true", help="Write probe_report.json")
    parser.add_argument("--md", action="store_true", help="Write probe_report.md")
    parser.add_argument("--html", action="store_true", help="Write probe_report.html")
    parser.add_argument("--no-network", action="store_true",
                        help="Skip outbound TCP / DNS network checks")
    args = parser.parse_args()

    out_dir = Path(args.output_dir).expanduser().resolve()
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[fatal] cannot create output dir {out_dir}: {exc}", file=sys.stderr)
        return 2

    checks: list[dict] = []
    checks += check_identity()
    checks += check_filesystem()
    checks += check_shell()
    checks += check_network(args.no_network)
    checks += check_credentials()
    checks += check_system()
    checks += check_gui()
    checks += check_security_posture()

    report = build_report(checks, args.no_network)

    any_flag = args.json or args.md or args.html
    want_json = args.json or (not any_flag)
    want_md = args.md or (not any_flag)
    want_html = args.html or (not any_flag)
    written = []
    if want_json:
        p = out_dir / "probe_report.json"
        p.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        written.append(str(p))
    if want_md:
        p = out_dir / "probe_report.md"
        p.write_text(render_markdown(report), encoding="utf-8")
        written.append(str(p))
    if want_html:
        p = out_dir / "probe_report.html"
        p.write_text(render_html(report), encoding="utf-8")
        written.append(str(p))

    print(f"[ok] probe finished: {len(checks)} checks")
    for w in written:
        print(f"[ok] report: {w}")
    print(f"[info] risk summary: {json.dumps(report['risk_summary'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
