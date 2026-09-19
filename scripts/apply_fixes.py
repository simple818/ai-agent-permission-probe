#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apply_fixes.py — optional hardening actions for ai-agent-permission-probe

Run AFTER the read-only probe. This script CHANGES user/system configuration,
so it never applies anything unless --apply is given. Use --fix <id> to
preview what would change, then --fix <id> --apply to do it for real.

Safety contract
- Idempotent: re-running a fix is harmless.
- Every modified config file is backed up to <file>.bak.<timestamp> first.
- Fixes that need administrator rights are detected and NOT applied when
  running as a normal user; the script tells you to run them with sudo.
- This script never reads or prints the content of secrets.

Usage:
    python3 apply_fixes.py --list
    python3 apply_fixes.py --fix fix-path              # preview only
    python3 apply_fixes.py --fix fix-path --apply      # apply for real
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import time
from pathlib import Path

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def home() -> Path:
    return Path.home()


def backup(path: Path) -> str | None:
    if not path.exists():
        return None
    bak = f"{path}.bak.{time.strftime('%Y%m%d%H%M%S')}"
    shutil.copy2(path, bak)
    return bak


def _user_writable_dir(p: str) -> bool:
    """Empty entries and '.' mean 'current dir' — also treated as risky."""
    if not p or p == ".":
        return True
    return os.path.isdir(p) and os.access(p, os.W_OK)


def _need_root(paths: list[str]) -> bool:
    try:
        return os.geteuid() != 0
    except AttributeError:
        return False


# --------------------------------------------------------------------------- #
# Individual fixes
# --------------------------------------------------------------------------- #

def fix_path(dry: bool) -> list[str]:
    """Remove user-writable / current-dir entries from PATH in shell configs."""
    msgs: list[str] = []
    path_assign = re.compile(r'(export\s+)?PATH=("?)([^"\n]+)("?)')
    for cfg in [home() / ".zshrc", home() / ".zprofile"]:
        if not cfg.exists():
            continue
        lines = cfg.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        new_lines = []
        changed = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                new_lines.append(line)
                continue
            m = path_assign.search(line)
            if m:
                parts = m.group(3).split(":")
                keep = [p for p in parts if p and not _user_writable_dir(p)]
                if len(keep) != len(parts):
                    new_val = ":".join(keep)
                    new_line = line[: m.start(3)] + new_val + line[m.end(3):]
                    new_lines.append(new_line)
                    changed = True
                    continue
            new_lines.append(line)
        if changed:
            msgs.append(f"  {cfg}: would rewrite PATH line(s) (drop {len(parts) - len(keep)} risky entr(ies))")
            if not dry:
                bak = backup(cfg)
                cfg.write_text("".join(new_lines), encoding="utf-8")
                msgs.append(f"    backup: {bak}")
    if not msgs:
        msgs.append("  no user-writable/current-dir PATH entries found in ~/.zshrc / ~/.zprofile")
    return msgs


def fix_umask(dry: bool) -> list[str]:
    """Ensure `umask 077` is present in ~/.zshrc."""
    msgs: list[str] = []
    cfg = home() / ".zshrc"
    body = cfg.read_text(encoding="utf-8", errors="replace") if cfg.exists() else ""
    if re.search(r'(^|\n)\s*umask\s+0', body):
        msgs.append("  ~/.zshrc already sets a restrictive umask; nothing to do")
        return msgs
    msgs.append("  ~/.zshrc: would append `umask 077`")
    if not dry:
        bak = backup(cfg) if cfg.exists() else None
        with cfg.open("a", encoding="utf-8") as fh:
            fh.write("\n# added by ai-agent-permission-probe (fix-umask)\numask 077\n")
        if bak:
            msgs.append(f"    backup: {bak}")
    return msgs


def fix_ssh_perm(dry: bool) -> list[str]:
    """Tighten ~/.ssh to 700 and its files to 600."""
    msgs: list[str] = []
    ssh = home() / ".ssh"
    if not ssh.is_dir():
        msgs.append("  ~/.ssh does not exist; nothing to do")
        return msgs
    changes = []
    if ssh.stat().st_mode & 0o077:
        changes.append(f"  {ssh}: chmod 700")
    for entry in sorted(ssh.iterdir()):
        if entry.is_dir():
            if entry.stat().st_mode & 0o077:
                changes.append(f"  {entry}: chmod 700 (dir)")
        else:
            if entry.stat().st_mode & 0o077:
                changes.append(f"  {entry}: chmod 600")
    if not changes:
        msgs.append("  ~/.ssh already tightened; nothing to do")
        return msgs
    msgs.extend(changes)
    if not dry:
        os.chmod(ssh, 0o700)
        for entry in sorted(ssh.iterdir()):
            os.chmod(entry, 0o700 if entry.is_dir() else 0o600)
    return msgs


def fix_local_bin(dry: bool) -> list[str]:
    """Tighten ~/.local/bin to 755 (owner-writable only)."""
    msgs: list[str] = []
    target = home() / ".local" / "bin"
    if not target.is_dir():
        msgs.append("  ~/.local/bin does not exist; nothing to do")
        return msgs
    if not (target.stat().st_mode & 0o022):
        msgs.append("  ~/.local/bin already tight; nothing to do")
        return msgs
    msgs.append(f"  {target}: chmod 755")
    if not dry:
        os.chmod(target, 0o755)
    return msgs


def fix_system_dir(dry: bool, paths: list[str], mode: int = 0o755) -> list[str]:
    """Tighten a system directory. Requires root."""
    msgs: list[str] = []
    if _need_root(paths):
        msgs.append(f"  needs admin: run this fix with sudo — chmod {mode:o} {' '.join(paths)}")
        return msgs
    for p in paths:
        path = Path(p)
        if not path.exists():
            msgs.append(f"  {p}: does not exist; skipped")
            continue
        msgs.append(f"  {p}: chmod {mode:o}")
        if not dry:
            os.chmod(path, mode)
    return msgs


def fix_filevault(dry: bool) -> list[str]:
    """FileVault cannot be enabled non-interactively; give clear guidance."""
    return [
        "  FileVault cannot be enabled from a non-interactive script safely.",
        "  Manual step: System Settings → Privacy & Security → FileVault → Turn On.",
        "  Or run: sudo fdesetup enable  (requires your password and may need recovery key setup).",
    ]


FIXES: dict[str, dict] = {
    "fix-path": {
        "title": "Clean user-writable directories from PATH (PATH hygiene)",
        "needs_sudo": False,
        "fn": fix_path,
    },
    "fix-umask": {
        "title": "Tighten default file permissions (umask 077)",
        "needs_sudo": False,
        "fn": fix_umask,
    },
    "fix-ssh-perm": {
        "title": "Tighten ~/.ssh permissions (700 / 600)",
        "needs_sudo": False,
        "fn": fix_ssh_perm,
    },
    "fix-local-bin": {
        "title": "Tighten ~/.local/bin to owner-writable (755)",
        "needs_sudo": False,
        "fn": fix_local_bin,
    },
    "fix-apps-perm": {
        "title": "Tighten /Applications write permission (755, admin)",
        "needs_sudo": True,
        "fn": lambda dry: fix_system_dir(dry, ["/Applications"]),
    },
    "fix-usr-local": {
        "title": "Tighten /usr/local and /usr/local/bin (755, admin)",
        "needs_sudo": True,
        "fn": lambda dry: fix_system_dir(dry, ["/usr/local", "/usr/local/bin"]),
    },
    "fix-py-framework": {
        "title": "Tighten Python framework bin (755, admin)",
        "needs_sudo": True,
        "fn": lambda dry: fix_system_dir(dry, ["/Library/Frameworks/Python.framework/Versions/3.12/bin"]),
    },
    "fix-filevault": {
        "title": "Enable FileVault full-disk encryption",
        "needs_sudo": True,
        "fn": fix_filevault,
    },
}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Optional hardening actions for ai-agent-permission-probe.")
    parser.add_argument("--list", action="store_true", help="List all available fixes")
    parser.add_argument("--fix", metavar="ID", help="Fix id to preview or apply")
    parser.add_argument("--apply", action="store_true",
                        help="Actually apply the fix (default is preview-only)")
    args = parser.parse_args()

    if args.list or not args.fix:
        print("Available fixes:")
        for fid, spec in FIXES.items():
            sudo = " [sudo]" if spec["needs_sudo"] else ""
            print(f"  {fid}{sudo}: {spec['title']}")
        if not args.fix:
            print("\nPreview: python3 apply_fixes.py --fix <id>")
            print("Apply:   python3 apply_fixes.py --fix <id> --apply")
        return 0

    spec = FIXES.get(args.fix)
    if not spec:
        print(f"[error] unknown fix id: {args.fix}", file=sys.stderr)
        print("Run --list to see available fixes.", file=sys.stderr)
        return 2

    mode = "APPLYING" if args.apply else "PREVIEW (no changes)"
    print(f"== fix: {args.fix} — {spec['title']}")
    print(f"== mode: {mode}")
    for msg in spec["fn"](not args.apply):
        print(msg)
    if not args.apply and not spec["needs_sudo"]:
        print("\nRe-run with --apply to make these changes for real.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
