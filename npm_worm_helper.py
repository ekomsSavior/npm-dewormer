#!/usr/bin/env python3
"""
npm_worm_helper.py

Local helper for the current Shai-Hulud npm worm campaign.
- Always runs a scan on start.
- If indicators are found, it PROMPTS the user to optionally quarantine them.
- Always writes a text report to ./reports/npm_worm_scan_<timestamp>.txt

This is conservative and DOES NOT guarantee full remediation.
Always:
  - Rotate credentials/tokens
  - Rebuild CI runners where possible
  - Follow vendor IR guidance
"""

import datetime
import os
import platform
import shutil
import subprocess
from pathlib import Path

# ---------------- IOCs (files / dirs / commands) ---------------- #
# Based on current public analyses of Shai-Hulud 2.0
# (setup_bun.js + bun_environment.js + TruffleHog-based harvesting)

FILE_INDICATORS = [
    "bun_environment.js",
    "setup_bun.js",
    "cloud.json",
    "contents.json",
    "environment.json",
    "truffleSecrets.json",
    ".truffler-cache/trufflehog",
    ".truffler-cache/trufflehog.exe",
]

DIR_INDICATORS = [
    ".truffler-cache",
    ".truffler-cache/extract",
]

CMD_INDICATORS = [
    'del /F /Q /S "%USERPROFILE%\\*"',   # aggressive wipe (Windows)
    "shred -uvz -n 1",                   # destructive shred (Linux/macOS)
    "cipher /W:%USERPROFILE%",           # free-space wipe (Windows)
    "curl -fsSL https://bun.sh/install | bash",
    'irm bun.sh/install.ps1|iex',
    'bun.sh/install.ps1|iex',
]

HISTORY_FILES = [
    ".bash_history",
    ".zsh_history",
    # you can add fish / PowerShell history paths here
]


# ---------------- helpers ---------------- #

def banner():
    print("=" * 72)
    print(" Shai-Hulud / npm Worm – Local IOC Scanner & Cleaner")
    print("=" * 72)
    print("This script will:")
    print("  - Scan for known npm worm indicators")
    print("  - Show anything suspicious it finds")
    print("  - Ask if you want to MOVE those files/dirs into quarantine\n")


def gather_scan_roots():
    roots = set()
    home = Path.home()
    roots.add(home)
    roots.add(Path.cwd())

    for sub in ("projects", "code", "repos", "src"):
        p = home / sub
        if p.exists():
            roots.add(p)

    return sorted(roots)


def scan_filesystem():
    roots = gather_scan_roots()
    print("[*] Scanning filesystem under:")
    for r in roots:
        print(f"    - {r}")

    found_files = []
    found_dirs = []

    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            base = Path(dirpath)

            # dir IOCs
            for d in list(dirnames):
                full = base / d
                full_str = full.as_posix()
                for ind in DIR_INDICATORS:
                    if full_str.endswith(ind):
                        found_dirs.append(full_str)

            # file IOCs (tightened matching logic)
            for f in filenames:
                full = base / f
                full_str = full.as_posix()

                for ind in FILE_INDICATORS:
                    # If indicator contains a path separator, treat it as a path suffix
                    # e.g. ".truffler-cache/trufflehog"
                    if "/" in ind:
                        if full_str.endswith(ind):
                            found_files.append(full_str)
                    else:
                        # Otherwise, match exact filename only
                        # prevents "contents.json" from matching "verified_contents.json"
                        if f == ind:
                            found_files.append(full_str)

    return sorted(set(found_files)), sorted(set(found_dirs))


def run_cmd(cmd):
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, text=True
        )
    except Exception:
        return ""


def scan_processes():
    print("\n[*] Checking running processes for suspicious commands...")
    system = platform.system().lower()
    out = ""

    if system in ("linux", "darwin"):
        out = run_cmd(["ps", "aux"])
    elif system == "windows":
        out = run_cmd(["wmic", "process", "get", "CommandLine,ProcessId"])
    else:
        print("    [!] Unknown OS for process scanning:", system)

    hits = set()
    if not out:
        print("    [!] Could not retrieve process list (permission/tool issue).")
        return hits

    low = out.lower()
    for ind in CMD_INDICATORS:
        if ind.lower() in low:
            hits.add(ind)
    return hits


def scan_history():
    print("\n[*] Searching shell history for suspicious commands...")
    home = Path.home()
    hits = []

    for fname in HISTORY_FILES:
        path = home / fname
        if not path.exists():
            continue
        try:
            data = path.read_text(errors="ignore")
        except Exception:
            continue

        low = data.lower()
        for ind in CMD_INDICATORS:
            if ind.lower() in low:
                hits.append((str(path), ind))
    return hits


def make_quarantine_root():
    base = Path.home() / "npm_worm_quarantine"
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    root = base / f"scan_{ts}"
    root.mkdir(parents=True, exist_ok=True)
    return root


def safe_relative(path: Path) -> Path:
    """
    Try to make a relative path inside quarantine so we preserve some structure
    without accidentally re-creating absolute paths with drive letters.
    """
    home = Path.home()
    try:
        return path.relative_to(home)
    except ValueError:
        return Path(path.name)


def perform_cleanup(file_paths, dir_paths):
    if not file_paths and not dir_paths:
        print("[!] No filesystem IOCs to clean.")
        return

    print("\n[!] CLEANUP MODE")
    print("    This will MOVE known IOC files/dirs into a quarantine folder.")
    print("    It will NOT run shred/cipher/format, and will not touch anything")
    print("    outside the exact paths listed above.\n")

    confirm = input("Type EXACTLY 'CLEAN' to proceed, or anything else to abort: ")
    if confirm.strip().upper() != "CLEAN":
        print("[-] Cleanup aborted by user.")
        return

    qroot = make_quarantine_root()
    print(f"\n[*] Quarantining into: {qroot}\n")

    # Move files
    for p_str in file_paths:
        src = Path(p_str)
        if not src.exists():
            continue
        rel = safe_relative(src)
        dst = qroot / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(src), str(dst))
            print(f"    [file] {src}  ->  {dst}")
        except Exception as e:
            print(f"    [!] Failed to move {src}: {e}")

    # Move dirs
    # Sort longest paths first so nested dirs move more cleanly
    for p_str in sorted(dir_paths, key=len, reverse=True):
        src = Path(p_str)
        if not src.exists():
            continue
        rel = safe_relative(src)
        dst = qroot / rel
        try:
            shutil.move(str(src), str(dst))
            print(f"    [dir]  {src}  ->  {dst}")
        except Exception as e:
            print(f"    [!] Failed to move {src}: {e}")

    print("\n[+] Cleanup done. Review quarantined contents, then:")
    print("    - Back up what you need from quarantine (if anything).")
    print("    - Delete the quarantine folder securely once you’re sure.")


def write_report(fs_files, fs_dirs, proc_hits, hist_hits, any_hit):
    """
    Write a plain-text report to ./reports/npm_worm_scan_<timestamp>.txt
    so users can attach it to IR tickets / bug bounty reports.
    """
    reports_dir = Path.cwd() / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = reports_dir / f"npm_worm_scan_{ts}.txt"

    lines = []
    lines.append("Shai-Hulud / npm Worm – Local IOC Scan Report")
    lines.append(f"Timestamp (UTC): {ts}")
    lines.append(f"Host: {platform.node()}")
    lines.append("")

    lines.append("=== Filesystem IOCs ===")
    if fs_files or fs_dirs:
        for d in fs_dirs:
            lines.append(f"[DIR]  {d}")
        for f in fs_files:
            lines.append(f"[FILE] {f}")
    else:
        lines.append("No matching IOC files/directories found.")
    lines.append("")

    lines.append("=== Process IOCs ===")
    if proc_hits:
        for c in proc_hits:
            lines.append(f"COMMAND MATCH: {c}")
    else:
        lines.append("No suspicious commands detected in running processes.")
    lines.append("")

    lines.append("=== History IOCs ===")
    if hist_hits:
        for path, cmd in hist_hits:
            lines.append(f"{path} -> {cmd}")
    else:
        lines.append("No suspicious commands found in shell history.")
    lines.append("")

    lines.append("=== Overall Assessment ===")
    if any_hit:
        lines.append("Indicators were found. This is NOT guaranteed remediation.")
        lines.append("Follow up with credential rotation, repo audit, and IR steps.")
    else:
        lines.append("No known npm worm indicators found by this script.")
    lines.append("")

    with report_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return report_path


def main():
    banner()

    fs_files, fs_dirs = scan_filesystem()
    proc_hits = scan_processes()
    hist_hits = scan_history()

    print("\n================ SCAN RESULTS ================")

    any_hit = False

    if fs_files or fs_dirs:
        any_hit = True
        print("\n[!] IOC files / directories found:")
        for d in fs_dirs:
            print(f"    [DIR]  {d}")
        for f in fs_files:
            print(f"    [FILE] {f}")
    else:
        print("\n[+] No matching IOC files/directories in scanned paths.")

    if proc_hits:
        any_hit = True
        print("\n[!] Suspicious patterns in RUNNING processes:")
        for c in proc_hits:
            print(f"    {c}")
    else:
        print("\n[+] No suspicious commands detected in current process list.")

    if hist_hits:
        any_hit = True
        print("\n[!] Suspicious commands in shell history:")
        for path, cmd in hist_hits:
            print(f"    {path}  ->  {cmd}")
    else:
        print("\n[+] No suspicious commands found in ~/.bash_history / ~/.zsh_history.")

    print("\n=============================================")

    # Always write a report
    report_path = write_report(fs_files, fs_dirs, proc_hits, hist_hits, any_hit)
    print(f"[+] Scan report saved to: {report_path}")

    if any_hit:
        print("[!] Indicators were found. This script CANNOT guarantee full cleanup.")
        print("    Strongly recommended:")
        print("      - Rotate GitHub, npm, cloud & CI/CD tokens/keys.")
        print("      - Audit your Git repos for malicious setup_bun.js/bun_environment.js.")
        print("      - Pause automatic dependency updates until you’re clean.")

        # Interactive prompt instead of CLI args
        choice = input(
            "\n[?] Do you want to MOVE the IOC files/dirs into a quarantine "
            "folder now? [y/N]: "
        )
        if choice.strip().lower().startswith("y"):
            perform_cleanup(fs_files, fs_dirs)
        else:
            print("\n[-] Cleanup skipped. You can re-run this script later to clean.")
    else:
        print("[+] No known worm indicators found by this script.")
        print("    Still review your npm deps and watch vendor advisories.")


if __name__ == "__main__":
    main()
