#!/usr/bin/env python3
"""Groom the LOLRMM threat feed into ControlD-format blocklists.

Pulls https://lolrmm.io/api/rmm_tools.json, extracts network IOCs (domains + IPs)
for a curated set of RMM/RAT tools defined in lolrmm.toml, grooms them, and writes
deterministic ControlD blocklist JSON files plus a plain-text IP list.

Python 3.11+ stdlib only (tomllib, urllib.request, json, ipaddress, re).
Designed to run in GitHub Actions on a weekly cron; the git diff between runs is
the review surface, so output is fully deterministic.

Usage:
    python3 groom_lolrmm.py [--config lolrmm.toml] [--dry-run]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

# Basic domain validity: 1+ labels then a dotted TLD. Labels are 1-63 chars of
# [a-z0-9-], not starting/ending with a hyphen; TLD is 2+ alpha chars. Already
# lowercased by the time we test.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)

ACTION = {"do": 0, "status": 1}


def warn(msg: str) -> None:
    print(f"WARNING: {msg}", file=sys.stderr)


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def fetch_feed(url: str) -> list:
    """Fetch the feed. Any failure aborts the run with no writes."""
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            data = resp.read()
    except Exception as exc:  # noqa: BLE001 — any fetch failure is fatal
        die(f"Failed to fetch feed {url}: {exc}")
    try:
        feed = json.loads(data)
    except json.JSONDecodeError as exc:
        die(f"Feed {url} is not valid JSON: {exc}")
    if not isinstance(feed, list) or not feed:
        die(f"Feed {url} did not return a non-empty JSON array")
    return feed


def index_feed(feed: list) -> dict[str, dict]:
    """Map lowercased tool Name -> tool object for exact, case-insensitive lookup."""
    index: dict[str, dict] = {}
    for tool in feed:
        name = tool.get("Name")
        if isinstance(name, str) and name.strip():
            index[name.strip().lower()] = tool
    return index


def domains_of(tool: dict) -> list[str]:
    """Collect Domains from all Artifacts.Network entries (note capitalization)."""
    out: list[str] = []
    artifacts = tool.get("Artifacts") or {}
    for entry in artifacts.get("Network") or []:
        if isinstance(entry, dict):
            for dom in entry.get("Domains") or []:
                if isinstance(dom, str):
                    out.append(dom)
    return out


def resolve_tools(names: list[str], index: dict[str, dict]) -> list[tuple[str, dict]]:
    """Resolve config tool names against the feed. Unknown names fail the run loudly."""
    resolved: list[tuple[str, dict]] = []
    unknown: list[str] = []
    for name in names:
        tool = index.get(name.strip().lower())
        if tool is None:
            unknown.append(name)
        else:
            resolved.append((tool.get("Name", name), tool))
    if unknown:
        die(
            "Unknown tool name(s) in config (must match feed 'Name' exactly, "
            "case-insensitive): " + ", ".join(repr(n) for n in unknown)
        )
    return resolved


def groom_domain(raw: str, never_block_apex: set[str], allowlist: set[str]):
    """Run one domain string through the grooming pipeline.

    Returns ("domain", value) for a kept domain, ("ip", value) for an IP to route
    to the IP list, or None if the entry was dropped.
    """
    # 1. Lowercase, strip whitespace.
    dom = raw.strip().lower()
    # 2. Drop sentinels / empties.
    if not dom or dom == "user_managed":
        return None
    # 3. IP fork: real IPs go to the IP list, not the domain list.
    try:
        ipaddress.ip_address(dom)
        return ("ip", dom)
    except ValueError:
        pass
    # 4. Wildcard collapse: *.foo.com -> foo.com (ControlD blocks subdomains natively).
    if dom.startswith("*."):
        dom = dom[2:]
    # 5. Guardrail: never emit a bare shared-infra apex. Hostnames under it pass.
    if dom in never_block_apex:
        warn(f"guardrail: refusing to block shared-infra apex {dom!r}")
        return None
    # 6. Allowlist.
    if dom in allowlist:
        return None
    # 7. Validity.
    if not DOMAIN_RE.match(dom):
        warn(f"dropping invalid domain {dom!r}")
        return None
    return ("domain", dom)


def drop_subsumed(domains: dict[str, str]) -> dict[str, str]:
    """If both foo.com and bar.foo.com survive, keep only foo.com.

    `domains` maps domain -> first contributing tool. Returns a filtered copy.
    """
    kept = set(domains)
    result: dict[str, str] = {}
    for dom, tool in domains.items():
        # Drop dom if any surviving apex is a parent of it.
        labels = dom.split(".")
        parents = {".".join(labels[i:]) for i in range(1, len(labels) - 1)}
        if parents & kept:
            continue
        result[dom] = tool
    return result


def build_blocklist(cfg, resolved_tools, never_block_apex, allowlist):
    """Groom one blocklist. Returns (domain->tool dict, set of IP strings)."""
    domains: dict[str, str] = {}  # domain -> first contributing tool (config order)
    ips: set[str] = set()
    for tool_name, tool in resolved_tools:
        for raw in domains_of(tool):
            result = groom_domain(raw, never_block_apex, allowlist)
            if result is None:
                continue
            kind, value = result
            if kind == "ip":
                ips.add(value)
            elif value not in domains:  # 8. dedupe; credit first contributing tool
                domains[value] = tool_name
    # 9. Drop subsumed subdomains.
    domains = drop_subsumed(domains)
    return domains, ips


def render_blocklist_json(group_name: str, domains: dict[str, str]) -> str:
    """Render deterministic ControlD blocklist JSON (2-space indent, trailing NL)."""
    rules = [
        {
            "PK": dom,
            "action": dict(ACTION),
            "comment": f"Block {domains[dom]} (LOLRMM)",
        }
        for dom in sorted(domains)  # rules sorted alphabetically by PK
    ]
    doc = {"group": {"group": group_name, "action": dict(ACTION)}, "rules": rules}
    return json.dumps(doc, indent=2) + "\n"


def render_ip_list(ips: set[str]) -> str:
    """Render deterministic plain-text IP list: sorted, deduped, trailing NL."""
    ordered = sorted(ips, key=lambda s: (ipaddress.ip_address(s).version, ipaddress.ip_address(s)))
    return "".join(f"{ip}\n" for ip in ordered)


def existing_pks(path: Path) -> set[str] | None:
    """Return the set of PKs in an existing blocklist JSON, or None if absent/unreadable."""
    if not path.exists():
        return None
    try:
        doc = json.loads(path.read_text())
        return {r["PK"] for r in doc.get("rules", []) if isinstance(r, dict) and "PK" in r}
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def existing_ips(path: Path) -> set[str] | None:
    if not path.exists():
        return None
    try:
        return {ln.strip() for ln in path.read_text().splitlines() if ln.strip()}
    except OSError:
        return None


def sanity_check(label: str, old: set[str] | None, new: set[str]) -> None:
    """Sanity brake: abort (no write) on suspiciously large removals/additions.

    Does not apply on first run (no existing file).
    """
    if old is None:
        return
    removed = old - new
    added = new - old
    if old and len(removed) > 0.30 * len(old):
        die(
            f"{label}: sanity brake — {len(removed)}/{len(old)} existing entries "
            f"({len(removed) / len(old):.0%}) would be removed (>30%). Refusing to write. "
            f"Removed: {', '.join(sorted(removed))}"
        )
    if len(added) > 50:
        die(
            f"{label}: sanity brake — {len(added)} entries would be added in one run "
            f"(>50). Refusing to write."
        )


def write_if_changed(path: Path, content: str, dry_run: bool) -> bool:
    """Write content unless unchanged. Returns True if it changed (or would change)."""
    current = path.read_text() if path.exists() else None
    if current == content:
        print(f"  unchanged: {path}")
        return False
    verb = "would write" if dry_run else "writing"
    print(f"  {verb}: {path}")
    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Groom LOLRMM feed into ControlD blocklists.")
    parser.add_argument("--config", default="lolrmm.toml", help="Config file (default: lolrmm.toml)")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without writing")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        die(f"Config file not found: {config_path}")
    with config_path.open("rb") as fh:
        cfg = tomllib.load(fh)

    feed_url = cfg["settings"]["feed_url"]
    allowlist = {d.strip().lower() for d in cfg.get("allowlist", {}).get("domains", [])}
    never_block_apex = {d.strip().lower() for d in cfg.get("guardrails", {}).get("never_block_apex", [])}
    blocklists = cfg.get("blocklists", {})
    if not blocklists:
        die("No [blocklists.*] tables defined in config.")

    print(f"Fetching feed: {feed_url}")
    feed = fetch_feed(feed_url)
    index = index_feed(feed)
    print(f"Feed loaded: {len(feed)} tools")

    # Groom every blocklist first (collecting IPs + referenced tools) so the sanity
    # brake can abort the whole run before any file is written.
    outputs: list[tuple[Path, str, set[str], set[str] | None]] = []  # path, content, new_pks, old_pks
    all_ips: set[str] = set()
    referenced_tools: dict[str, dict] = {}  # lowercased name -> tool (union across lists)

    for key, bl in blocklists.items():
        group_name = bl["group_name"]
        out_path = Path(bl["output"])
        resolved = resolve_tools(bl["tools"], index)
        for name, tool in resolved:
            referenced_tools[name.lower()] = tool
        domains, ips = build_blocklist(bl, resolved, never_block_apex, allowlist)
        all_ips |= ips
        print(f"[{key}] {len(domains)} domains, {len(ips)} IPs routed to IP list")
        content = render_blocklist_json(group_name, domains)
        new_pks = set(domains)
        old_pks = existing_pks(out_path)
        sanity_check(f"[{key}] {out_path}", old_pks, new_pks)
        outputs.append((out_path, content, new_pks, old_pks))

    # IP list: gather IPs from the configured set of tools.
    ipcfg = cfg.get("ip_blocklist")
    if ipcfg:
        ip_out = Path(ipcfg["output"])
        which = ipcfg.get("tools", "all")
        if which == "all":
            ip_tools = list(referenced_tools.values())
        else:
            ip_tools = [t for _, t in resolve_tools(which, index)]
        ips: set[str] = set()
        for tool in ip_tools:
            for raw in domains_of(tool):
                res = groom_domain(raw, never_block_apex, allowlist)
                if res and res[0] == "ip":
                    ips.add(res[1])
        print(f"[ip_blocklist] {len(ips)} IPs")
        ip_content = render_ip_list(ips)
        sanity_check(f"[ip_blocklist] {ip_out}", existing_ips(ip_out), ips)
        outputs.append((ip_out, ip_content, ips, None))

    changed = False
    for path, content, _new, _old in outputs:
        if write_if_changed(path, content, args.dry_run):
            changed = True

    if args.dry_run:
        print("Dry run: no files written.")
    elif not changed:
        print("No changes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
