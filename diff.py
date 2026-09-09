"""
diff.py

Compares a "baseline" SysmonConfig (snapshotted when a file is opened) with
the current, possibly-edited one, and reports what changed at the rule and
nested-group level so the UI can highlight added/modified/deleted items and
support reverting individual changes.

Matching is done by uid. Since uids are assigned once at parse/creation time
and never reused, a uid present in current-but-not-baseline is "added", one
in baseline-but-not-current is "deleted", and one present in both with
different content is "modified".

Rules that belong to a *deleted* nested group are reported only once, as
part of that group's entry (not also individually) - the group's own entry
carries its full rule list so a single revert can restore the whole thing.
Rules that belong to a *newly added* group ARE also reported individually
(each shows as newly added, same as any other new rule); the frontend can
tell it's inside a brand-new group by cross-referencing the group's own
"added" entry.
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime
from typing import Dict, List, Optional

from model import SysmonConfig


def _rule_dict(r, tag, onmatch, group_name, container_group_uid):
    return {
        "uid": r.uid, "tag": tag, "onmatch": onmatch, "group_name": group_name,
        "container_group_uid": container_group_uid,
        "field": r.rule_field, "condition": r.condition, "value": r.value,
        "comment": r.comment, "name": r.name,
    }


def _rule_content_key(d):
    return (d["tag"], d["onmatch"], d["group_name"], d["container_group_uid"],
            d["field"], d["condition"], d["value"], d["comment"], d["name"])


def _index_config(cfg: SysmonConfig):
    """Returns (rule_index: uid -> rule_dict, group_index: uid -> group_dict)."""
    rules: Dict[int, dict] = {}
    groups: Dict[int, dict] = {}
    for rg in cfg.rule_groups:
        for eb in rg.event_blocks:
            for r in eb.rules:
                rules[r.uid] = _rule_dict(r, eb.tag, eb.onmatch, rg.name, None)
            for grp in eb.groups:
                groups[grp.uid] = {
                    "uid": grp.uid, "tag": eb.tag, "onmatch": eb.onmatch, "group_name": rg.name,
                    "name": grp.name, "group_relation": grp.group_relation,
                    "rules": [_rule_dict(r, eb.tag, eb.onmatch, rg.name, grp.uid) for r in grp.rules],
                }
                for r in grp.rules:
                    rules[r.uid] = _rule_dict(r, eb.tag, eb.onmatch, rg.name, grp.uid)
    return rules, groups


def _group_content_key(g):
    return (g["tag"], g["onmatch"], g["group_name"], g["name"], g["group_relation"])


SETTINGS_FIELDS = [
    ("hash_algorithms", "Hash Algorithms"),
    ("check_revocation", "Check Revocation"),
    ("dns_lookup", "DNS Lookup"),
    ("archive_directory", "Archive Directory"),
]


def _compute_settings_diff(baseline: SysmonConfig, current: SysmonConfig) -> dict:
    diffs = {}
    for attr, label in SETTINGS_FIELDS:
        b, c = getattr(baseline, attr), getattr(current, attr)
        if b != c:
            diffs[attr] = {"label": label, "baseline": b, "current": c}
    return diffs


def compute_diff(baseline: Optional[SysmonConfig], current: SysmonConfig) -> dict:
    if baseline is None:
        return {"rules": {}, "groups": {}, "settings": {}}

    base_rules, base_groups = _index_config(baseline)
    cur_rules, cur_groups = _index_config(current)

    group_diff = {}
    for uid, g in cur_groups.items():
        if uid not in base_groups:
            group_diff[uid] = {"status": "added", "current": g}
        else:
            b = base_groups[uid]
            if _group_content_key(b) != _group_content_key(g):
                group_diff[uid] = {"status": "modified", "baseline": b, "current": g}
    for uid, g in base_groups.items():
        if uid not in cur_groups:
            group_diff[uid] = {"status": "deleted", "baseline": g}

    deleted_group_uids = {uid for uid, d in group_diff.items() if d["status"] == "deleted"}

    rule_diff = {}
    for uid, r in cur_rules.items():
        if uid not in base_rules:
            rule_diff[uid] = {"status": "added", "current": r}
        else:
            b = base_rules[uid]
            if _rule_content_key(b) != _rule_content_key(r):
                rule_diff[uid] = {"status": "modified", "baseline": b, "current": r}
    for uid, r in base_rules.items():
        if uid not in cur_rules:
            if r["container_group_uid"] in deleted_group_uids:
                continue  # covered by the group's own "deleted" entry
            rule_diff[uid] = {"status": "deleted", "baseline": r}

    return {"rules": rule_diff, "groups": group_diff,
            "settings": _compute_settings_diff(baseline, current)}


_STATUS_ORDER = {"added": 0, "modified": 1, "deleted": 2}


def format_changelog_section(diff: dict, section_title: str) -> str:
    """Renders one dated batch of changes (used to build up an accumulating
    changelog across multiple 'Apply Changes' actions, or a final
    'uncommitted' section for whatever hasn't been applied yet)."""
    rules = diff.get("rules", {})
    groups = diff.get("groups", {})
    settings = diff.get("settings", {})
    total = len(rules) + len(groups) + len(settings)

    counts = {"added": 0, "modified": 0, "deleted": 0}
    for info in rules.values():
        counts[info["status"]] += 1
    for info in groups.values():
        counts[info["status"]] += 1
    counts["modified"] += len(settings)

    lines = [
        "-" * 60,
        section_title,
        "-" * 60,
        f"{total} change(s): {counts['added']} added, {counts['modified']} modified, {counts['deleted']} deleted",
        "",
    ]

    if rules:
        lines += ["RULES", "-" * 20]
        for uid, info in sorted(rules.items(), key=lambda kv: _STATUS_ORDER[kv[1]["status"]]):
            d = info.get("current") or info.get("baseline")
            tag, status = f"<{d['tag']}>", info["status"].upper()
            lines.append(f"[{status}] {tag}")
            if info["status"] == "modified":
                b, c = info["baseline"], info["current"]
                lines.append(f'  {b["field"]} {b["condition"]}: "{b["value"]}" -> "{c["value"]}"')
            else:
                lines.append(f'  {d["field"]} {d["condition"]} "{d["value"]}"')
            lines.append("")

    if groups:
        lines += ["NESTED GROUPS", "-" * 20]
        for uid, info in sorted(groups.items(), key=lambda kv: _STATUS_ORDER[kv[1]["status"]]):
            d = info.get("current") or info.get("baseline")
            tag, status = f"<{d['tag']}>", info["status"].upper()
            if info["status"] == "modified":
                b, c = info["baseline"], info["current"]
                parts = []
                if b["name"] != c["name"]:
                    parts.append(f'renamed "{b["name"] or "(unnamed)"}" -> "{c["name"] or "(unnamed)"}"')
                if b["group_relation"] != c["group_relation"]:
                    parts.append(f'{b["group_relation"].upper()} -> {c["group_relation"].upper()}')
                if b["onmatch"] != c["onmatch"]:
                    parts.append(f'{b["onmatch"]} -> {c["onmatch"]}')
                lines.append(f"[{status}] {tag} Rule group: {', '.join(parts)}")
            else:
                label = d.get("name") or "(unnamed)"
                lines.append(f'[{status}] {tag} Rule group "{label}" '
                              f'({d["group_relation"].upper()}, {len(d["rules"])} filter(s))')
            lines.append("")

    if settings:
        lines += ["GLOBAL SETTINGS", "-" * 20]
        for field_name, info in settings.items():
            b = info["baseline"] if info["baseline"] not in (None, "") else "(not set)"
            c = info["current"] if info["current"] not in (None, "") else "(not set)"
            lines.append(f"{info['label']}: {b} -> {c}")
        lines.append("")

    if total == 0:
        lines.append("No changes in this section.")

    return "\n".join(lines)


def format_full_changelog(sections: List[str], source_path: Optional[str], schema_version: str) -> str:
    """Wraps one or more format_changelog_section() outputs with the overall
    archive header, for the final changelog.txt in an export."""
    header = [
        "Sysmon Config Change Archive",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Source file: {source_path or '(unsaved)'}",
        f"Active schema: v{schema_version}",
        "",
    ]
    body = "\n\n".join(sections) if sections else "No changes recorded."
    return "\n".join(header) + "\n" + body + "\n"
