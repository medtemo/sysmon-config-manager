"""
validator.py

Validates a SysmonConfig against a specific Sysmon SchemaManifest (see
schema_loader.py / schema_registry.py) and flags common mistakes before the
user tries to load it into the real Sysmon service. This is not a full XSD
validation (Microsoft doesn't publish one), it's a practical set of checks
based on documented Sysmon behavior - now driven by the *active* schema
version instead of a single hardcoded field/condition list, so switching
the active schema changes what counts as valid.

Each issue also carries enough info for the UI to jump straight to it:
- kind="rule" + uid -> a specific FilterRule (flat or nested)
- kind="group" + uid -> a specific nested RuleBlock (whole group)
- kind="tag" + tag -> no single row to highlight, but the UI can at least
  switch to that event type's tab (e.g. "this whole block has no rules")
- kind="" -> nothing to jump to (e.g. a config-wide schemaversion issue)
"""

from dataclasses import dataclass
from typing import List, Optional

from model import SysmonConfig
from schema_loader import SchemaManifest, NUMERIC_CONDITIONS, ONMATCH_VALUES


@dataclass
class ValidationIssue:
    severity: str   # "error" or "warning"
    message: str
    location: str = ""
    kind: str = ""              # "rule" | "group" | "tag" | ""
    uid: Optional[int] = None   # rule uid or group uid, when kind is "rule"/"group"
    tag: str = ""               # event tag, set whenever known (lets the UI switch tabs)


def validate(cfg: SysmonConfig, manifest: SchemaManifest) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []

    _check_schema_version(cfg, manifest, issues)
    _check_rule_groups(cfg, manifest, issues)

    return issues


def _check_schema_version(cfg: SysmonConfig, manifest: SchemaManifest, issues):
    try:
        major, minor = (int(x) for x in cfg.schema_version.split("."))
    except (ValueError, AttributeError):
        issues.append(ValidationIssue(
            "error", f"schemaversion '{cfg.schema_version}' is not a valid X.Y version string"))
        return
    if (major, minor) < (4, 0):
        issues.append(ValidationIssue(
            "warning",
            f"schemaversion {cfg.schema_version} is old; Sysmon 13+ expects 4.0 or higher for "
            "full syntax support (e.g. 'contains any', per-condition groups)."))

    if cfg.schema_version != manifest.version:
        issues.append(ValidationIssue(
            "warning",
            f"This config declares schemaversion=\"{cfg.schema_version}\" but you're validating "
            f"against the active schema v{manifest.version}. Fields/tags/conditions checked below "
            f"are v{manifest.version}'s, which may differ from what the config was written for."))


def _check_rule_groups(cfg: SysmonConfig, manifest: SchemaManifest, issues):
    seen_group_names = set()
    for rg in cfg.rule_groups:
        if rg.name in seen_group_names and rg.name != "":
            issues.append(ValidationIssue(
                "warning", f"Duplicate RuleGroup name '{rg.name}' — groups with the same "
                           "name are still processed independently by Sysmon, but it can be confusing."))
        seen_group_names.add(rg.name)

        if rg.group_relation not in ("or", "and"):
            issues.append(ValidationIssue(
                "error", f"RuleGroup groupRelation must be 'or' or 'and', got '{rg.group_relation}'",
                location=f"RuleGroup name='{rg.name}'"))

        for eb in rg.event_blocks:
            _check_event_block(eb, rg, manifest, issues)


def _check_event_block(eb, rg, manifest: SchemaManifest, issues):
    loc = f"RuleGroup name='{rg.name}' / <{eb.tag}>"
    tag = eb.tag

    if eb.tag not in manifest.all_tags():
        issues.append(ValidationIssue(
            "error",
            f"<{eb.tag}> is not a recognized event type in the active schema (v{manifest.version}).",
            loc, kind="tag", tag=tag))
        return

    if eb.onmatch not in ONMATCH_VALUES:
        issues.append(ValidationIssue(
            "error", f"onmatch must be 'include' or 'exclude', got '{eb.onmatch}'", loc,
            kind="tag", tag=tag))

    valid_fields = set(manifest.fields_for_tag(eb.tag))

    if not eb.rules and not eb.groups:
        issues.append(ValidationIssue(
            "warning", f"<{eb.tag}> block has no rules and will be dropped on save.", loc,
            kind="tag", tag=tag))

    _check_rule_list(eb.rules, tag, valid_fields, manifest, loc, issues)

    for grp in eb.groups:
        grp_label = f' name="{grp.name}"' if grp.name else ""
        grp_loc = f"{loc} / <Rule{grp_label} groupRelation=\"{grp.group_relation}\">"
        if grp.group_relation not in ("and", "or"):
            issues.append(ValidationIssue(
                "error", f"Nested Rule groupRelation must be 'and' or 'or', got '{grp.group_relation}'",
                grp_loc, kind="group", uid=grp.uid, tag=tag))
        if not grp.rules:
            issues.append(ValidationIssue(
                "warning", "Nested Rule sub-group has no filters and will be dropped on save.", grp_loc,
                kind="group", uid=grp.uid, tag=tag))
        elif len(grp.rules) < 2:
            issues.append(ValidationIssue(
                "warning",
                "Nested Rule sub-group has only one filter — same effect as a bare filter under "
                f"<{eb.tag}>, possibly pre-structured for future enrichment.", grp_loc,
                kind="group", uid=grp.uid, tag=tag))
        _check_rule_list(grp.rules, tag, valid_fields, manifest, grp_loc, issues)

    # onmatch="include" with zero rules/groups effectively logs nothing for this event type.
    if eb.onmatch == "include" and not eb.rules and not eb.groups:
        issues.append(ValidationIssue(
            "warning",
            f"<{eb.tag} onmatch=\"include\"> with no rules means NOTHING of this event type "
            "will be logged.", loc, kind="tag", tag=tag))


def _check_rule_list(rules, tag, valid_fields, manifest: SchemaManifest, loc, issues):
    for rule in rules:
        rule_loc = f"{loc} / {rule.rule_field}"

        if rule.rule_field not in valid_fields:
            issues.append(ValidationIssue(
                "warning",
                f"Field '{rule.rule_field}' is not in the active schema's (v{manifest.version}) "
                f"filterable-field list for <{tag}> ({manifest.description_for_tag(tag)}). It may "
                "still work if your actual Sysmon version supports it, but double-check spelling "
                "and consider switching the active schema.",
                rule_loc, kind="rule", uid=rule.uid, tag=tag))

        if rule.condition not in manifest.conditions:
            issues.append(ValidationIssue(
                "error",
                f"'{rule.condition}' is not a valid condition operator in the active schema "
                f"(v{manifest.version}).", rule_loc, kind="rule", uid=rule.uid, tag=tag))
        elif rule.condition in NUMERIC_CONDITIONS:
            if not rule.value.strip().lstrip("-").isdigit():
                issues.append(ValidationIssue(
                    "warning",
                    f"Condition '{rule.condition}' is typically used with numeric values; "
                    f"value '{rule.value}' does not look numeric.",
                    rule_loc, kind="rule", uid=rule.uid, tag=tag))

        if "&" in rule.value:
            issues.append(ValidationIssue(
                "error",
                "Value contains a literal '&'. Sysmon XML requires '&amp;' instead — "
                "this will fail to parse as-is.",
                rule_loc, kind="rule", uid=rule.uid, tag=tag))

        if not rule.value.strip():
            issues.append(ValidationIssue(
                "warning", "Rule has an empty value.", rule_loc, kind="rule", uid=rule.uid, tag=tag))


def format_issues(issues: List[ValidationIssue]) -> str:
    if not issues:
        return "No issues found. Configuration looks valid."
    lines = []
    errors = [i for i in issues if i.severity == "error"]
    warnings = [i for i in issues if i.severity == "warning"]
    lines.append(f"{len(errors)} error(s), {len(warnings)} warning(s)")
    lines.append("")
    for i in issues:
        tag = "ERROR" if i.severity == "error" else "WARN "
        loc = f"  [{i.location}]" if i.location else ""
        lines.append(f"[{tag}] {i.message}{loc}")
    return "\n".join(lines)
