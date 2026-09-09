"""
xml_io.py

Parses a Sysmon XML config file into the SysmonConfig model, and serializes
a SysmonConfig back to XML text in a style close to the community-standard
sysmon-config formatting (tab indentation, inline trailing comments on each
filter rule).

Comment handling: real-world Sysmon configs (like SwiftOnSecurity's) rely
heavily on trailing XML comments to document *why* a rule exists, e.g.:

    <Image condition="is">C:\\Windows\\system32\\conhost.exe</Image> <!--Windows: Command line interface host process-->

Plain xml.etree.ElementTree discards comments by default. We use a
TreeBuilder with insert_comments=True so comment nodes remain in the tree in
document order, then treat a comment that immediately follows a filter
element as "belonging" to that rule.
"""

import re
import xml.etree.ElementTree as ET
from typing import Optional

from model import SysmonConfig, RuleGroup, EventBlock, RuleBlock, FilterRule

COMMENT_TAG = ET.Comment


def _make_parser():
    target = ET.TreeBuilder(insert_comments=True)
    return ET.XMLParser(target=target)


def _extract_header_comment(raw_text: str) -> str:
    """Grab the big leading <!-- ... --> block before <Sysmon ...> if present."""
    match = re.match(r"\s*<!--(.*?)-->\s*(?=<Sysmon)", raw_text, re.DOTALL)
    if match:
        return match.group(1)
    return ""


def load_config(path: str) -> SysmonConfig:
    with open(path, "r", encoding="utf-8-sig") as f:
        raw_text = f.read()
    cfg = load_config_from_string(raw_text)
    cfg.source_path = path
    return cfg


def load_config_from_string(raw_text: str) -> SysmonConfig:
    parser = _make_parser()
    parser.feed(raw_text)
    root = parser.close()

    if root.tag != "Sysmon":
        raise ValueError(f"Root element is <{root.tag}>, expected <Sysmon>")

    cfg = SysmonConfig()
    cfg.schema_version = root.get("schemaversion", "4.50")
    cfg.header_comment = _extract_header_comment(raw_text)

    # Top-level meta config, before <EventFiltering>
    for child in root:
        if child.tag == COMMENT_TAG:
            continue
        if child.tag == "HashAlgorithms":
            cfg.hash_algorithms = (child.text or "").strip()
        elif child.tag == "CheckRevocation":
            text = (child.text or "").strip().lower()
            # Some configs self-close this tag to mean "enabled" (SwiftOnSecurity
            # style); others give it explicit true/false text (sysmon-modular
            # style, e.g. <CheckRevocation>False</CheckRevocation>).
            cfg.check_revocation = text not in ("false", "0")
        elif child.tag == "ArchiveDirectory":
            cfg.archive_directory = (child.text or "").strip()
        elif child.tag == "DnsLookup":
            cfg.dns_lookup = (child.text or "").strip().lower() == "true"
        elif child.tag == "EventFiltering":
            _parse_event_filtering(child, cfg)

    return cfg


def _parse_event_filtering(ef_elem, cfg: SysmonConfig):
    pending_comment_parts = []
    for node in ef_elem:
        if node.tag == COMMENT_TAG:
            text = (node.text or "").strip()
            if text:
                pending_comment_parts.append(text)
            continue
        if node.tag != "RuleGroup":
            continue
        header_comment = "\n".join(pending_comment_parts)
        pending_comment_parts = []
        rg_elem = node
        rg = RuleGroup(
            name=rg_elem.get("name", ""),
            group_relation=rg_elem.get("groupRelation", "or"),
        )
        children = list(rg_elem)
        i = 0
        first_eb = True
        while i < len(children):
            node2 = children[i]
            if node2.tag == COMMENT_TAG:
                i += 1
                continue
            eb = EventBlock(tag=node2.tag, onmatch=node2.get("onmatch", "include"))
            if first_eb:
                eb.header_comment = header_comment
                first_eb = False
            _parse_event_block(node2, eb)
            rg.event_blocks.append(eb)
            i += 1
        cfg.rule_groups.append(rg)


def _parse_event_block(node, eb: EventBlock):
    children = list(node)
    i = 0
    while i < len(children):
        child = children[i]
        if child.tag == COMMENT_TAG:
            i += 1
            continue
        if child.tag == "Rule":
            eb.groups.append(_parse_rule_block(child))
            i += 1
            continue
        comment_text = ""
        if i + 1 < len(children) and children[i + 1].tag == COMMENT_TAG:
            comment_text = (children[i + 1].text or "").strip()
        rule = FilterRule(
            rule_field=child.tag,
            condition=child.get("condition", "is"),
            value=(child.text or "").strip(),
            comment=comment_text,
            name=child.get("name", ""),
        )
        eb.rules.append(rule)
        i += 1


def _parse_rule_block(node) -> RuleBlock:
    """Parse a nested <Rule name="..." groupRelation="and|or"> sub-group."""
    block = RuleBlock(name=node.get("name", ""), group_relation=node.get("groupRelation", "and"))
    children = list(node)
    i = 0
    while i < len(children):
        child = children[i]
        if child.tag == COMMENT_TAG:
            i += 1
            continue
        comment_text = ""
        if i + 1 < len(children) and children[i + 1].tag == COMMENT_TAG:
            comment_text = (children[i + 1].text or "").strip()
        block.rules.append(FilterRule(
            rule_field=child.tag,
            condition=child.get("condition", "is"),
            value=(child.text or "").strip(),
            comment=comment_text,
            name=child.get("name", ""),
        ))
        i += 1
    return block


def _xml_escape(text: str) -> str:
    # Sysmon XML cannot contain a literal ampersand; caller is expected to
    # have already validated/escaped, but we double-escape safety here.
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))


def to_xml_string(cfg: SysmonConfig, include_header_comment: bool = True) -> str:
    lines = []

    if include_header_comment and cfg.header_comment:
        lines.append(f"<!--{cfg.header_comment}-->")
        lines.append("")

    lines.append(f'<Sysmon schemaversion="{cfg.schema_version}">')
    lines.append(f"\t<HashAlgorithms>{_xml_escape(cfg.hash_algorithms)}</HashAlgorithms>")
    lines.append(f"\t<CheckRevocation>{'true' if cfg.check_revocation else 'false'}</CheckRevocation>")
    if cfg.archive_directory:
        lines.append(f"\t<ArchiveDirectory>{_xml_escape(cfg.archive_directory)}</ArchiveDirectory>")
    if cfg.dns_lookup is not None:
        lines.append(f"\t<DnsLookup>{'true' if cfg.dns_lookup else 'false'}</DnsLookup>")
    lines.append("")
    lines.append("\t<EventFiltering>")

    for rg in cfg.rule_groups:
        if not rg.event_blocks:
            continue
        header_comment = next((eb.header_comment for eb in rg.event_blocks if eb.header_comment), "")
        if header_comment:
            for comment_line in header_comment.split("\n"):
                lines.append(f"\t<!-- {comment_line} -->")
        name_attr = _xml_escape(rg.name)
        lines.append(f'\t<RuleGroup name="{name_attr}" groupRelation="{rg.group_relation}">')
        for eb in rg.event_blocks:
            if not eb.rules and not eb.groups:
                continue
            lines.append(f'\t\t<{eb.tag} onmatch="{eb.onmatch}">')
            for r in eb.rules:
                lines.append("\t\t\t" + _render_filter_line(r))
            for grp in eb.groups:
                if not grp.rules:
                    continue
                name_part = f' name="{_xml_escape(grp.name)}"' if grp.name else ""
                lines.append(f'\t\t\t<Rule{name_part} groupRelation="{grp.group_relation}">')
                for r in grp.rules:
                    lines.append("\t\t\t\t" + _render_filter_line(r))
                lines.append("\t\t\t</Rule>")
            lines.append(f"\t\t</{eb.tag}>")
        lines.append("\t</RuleGroup>")

    lines.append("\t</EventFiltering>")
    lines.append("</Sysmon>")
    return "\n".join(lines) + "\n"


def _render_filter_line(r: FilterRule) -> str:
    val = _xml_escape(r.value)
    name_part = f' name="{_xml_escape(r.name)}"' if r.name else ""
    comment = f" <!--{r.comment}-->" if r.comment else ""
    return f'<{r.rule_field}{name_part} condition="{r.condition}">{val}</{r.rule_field}>{comment}'


def save_config(cfg: SysmonConfig, path: str, include_header_comment: bool = True):
    text = to_xml_string(cfg, include_header_comment=include_header_comment)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    cfg.source_path = path
