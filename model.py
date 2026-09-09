"""
model.py

In-memory data model for a Sysmon configuration, independent of XML I/O so
it's easy to unit test and to drive from the GUI.

Real-world Sysmon configs (e.g. Olaf Hartong's sysmon-modular) have a third
level of nesting beyond RuleGroup -> EventBlock -> filter:

    <ProcessCreate onmatch="include">
        <ParentImage condition="image">sethc.exe</ParentImage>       <- flat filter, OR'd with siblings
        <Rule name="Eventviewer Bypass UAC" groupRelation="and">     <- nested sub-group
            <ParentImage condition="image">eventvwr.exe</ParentImage>
            <Image condition="is not">c:\\windows\\system32\\mmc.exe</Image>
        </Rule>
    </ProcessCreate>

A bare filter directly under the event tag is implicitly OR'd with its
siblings. A <Rule groupRelation="and|or"> wraps 2+ filters that must all
(and) or any (or) match together to count as one hit. This module models
both: EventBlock.rules holds the flat/top-level filters, EventBlock.groups
holds the nested RuleBlocks.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple
import itertools

_id_counter = itertools.count(1)


def _next_id():
    return next(_id_counter)


@dataclass
class FilterRule:
    """A single filter condition, e.g. <Image condition="end with">powershell.exe</Image>.
    Can live directly under an EventBlock (flat/OR'd) or inside a RuleBlock (nested AND/OR)."""
    rule_field: str            # e.g. "Image", "CommandLine"
    condition: str             # e.g. "is", "contains", "end with"
    value: str                 # the text content
    comment: str = ""          # trailing XML comment, e.g. "Windows: ..."
    name: str = ""             # optional name= attribute, often ATT&CK metadata
                                # e.g. "technique_id=T1055,technique_name=Process Injection"
    uid: int = field(default_factory=_next_id)


@dataclass
class RuleBlock:
    """A nested <Rule name="..." groupRelation="and|or"> sub-group. All (or any)
    of its FilterRules must match together for the sub-group to count as a hit."""
    name: str = ""
    group_relation: str = "and"
    rules: List[FilterRule] = field(default_factory=list)
    uid: int = field(default_factory=_next_id)


@dataclass
class EventBlock:
    """One <ProcessCreate onmatch="exclude"> ... </ProcessCreate> block."""
    tag: str                    # e.g. "ProcessCreate"
    onmatch: str                # "include" or "exclude"
    rules: List[FilterRule] = field(default_factory=list)   # flat, top-level filters
    groups: List[RuleBlock] = field(default_factory=list)   # nested Rule sub-groups
    uid: int = field(default_factory=_next_id)
    header_comment: str = ""    # standalone <!-- --> comment(s) that preceded this
                                 # block's enclosing RuleGroup in the source XML
                                 # (e.g. "Event ID 26 == File Delete ... - Includes")


@dataclass
class RuleGroup:
    """<RuleGroup name="" groupRelation="or"> ... </RuleGroup>"""
    name: str = ""
    group_relation: str = "or"
    event_blocks: List[EventBlock] = field(default_factory=list)
    uid: int = field(default_factory=_next_id)


@dataclass
class SysmonConfig:
    schema_version: str = "4.50"
    hash_algorithms: str = "md5,sha256,IMPHASH"
    check_revocation: bool = True
    archive_directory: Optional[str] = None
    dns_lookup: Optional[bool] = None
    rule_groups: List[RuleGroup] = field(default_factory=list)
    source_path: Optional[str] = None
    header_comment: str = ""   # preserved leading XML comment block, if any

    def blocks_for_tag(self, tag: str) -> List[EventBlock]:
        out = []
        for rg in self.rule_groups:
            for eb in rg.event_blocks:
                if eb.tag == tag:
                    out.append(eb)
        return out

    def all_tags_present(self) -> List[str]:
        tags = set()
        for rg in self.rule_groups:
            for eb in rg.event_blocks:
                tags.add(eb.tag)
        return sorted(tags)

    def _find_or_create_block(self, tag: str, onmatch: str, group_name: str) -> Tuple[RuleGroup, EventBlock]:
        rg = None
        for candidate in self.rule_groups:
            if candidate.name == group_name:
                rg = candidate
                break
        if rg is None:
            rg = RuleGroup(name=group_name, group_relation="or")
            self.rule_groups.append(rg)

        eb = None
        for candidate in rg.event_blocks:
            if candidate.tag == tag and candidate.onmatch == onmatch:
                eb = candidate
                break
        if eb is None:
            eb = EventBlock(tag=tag, onmatch=onmatch)
            rg.event_blocks.append(eb)

        return rg, eb

    def add_rule(self, tag: str, onmatch: str, rule_field: str, condition: str,
                 value: str, comment: str = "", group_name: str = "",
                 name: str = "") -> FilterRule:
        """Find or create a RuleGroup/EventBlock matching (group_name, tag,
        onmatch) and append a new top-level (flat) FilterRule to it."""
        _, eb = self._find_or_create_block(tag, onmatch, group_name)
        rule = FilterRule(rule_field=rule_field, condition=condition,
                           value=value, comment=comment, name=name)
        eb.rules.append(rule)
        return rule

    def add_group(self, tag: str, onmatch: str, name: str = "", group_relation: str = "and",
                   group_name: str = "") -> RuleBlock:
        """Find or create a RuleGroup/EventBlock and append a new, empty nested
        Rule sub-group to it. Add filters into it with add_rule_to_group()."""
        _, eb = self._find_or_create_block(tag, onmatch, group_name)
        block = RuleBlock(name=name, group_relation=group_relation)
        eb.groups.append(block)
        return block

    def add_rule_to_group(self, group_uid: int, rule_field: str, condition: str,
                           value: str, comment: str = "", name: str = "") -> Optional[FilterRule]:
        for rg in self.rule_groups:
            for eb in rg.event_blocks:
                for grp in eb.groups:
                    if grp.uid == group_uid:
                        rule = FilterRule(rule_field=rule_field, condition=condition,
                                           value=value, comment=comment, name=name)
                        grp.rules.append(rule)
                        return rule
        return None

    def locate_rule(self, uid: int):
        """Returns (rule_group, event_block, container, rule) where container is
        either the event_block itself (flat rule) or the RuleBlock it's nested in.
        Returns None if not found."""
        for rg in self.rule_groups:
            for eb in rg.event_blocks:
                for r in eb.rules:
                    if r.uid == uid:
                        return rg, eb, eb, r
                for grp in eb.groups:
                    for r in grp.rules:
                        if r.uid == uid:
                            return rg, eb, grp, r
        return None

    def update_rule(self, uid: int, rule_field: str, condition: str, value: str,
                     comment: str = "", name: str = "") -> bool:
        """Update a rule's field/condition/value/comment/name in place,
        wherever it lives (flat or nested) - preserves its position in the tree."""
        found = self.locate_rule(uid)
        if not found:
            return False
        _, _, _, rule = found
        rule.rule_field = rule_field
        rule.condition = condition
        rule.value = value
        rule.comment = comment
        rule.name = name
        return True

    def remove_rule(self, uid: int) -> bool:
        for rg in self.rule_groups:
            for eb in rg.event_blocks:
                before = len(eb.rules)
                eb.rules = [r for r in eb.rules if r.uid != uid]
                if len(eb.rules) != before:
                    return True
                for grp in eb.groups:
                    before_g = len(grp.rules)
                    grp.rules = [r for r in grp.rules if r.uid != uid]
                    if len(grp.rules) != before_g:
                        return True
        return False

    def remove_group(self, group_uid: int) -> bool:
        for rg in self.rule_groups:
            for eb in rg.event_blocks:
                before = len(eb.groups)
                eb.groups = [g for g in eb.groups if g.uid != group_uid]
                if len(eb.groups) != before:
                    return True
        return False

    def set_group_relation(self, name: str, group_relation: str) -> bool:
        """Set the AND/OR groupRelation on a top-level <RuleGroup name="...">."""
        for rg in self.rule_groups:
            if rg.name == name:
                rg.group_relation = group_relation
                return True
        return False

    def update_group(self, group_uid: int, name: str, group_relation: str,
                      onmatch: Optional[str] = None) -> bool:
        """Update a nested Rule sub-group's name/AND-OR relation in place. If
        onmatch is given and differs from its current event block's onmatch,
        the group (and only that group - its siblings are unaffected) is
        moved to the matching onmatch bucket under the same tag/RuleGroup."""
        for rg in self.rule_groups:
            for eb in rg.event_blocks:
                for grp in eb.groups:
                    if grp.uid != group_uid:
                        continue
                    grp.name = name
                    grp.group_relation = group_relation
                    if onmatch is not None and onmatch != eb.onmatch:
                        eb.groups.remove(grp)
                        _, target_eb = self._find_or_create_block(eb.tag, onmatch, rg.name)
                        target_eb.groups.append(grp)
                    return True
        return False

    def duplicate_group(self, group_uid: int, name: Optional[str] = None,
                         group_relation: Optional[str] = None,
                         onmatch: Optional[str] = None) -> Optional[RuleBlock]:
        """Clone a nested Rule sub-group (and all its filters, each getting a
        fresh uid). name/group_relation/onmatch override the source group's
        values if given (used when the user edits the duplicate before
        confirming); otherwise the exact source values are used. If the
        resolved onmatch differs from the source's, the duplicate goes into
        that onmatch's bucket instead of alongside the original."""
        for rg in self.rule_groups:
            for eb in rg.event_blocks:
                for grp in eb.groups:
                    if grp.uid != group_uid:
                        continue
                    new_name = grp.name if name is None else name
                    new_relation = grp.group_relation if group_relation is None else group_relation
                    new_block = RuleBlock(name=new_name, group_relation=new_relation)
                    for r in grp.rules:
                        new_block.rules.append(FilterRule(
                            rule_field=r.rule_field, condition=r.condition, value=r.value,
                            comment=r.comment, name=r.name,
                        ))
                    target_onmatch = eb.onmatch if onmatch is None else onmatch
                    if target_onmatch != eb.onmatch:
                        _, target_eb = self._find_or_create_block(eb.tag, target_onmatch, rg.name)
                        target_eb.groups.append(new_block)
                    else:
                        eb.groups.append(new_block)
                    return new_block
        return None

    def clone(self) -> "SysmonConfig":
        import copy
        return copy.deepcopy(self)

    def restore_rule(self, uid: int, tag: str, onmatch: str, group_name: str,
                      rule_field: str, condition: str, value: str, comment: str,
                      name: str, container_group_uid) -> Optional[FilterRule]:
        """Re-insert a previously-deleted rule with its ORIGINAL uid, used to
        revert a diff. If container_group_uid is set, the rule is restored into
        that (still-existing) nested RuleBlock; otherwise it goes back in flat."""
        _, eb = self._find_or_create_block(tag, onmatch, group_name)
        rule = FilterRule(rule_field=rule_field, condition=condition, value=value,
                           comment=comment, name=name, uid=uid)
        if container_group_uid is not None:
            for grp in eb.groups:
                if grp.uid == container_group_uid:
                    grp.rules.append(rule)
                    return rule
            return None  # the group itself no longer exists; caller must restore it first
        eb.rules.append(rule)
        return rule

    def restore_group(self, group_uid: int, tag: str, onmatch: str, group_name: str,
                       name: str, group_relation: str, rules_data: list) -> RuleBlock:
        """Re-insert a previously-deleted nested Rule sub-group (and all its
        rules) with their ORIGINAL uids, used to revert a diff."""
        _, eb = self._find_or_create_block(tag, onmatch, group_name)
        block = RuleBlock(name=name, group_relation=group_relation, uid=group_uid)
        for rd in rules_data:
            block.rules.append(FilterRule(
                rule_field=rd["field"], condition=rd["condition"], value=rd["value"],
                comment=rd.get("comment", ""), name=rd.get("name", ""), uid=rd["uid"],
            ))
        eb.groups.append(block)
        return block

    def prune_empty(self):
        """Remove groups/event blocks/rule groups left with no rules."""
        for rg in self.rule_groups:
            for eb in rg.event_blocks:
                eb.groups = [g for g in eb.groups if g.rules]
            rg.event_blocks = [eb for eb in rg.event_blocks if eb.rules or eb.groups]
        self.rule_groups = [rg for rg in self.rule_groups if rg.event_blocks]
