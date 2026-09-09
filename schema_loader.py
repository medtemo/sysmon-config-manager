"""
schema_loader.py

Parses Sysmon's own schema export format (`sysmon -s` / `sysmon.exe -s`,
also called a "manifest") into a structured, queryable SchemaManifest.
This is the authoritative source of truth for a given Sysmon version's
valid event types, fields, and filter conditions - replacing the
hand-maintained lists that used to live in schema.py.

Manifest shape (abbreviated):

    <manifest schemaversion="4.82" binaryversion="17">
      <configuration>
        <options>...</options>
        <filters default="is">is,is not,contains,...</filters>
      </configuration>
      <events>
        <event name="SYSMONEVENT_CREATE_PROCESS" value="1" level="Informational"
               template="Process Create" rulename="ProcessCreate" ruledefault="include" version="5">
          <data name="RuleName" inType="win:UnicodeString" outType="xs:string" />
          <data name="UtcTime" .../>
          ...
        </event>
        ...
      </events>
    </manifest>

Not every <event> is rule-filterable (e.g. SYSMONEVENT_ERROR / internal
service-state events have no `rulename` attribute) - those are skipped.
Some event IDs share a rulename (12/13/14 all -> RegistryEvent); fields are
unioned across them the same way the rest of the app already expects.

Manifest files may be UTF-8, UTF-8 with BOM, or UTF-16 (Sysmon on Windows
tends to emit UTF-16LE) - _decode() handles all three.
"""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Dict


# Conditions that only make sense on numeric fields. The manifest's <filters>
# list doesn't distinguish these, so we classify by name.
NUMERIC_CONDITIONS = {"less than", "more than"}

ONMATCH_VALUES = ["include", "exclude"]


@dataclass
class SchemaEvent:
    event_id: int
    tag: str              # rulename, e.g. "ProcessCreate"
    description: str      # template, e.g. "Process Create"
    ruledefault: str      # "include" | "exclude" | ""
    fields: List[str] = field(default_factory=list)


@dataclass
class SchemaManifest:
    version: str
    binary_version: str
    conditions: List[str]
    events: List[SchemaEvent]
    source: str = "bundled"   # "bundled" | "uploaded"

    def all_tags(self) -> List[str]:
        seen = []
        for e in sorted(self.events, key=lambda e: e.event_id):
            if e.tag not in seen:
                seen.append(e.tag)
        return seen

    def fields_for_tag(self, tag: str) -> List[str]:
        out, seen = [], set()
        for e in self.events:
            if e.tag != tag:
                continue
            for f in e.fields:
                if f not in seen:
                    seen.add(f)
                    out.append(f)
        return out

    def description_for_tag(self, tag: str) -> str:
        descs = [e.description for e in self.events if e.tag == tag]
        return " / ".join(dict.fromkeys(descs))

    def event_ids_for_tag(self, tag: str) -> List[int]:
        return sorted(e.event_id for e in self.events if e.tag == tag)

    def ruledefault_for_tag(self, tag: str) -> str:
        for e in self.events:
            if e.tag == tag and e.ruledefault:
                return e.ruledefault
        return "exclude"


class SchemaParseError(ValueError):
    pass


def _decode(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe"):
        return raw.decode("utf-16-le")
    if raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16-be")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    # No BOM: sniff for UTF-16's telltale NUL-byte pattern before assuming UTF-8.
    if b"\x00" in raw[:200]:
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    return raw.decode("utf-8", errors="replace")


def parse_manifest_bytes(raw: bytes, source: str = "uploaded") -> SchemaManifest:
    text = _decode(raw)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise SchemaParseError(f"Not valid XML: {exc}") from exc

    if root.tag != "manifest":
        raise SchemaParseError(f"Root element is <{root.tag}>, expected <manifest> "
                                "(this doesn't look like a `sysmon -s` schema export).")

    version = root.get("schemaversion")
    if not version:
        raise SchemaParseError("Missing schemaversion attribute on <manifest>.")

    filters_elem = root.find("./configuration/filters")
    if filters_elem is not None and filters_elem.text:
        conditions = [c.strip() for c in filters_elem.text.split(",") if c.strip()]
    else:
        conditions = ["is", "is not", "contains", "begin with", "end with"]

    events = []
    for e in root.findall("./events/event"):
        tag = e.get("rulename")
        if not tag:
            continue  # not a filterable/rule-bearing event (errors, service state, etc.)
        try:
            event_id = int(e.get("value"))
        except (TypeError, ValueError):
            continue
        fields = [d.get("name") for d in e.findall("data") if d.get("name")]
        events.append(SchemaEvent(
            event_id=event_id,
            tag=tag,
            description=e.get("template", tag),
            ruledefault=e.get("ruledefault", ""),
            fields=fields,
        ))

    if not events:
        raise SchemaParseError("No rule-filterable <event> elements with a rulename found.")

    return SchemaManifest(version=version, binary_version=root.get("binaryversion", ""),
                           conditions=conditions, events=events, source=source)


def parse_manifest_file(path: str, source: str = "bundled") -> SchemaManifest:
    with open(path, "rb") as f:
        raw = f.read()
    return parse_manifest_bytes(raw, source=source)
