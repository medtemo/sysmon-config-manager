"""
schema_registry.py

Holds every SchemaManifest currently known to the app (the bundled
defaults, plus anything uploaded this session) and tracks which one is
"active" - i.e. which version's fields/conditions/event tags currently
constrain the UI and the validator.
"""

import glob
import os
from typing import Dict, List, Optional

import schema_loader
from schema_loader import SchemaManifest


class SchemaRegistry:
    def __init__(self):
        self.manifests: Dict[str, SchemaManifest] = {}
        self.active_version: Optional[str] = None

    def load_bundled_dir(self, dir_path: str):
        for path in sorted(glob.glob(os.path.join(dir_path, "*.xml"))):
            try:
                manifest = schema_loader.parse_manifest_file(path, source="bundled")
            except schema_loader.SchemaParseError as exc:
                print(f"Warning: could not load bundled schema {path}: {exc}")
                continue
            self.manifests[manifest.version] = manifest
        if self.manifests and not self.active_version:
            # Default to the highest version number available.
            self.active_version = sorted(self.manifests, key=_version_key)[-1]

    def register(self, manifest: SchemaManifest, activate: bool = False):
        self.manifests[manifest.version] = manifest
        if activate or not self.active_version:
            self.active_version = manifest.version

    def has_version(self, version: str) -> bool:
        return version in self.manifests

    def activate(self, version: str) -> SchemaManifest:
        if version not in self.manifests:
            raise KeyError(version)
        self.active_version = version
        return self.manifests[version]

    def active(self) -> SchemaManifest:
        if not self.active_version or self.active_version not in self.manifests:
            raise RuntimeError("No active schema manifest loaded.")
        return self.manifests[self.active_version]

    def list_summary(self) -> List[dict]:
        out = []
        for version, m in sorted(self.manifests.items(), key=lambda kv: _version_key(kv[0])):
            out.append({
                "version": version,
                "source": m.source,
                "event_count": len(m.all_tags()),
                "active": version == self.active_version,
            })
        return out


def _version_key(version: str):
    parts = []
    for p in version.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)
