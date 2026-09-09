"""
server.py

Flask backend for the Sysmon Config Manager web UI. Serves a small REST API
over the same UI-agnostic logic used previously by the Tkinter version
(schema.py, model.py, xml_io.py, validator.py, templates.py, apply.py) plus
the static HTML/CSS/JS frontend in static/.

Run with:  python3 server.py [path/to/config.xml]
Then open: http://127.0.0.1:5000
"""

import hashlib
import io
import os
import sys
import threading
import zipfile
from datetime import datetime

from flask import Flask, jsonify, request, send_from_directory, Response

import xml_io
import validator
import apply as apply_mod
import templates as templates_mod
import diff as diff_mod
import schema_loader
from schema_registry import SchemaRegistry
from model import SysmonConfig

app = Flask(__name__, static_folder="static", static_url_path="")

_lock = threading.Lock()
_state = {
    "cfg": SysmonConfig(),
    "current_path": None,
    "baseline_cfg": None,   # snapshot taken on New/Open, used for diff tracking
    "accumulated_changelog": [],  # changelog sections from each "Apply Changes" since the last export/open
}

registry = SchemaRegistry()
registry.load_bundled_dir(os.path.join(os.path.dirname(__file__), "schemas"))


def _auto_activate_for(cfg: SysmonConfig):
    """If the loaded config's declared schemaversion matches a registered
    manifest exactly, switch the active schema to match it."""
    if registry.has_version(cfg.schema_version):
        registry.activate(cfg.schema_version)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def serialize_rule(r):
    return {
        "uid": r.uid,
        "field": r.rule_field,
        "condition": r.condition,
        "value": r.value,
        "comment": r.comment,
        "name": r.name,
    }


def serialize_config(cfg: SysmonConfig, current_path):
    rule_groups = []
    for rg in cfg.rule_groups:
        blocks = []
        for eb in rg.event_blocks:
            rules = [serialize_rule(r) for r in eb.rules]
            groups = [{
                "uid": g.uid,
                "name": g.name,
                "group_relation": g.group_relation,
                "rules": [serialize_rule(r) for r in g.rules],
            } for g in eb.groups]
            blocks.append({"tag": eb.tag, "onmatch": eb.onmatch, "rules": rules, "groups": groups,
                            "header_comment": eb.header_comment})
        rule_groups.append({"name": rg.name, "group_relation": rg.group_relation,
                             "event_blocks": blocks})
    return {
        "current_path": current_path,
        "schema_version": cfg.schema_version,
        "hash_algorithms": cfg.hash_algorithms,
        "check_revocation": cfg.check_revocation,
        "archive_directory": cfg.archive_directory,
        "dns_lookup": cfg.dns_lookup,
        "rule_groups": rule_groups,
        "group_names": sorted({rg.name for rg in cfg.rule_groups}),
        "has_baseline": _state["baseline_cfg"] is not None,
    }


def serialize_schema():
    manifest = registry.active()
    tags = []
    for tag in manifest.all_tags():
        tags.append({
            "tag": tag,
            "description": manifest.description_for_tag(tag),
            "event_ids": manifest.event_ids_for_tag(tag),
            "fields": manifest.fields_for_tag(tag),
            "ruledefault": manifest.ruledefault_for_tag(tag),
        })
    return {
        "active_version": manifest.version,
        "tags": tags,
        "conditions": manifest.conditions,
        "numeric_conditions": sorted(schema_loader.NUMERIC_CONDITIONS),
        "onmatch_values": schema_loader.ONMATCH_VALUES,
    }


def serialize_templates():
    out = []
    for t in templates_mod.BUILTIN_TEMPLATES:
        out.append({
            "id": t.template_id,
            "name": t.name,
            "mitre_id": t.mitre_id,
            "mitre_name": t.mitre_name,
            "category": t.category,
            "tag": t.tag,
            "onmatch": t.onmatch,
            "description": t.description,
            "rules": [{"field": f, "condition": c, "value": v, "comment": cm}
                      for f, c, v, cm in t.rules],
        })
    return out


def serialize_issues(issues):
    return [{"severity": i.severity, "message": i.message, "location": i.location,
              "kind": i.kind, "uid": i.uid, "tag": i.tag}
            for i in issues]


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------------------------------------------------------------------------
# Read-only API
# ---------------------------------------------------------------------------

@app.route("/api/schema")
def api_schema():
    return jsonify(serialize_schema())


@app.route("/api/schemas")
def api_schemas():
    return jsonify(registry.list_summary())


@app.route("/api/schemas/activate", methods=["POST"])
def api_schemas_activate():
    data = request.get_json(silent=True) or {}
    version = data.get("version")
    if not version:
        return jsonify({"error": "Missing 'version'."}), 400
    try:
        registry.activate(version)
    except KeyError:
        return jsonify({"error": f"Unknown schema version '{version}'."}), 404
    return jsonify({"schema": serialize_schema(), "schemas": registry.list_summary()})


@app.route("/api/schemas/upload", methods=["POST"])
def api_schemas_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    raw = request.files["file"].read()
    try:
        manifest = schema_loader.parse_manifest_bytes(raw, source="uploaded")
    except schema_loader.SchemaParseError as exc:
        return jsonify({"error": str(exc)}), 400
    registry.register(manifest, activate=True)
    return jsonify({"schema": serialize_schema(), "schemas": registry.list_summary()})


@app.route("/api/templates")
def api_templates():
    return jsonify(serialize_templates())


@app.route("/api/state")
def api_state():
    with _lock:
        return jsonify(serialize_config(_state["cfg"], _state["current_path"]))


@app.route("/api/preview")
def api_preview():
    with _lock:
        xml_text = xml_io.to_xml_string(_state["cfg"], include_header_comment=False)
    return jsonify({"xml": xml_text})


@app.route("/api/validate")
def api_validate():
    with _lock:
        issues = validator.validate(_state["cfg"], registry.active())
    errors = sum(1 for i in issues if i.severity == "error")
    warnings = sum(1 for i in issues if i.severity == "warning")
    return jsonify({"issues": serialize_issues(issues), "errors": errors, "warnings": warnings})


@app.route("/api/diff")
def api_diff():
    with _lock:
        return jsonify(diff_mod.compute_diff(_state["baseline_cfg"], _state["cfg"]))


@app.route("/api/download")
def api_download():
    with _lock:
        xml_text = xml_io.to_xml_string(_state["cfg"], include_header_comment=True)
        path = _state["current_path"]
    filename = os.path.basename(path) if path else "sysmonconfig.xml"
    return Response(
        xml_text, mimetype="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/export-archive")
def api_export_archive():
    """Downloads a zip containing the current config XML, its SHA256/MD5
    hashes, a human-readable changelog, and the bundled Sysmon CLI reference -
    an audit-trail package, independent of Apply Changes. The changelog
    combines every batch of changes already applied since the last export
    (accumulated across however many "Apply Changes" clicks happened in
    between) plus, as a final section, whatever is still uncommitted (edited
    but not yet applied) right now. The accumulated log is cleared after a
    successful export, ready for the next round."""
    with _lock:
        cfg = _state["cfg"]
        current_path = _state["current_path"]
        xml_text = xml_io.to_xml_string(cfg, include_header_comment=True)
        schema_version = registry.active().version

        sections = list(_state["accumulated_changelog"])
        uncommitted = diff_mod.compute_diff(_state["baseline_cfg"], cfg)
        if len(uncommitted["rules"]) + len(uncommitted["groups"]) + len(uncommitted["settings"]) > 0:
            title = f"Uncommitted changes (not yet applied) - as of {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            sections.append(diff_mod.format_changelog_section(uncommitted, title))

        changelog = diff_mod.format_full_changelog(sections, current_path, schema_version)
        _state["accumulated_changelog"] = []

    xml_bytes = xml_text.encode("utf-8")
    sha256_hex = hashlib.sha256(xml_bytes).hexdigest()
    md5_hex = hashlib.md5(xml_bytes).hexdigest()

    filename_base = os.path.splitext(os.path.basename(current_path))[0] if current_path else "sysmonconfig"
    xml_filename = f"{filename_base}.xml"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(xml_filename, xml_bytes)
        zf.writestr(f"{xml_filename}.sha256", f"{sha256_hex}  {xml_filename}\n")
        zf.writestr(f"{xml_filename}.md5", f"{md5_hex}  {xml_filename}\n")
        zf.writestr("changelog.txt", changelog)
        cli_reference_path = os.path.join(os.path.dirname(__file__), "CLI_EXAMPLES.txt")
        if os.path.isfile(cli_reference_path):
            zf.write(cli_reference_path, "CLI_EXAMPLES.txt")
    buf.seek(0)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    bundle_name = f"{filename_base}_bundle_{timestamp}.zip"
    return Response(
        buf.getvalue(), mimetype="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{bundle_name}"'},
    )


# ---------------------------------------------------------------------------
# File operations
# ---------------------------------------------------------------------------

@app.route("/api/new", methods=["POST"])
def api_new():
    with _lock:
        _state["cfg"] = SysmonConfig()
        _state["current_path"] = None
        _state["baseline_cfg"] = _state["cfg"].clone()
        _state["accumulated_changelog"] = []
        _auto_activate_for(_state["cfg"])
        return jsonify(serialize_config(_state["cfg"], _state["current_path"]))


@app.route("/api/open", methods=["POST"])
def api_open():
    # Either a multipart file upload (field "file") or a JSON {"path": "..."}
    # for loading a file that's already on the server's filesystem (handy
    # when the browser and the Flask process are on the same machine, e.g.
    # this app running locally in WSL and opened in a local browser tab).
    if "file" in request.files:
        f = request.files["file"]
        raw_text = f.read().decode("utf-8-sig", errors="replace")
        try:
            cfg = xml_io.load_config_from_string(raw_text)
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": str(exc)}), 400
        with _lock:
            _state["cfg"] = cfg
            _state["current_path"] = f.filename
            _state["baseline_cfg"] = cfg.clone()
            _state["accumulated_changelog"] = []
            _auto_activate_for(cfg)
        return jsonify(serialize_config(cfg, f.filename))

    data = request.get_json(silent=True) or {}
    path = data.get("path")
    if not path:
        return jsonify({"error": "No file uploaded and no 'path' provided."}), 400
    if not os.path.isfile(path):
        return jsonify({"error": f"File not found on server: {path}"}), 404
    try:
        cfg = xml_io.load_config(path)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 400
    with _lock:
        _state["cfg"] = cfg
        _state["current_path"] = path
        _state["baseline_cfg"] = cfg.clone()
        _state["accumulated_changelog"] = []
        _auto_activate_for(cfg)
    return jsonify(serialize_config(cfg, path))


@app.route("/api/save", methods=["POST"])
def api_save():
    data = request.get_json(silent=True) or {}
    path = data.get("path")
    if not path:
        return jsonify({"error": "No 'path' provided."}), 400
    with _lock:
        try:
            xml_io.save_config(_state["cfg"], path)
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": str(exc)}), 400
        _state["current_path"] = path
        # Baseline intentionally NOT reset here - the diff view keeps
        # comparing against the originally opened file for the whole session.
    return jsonify({"ok": True, "path": path})


# ---------------------------------------------------------------------------
# Rule CRUD
# ---------------------------------------------------------------------------

@app.route("/api/rules", methods=["POST"])
def api_add_rule():
    data = request.get_json(silent=True) or {}
    required = ["tag", "onmatch", "field", "condition", "value"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
    with _lock:
        rule = _state["cfg"].add_rule(
            data["tag"], data["onmatch"], data["field"], data["condition"],
            data["value"], data.get("comment", ""), group_name=data.get("group_name", ""),
            name=data.get("name", ""),
        )
        result = serialize_config(_state["cfg"], _state["current_path"])
        result["affected_rule_uid"] = rule.uid
        return jsonify(result)


@app.route("/api/rules/<int:uid>", methods=["PUT"])
def api_edit_rule(uid):
    data = request.get_json(silent=True) or {}
    required = ["tag", "onmatch", "field", "condition", "value"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
    with _lock:
        cfg = _state["cfg"]
        located = cfg.locate_rule(uid)
        if not located:
            return jsonify({"error": f"Rule {uid} not found."}), 404
        rg, eb, container, _rule = located
        same_bucket = (eb.tag == data["tag"] and eb.onmatch == data["onmatch"]
                       and rg.name == data.get("group_name", ""))
        if same_bucket:
            # In-place update: preserves the rule's uid and its position in the
            # tree (top-level or nested inside a Rule sub-group).
            cfg.update_rule(uid, data["field"], data["condition"], data["value"],
                             data.get("comment", ""), data.get("name", ""))
            affected_uid = uid
        else:
            # Moving to a different tag/onmatch/RuleGroup bucket: only supported
            # for top-level rules. A rule nested inside a Rule sub-group keeps
            # its tag/onmatch fixed in the UI, so this path is flat-rule-only.
            cfg.remove_rule(uid)
            cfg.prune_empty()
            new_rule = cfg.add_rule(data["tag"], data["onmatch"], data["field"], data["condition"],
                         data["value"], data.get("comment", ""), group_name=data.get("group_name", ""),
                         name=data.get("name", ""))
            affected_uid = new_rule.uid
        result = serialize_config(cfg, _state["current_path"])
        result["affected_rule_uid"] = affected_uid
        return jsonify(result)


@app.route("/api/rules/<int:uid>", methods=["DELETE"])
def api_delete_rule(uid):
    with _lock:
        removed = _state["cfg"].remove_rule(uid)
        if not removed:
            return jsonify({"error": f"Rule {uid} not found."}), 404
        _state["cfg"].prune_empty()
        return jsonify(serialize_config(_state["cfg"], _state["current_path"]))


# ---------------------------------------------------------------------------
# Nested Rule sub-groups
# ---------------------------------------------------------------------------

@app.route("/api/groups", methods=["POST"])
def api_add_group():
    data = request.get_json(silent=True) or {}
    required = ["tag", "onmatch"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
    with _lock:
        group = _state["cfg"].add_group(
            data["tag"], data["onmatch"], name=data.get("name", ""),
            group_relation=data.get("group_relation", "and"),
            group_name=data.get("group_name", ""),
        )
        result = serialize_config(_state["cfg"], _state["current_path"])
        result["affected_group_uid"] = group.uid
        return jsonify(result)


@app.route("/api/groups/<int:group_uid>/rules", methods=["POST"])
def api_add_rule_to_group(group_uid):
    data = request.get_json(silent=True) or {}
    required = ["field", "condition", "value"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400
    with _lock:
        rule = _state["cfg"].add_rule_to_group(
            group_uid, data["field"], data["condition"], data["value"],
            comment=data.get("comment", ""), name=data.get("name", ""),
        )
        if rule is None:
            return jsonify({"error": f"Group {group_uid} not found."}), 404
        result = serialize_config(_state["cfg"], _state["current_path"])
        result["affected_rule_uid"] = rule.uid
        result["affected_group_uid"] = group_uid
        return jsonify(result)


@app.route("/api/groups/<int:group_uid>", methods=["DELETE"])
def api_delete_group(group_uid):
    with _lock:
        removed = _state["cfg"].remove_group(group_uid)
        if not removed:
            return jsonify({"error": f"Group {group_uid} not found."}), 404
        _state["cfg"].prune_empty()
        return jsonify(serialize_config(_state["cfg"], _state["current_path"]))


@app.route("/api/groups/<int:group_uid>", methods=["PUT"])
def api_edit_group(group_uid):
    data = request.get_json(silent=True) or {}
    if "group_relation" not in data:
        return jsonify({"error": "Missing 'group_relation'."}), 400
    if data["group_relation"] not in ("and", "or"):
        return jsonify({"error": "group_relation must be 'and' or 'or'."}), 400
    with _lock:
        ok = _state["cfg"].update_group(
            group_uid, data.get("name", ""), data["group_relation"], data.get("onmatch"),
        )
        if not ok:
            return jsonify({"error": f"Group {group_uid} not found."}), 404
        result = serialize_config(_state["cfg"], _state["current_path"])
        result["affected_group_uid"] = group_uid
        return jsonify(result)


@app.route("/api/groups/<int:group_uid>/duplicate", methods=["POST"])
def api_duplicate_group(group_uid):
    data = request.get_json(silent=True) or {}
    with _lock:
        new_group = _state["cfg"].duplicate_group(
            group_uid, name=data.get("name"), group_relation=data.get("group_relation"),
            onmatch=data.get("onmatch"),
        )
        if new_group is None:
            return jsonify({"error": f"Group {group_uid} not found."}), 404
        result = serialize_config(_state["cfg"], _state["current_path"])
        result["affected_group_uid"] = new_group.uid
        return jsonify(result)


# ---------------------------------------------------------------------------
# RuleGroup (top-level AND/OR) controls
# ---------------------------------------------------------------------------

@app.route("/api/rulegroups/relation", methods=["PUT"])
def api_set_rulegroup_relation():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "")
    relation = data.get("group_relation")
    if relation not in ("and", "or"):
        return jsonify({"error": "group_relation must be 'and' or 'or'."}), 400
    with _lock:
        ok = _state["cfg"].set_group_relation(name, relation)
        if not ok:
            return jsonify({"error": f"RuleGroup '{name}' not found."}), 404
        return jsonify(serialize_config(_state["cfg"], _state["current_path"]))


# ---------------------------------------------------------------------------
# Global settings (top-level <Sysmon> elements: HashAlgorithms, CheckRevocation,
# DnsLookup, ArchiveDirectory - apply to the whole config, not a specific rule)
# ---------------------------------------------------------------------------

@app.route("/api/settings", methods=["PUT"])
def api_update_settings():
    data = request.get_json(silent=True) or {}
    with _lock:
        cfg = _state["cfg"]
        if "hash_algorithms" in data:
            cfg.hash_algorithms = str(data["hash_algorithms"] or "")
        if "check_revocation" in data:
            cfg.check_revocation = bool(data["check_revocation"])
        if "dns_lookup" in data:
            val = data["dns_lookup"]
            cfg.dns_lookup = None if val is None else bool(val)
        if "archive_directory" in data:
            ad = data["archive_directory"]
            cfg.archive_directory = ad.strip() if ad and ad.strip() else None
        return jsonify(serialize_config(cfg, _state["current_path"]))


@app.route("/api/revert/settings/<field_name>", methods=["POST"])
def api_revert_setting(field_name):
    with _lock:
        cfg = _state["cfg"]
        baseline = _state["baseline_cfg"]
        if baseline is None or not hasattr(cfg, field_name):
            return jsonify({"error": f"Unknown setting '{field_name}'."}), 404
        setattr(cfg, field_name, getattr(baseline, field_name))
        return jsonify(serialize_config(cfg, _state["current_path"]))


# ---------------------------------------------------------------------------
# Diff revert
# ---------------------------------------------------------------------------

@app.route("/api/revert/rule/<int:uid>", methods=["POST"])
def api_revert_rule(uid):
    with _lock:
        cfg = _state["cfg"]
        d = diff_mod.compute_diff(_state["baseline_cfg"], cfg)
        info = d["rules"].get(uid)
        if not info:
            return jsonify({"error": f"No pending change for rule {uid}."}), 404

        if info["status"] == "added":
            cfg.remove_rule(uid)
            cfg.prune_empty()
        elif info["status"] == "modified":
            b = info["baseline"]
            cfg.update_rule(uid, b["field"], b["condition"], b["value"], b["comment"], b["name"])
        elif info["status"] == "deleted":
            b = info["baseline"]
            restored = cfg.restore_rule(uid, b["tag"], b["onmatch"], b["group_name"],
                                         b["field"], b["condition"], b["value"], b["comment"],
                                         b["name"], b["container_group_uid"])
            if restored is None:
                return jsonify({"error": "This rule's group was also deleted - revert the "
                                          "group first."}), 409
        return jsonify(serialize_config(cfg, _state["current_path"]))


@app.route("/api/revert/group/<int:group_uid>", methods=["POST"])
def api_revert_group(group_uid):
    with _lock:
        cfg = _state["cfg"]
        d = diff_mod.compute_diff(_state["baseline_cfg"], cfg)
        info = d["groups"].get(group_uid)
        if not info:
            return jsonify({"error": f"No pending change for group {group_uid}."}), 404

        if info["status"] == "added":
            cfg.remove_group(group_uid)
            cfg.prune_empty()
        elif info["status"] == "modified":
            b = info["baseline"]
            cfg.update_group(group_uid, b["name"], b["group_relation"], b["onmatch"])
        elif info["status"] == "deleted":
            b = info["baseline"]
            cfg.restore_group(group_uid, b["tag"], b["onmatch"], b["group_name"],
                               b["name"], b["group_relation"], b["rules"])
        return jsonify(serialize_config(cfg, _state["current_path"]))


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

@app.route("/api/templates/<template_id>/insert", methods=["POST"])
def api_insert_template(template_id):
    try:
        t = templates_mod.get_template(template_id)
    except KeyError:
        return jsonify({"error": f"Unknown template '{template_id}'"}), 404
    with _lock:
        for f, cond, val, comment in t.rules:
            _state["cfg"].add_rule(
                t.tag, t.onmatch, f, cond, val,
                comment=comment or f"Template: {t.mitre_id} {t.name}", group_name="",
            )
        return jsonify(serialize_config(_state["cfg"], _state["current_path"]))


# ---------------------------------------------------------------------------
# Apply to Sysmon
# ---------------------------------------------------------------------------

@app.route("/api/apply", methods=["POST"])
def api_apply():
    with _lock:
        path = _state["current_path"]
        cfg = _state["cfg"]
    if not path:
        return jsonify({"error": "Save the config to a file first."}), 400
    try:
        xml_io.save_config(cfg, path)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Could not save before applying: {exc}"}), 400
    ok, message = apply_mod.apply_config(path)
    return jsonify({"ok": ok, "message": message})


@app.route("/api/baseline/reset", methods=["POST"])
def api_reset_baseline():
    """Accepts the current in-app state as the new baseline: clears the
    Changes panel and resets the diff counter to zero. Purely an in-app
    bookkeeping action - does not touch disk or the local Sysmon service.
    Before resetting, the about-to-be-wiped diff is appended to an
    in-memory accumulating changelog, so a later Export Bundle still
    captures everything applied since the last export - not just since
    the last edit."""
    with _lock:
        cfg = _state["cfg"]
        diff = diff_mod.compute_diff(_state["baseline_cfg"], cfg)
        total = len(diff["rules"]) + len(diff["groups"]) + len(diff["settings"])
        if total > 0:
            title = f"Applied at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            _state["accumulated_changelog"].append(diff_mod.format_changelog_section(diff, title))
        _state["baseline_cfg"] = cfg.clone()
        return jsonify(serialize_config(cfg, _state["current_path"]))


def _detect_lan_ip():
    """Best-effort detection of this machine's LAN IP (for printing a
    ready-to-use URL when binding to 0.0.0.0) - opens a UDP "connection" to a
    public address without sending any data, just to see which local
    interface/IP the OS would route it through."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Sysmon Config Manager")
    parser.add_argument("path", nargs="?", help="Sysmon config XML file to open on startup")
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Interface to bind to. Default 127.0.0.1 (this machine only). "
             "Use 0.0.0.0 to allow other devices on your network to connect "
             "(e.g. for testing from a phone or another machine) - anyone on "
             "your network could then reach it too, so only do this on a "
             "network you trust.",
    )
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default 5000)")
    args = parser.parse_args()

    if args.path:
        path = args.path
        try:
            cfg = xml_io.load_config(path)
            _state["cfg"] = cfg
            _state["current_path"] = path
            _state["baseline_cfg"] = cfg.clone()
            _auto_activate_for(cfg)
            print(f"Loaded {path}")
        except Exception as exc:  # noqa: BLE001
            print(f"Warning: could not load '{path}': {exc}", file=sys.stderr)
    else:
        _state["baseline_cfg"] = _state["cfg"].clone()

    print(f"Active schema: v{registry.active_version} "
          f"(available: {', '.join(sorted(registry.manifests))})")

    if args.host == "0.0.0.0":
        lan_ip = _detect_lan_ip()
        print(f"Sysmon Config Manager running at http://127.0.0.1:{args.port} (this machine)")
        if lan_ip:
            print(f"                            also at http://{lan_ip}:{args.port} (other devices on your network)")
        else:
            print("Could not auto-detect your LAN IP - check it with `ipconfig` (Windows) or `ip addr` (Linux/Mac).")
    else:
        print(f"Sysmon Config Manager running at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()

