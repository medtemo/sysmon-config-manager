"use strict";

const state = {
  schema: null,        // { active_version, tags: [...], conditions: [...], onmatch_values: [...] }
  schemas: [],          // [{version, source, event_count, active}, ...]
  cfg: null,           // serialized SysmonConfig from /api/state
  diff: { rules: {}, groups: {}, settings: {} },  // from /api/diff, keyed by uid (string keys, JSON-side)
  onmatchFilter: "all", // "all" | "include" | "exclude"
  currentTag: null,
  editingUid: null,      // set when the rule modal is editing an existing rule in place
  targetGroupUid: null,  // set when adding/duplicating a rule INTO a specific nested Rule sub-group
  editingGroupUid: null, // set when the group modal is editing an existing nested group in place
  duplicateSourceGroupUid: null, // set when the group modal is duplicating (review-before-create)
  pathModalMode: null, // "open" | "save"
  sidebarCollapsed: false,
  sidePanelCollapsed: false,
  collapsedGroups: new Set(),   // nested-group uids currently collapsed (persists across renders)
  collapsedSections: new Set(), // "<tag>:<onmatch>" keys currently collapsed (Include/Exclude sections)
  sortColumn: null,             // active sort column key, or null
  sortDir: "asc",                // "asc" | "desc"
  columnFilters: { group: "", onmatch: "", field: "", condition: "", value: "", technique: "", comment: "", status: "" },
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

function toast(message, kind) {
  const el = $("toast");
  el.textContent = message;
  el.className = "toast" + (kind ? " " + kind : "");
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 3500);
}

function setStatus(text) {
  $("statusMessage").textContent = text;
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: options.body instanceof FormData ? {} : { "Content-Type": "application/json" },
    ...options,
  });
  let data = null;
  try { data = await res.json(); } catch (_) { /* non-JSON (e.g. download) */ }
  if (!res.ok) {
    const msg = (data && data.error) ? data.error : `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return data;
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// Best-effort parse of the ATT&CK-style name= convention used by configs like
// sysmon-modular, e.g. "technique_id=T1055,technique_name=Process Injection".
// Falls back to showing the raw name for freeform labels that don't match.
function formatTechnique(name) {
  if (!name) return "";
  const idMatch = name.match(/technique[_]?id=([^,]+)/i);
  const nameMatch = name.match(/technique[_]?name=([^,]+)/i);
  if (idMatch || nameMatch) {
    return [idMatch?.[1], nameMatch?.[1]].filter(Boolean).join(" — ");
  }
  return name;
}

// Builds a readable "what changed" line for a modified nested group, e.g.
// 'AND → OR', 'include → exclude', 'renamed "Old" → "New"'.
function groupModifiedSummary(groupDiff) {
  const b = groupDiff.baseline, c = groupDiff.current;
  const parts = [];
  if (b.name !== c.name) {
    parts.push(`renamed "${escapeHtml(b.name || "(unnamed)")}" → "${escapeHtml(c.name || "(unnamed)")}"`);
  }
  if (b.group_relation !== c.group_relation) {
    parts.push(`${b.group_relation.toUpperCase()} → ${c.group_relation.toUpperCase()}`);
  }
  if (b.onmatch !== c.onmatch) {
    parts.push(`${b.onmatch} → ${c.onmatch}`);
  }
  return parts.join(", ") || "modified";
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

async function init() {
  bindGlobalEvents();
  applyStoredTheme();
  try {
    state.schema = await api("/api/schema");
    state.schemas = await api("/api/schemas");
    state.cfg = await api("/api/state");
  } catch (err) {
    toast("Failed to load app: " + err.message, "error");
    return;
  }
  state.currentTag = state.schema.tags[0]?.tag || null;
  await renderAll();
  warnIfSchemaMismatchOnLoad();
  showPendingToast();
}

// Reload-based resets (New/Close/Open) wipe out any toast shown right before
// the reload, so the confirmation message is stashed here and picked back up
// once the fresh page finishes loading.
function stashPendingToast(message, type) {
  sessionStorage.setItem("pendingToast", JSON.stringify({ message, type }));
}

function showPendingToast() {
  const raw = sessionStorage.getItem("pendingToast");
  if (!raw) return;
  sessionStorage.removeItem("pendingToast");
  try {
    const { message, type } = JSON.parse(raw);
    toast(message, type);
  } catch { /* ignore malformed/stale entry */ }
}

async function renderAll() {
  await refreshDiff();
  renderFileLabel();
  renderSchemaSelect();
  renderSidebar();
  renderRulesPanel();
  refreshPreview();
  renderStatusStats();
}

// Whole-config summary shown on the right side of the footer.
function renderStatusStats() {
  let totalRules = 0, totalGroups = 0, includeCount = 0, excludeCount = 0;
  const tagsWithRules = new Set();
  for (const rg of state.cfg.rule_groups) {
    for (const eb of rg.event_blocks) {
      let hasContent = false;
      for (const r of eb.rules) {
        totalRules++;
        hasContent = true;
        if (eb.onmatch === "include") includeCount++; else excludeCount++;
      }
      for (const g of eb.groups) {
        totalGroups++;
        for (const r of g.rules) {
          totalRules++;
          hasContent = true;
          if (eb.onmatch === "include") includeCount++; else excludeCount++;
        }
      }
      if (hasContent) tagsWithRules.add(eb.tag);
    }
  }
  $("statusStats").textContent =
    `${totalRules} rules · ${totalGroups} groups · ${tagsWithRules.size} event types · ` +
    `${includeCount} include / ${excludeCount} exclude`;
}

function renderFileLabel() {
  $("fileLabel").textContent = state.cfg.current_path
    ? state.cfg.current_path.split(/[\\/]/).pop()
    : "untitled";
}

// ---------------------------------------------------------------------------
// Schema indicator / switcher
// ---------------------------------------------------------------------------

function renderSchemaSelect() {
  const active = state.schemas.find((s) => s.active);
  const btn = $("btnSchemaMenu");
  btn.textContent = (active
    ? `v${active.version} (${active.event_count} events${active.source === "uploaded" ? ", uploaded" : ""})`
    : "—") + " ▾";
  $("schemaMenuList").innerHTML = state.schemas.map((s) =>
    `<button class="dropdown-item" data-version="${escapeHtml(s.version)}">` +
    `v${escapeHtml(s.version)} (${s.event_count} events${s.source === "uploaded" ? ", uploaded" : ""})</button>`
  ).join("");
  $("schemaMenuList").querySelectorAll("[data-version]").forEach((item) => {
    item.onclick = () => {
      $("schemaMenuList").hidden = true;
      activateSchema(item.dataset.version);
    };
  });
  updateSchemaMismatchBadge();
}

// Returns {declared, active} if the loaded config's own schemaversion isn't
// the currently active one (i.e. no matching schema was found to
// auto-activate), or null if they agree / there's nothing loaded yet.
function schemaMismatchInfo() {
  if (!state.cfg?.current_path) return null; // no real file loaded yet ("untitled") - nothing to warn about
  const declared = state.cfg?.schema_version;
  const active = state.schema?.active_version;
  if (!declared || !active || declared === active) return null;
  return { declared, active };
}

function updateSchemaMismatchBadge() {
  const badge = $("schemaMismatchBadge");
  const mismatch = schemaMismatchInfo();
  if (mismatch) {
    badge.hidden = false;
    badge.title = `This config declares schema v${mismatch.declared}, which isn't loaded — currently `
      + `validating against v${mismatch.active} instead. Upload the v${mismatch.declared} schema `
      + `(Upload… button) for accurate results.`;
  } else {
    badge.hidden = true;
  }
}

// Call right after a file finishes loading (not on every render) so the
// toast only fires once per load, not on every subsequent edit.
function warnIfSchemaMismatchOnLoad() {
  const mismatch = schemaMismatchInfo();
  if (mismatch) {
    toast(`This config declares schema v${mismatch.declared}, which isn't loaded — validating against `
      + `v${mismatch.active} instead. Upload the correct schema for accurate results.`, "error");
  }
}

async function activateSchema(version) {
  try {
    const data = await api("/api/schemas/activate", { method: "POST", body: JSON.stringify({ version }) });
    state.schema = data.schema;
    state.schemas = data.schemas;
    // The active tag list may have changed - keep currentTag if it still exists, else fall back.
    if (!state.schema.tags.some((t) => t.tag === state.currentTag)) {
      state.currentTag = state.schema.tags[0]?.tag || null;
    }
    await renderAll();
    setStatus(`Active schema switched to v${version}.`);
    if (!$("validateBox").hidden) runValidate();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function uploadSchema(file) {
  const fd = new FormData();
  fd.append("file", file);
  try {
    const data = await api("/api/schemas/upload", { method: "POST", body: fd });
    state.schema = data.schema;
    state.schemas = data.schemas;
    if (!state.schema.tags.some((t) => t.tag === state.currentTag)) {
      state.currentTag = state.schema.tags[0]?.tag || null;
    }
    await renderAll();
    toast(`Loaded schema v${data.schema.active_version} from ${file.name}.`, "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

// ---------------------------------------------------------------------------
// Diff / change tracking
// ---------------------------------------------------------------------------

let _diffFetchSeq = 0;

async function refreshDiff() {
  const seq = ++_diffFetchSeq;
  let result;
  try {
    result = await api("/api/diff");
  } catch (err) {
    result = { rules: {}, groups: {}, settings: {} };
  }
  if (seq !== _diffFetchSeq) return; // a newer refreshDiff() call started since this one began - discard stale result
  state.diff = result;
  const total = Object.keys(state.diff.rules).length + Object.keys(state.diff.groups).length
    + Object.keys(state.diff.settings || {}).length;
  const pill = $("diffCount");
  if (total > 0) {
    pill.textContent = String(total);
    pill.hidden = false;
  } else {
    pill.hidden = true;
  }
  if (!$("changesPanel").hidden) renderChangesPanel();
}

function ruleDiffInfo(uid) {
  return state.diff.rules[String(uid)] || null;
}

function groupDiffInfo(uid) {
  return state.diff.groups[String(uid)] || null;
}

// ---------------------------------------------------------------------------
// Sidebar navigation (categorized event list)
// ---------------------------------------------------------------------------

// Cosmetic grouping only - purely for sidebar organization. Sysmon itself
// has no notion of these categories; every tag still maps 1:1 to its real
// XML element regardless of which bucket it's shown under here.
const EVENT_CATEGORIES = [
  { label: "Process & Execution", tags: ["ProcessCreate", "ProcessTerminate", "ProcessAccess", "ProcessTampering", "CreateRemoteThread", "ImageLoad"] },
  { label: "File & Storage", tags: ["FileCreate", "FileCreateTime", "FileCreateStreamHash", "FileDelete", "FileDeleteDetected", "FileBlockExecutable", "FileBlockShredding", "FileExecutableDetected", "RawAccessRead"] },
  { label: "Network & Remote", tags: ["NetworkConnect", "DnsQuery", "PipeEvent"] },
  { label: "Registry & System", tags: ["RegistryEvent", "DriverLoad", "WmiEvent", "SysmonConfigChange"] },
  { label: "Other", tags: [] }, // catch-all, filled in dynamically below
];

function countForTag(tag) {
  let n = 0;
  for (const rg of state.cfg.rule_groups) {
    for (const eb of rg.event_blocks) {
      if (eb.tag !== tag) continue;
      n += eb.rules.length;
      for (const g of eb.groups) n += g.rules.length;
    }
  }
  return n;
}

function renderSidebar() {
  const tree = $("eventTree");
  const query = $("sidebarFilter").value.trim().toLowerCase();
  const availableTags = new Set(state.schema.tags.map((t) => t.tag));

  const categorized = new Set();
  for (const cat of EVENT_CATEGORIES) {
    if (cat.label !== "Other") cat.tags.forEach((t) => categorized.add(t));
  }
  const otherTags = state.schema.tags.map((t) => t.tag).filter((t) => !categorized.has(t));

  tree.innerHTML = "";
  let anyVisible = false;

  for (const cat of EVENT_CATEGORIES) {
    const tags = (cat.label === "Other" ? otherTags : cat.tags).filter((t) => availableTags.has(t));
    const visibleTags = query ? tags.filter((t) => t.toLowerCase().includes(query)) : tags;
    if (visibleTags.length === 0) continue;
    anyVisible = true;

    const header = document.createElement("div");
    header.className = "event-category";
    header.textContent = cat.label;
    tree.appendChild(header);

    for (const tag of visibleTags) {
      const item = document.createElement("div");
      item.className = "event-item" + (tag === state.currentTag ? " active" : "");
      const count = countForTag(tag);
      item.innerHTML = `<span class="event-name">${escapeHtml(tag)}</span>` +
        (count ? `<span class="count">${count}</span>` : "");
      item.onclick = () => { state.currentTag = tag; renderSidebar(); renderRulesPanel(); };
      tree.appendChild(item);
    }
  }

  if (!anyVisible) {
    tree.innerHTML = '<p class="event-tree-empty">No event types match your filter.</p>';
  }
}

// ---------------------------------------------------------------------------
// Collapsible sidebar / side panel
// ---------------------------------------------------------------------------

function toggleSidebar() {
  state.sidebarCollapsed = !state.sidebarCollapsed;
  $("sidebar").classList.toggle("collapsed", state.sidebarCollapsed);
  $("sidebarDividerToggle").textContent = state.sidebarCollapsed ? "›" : "‹";
  setTimeout(updateTableOverlays, 50);
}

function toggleSidePanel() {
  state.sidePanelCollapsed = !state.sidePanelCollapsed;
  $("sidePanel").classList.toggle("collapsed", state.sidePanelCollapsed);
  $("sidePanelDividerToggle").textContent = state.sidePanelCollapsed ? "‹" : "›";
  setTimeout(updateTableOverlays, 50);
}

// Drag-to-resize on the pane dividers. Clicking the centered toggle button
// (rather than dragging the divider itself) collapses/expands instead.
function initPaneResize() {
  function makeDraggable(handle, targetEl, { min, max, invert }) {
    let dragging = null;
    handle.addEventListener("mousedown", (e) => {
      if (e.target.closest(".divider-toggle")) return;
      e.preventDefault();
      dragging = { startX: e.clientX, startWidth: targetEl.getBoundingClientRect().width };
      handle.classList.add("dragging");
    });
    document.addEventListener("mousemove", (e) => {
      if (!dragging) return;
      let delta = e.clientX - dragging.startX;
      if (invert) delta = -delta;
      const newWidth = Math.max(min, Math.min(max, dragging.startWidth + delta));
      targetEl.style.width = newWidth + "px";
      targetEl.style.flexBasis = newWidth + "px";
      updateTableOverlays();
    });
    document.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = null;
      handle.classList.remove("dragging");
    });
  }
  makeDraggable($("sidebarDivider"), $("sidebar"), { min: 160, max: 420, invert: false });
  makeDraggable($("sidePanelDivider"), $("sidePanel"), { min: 260, max: 640, invert: true });
}

// ---------------------------------------------------------------------------
// Excel-style column sort / filter / resize (main rules table)
// ---------------------------------------------------------------------------

function sortByColumn(col) {
  if (state.sortColumn === col) {
    state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
  } else {
    state.sortColumn = col;
    state.sortDir = "asc";
  }
  document.querySelectorAll("#headerRow th[data-col]").forEach((th) => {
    th.classList.remove("sorted-asc", "sorted-desc");
    if (th.dataset.col === state.sortColumn) th.classList.add(`sorted-${state.sortDir}`);
  });
  renderRulesTable();
}

function clearColumnFilters(rerender) {
  for (const key of Object.keys(state.columnFilters)) state.columnFilters[key] = "";
  document.querySelectorAll("#filterRow [data-filter-col]").forEach((el) => { el.value = ""; });
  if (rerender !== false) { renderRulesTable(); }
}

function initColumnResize() {
  let dragging = null; // { colIndex, startX, startWidth }

  document.querySelectorAll("#headerRow .col-resizer").forEach((handle) => {
    handle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const th = handle.closest("th");
      const colIndex = [...th.parentElement.children].indexOf(th);
      dragging = { colIndex, startX: e.clientX, startWidth: th.getBoundingClientRect().width };
      handle.classList.add("resizing");
    });
  });

  document.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    const newWidth = Math.max(50, dragging.startWidth + (e.clientX - dragging.startX));
    const px = newWidth + "px";
    // The header (#rulesHeaderTable) and body (#rulesTable) are two separate
    // <table> elements now - see .rules-header-wrap - so a resize has to
    // update both the header's <th> width and the body's matching <col> by
    // index to keep their columns visually aligned.
    document.querySelectorAll(`#rulesHeaderTable #headerRow th:nth-child(${dragging.colIndex + 1})`)
      .forEach((th) => { th.style.width = px; });
    document.querySelectorAll(`#rulesTable colgroup col:nth-child(${dragging.colIndex + 1})`)
      .forEach((col) => { col.style.width = px; });
  });

  document.addEventListener("mouseup", () => {
    if (!dragging) return;
    document.querySelectorAll("#headerRow .col-resizer.resizing").forEach((h) => h.classList.remove("resizing"));
    dragging = null;
  });
}

// ---------------------------------------------------------------------------
// Rules table
// ---------------------------------------------------------------------------

function currentTagMeta() {
  return state.schema.tags.find((t) => t.tag === state.currentTag);
}

function flatRulesForCurrentTag() {
  const out = [];
  for (const rg of state.cfg.rule_groups) {
    for (const eb of rg.event_blocks) {
      if (eb.tag !== state.currentTag) continue;
      for (const r of eb.rules) {
        out.push({ ...r, groupName: rg.name, onmatch: eb.onmatch });
      }
    }
  }
  // Inject individually-deleted flat rules (still shown, struck through, revertible)
  // whose original bucket was this same tag and whose container still exists as flat.
  for (const [uidStr, info] of Object.entries(state.diff.rules)) {
    if (info.status !== "deleted") continue;
    const b = info.baseline;
    if (b.tag !== state.currentTag || b.container_group_uid !== null) continue;
    out.push({
      uid: Number(uidStr), field: b.field, condition: b.condition, value: b.value,
      comment: b.comment, name: b.name, groupName: b.group_name, onmatch: b.onmatch,
    });
  }
  return out;
}

function nestedGroupsForCurrentTag() {
  const out = [];
  for (const rg of state.cfg.rule_groups) {
    for (const eb of rg.event_blocks) {
      if (eb.tag !== state.currentTag) continue;
      for (const g of eb.groups) {
        out.push({ ...g, groupName: rg.name, onmatch: eb.onmatch });
      }
    }
  }
  // Inject fully-deleted groups (whole card shown struck through, revertible as a unit).
  for (const [uidStr, info] of Object.entries(state.diff.groups)) {
    if (info.status !== "deleted") continue;
    const b = info.baseline;
    if (b.tag !== state.currentTag) continue;
    out.push({
      uid: Number(uidStr), name: b.name, group_relation: b.group_relation,
      groupName: b.group_name, onmatch: b.onmatch, rules: b.rules,
    });
  }
  return out;
}

function renderRulesPanel() {
  const meta = currentTagMeta();
  $("tagTitle").textContent = state.currentTag || "";
  $("tagDesc").textContent = meta ? meta.description : "";
  renderRulesTable();
}

function renderRulesTable() {
  const tbody = $("rulesTbody");
  const query = $("searchBox").value.trim().toLowerCase();
  let rows = flatRulesForCurrentTag();
  if (query) {
    rows = rows.filter((r) =>
      [r.field, r.condition, r.value, r.comment, r.groupName, r.name]
        .some((v) => String(v || "").toLowerCase().includes(query)));
  }

  // Excel-style per-column filters
  rows = rows.filter((r) => rowMatchesColumnFilters(r));

  function sortRows(list) {
    if (!state.sortColumn) return list;
    const col = state.sortColumn, dir = state.sortDir === "asc" ? 1 : -1;
    return [...list].sort((a, b) => {
      const av = String(columnValue(a, col) || "").toLowerCase();
      const bv = String(columnValue(b, col) || "").toLowerCase();
      return av < bv ? -1 * dir : av > bv ? 1 * dir : 0;
    });
  }

  const includeRows = sortRows(rows.filter((r) => r.onmatch === "include"));
  const excludeRows = sortRows(rows.filter((r) => r.onmatch === "exclude"));

  const sections = [];
  if (state.onmatchFilter === "all" || state.onmatchFilter === "include") sections.push("include");
  if (state.onmatchFilter === "all" || state.onmatchFilter === "exclude") sections.push("exclude");

  tbody.innerHTML = "";
  $("emptyState").hidden = true; // replaced by inline per-section empty state below

  for (const onmatch of sections) {
    const list = onmatch === "include" ? includeRows : excludeRows;
    const { trs: groupRows, count: groupCount } = buildGroupCardsForSection(onmatch);
    tbody.appendChild(buildSectionHeaderRow(onmatch, list.length, groupCount));
    const key = `${state.currentTag}:${onmatch}`;
    // A collapsed section still gets skipped normally, but not if the
    // current search query actually has matches inside it - otherwise the
    // results are just silently invisible with no indication they exist,
    // and the person has to already know to go expand a section manually
    // before their search can even show anything.
    const hasSearchMatch = query && (list.length > 0 || groupCount > 0);
    if (state.collapsedSections.has(key) && !hasSearchMatch) continue;

    // Everything appended below belongs to this section, and is marked as
    // such so it renders as a child of it - indented, hung off a tree spine
    // in the section's own colour. Collected rather than classed inline so
    // the last one can be told apart: its spine stops at its elbow instead
    // of running on into the next section.
    const children = [];
    if (list.length === 0 && groupCount === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="9" class="section-empty">No ${onmatch} rules for this event type.</td>`;
      children.push(tr);
    } else {
      for (const r of list) {
        children.push(buildRuleRow(r, null, false, "flat"));
      }
      for (const groupTr of groupRows) {
        children.push(groupTr);
      }
    }
    children.forEach((tr, i) => {
      tr.classList.add("sec-child", `sec-child-${onmatch}`);
      if (i === children.length - 1) tr.classList.add("sec-child-last");
      tbody.appendChild(tr);
    });
  }
  updateTableOverlays();
}

// The full-width header row shown above each Include/Exclude section: collapse
// chevron, rule + group counts, a note about the implicit OR logic between
// flat rules, this block's preserved source-XML header comment (if it had
// one), and per-section Collapse All / Expand All for its nested groups.
function buildSectionHeaderRow(onmatch, ruleCount, groupCount) {
  const key = `${state.currentTag}:${onmatch}`;
  const collapsed = state.collapsedSections.has(key);
  const comment = getSectionComment(state.currentTag, onmatch);
  const tr = document.createElement("tr");
  tr.className = "section-header-row";
  tr.dataset.onmatch = onmatch;
  tr.dataset.ruleCount = String(ruleCount);
  tr.dataset.groupCount = String(groupCount);
  const label = onmatch === "include" ? "Include" : "Exclude";
  const countText = `${ruleCount} rule${ruleCount === 1 ? "" : "s"}`
    + (groupCount > 0 ? ` · ${groupCount} group${groupCount === 1 ? "" : "s"}` : "");
  tr.innerHTML = `<td colspan="9">
      <button class="section-collapse-btn" title="${collapsed ? "Expand" : "Collapse"}">${collapsed ? "▶" : "▼"}</button>
      <span class="section-label section-label-${onmatch}">${label}</span>
      <span class="section-count">${countText}</span>
      <span class="section-ornote muted">OR logic — any match below triggers this</span>
      ${comment ? `<span class="section-comment" title="${escapeHtml(comment)}">— ${escapeHtml(comment.split("\n")[0])}</span>` : ""}
      ${groupCount > 0 ? `<span class="section-group-actions">
        <button class="btn btn-sm" data-act="collapseallgroups">Collapse All Groups</button>
        <button class="btn btn-sm" data-act="expandallgroups">Expand All Groups</button>
      </span>` : ""}
    </td>`;
  tr.querySelector(".section-collapse-btn").onclick = () => {
    if (state.collapsedSections.has(key)) state.collapsedSections.delete(key);
    else state.collapsedSections.add(key);
    renderRulesTable();
  };
  if (groupCount > 0) {
    tr.querySelector('[data-act="collapseallgroups"]').onclick = () => collapseAllGroups(onmatch);
    tr.querySelector('[data-act="expandallgroups"]').onclick = () => expandAllGroups(onmatch);
  }
  return tr;
}

// Looks up the preserved source-XML comment for a tag+onmatch combination
// (e.g. "Event ID 26 == File Delete ... - Includes"), if the config had one.
function getSectionComment(tag, onmatch) {
  for (const rg of state.cfg.rule_groups) {
    for (const eb of rg.event_blocks) {
      if (eb.tag === tag && eb.onmatch === onmatch && eb.header_comment) return eb.header_comment;
    }
  }
  return "";
}

// The Include/Exclude section headers pin to the top of the table with
// native CSS position:sticky, applied to each header row's <td> (see
// style.css). Sticky is handled by the compositor, so a pinned header is
// nailed in place on the very same frame the scroll is painted.
//
// An earlier version drew the pinned headers as a JS-positioned fixed
// overlay instead. That could never be fully still: scrolling in Chrome is
// composited off the main thread, so the scrolled frame is already on
// screen by the time the scroll event - and any rAF after it - runs. The
// real header row had therefore already moved by a frame's worth of scroll
// before the overlay was repositioned over it, which is the jump visible at
// the start of every scroll. No amount of threshold tuning fixes that; the
// only cure is to let the compositor do the sticking.
//
// (The old code's note that native sticky "doesn't hold up" in this layout
// was about position:sticky on the <tr>, which Chrome does ignore. On the
// <td> it works exactly as documented, the same way #headerRow th already
// relies on it.)
//
// All this needs from JS is each section's sticky offset, since they stack:
// Include rests directly at the top of .table-wrap, Exclude under Include.
// (The column headers used to live inside .table-wrap too, which is why this
// once started from their height instead of 0 - they've since moved to their
// own non-scrolling table above .table-wrap - see .rules-header-wrap in
// style.css - so they no longer take up any space for this to account for.)
// These offsets depend on measured heights, so they're written once per
// render and on resize - never during a scroll.
function applyStickySectionOffsets() {
  const rows = [...document.querySelectorAll("#rulesTbody .section-header-row")];
  let offset = 0;
  rows.forEach((tr, i) => {
    const td = tr.querySelector("td");
    if (!td) return;
    // Full fractional precision, then pulled up by 1px per level of stacking.
    // The overlap is not cosmetic paranoia - without it there is a visible
    // 1px transparent line at each seam, showing the rules scrolling past
    // behind the headers. A stuck cell is composited into its own layer that
    // is snapped to whole device pixels and clipped to its own box, and the
    // element above it is snapped independently: at every device pixel ratio
    // tested (1x, 1.25x, 1.5x, 2x) the two rounded away from each other and
    // left a gap. Nothing paintable can fill it - an outset shadow or an
    // overhanging pseudo-element is clipped away with the layer - so the
    // boxes themselves have to overlap.
    //
    // The bias accumulates (0px for the first section, 1px for the second,
    // ...), because a uniform shift moves the whole stack together and
    // leaves the sections still exactly adjacent to each other. Each section
    // therefore laps 1px under the one above it, and the descending z-index
    // means the upper element always paints over that lap, so the overlap
    // is invisible while the gap it replaces was not. The first section gets
    // no bias at all: the column headers it would otherwise be lapping are a
    // plain non-sticky div now (see above), not a compositor-sticky layer of
    // their own, so there's no independently-snapped neighbour for it to
    // gap against in the first place.
    //
    // Cost: a pinned header sits 1px above the flow position it occupied at
    // rest, so it shifts by that 1px the moment it pins. That is the
    // deliberate trade - a 1px settle nobody can see, against a transparent
    // line anybody can.
    td.style.top = (offset - i) + "px";
    td.style.zIndex = String(10 - i);
    offset += tr.getBoundingClientRect().height;
  });
}

// Keeps the floating scroll-to-top button parked in the bottom-right corner
// of .table-wrap's own visible viewport (not its scrolled content). It's
// position:fixed with JS-computed coordinates because position:absolute
// isn't reliable here - .table-wrap's offsetParent came back null in this
// nested-flex layout. Unlike the section headers this doesn't have to track
// scrolling, only layout changes.
function updateFloatingScrollButton() {
  const tableWrap = document.querySelector(".table-wrap");
  const scrollBtn = $("btnScrollTop");
  if (!tableWrap || !scrollBtn) return;
  const wrapRect = tableWrap.getBoundingClientRect();

  // Actual reserved scrollbar width, computed live rather than assumed - 0 on
  // browsers/platforms that use overlay-style scrollbars (which don't take up
  // layout space), but ~15-17px on classic scrollbars (Windows Chrome/Edge
  // default) that DO reserve a strip on the right edge. Browser-drawn
  // scrollbars always render on top of page content, so anything we position
  // past this point gets visibly cut into by the scrollbar thumb/track.
  const scrollbarWidth = tableWrap.offsetWidth - tableWrap.clientWidth;
  const contentRight = wrapRect.right - scrollbarWidth;

  scrollBtn.style.left = (contentRight - 30 - 14) + "px";
  scrollBtn.style.top = (wrapRect.bottom - 30 - 14) + "px";
}

// Re-measures everything that depends on the panel's layout. Called after a
// render and whenever the panes are resized - never on scroll.
function updateTableOverlays() {
  applyStickySectionOffsets();
  updateFloatingScrollButton();
}

// Reads the display value for a given column key off a row object (rule or
// diff-reconstructed rule), used by both filtering and sorting.
function columnValue(r, col) {
  switch (col) {
    case "group": return r.groupName || "(default)";
    case "onmatch": return r.onmatch;
    case "field": return r.field;
    case "condition": return r.condition;
    case "value": return r.value;
    case "technique": return formatTechnique(r.name);
    case "comment": return r.comment;
    case "status": return (ruleDiffInfo(r.uid)?.status) || "unchanged";
    default: return "";
  }
}

function rowMatchesColumnFilters(r, filters) {
  filters = filters || state.columnFilters;
  for (const [col, filterVal] of Object.entries(filters)) {
    if (!filterVal) continue;
    const cellVal = String(columnValue(r, col) || "").toLowerCase();
    if (col === "status" && filterVal === "changed") {
      if (cellVal === "unchanged") return false;
    } else if (col === "onmatch" || col === "status") {
      if (cellVal !== filterVal) return false;
    } else if (!cellVal.includes(filterVal.toLowerCase())) {
      return false;
    }
  }
  return true;
}

function buildRuleRow(r, groupUid, suppressActions, mode) {
  const tr = document.createElement("tr");
  tr.dataset.uid = r.uid;
  const technique = formatTechnique(r.name);
  const diffInfo = ruleDiffInfo(r.uid);
  const status = diffInfo ? diffInfo.status : "unchanged";
  if (diffInfo) tr.classList.add(`diff-${diffInfo.status}`);
  const revertBtn = diffInfo ? `<button class="icon-btn-sm revert" data-act="revert" title="Revert">↺</button>` : "";
  const disableEdit = suppressActions || (diffInfo && diffInfo.status === "deleted");

  const meta = state.schema.tags.find((t) => t.tag === (r.tag || state.currentTag));
  const fieldUnknown = meta && !meta.fields.includes(r.field);
  const fieldCell = fieldUnknown
    ? `<span class="field-warning" title="Field '${escapeHtml(r.field)}' is not in the active schema (v${escapeHtml(state.schema.active_version)}) for this event type.">${escapeHtml(r.field)}</span>` +
      `<span class="field-warning-icon" title="Not in active schema v${escapeHtml(state.schema.active_version)}">⚠</span>`
    : escapeHtml(r.field);

  const statusCell = `<td><span class="status-cell-badge ${status}">${status}</span></td>`;
  const actionsCell = `
      <td class="row-actions"><div class="row-actions-inner">
        ${revertBtn}
        ${disableEdit ? "" : `<button class="icon-btn-sm" data-act="dup" title="Duplicate">⧉</button>
        <button class="icon-btn-sm" data-act="edit" title="Edit">✎</button>
        <button class="icon-btn-sm danger" data-act="del" title="Delete">🗑</button>`}
      </div></td>`;

  if (mode === "flat") {
    tr.innerHTML = `
      <td>${escapeHtml(r.groupName || "(default)")}</td>
      <td><span class="badge badge-${r.onmatch}">${r.onmatch}</span></td>
      <td>${fieldCell}</td>
      <td>${escapeHtml(r.condition)}</td>
      <td class="value-cell">${escapeHtml(r.value)}</td>
      <td>${technique ? `<span class="technique-chip" title="${escapeHtml(r.name)}">${escapeHtml(technique)}</span>` : ""}</td>
      <td>${escapeHtml(r.comment)}</td>
      ${statusCell}
      ${actionsCell}`;
  } else {
    tr.innerHTML = `
      <td>${fieldCell}</td>
      <td>${escapeHtml(r.condition)}</td>
      <td class="value-cell">${escapeHtml(r.value)}</td>
      <td>${technique ? `<span class="technique-chip" title="${escapeHtml(r.name)}">${escapeHtml(technique)}</span>` : ""}</td>
      <td>${escapeHtml(r.comment)}</td>
      ${statusCell}
      ${actionsCell}`;
  }
  if (!disableEdit) {
    tr.querySelector('[data-act="dup"]').onclick = () => openDuplicateModal(r, groupUid);
    tr.querySelector('[data-act="edit"]').onclick = () => openRuleModal(r, groupUid);
    tr.querySelector('[data-act="del"]').onclick = () => deleteRule(r.uid);
  }
  if (diffInfo) {
    tr.querySelector('[data-act="revert"]').onclick = () => revertRule(r.uid);
  }
  return tr;
}

// Rules that were deleted from a group that's still alive (not itself deleted)
// need to stay visually anchored inside that group's card, struck-through with
// a Revert button, right alongside their ADDED/MODIFIED siblings.
function deletedRulesStillInGroup(groupUid) {
  const out = [];
  for (const [uidStr, info] of Object.entries(state.diff.rules)) {
    if (info.status !== "deleted") continue;
    const b = info.baseline;
    if (b.container_group_uid !== groupUid) continue;
    out.push({
      uid: Number(uidStr), field: b.field, condition: b.condition, value: b.value,
      comment: b.comment, name: b.name,
    });
  }
  return out;
}

// Builds the nested-group cards belonging to one Include/Exclude section
// (each wrapped in a full-width <tr><td colspan> so they're valid inside the
// same <tbody> as the flat rule rows), applying the same search/column-filter
// logic as the flat rows so both stay in sync.
function buildGroupCardsForSection(onmatch) {
  const query = $("searchBox").value.trim().toLowerCase();
  let groups = nestedGroupsForCurrentTag().filter((g) => g.onmatch === onmatch);

  const rowsForGroup = new Map();
  const kept = [];
  for (const g of groups) {
    const groupDiff = groupDiffInfo(g.uid);
    const isDeleted = groupDiff && groupDiff.status === "deleted";
    let rules = isDeleted ? g.rules : [...g.rules, ...deletedRulesStillInGroup(g.uid)];

    const statusFilter = state.columnFilters.status;
    const groupItselfMatchesStatus = !!(statusFilter && groupDiff &&
      (statusFilter === "changed" || groupDiff.status === statusFilter));

    const hasActiveColumnFilter = Object.values(state.columnFilters).some((v) => v);
    if (hasActiveColumnFilter) {
      if (groupItselfMatchesStatus) {
        const nonStatusFilters = { ...state.columnFilters, status: "" };
        if (Object.values(nonStatusFilters).some((v) => v)) {
          rules = rules.filter((r) => rowMatchesColumnFilters({ ...r, groupName: g.groupName, onmatch: g.onmatch }, nonStatusFilters));
        }
      } else {
        rules = rules.filter((r) => rowMatchesColumnFilters({ ...r, groupName: g.groupName, onmatch: g.onmatch }));
        if (rules.length === 0) continue;
      }
    }

    if (query) {
      const matches = rules.some((r) =>
        [r.field, r.condition, r.value, r.comment, r.name, g.name]
          .some((v) => String(v || "").toLowerCase().includes(query)));
      if (!matches) continue;
    }

    rowsForGroup.set(g.uid, rules);
    kept.push(g);
  }

  const trs = [];
  for (const g of kept) {
    const card = buildGroupCard(g, rowsForGroup.get(g.uid));
    const tr = document.createElement("tr");
    tr.className = "group-card-row";
    const td = document.createElement("td");
    td.colSpan = 9;
    td.appendChild(card);
    tr.appendChild(td);
    trs.push(tr);
  }
  return { trs, count: kept.length };
}

// Builds a single nested-group card element (used above, and shares all the
// existing card behavior: collapse, diff highlighting, Duplicate/Edit/Delete).
function buildGroupCard(g, rules) {
  const groupDiff = groupDiffInfo(g.uid);
  const isDeleted = groupDiff && groupDiff.status === "deleted";
  const card = document.createElement("div");
  card.dataset.groupUid = g.uid;
  // A group card only reaches here at all, while a search query is active,
  // because buildGroupCardsForSection() already confirmed it has a match
  // inside - so its own collapsed state gets the same override as sections
  // above: showing the card but hiding the matching row behind a collapse
  // toggle isn't meaningfully different from not showing it at all.
  const query = $("searchBox").value.trim().toLowerCase();
  const isCollapsed = state.collapsedGroups.has(g.uid) && !query;
  card.className = "group-card" + (groupDiff ? ` diff-${groupDiff.status}` : "") + (isCollapsed ? " collapsed" : "");
  const technique = formatTechnique(g.name);
  const diffTag = groupDiff ? `<span class="diff-tag diff-tag-${groupDiff.status}">${groupDiff.status}</span>` : "";
  let diffSubtitle = "";
  if (groupDiff && groupDiff.status === "modified") {
    diffSubtitle = `<div class="group-diff-subtitle">${groupModifiedSummary(groupDiff)}</div>`;
  }
  const collapseSummary = isCollapsed
    ? `<span class="group-collapsed-summary">${rules.length} filter${rules.length === 1 ? "" : "s"}</span>` : "";
  card.innerHTML = `
    <div class="group-card-header">
      <button class="group-collapse-btn" data-act="togglecollapse" title="${isCollapsed ? "Expand" : "Collapse"}">${isCollapsed ? "+" : "−"}</button>
      ${diffTag}
      <span class="badge badge-relation">${g.group_relation.toUpperCase()}</span>
      <span class="badge badge-${g.onmatch}">${g.onmatch}</span>
      <span class="group-title">${escapeHtml(technique || g.name || "(unnamed group)")}</span>
      <span class="group-meta muted">${g.groupName ? `RuleGroup: ${escapeHtml(g.groupName)}` : ""}</span>
      ${collapseSummary}
      <div class="group-card-actions">
        ${groupDiff ? '<button class="btn btn-sm btn-revert" data-act="revertgroup">Revert</button>' : ""}
        ${isDeleted ? "" : `<button class="btn btn-sm" data-act="dupgroup">Duplicate</button>
        <button class="btn btn-sm" data-act="editgroup">Edit</button>
        <button class="btn btn-sm" data-act="addrule">+ Add rule to group</button>
        <button class="btn btn-sm btn-danger" data-act="delgroup">Delete group</button>`}
      </div>
    </div>
    ${diffSubtitle}
    <div class="group-table-wrap" ${isCollapsed ? "hidden" : ""}>
      <table class="group-table">
        <thead><tr><th>Field</th><th>Condition</th><th>Value</th><th>Technique</th><th>Comment</th><th>Status</th><th></th></tr></thead>
        <tbody></tbody>
      </table>
    </div>`;

  card.querySelector('[data-act="togglecollapse"]').onclick = () => toggleGroupCollapse(g.uid);

  const tbody = card.querySelector("tbody");
  for (const r of rules) {
    const row = buildRuleRow({ ...r, groupName: g.groupName, onmatch: g.onmatch },
                              isDeleted ? null : g.uid, isDeleted, "nested");
    tbody.appendChild(row);
  }

  if (!isDeleted) {
    card.querySelector('[data-act="addrule"]').onclick = () => openAddToGroupModal(g);
    card.querySelector('[data-act="delgroup"]').onclick = () => deleteGroup(g.uid, technique || g.name);
    card.querySelector('[data-act="dupgroup"]').onclick = () => openDuplicateGroupModal(g);
    card.querySelector('[data-act="editgroup"]').onclick = () => openEditGroupModal(g);
  }
  if (groupDiff) {
    card.querySelector('[data-act="revertgroup"]').onclick = () => revertGroup(g.uid);
  }
  return card;
}

// Backward-compatible alias - groups now render as part of renderRulesTable().
function renderGroupsSection() {
  renderRulesTable();
}

async function deleteRule(uid) {
  if (!confirm("Delete this rule?")) return;
  try {
    state.cfg = await api(`/api/rules/${uid}`, { method: "DELETE" });
    renderAll();
    setStatus("Rule deleted.");
  } catch (err) {
    toast(err.message, "error");
  }
}

function toggleGroupCollapse(uid) {
  if (state.collapsedGroups.has(uid)) state.collapsedGroups.delete(uid);
  else state.collapsedGroups.add(uid);
  renderGroupsSection();
}

function collapseAllGroups(onmatch) {
  for (const g of nestedGroupsForCurrentTag()) {
    if (!onmatch || g.onmatch === onmatch) state.collapsedGroups.add(g.uid);
  }
  renderRulesTable();
}

function expandAllGroups(onmatch) {
  for (const g of nestedGroupsForCurrentTag()) {
    if (!onmatch || g.onmatch === onmatch) state.collapsedGroups.delete(g.uid);
  }
  renderRulesTable();
}

async function deleteGroup(uid, label) {
  if (!confirm(`Delete the nested rule group "${label || "(unnamed)"}" and all ${""}its filters?`)) return;
  try {
    state.cfg = await api(`/api/groups/${uid}`, { method: "DELETE" });
    renderAll();
    setStatus("Rule group deleted.");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function revertRule(uid) {
  try {
    state.cfg = await api(`/api/revert/rule/${uid}`, { method: "POST" });
    renderAll();
    setStatus("Change reverted.");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function revertGroup(uid) {
  try {
    state.cfg = await api(`/api/revert/group/${uid}`, { method: "POST" });
    renderAll();
    setStatus("Change reverted.");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function revertSetting(fieldName) {
  try {
    state.cfg = await api(`/api/revert/settings/${fieldName}`, { method: "POST" });
    renderAll();
    setStatus("Setting reverted.");
  } catch (err) {
    toast(err.message, "error");
  }
}

// ---------------------------------------------------------------------------
// Add / Edit rule modal
// ---------------------------------------------------------------------------

function openRuleModal(existing, groupUid) {
  state.editingUid = existing ? existing.uid : null;
  state.targetGroupUid = groupUid || null;
  $("ruleModalTitle").textContent = existing ? "Edit Rule" : "Add Rule";
  populateRuleForm(existing);
  toggleBucketFields(!groupUid);
  $("ruleModalOverlay").hidden = false;
  $("fValue").focus();
}

function openDuplicateModal(existing, groupUid) {
  state.editingUid = null; // saving creates a new rule instead of replacing the original
  state.targetGroupUid = groupUid || null;
  $("ruleModalTitle").textContent = "Duplicate Rule";
  populateRuleForm(existing);
  toggleBucketFields(!groupUid);
  $("ruleModalOverlay").hidden = false;
  $("fValue").focus();
  $("fValue").select();
}

function openAddToGroupModal(group) {
  state.editingUid = null;
  state.targetGroupUid = group.uid;
  $("ruleModalTitle").textContent = `Add Rule to Group${group.name ? ": " + group.name : ""}`;
  populateRuleForm(null);
  toggleBucketFields(false);
  $("ruleModalOverlay").hidden = false;
  $("fValue").focus();
}

// Hides the Match-type / RuleGroup-name controls when the target is a specific
// nested group (its onmatch/RuleGroup are already fixed by its parent block).
function toggleBucketFields(show) {
  document.querySelectorAll(".bucket-row").forEach((el) => { el.style.display = show ? "" : "none"; });
}

function populateRuleForm(existing) {
  const meta = currentTagMeta();
  const fieldSel = $("fField");
  fieldSel.innerHTML = meta.fields.map((f) => `<option value="${escapeHtml(f)}">${escapeHtml(f)}</option>`).join("");

  const condSel = $("fCondition");
  condSel.innerHTML = state.schema.conditions.map((c) => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");

  $("groupNames").innerHTML = (state.cfg.group_names || [])
    .map((g) => `<option value="${escapeHtml(g)}">`).join("");

  $("fGroup").value = existing ? existing.groupName || "" : "";
  document.querySelector(`input[name="onmatch"][value="${existing ? existing.onmatch : "exclude"}"]`).checked = true;
  fieldSel.value = existing ? existing.field : meta.fields[0];
  condSel.value = existing ? existing.condition : "is";
  $("fValue").value = existing ? existing.value : "";
  $("fComment").value = existing ? existing.comment : "";
  $("fName").value = existing ? existing.name || "" : "";
}

function closeRuleModal() {
  $("ruleModalOverlay").hidden = true;
  state.editingUid = null;
  state.targetGroupUid = null;
}

async function saveRuleModal() {
  const value = $("fValue").value.trim();
  if (!value) { toast("Please enter a value.", "error"); return; }

  const common = {
    field: $("fField").value,
    condition: $("fCondition").value,
    value,
    comment: $("fComment").value.trim(),
    name: $("fName").value.trim(),
  };

  try {
    let resp;
    if (state.editingUid) {
      const payload = {
        ...common,
        tag: state.currentTag,
        onmatch: document.querySelector('input[name="onmatch"]:checked').value,
        group_name: $("fGroup").value.trim(),
      };
      resp = await api(`/api/rules/${state.editingUid}`, { method: "PUT", body: JSON.stringify(payload) });
      setStatus("Rule updated.");
    } else if (state.targetGroupUid) {
      resp = await api(`/api/groups/${state.targetGroupUid}/rules`, { method: "POST", body: JSON.stringify(common) });
      setStatus("Rule added to group.");
    } else {
      const payload = {
        ...common,
        tag: state.currentTag,
        onmatch: document.querySelector('input[name="onmatch"]:checked').value,
        group_name: $("fGroup").value.trim(),
      };
      resp = await api("/api/rules", { method: "POST", body: JSON.stringify(payload) });
      setStatus("Rule added.");
    }
    state.cfg = resp;
    closeRuleModal();
    focusAfterSave("rule", resp.affected_rule_uid);
  } catch (err) {
    toast(err.message, "error");
  }
}

// ---------------------------------------------------------------------------
// Add Group modal
// ---------------------------------------------------------------------------

function openAddGroupModal() {
  state.editingGroupUid = null;
  state.duplicateSourceGroupUid = null;
  $("groupModalTitle").textContent = "Add Nested Rule Group";
  $("groupModalHint").textContent = "Creates an empty AND/OR sub-group under the current event type. "
    + "Add filters to it afterward with \u201c+ Add rule to group\u201d.";
  $("groupSaveBtn").textContent = "Create";
  $("groupNameInput").value = "";
  document.querySelector('input[name="groupRelation"][value="and"]').checked = true;
  document.querySelector('input[name="groupOnmatch"][value="exclude"]').checked = true;
  $("groupModalOverlay").hidden = false;
  $("groupNameInput").focus();
}

function openEditGroupModal(g) {
  state.editingGroupUid = g.uid;
  state.duplicateSourceGroupUid = null;
  $("groupModalTitle").textContent = "Edit Rule Group";
  $("groupModalHint").textContent = "Changing match type moves this group (and only this group - its "
    + "siblings are unaffected) to the include/exclude bucket for this event type.";
  $("groupSaveBtn").textContent = "Save";
  $("groupNameInput").value = g.name || "";
  document.querySelector(`input[name="groupRelation"][value="${g.group_relation}"]`).checked = true;
  document.querySelector(`input[name="groupOnmatch"][value="${g.onmatch}"]`).checked = true;
  $("groupModalOverlay").hidden = false;
  $("groupNameInput").focus();
}

// ---------------------------------------------------------------------------
// Global settings modal (HashAlgorithms / CheckRevocation / DnsLookup / ArchiveDirectory)
// ---------------------------------------------------------------------------

function openSettingsModal() {
  const algos = (state.cfg.hash_algorithms || "").split(",").map((s) => s.trim().toUpperCase()).filter(Boolean);
  const isAll = algos.includes("*");
  $("hashAll").checked = isAll;
  document.querySelectorAll(".hash-individual").forEach((cb) => {
    cb.checked = !isAll && algos.includes(cb.value);
    cb.disabled = isAll;
  });

  document.querySelector(`input[name="checkRevocation"][value="${state.cfg.check_revocation ? "true" : "false"}"]`).checked = true;

  $("dnsLookupSelect").value = state.cfg.dns_lookup === null || state.cfg.dns_lookup === undefined
    ? "" : (state.cfg.dns_lookup ? "true" : "false");

  $("archiveDirInput").value = state.cfg.archive_directory || "";

  $("settingsModalOverlay").hidden = false;
}

async function saveSettingsModal() {
  const isAll = $("hashAll").checked;
  const hash_algorithms = isAll
    ? "*"
    : [...document.querySelectorAll(".hash-individual:checked")].map((cb) => cb.value).join(",");

  const check_revocation = document.querySelector('input[name="checkRevocation"]:checked').value === "true";

  const dnsVal = $("dnsLookupSelect").value;
  const dns_lookup = dnsVal === "" ? null : dnsVal === "true";

  const archive_directory = $("archiveDirInput").value.trim();

  try {
    state.cfg = await api("/api/settings", {
      method: "PUT",
      body: JSON.stringify({ hash_algorithms, check_revocation, dns_lookup, archive_directory }),
    });
    $("settingsModalOverlay").hidden = true;
    renderAll();
    setStatus("Global settings updated.");
  } catch (err) {
    toast(err.message, "error");
  }
}

function openDuplicateGroupModal(g) {
  state.editingGroupUid = null;
  state.duplicateSourceGroupUid = g.uid;
  $("groupModalTitle").textContent = "Duplicate Rule Group";
  $("groupModalHint").textContent = `Review before creating: this will clone all ${g.rules.length} `
    + "filter(s) from the original group into a new one. Nothing is created until you confirm.";
  $("groupSaveBtn").textContent = "Duplicate";
  $("groupNameInput").value = g.name || "";
  document.querySelector(`input[name="groupRelation"][value="${g.group_relation}"]`).checked = true;
  document.querySelector(`input[name="groupOnmatch"][value="${g.onmatch}"]`).checked = true;
  $("groupModalOverlay").hidden = false;
  $("groupNameInput").focus();
  $("groupNameInput").select();
}

async function saveGroupModal() {
  const name = $("groupNameInput").value.trim();
  const group_relation = document.querySelector('input[name="groupRelation"]:checked').value;
  const onmatch = document.querySelector('input[name="groupOnmatch"]:checked').value;
  try {
    let resp;
    if (state.editingGroupUid) {
      resp = await api(`/api/groups/${state.editingGroupUid}`, {
        method: "PUT", body: JSON.stringify({ name, group_relation, onmatch }),
      });
      setStatus("Rule group updated.");
    } else if (state.duplicateSourceGroupUid) {
      resp = await api(`/api/groups/${state.duplicateSourceGroupUid}/duplicate`, {
        method: "POST", body: JSON.stringify({ name, group_relation, onmatch }),
      });
      setStatus("Rule group duplicated.");
    } else {
      resp = await api("/api/groups", {
        method: "POST",
        body: JSON.stringify({ tag: state.currentTag, onmatch, name, group_relation, group_name: "" }),
      });
      setStatus("Rule group created. Use \u201c+ Add rule to group\u201d to populate it.");
    }
    state.cfg = resp;
    $("groupModalOverlay").hidden = true;
    focusAfterSave("group", resp.affected_group_uid);
  } catch (err) {
    toast(err.message, "error");
  }
}

// ---------------------------------------------------------------------------
// Preview / Validate side panel
// ---------------------------------------------------------------------------

async function refreshPreview() {
  try {
    const data = await api("/api/preview");
    $("previewBox").textContent = data.xml;
  } catch (err) {
    toast(err.message, "error");
  }
}

async function runValidate() {
  try {
    const data = await api("/api/validate");
    showSidePanel("validate");
    const box = $("validateBox");
    if (data.issues.length === 0) {
      box.innerHTML = '<p class="issue-ok">No issues found. Configuration looks valid.</p>';
    } else {
      box.innerHTML = data.issues.map((i, idx) => `
        <div class="issue issue-${i.severity}">
          <div class="issue-top">
            <div class="issue-msg">${escapeHtml(i.message)}</div>
            ${i.tag ? `<button class="btn btn-sm" data-idx="${idx}">View</button>` : ""}
          </div>
          ${i.location ? `<div class="issue-loc">${escapeHtml(i.location)}</div>` : ""}
        </div>`).join("");
      box.querySelectorAll("[data-idx]").forEach((btn) => {
        btn.onclick = () => jumpToValidationIssue(data.issues[Number(btn.dataset.idx)]);
      });
    }
    setStatus(`Validation complete: ${data.errors} error(s), ${data.warnings} warning(s).`);
  } catch (err) {
    toast(err.message, "error");
  }
}

// Switches to the issue's event tab and, if it points at a specific rule or
// nested group, scrolls to and highlights it (reusing the same mechanism as
// the Changes panel's "View"). Issues with no addressable rule/group (e.g.
// "this whole block has no rules") still switch tabs so you land in the
// right place, just without a single row to highlight.
async function jumpToValidationIssue(issue) {
  if (!issue.tag) return;
  state.currentTag = issue.tag;
  $("searchBox").value = "";
  clearColumnFilters(false);
  state.onmatchFilter = "all";
  document.querySelectorAll("#onmatchFilter .segment")
    .forEach((b) => b.classList.toggle("active", b.dataset.value === "all"));
  renderSidebar();
  renderRulesPanel();
  if (issue.kind === "rule" || issue.kind === "group") {
    setTimeout(() => tryHighlight(issue.kind, issue.uid), 60);
  }
}

function showSidePanel(which) {
  document.querySelectorAll(".side-tab").forEach((el) => el.classList.toggle("active", el.dataset.side === which));
  $("previewBox").hidden = which !== "preview";
  $("validateBox").hidden = which !== "validate";
  $("changesPanel").hidden = which !== "changes";
  if (which === "changes") renderChangesPanel();
}

function renderChangesPanel() {
  const box = $("changesBox");
  const query = $("changesSearchBox").value.trim().toLowerCase();
  const entries = [];

  for (const [uidStr, info] of Object.entries(state.diff.rules)) {
    const d = info.current || info.baseline;
    entries.push({ kind: "rule", uid: Number(uidStr), status: info.status, info, tag: d.tag });
  }
  for (const [uidStr, info] of Object.entries(state.diff.groups)) {
    const d = info.current || info.baseline;
    entries.push({ kind: "group", uid: Number(uidStr), status: info.status, info, tag: d.tag });
  }
  for (const [field, info] of Object.entries(state.diff.settings || {})) {
    entries.push({ kind: "settings", uid: field, status: "modified", info, tag: "Global Settings" });
  }

  if (entries.length === 0) {
    box.innerHTML = '<p class="issue-ok">No changes since this file was opened.</p>';
    return;
  }

  const order = { added: 0, modified: 1, deleted: 2 };
  entries.sort((a, b) => (order[a.status] - order[b.status]) || a.tag.localeCompare(b.tag));

  const visible = query ? entries.filter((e) => changeEntryMatches(e, query)) : entries;

  if (visible.length === 0) {
    box.innerHTML = '<p class="muted" style="padding:8px;">No changes match "' + escapeHtml(query) + '".</p>';
    return;
  }

  box.innerHTML = "";
  for (const e of visible) {
    const item = document.createElement("div");
    item.className = "changes-list-item";
    let detail = "";
    if (e.kind === "rule") {
      if (e.status === "modified") {
        const b = e.info.baseline, c = e.info.current;
        detail = `${escapeHtml(b.field)} ${escapeHtml(b.condition)} <span class="cli-detail">"${escapeHtml(b.value)}"</span>`
          + `<span class="cli-arrow">→</span><span class="cli-detail">"${escapeHtml(c.value)}"</span>`;
      } else {
        const d = e.info.current || e.info.baseline;
        detail = `${escapeHtml(d.field)} ${escapeHtml(d.condition)} <span class="cli-detail">"${escapeHtml(d.value)}"</span>`;
      }
    } else if (e.kind === "group" && e.status === "modified") {
      detail = `Rule group: ${groupModifiedSummary(e.info)}`;
    } else if (e.kind === "group") {
      const d = e.info.current || e.info.baseline;
      detail = `Rule group ${d.name ? `"${escapeHtml(d.name)}"` : "(unnamed)"} (${d.group_relation.toUpperCase()}, ${d.rules.length} filter(s))`;
    } else {
      // settings
      const fmt = (v) => v === null || v === undefined || v === "" ? "(not set)" : String(v);
      detail = `${escapeHtml(e.info.label)}: <span class="cli-detail">${escapeHtml(fmt(e.info.baseline))}</span>` +
        `<span class="cli-arrow">→</span><span class="cli-detail">${escapeHtml(fmt(e.info.current))}</span>`;
    }
    item.innerHTML = `
      <div class="cli-top">
        <span class="diff-tag diff-tag-${e.status}">${e.status}</span>
        <strong>&lt;${escapeHtml(e.tag)}&gt;</strong>
      </div>
      <div class="cli-detail">${detail}</div>
      <div class="cli-actions-row">
        <button class="icon-btn-sm" data-act="jump" title="View">👁</button>
        <button class="icon-btn-sm revert" data-act="revert" title="Revert">↺</button>
      </div>`;
    item.querySelector('[data-act="jump"]').onclick = () =>
      e.kind === "settings" ? openSettingsModal() : jumpToChange(e);
    item.querySelector('[data-act="revert"]').onclick = () => {
      if (e.kind === "rule") revertRule(e.uid);
      else if (e.kind === "group") revertGroup(e.uid);
      else revertSetting(e.uid);
    };
    box.appendChild(item);
  }
}

// Switches to the change's tab, clears any filters that could hide it, then
// scrolls the exact row (or group card) into view and briefly flashes it.
function changeEntryMatches(e, query) {
  const bits = [e.tag, e.status];
  if (e.kind === "rule") {
    for (const d of [e.info.baseline, e.info.current]) {
      if (!d) continue;
      bits.push(d.field, d.condition, d.value, d.comment, d.name, d.group_name);
    }
  } else if (e.kind === "group") {
    for (const d of [e.info.baseline, e.info.current]) {
      if (!d) continue;
      bits.push(d.name, d.group_relation, d.onmatch, d.group_name);
      for (const r of d.rules || []) bits.push(r.field, r.condition, r.value, r.name);
    }
  } else {
    bits.push(e.info.label, e.info.baseline, e.info.current);
  }
  return bits.some((v) => String(v || "").toLowerCase().includes(query));
}

// After creating/editing/duplicating a rule or group, scroll to it and
// briefly highlight it so you land exactly where the result ended up
// instead of just closing the modal and leaving you where you were.
async function focusAfterSave(kind, uid) {
  if (uid === null || uid === undefined) return;
  await renderAll();
  if (tryHighlight(kind, uid)) return;

  // Not visible under the current filters/search - clear them and retry once.
  $("searchBox").value = "";
  clearColumnFilters(false);
  state.onmatchFilter = "all";
  document.querySelectorAll("#onmatchFilter .segment")
    .forEach((b) => b.classList.toggle("active", b.dataset.value === "all"));
  renderRulesPanel();
  tryHighlight(kind, uid);
}

function tryHighlight(kind, uid) {
  let el = kind === "group"
    ? document.querySelector(`.group-card[data-group-uid="${uid}"]`)
    : document.querySelector(`tr[data-uid="${uid}"]`);
  if (!el) return false;

  const collapsedCard = el.closest(".group-card.collapsed");
  if (collapsedCard) {
    state.collapsedGroups.delete(Number(collapsedCard.dataset.groupUid));
    renderGroupsSection();
    el = kind === "group"
      ? document.querySelector(`.group-card[data-group-uid="${uid}"]`)
      : document.querySelector(`tr[data-uid="${uid}"]`);
    if (!el) return false;
  }

  el.scrollIntoView({ behavior: "smooth", block: "center" });
  el.classList.add("jump-highlight");
  setTimeout(() => el.classList.remove("jump-highlight"), 1600);
  return true;
}

function jumpToChange(e) {
  state.currentTag = e.tag;
  $("searchBox").value = "";
  state.onmatchFilter = "all";
  document.querySelectorAll("#onmatchFilter .segment")
    .forEach((b) => b.classList.toggle("active", b.dataset.value === "all"));
  clearColumnFilters(false);

  // Make sure the target isn't hidden inside a collapsed group.
  if (e.kind === "rule") {
    const d = e.info.current || e.info.baseline;
    if (d && d.container_group_uid) state.collapsedGroups.delete(d.container_group_uid);
  } else if (e.kind === "group") {
    state.collapsedGroups.delete(e.uid);
  }

  renderSidebar();
  renderRulesPanel();
  // Deliberately does NOT call showSidePanel() - stays on whichever side-panel
  // tab the user currently has open instead of hijacking it.

  setTimeout(() => {
    const el = e.kind === "group"
      ? document.querySelector(`.group-card[data-group-uid="${e.uid}"]`)
      : document.querySelector(`tr[data-uid="${e.uid}"]`);
    if (!el) return;
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.classList.add("jump-highlight");
    setTimeout(() => el.classList.remove("jump-highlight"), 1600);
  }, 60);
}

// ---------------------------------------------------------------------------
// File operations
// ---------------------------------------------------------------------------

// Re-fetches the active schema + schema list from the server. Needed after
// any action that can trigger server-side auto-activation (New/Open) since
// the dropdown otherwise keeps showing whatever was active before that -
// the backend was already using the right schema (e.g. Validate reflected
// it correctly), just the UI hadn't caught up.
async function refreshSchemaInfo() {
  state.schema = await api("/api/schema");
  state.schemas = await api("/api/schemas");
}

async function newConfig() {
  if (!confirm("Discard the current config and start a new blank one?")) return;
  await api("/api/new", { method: "POST" });
  stashPendingToast("Started a new blank configuration.", "success");
  // Full page reload rather than manually resetting UI state piece by piece -
  // guarantees every bit of transient state (search text, filters, sort,
  // collapsed sections, active tab, etc.) actually goes back to a clean
  // slate, the same way it would after pressing F5, instead of relying on
  // an ever-growing manual reset list that's one missed field away from the
  // exact "stale leftover state" bug this replaced.
  location.reload();
}

async function openFromUpload(file) {
  const fd = new FormData();
  fd.append("file", file);
  try {
    await api("/api/open", { method: "POST", body: fd });
    stashPendingToast(`Loaded ${file.name}`, "success");
    location.reload();
  } catch (err) {
    toast(err.message, "error");
  }
}

function openPathModal(mode) {
  state.pathModalMode = mode;
  $("pathModalTitle").textContent = mode === "save" ? "Save config" : "Open config from server path";
  $("pathInput").value = state.cfg.current_path || "";
  $("pathModalOverlay").hidden = false;
  $("pathInput").focus();
}

async function confirmPathModal() {
  const path = $("pathInput").value.trim();
  if (!path) { toast("Please enter a path.", "error"); return; }
  try {
    if (state.pathModalMode === "save") {
      await api("/api/save", { method: "POST", body: JSON.stringify({ path }) });
      state.cfg.current_path = path;
      renderFileLabel();
      setStatus(`Saved ${path}`);
      toast("Saved.", "success");
    } else {
      await api("/api/open", { method: "POST", body: JSON.stringify({ path }) });
      stashPendingToast(`Loaded ${path}`, "success");
      $("pathModalOverlay").hidden = true;
      location.reload();
      return;
    }
    $("pathModalOverlay").hidden = true;
  } catch (err) {
    toast(err.message, "error");
  }
}

function downloadConfig() {
  window.location.href = "/api/download";
}

function exportArchive() {
  window.location.href = "/api/export-archive";
}

async function quickSave() {
  if (!state.cfg.current_path) {
    openPathModal("save"); // no known path yet - behaves like Save As
    return;
  }
  try {
    await api("/api/save", { method: "POST", body: JSON.stringify({ path: state.cfg.current_path }) });
    setStatus(`Saved ${state.cfg.current_path}`);
    toast("Saved.", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

async function applyChanges() {
  const total = Object.keys(state.diff.rules).length + Object.keys(state.diff.groups).length
    + Object.keys(state.diff.settings || {}).length;
  if (total === 0) {
    toast("No pending changes to apply.", "error");
    return;
  }
  if (!confirm(`This marks all ${total} current change(s) as the new baseline - the Changes panel `
    + "will reset to empty and can no longer be reverted. This only affects this app's session; "
    + "it does not touch your OS or the Sysmon service. Continue?")) return;
  try {
    state.cfg = await api("/api/baseline/reset", { method: "POST" });
    renderAll();
    toast("Changes applied.", "success");
    setStatus("Current state accepted as the new baseline.");
  } catch (err) {
    toast(err.message, "error");
  }
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

function applyStoredTheme() {
  const saved = localStorage.getItem("sysmon-theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
}

function toggleTheme() {
  const cur = document.documentElement.getAttribute("data-theme");
  const next = cur === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("sysmon-theme", next);
}

// ---------------------------------------------------------------------------
// Event wiring
// ---------------------------------------------------------------------------

function bindGlobalEvents() {
  $("btnFileMenu").onclick = (e) => {
    e.stopPropagation();
    $("fileMenuList").hidden = !$("fileMenuList").hidden;
  };
  document.addEventListener("click", (e) => {
    if (!$("fileMenuDropdown").contains(e.target)) $("fileMenuList").hidden = true;
    if (!$("schemaMenuDropdown").contains(e.target)) $("schemaMenuList").hidden = true;
  });

  const scrollTopBtn = $("btnScrollTop");
  const tableWrap = document.querySelector(".table-wrap");
  // Scrolling does no positioning work at all any more - the section headers
  // pin themselves via native sticky, on the compositor. All that's left is
  // showing/hiding the scroll-to-top button, still rAF-throttled so it runs
  // once per painted frame rather than on every raw scroll event.
  let scrollRAF = null;
  tableWrap.addEventListener("scroll", () => {
    if (scrollRAF) return;
    scrollRAF = requestAnimationFrame(() => {
      scrollRAF = null;
      scrollTopBtn.hidden = tableWrap.scrollTop < 300;
    });
  });
  scrollTopBtn.onclick = () => tableWrap.scrollTo({ top: 0, behavior: "smooth" });
  window.addEventListener("resize", updateTableOverlays);

  $("miNew").onclick = () => { $("fileMenuList").hidden = true; newConfig(); };
  $("miClose").onclick = () => { $("fileMenuList").hidden = true; newConfig(); };
  $("miOpen").onclick = () => { $("fileMenuList").hidden = true; $("fileInput").click(); };
  $("fileInput").onchange = (e) => { if (e.target.files[0]) openFromUpload(e.target.files[0]); e.target.value = ""; };
  $("miSave").onclick = () => { $("fileMenuList").hidden = true; quickSave(); };
  $("miSaveAs").onclick = () => { $("fileMenuList").hidden = true; openPathModal("save"); };
  $("miDownload").onclick = () => { $("fileMenuList").hidden = true; downloadConfig(); };
  $("miExportArchive").onclick = () => { $("fileMenuList").hidden = true; exportArchive(); };

  $("btnValidate").onclick = runValidate;
  $("btnDiff").onclick = () => showSidePanel("changes");
  $("btnApply").onclick = applyChanges;
  $("btnHelp").onclick = () => { $("helpModalOverlay").hidden = false; };
  $("helpCloseBtn").onclick = () => { $("helpModalOverlay").hidden = true; };
  $("btnTheme").onclick = toggleTheme;

  $("btnGlobalSettings").onclick = openSettingsModal;
  $("settingsCancelBtn").onclick = () => { $("settingsModalOverlay").hidden = true; };
  $("settingsSaveBtn").onclick = saveSettingsModal;
  $("hashAll").onchange = (e) => {
    document.querySelectorAll(".hash-individual").forEach((cb) => {
      cb.disabled = e.target.checked;
      if (e.target.checked) cb.checked = false;
    });
  };

  $("btnSchemaMenu").onclick = (e) => {
    e.stopPropagation();
    $("schemaMenuList").hidden = !$("schemaMenuList").hidden;
  };
  $("btnUploadSchema").onclick = () => $("schemaFileInput").click();
  $("schemaFileInput").onchange = (e) => { if (e.target.files[0]) uploadSchema(e.target.files[0]); e.target.value = ""; };

  $("btnAddRule").onclick = () => openRuleModal(null, null);
  $("btnAddGroup").onclick = openAddGroupModal;
  $("searchBox").oninput = () => { renderRulesTable(); };
  $("sidebarFilter").oninput = renderSidebar;
  $("changesSearchBox").oninput = renderChangesPanel;

  $("sidebarDividerToggle").onclick = toggleSidebar;
  $("sidePanelDividerToggle").onclick = toggleSidePanel;
  initPaneResize();


  document.querySelectorAll("#headerRow th[data-col]").forEach((th) => {
    th.addEventListener("click", (e) => {
      if (e.target.classList.contains("col-resizer")) return;
      sortByColumn(th.dataset.col);
    });
  });
  initColumnResize();

  document.querySelectorAll("#filterRow [data-filter-col]").forEach((el) => {
    el.addEventListener(el.tagName === "SELECT" ? "change" : "input", () => {
      state.columnFilters[el.dataset.filterCol] = el.value;
      renderRulesTable();
    });
    el.addEventListener("click", (e) => e.stopPropagation()); // don't trigger header sort
  });
  $("clearColumnFilters").onclick = () => clearColumnFilters(true);

  $("btnToggleFilterRow").onclick = () => {
    const row = $("filterRow");
    row.hidden = !row.hidden;
    $("btnToggleFilterRow").classList.toggle("active", !row.hidden);
    // It's now a static part of the panel header (not inside the scrollable
    // table), so it's always visible once revealed - no scroll needed.
  };

  document.querySelectorAll("#onmatchFilter .segment").forEach((btn) => {
    btn.onclick = () => {
      state.onmatchFilter = btn.dataset.value;
      document.querySelectorAll("#onmatchFilter .segment").forEach((b) => b.classList.toggle("active", b === btn));
      renderRulesTable();
    };
  });

  $("ruleCancelBtn").onclick = closeRuleModal;
  $("ruleSaveBtn").onclick = saveRuleModal;

  $("groupCancelBtn").onclick = () => {
    $("groupModalOverlay").hidden = true;
    state.editingGroupUid = null;
    state.duplicateSourceGroupUid = null;
  };
  $("groupSaveBtn").onclick = saveGroupModal;

  $("pathCancelBtn").onclick = () => { $("pathModalOverlay").hidden = true; };
  $("pathConfirmBtn").onclick = confirmPathModal;

  document.querySelectorAll(".side-tab").forEach((el) => {
    el.onclick = () => showSidePanel(el.dataset.side);
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      $("ruleModalOverlay").hidden = true;
      $("pathModalOverlay").hidden = true;
      $("groupModalOverlay").hidden = true;
      $("settingsModalOverlay").hidden = true;
      $("helpModalOverlay").hidden = true;
      $("fileMenuList").hidden = true;
      $("schemaMenuList").hidden = true;
    }
  });
}

init();
