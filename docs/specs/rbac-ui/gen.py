#!/usr/bin/env python3
"""RBAC console mockups: real console pages (captured from the demo build)
with the new parts edited in by a small script per screen.

Usage: gen.py BASE_DIR OUT_DIR [OUT_DIR...]
BASE_DIR holds base-*.json (captured body HTML), console.css (the demo
build's stylesheet) and brand/ (the logos)."""
import base64
import json
import sys
from pathlib import Path

base_dir = Path(sys.argv[1])
outs = [Path(p) for p in sys.argv[2:]]
CSS = (base_dir / "console.css").read_text()


def load(name):
    html = json.loads((base_dir / f"base-{name}.json").read_text())["html"]
    for svg in (base_dir / "brand").glob("*.svg"):
        uri = "data:image/svg+xml;base64," + base64.b64encode(svg.read_bytes()).decode()
        html = html.replace(f'src="/brand/{svg.name}"', f'src="{uri}"')
    return html


ICONS = json.loads((base_dir / "icons.json").read_text())
BASES = {n: load(n) for n in ["settings-access", "user-panel", "host-details", "alarm-panel", "suppressions", "dashboards", "ports", "services", "software", "vulns", "compliance", "alarms", "cases"]}

# The permission matrix: area -> [(full name, chip label, all-hosts-only, column)].
# Columns: 0 View, 1 Change, 2 Export, 3 Approve and publish.
COLUMNS = ["View", "Change", "Export", "Approve and publish"]
CATALOGUE = [
    ("Alarms", [("View alarms", "Alarms", 0, 0), ("View suppressions", "Suppressions", 0, 0), ("Triage alarms", "Triage", 0, 1),
                ("Suppress alarms (with a reason)", "Suppress", 0, 1), ("Export alarms", "Export", 0, 2), ("Approve suppressions", "Approve suppressions", 0, 3)]),
    ("Compliance", [("View findings", "Findings", 0, 0), ("Triage findings", "Triage", 0, 1), ("Export findings", "Export", 0, 2)]),
    ("Vulnerabilities", [("View vulnerabilities", "Vulnerabilities", 0, 0), ("Triage vulnerabilities", "Triage", 0, 1), ("Export vulnerabilities", "Export", 0, 2)]),
    ("Hosts", [("View hosts", "Hosts", 0, 0), ("Label hosts", "Labels", 0, 1),
               ("Revoke a host", "Revoke", 1, 1), ("Export host data", "Export", 0, 2)]),
    ("Cases", [("View cases", "Cases", 0, 0), ("Create and edit cases", "Create and edit", 0, 1), ("Assign cases", "Assign", 0, 1)]),
    ("Rule sets", [("View rule sets and versions", "Sets and versions", 0, 0), ("View where sets run", "Where they run", 0, 0),
                   ("View ATT&CK coverage", "ATT&CK coverage", 0, 0), ("View rule contents", "Rule contents", 0, 0),
                   ("Change where sets run", "Where they run", 1, 1), ("Publish a rule bundle", "Publish a bundle", 1, 3)]),
    ("Site rules", [("View site rule drafts", "Drafts", 0, 0), ("Edit site rule drafts", "Edit drafts", 0, 1),
                    ("Test a draft on a host", "Test on a host", 0, 1), ("Publish site rules", "Publish", 1, 3)]),
    ("Dashboards", [("Share dashboards with your roles", "Share with your roles", 0, 1), ("Publish dashboards to everyone", "Publish to everyone", 0, 3)]),
    ("Assistant", [("Use the assistant", "Use the assistant", 0, 0), ("Configure internet lookups", "Internet lookups", 1, 1)]),
    ("Access", [("View people and roles", "People and roles", 0, 0), ("Create and disable users", "Users", 0, 1), ("Create and edit roles", "Roles", 0, 1),
                ("Give people roles", "Give roles", 0, 1), ("Manage host groups", "Host groups", 1, 1)]),
    ("Service accounts", [("View service accounts", "Accounts", 0, 0), ("Create and disable service accounts", "Create and disable", 0, 1),
                          ("Issue and revoke their tokens", "Their tokens", 0, 1)]),
    ("Enrollment", [("View enrollment tokens", "Tokens", 1, 0), ("Create and revoke tokens", "Create and revoke", 1, 1),
                    ("Download the agent installer", "Agent installer", 1, 2)]),
    ("Audit log", [("View the audit log", "Audit log", 1, 0), ("Change retention", "Retention", 1, 1), ("Export the audit log", "Export", 1, 2)]),
    ("General settings", [("Change general settings", "General settings", 1, 1)]),
]

VIEWER = ["View alarms", "View suppressions", "View findings", "View vulnerabilities", "View hosts", "View cases",
          "View rule sets and versions", "View ATT&CK coverage"]
ANALYST = VIEWER + ["Triage alarms", "Suppress alarms (with a reason)", "Triage findings", "Triage vulnerabilities",
                    "Create and edit cases", "Use the assistant"]
TEMPLATE_PERMS = {
    "Viewer": VIEWER,
    "Analyst": ANALYST,
    "Operator": ["View alarms", "View findings", "View vulnerabilities", "View hosts", "Label hosts",
                 "Revoke a host", "View enrollment tokens", "Create and revoke tokens", "Download the agent installer",
                 "View rule sets and versions", "View where sets run", "View ATT&CK coverage", "View rule contents",
                 "Publish a rule bundle", "Change where sets run"],
    "Team lead": ANALYST + ["Approve suppressions", "Label hosts", "Share dashboards with your roles", "View people and roles",
                            "Give people roles"],
    "Auditor": ["View alarms", "View suppressions", "Export alarms", "View findings", "Export findings", "View vulnerabilities",
                "Export vulnerabilities", "View hosts", "Export host data", "View cases", "View rule sets and versions",
                "View where sets run", "View ATT&CK coverage", "View rule contents", "View site rule drafts",
                "View people and roles", "View service accounts", "View enrollment tokens", "View the audit log",
                "Export the audit log"],
    "Rule author": ["View hosts", "View rule sets and versions", "View where sets run", "View ATT&CK coverage",
                    "View rule contents", "View site rule drafts", "Edit site rule drafts", "Test a draft on a host",
                    "Publish site rules"],
}
TEMPLATES = [
    ["Viewer", "Sees alarms, findings, vulnerabilities, hosts and dashboards."],
    ["Analyst", "Viewer, plus triage, cases, suppressing with a reason, and the assistant."],
    ["Operator", "Runs the fleet: enrollment, labels, revoking hosts, publishing rules and where they run."],
    ["Team lead", "For a role limited to some groups: Analyst, plus approving suppressions, labels, sharing dashboards and giving roles within its share."],
    ["Auditor", "Reads everything, plus the audit log and its export. Changes nothing."],
    ["Rule author", "Site rule drafts, testing on a host, publishing, and coverage."],
]
WINDOWS_LEAD = TEMPLATE_PERMS["Team lead"] + ["Export alarms", "Assign cases"]

# What each permission needs to be usable (the page that shows it, the list it acts on).
NEEDS = {
    "Triage alarms": ["View alarms"], "View suppressions": ["View alarms"], "Suppress alarms (with a reason)": ["View alarms", "View suppressions"],
    "Approve suppressions": ["View suppressions"], "Export alarms": ["View alarms"],
    "Triage findings": ["View findings"], "Export findings": ["View findings"],
    "Triage vulnerabilities": ["View vulnerabilities"], "Export vulnerabilities": ["View vulnerabilities"],
    "Label hosts": ["View hosts"], "Revoke a host": ["View hosts"], "Export host data": ["View hosts"],
    "Create and edit cases": ["View cases"], "Assign cases": ["Create and edit cases"],
    "View where sets run": ["View rule sets and versions"], "View rule contents": ["View rule sets and versions"],
    "Change where sets run": ["View where sets run"], "Publish a rule bundle": ["View rule sets and versions"],
    "Edit site rule drafts": ["View site rule drafts"], "Test a draft on a host": ["Edit site rule drafts", "View hosts"],
    "Publish site rules": ["Edit site rule drafts"],
    "Publish dashboards to everyone": ["Share dashboards with your roles"],
    "Create and disable users": ["View people and roles"], "Create and edit roles": ["View people and roles"],
    "Give people roles": ["View people and roles"], "Manage host groups": ["View people and roles", "View hosts"],
    "Create and disable service accounts": ["View service accounts"], "Issue and revoke their tokens": ["View service accounts"],
    "Create and revoke tokens": ["View enrollment tokens"], "Download the agent installer": ["View enrollment tokens"],
    "Change retention": ["View the audit log"], "Export the audit log": ["View the audit log"],
}
GROUPS = [["LinuxServers", 41], ["WindowsServers", 23], ["MailServers", 6], ["FileServers", 9], ["Lab", 8], ["Production", 52], ["Staging", 11]]

# Permissions that are not about hosts: they apply to the whole platform in any role.
PLATFORM = ["View rule sets and versions", "View where sets run", "View ATT&CK coverage", "View rule contents",
            "Change where sets run", "Publish a rule bundle", "View site rule drafts", "Edit site rule drafts",
            "Test a draft on a host", "Publish site rules", "Share dashboards with your roles", "Publish dashboards to everyone",
            "Configure internet lookups", "View people and roles", "Create and disable users", "Create and edit roles",
            "Give people roles", "Manage host groups", "View service accounts", "Create and disable service accounts",
            "Issue and revoke their tokens", "View enrollment tokens", "Create and revoke tokens", "Download the agent installer",
            "View the audit log", "Change retention", "Export the audit log", "Change general settings"]

HELPERS = r"""
const PLATFORM_TIP = "Applies to the whole platform: the role's Hosts don't limit it";
const infoMark = (size = 13) => `<span aria-label="Platform-wide" title="${PLATFORM_TIP}" style="display:inline-flex;color:var(--text-3)">${ICON_INFO.replace(/width="16" height="16"/, `width="${size}" height="${size}"`)}</span>`;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const h = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
const seg = (label, opts, chosen) => `<div class="seg" role="radiogroup" aria-label="${label}">${opts.map(o => `<button type="button" role="radio" class="seg__opt" aria-checked="${o === chosen}">${o}</button>`).join('')}</div>`;
const TABS = ['General', 'People', 'Roles', 'Host groups', 'Service accounts', 'Enrollment', 'Rule sets', 'Assistant'];
const ALL_PERMS = CATALOGUE.flatMap(([, ps]) => ps);
function settingsTabs(active) {
  $('.tabs[role=tablist]').innerHTML = TABS.map(t => `<button type="button" role="tab" aria-selected="${t === active}">${t}</button>`).join('');
  const outer = $('.view-header__tools'); if (outer) outer.remove();
}
function tabPanel(html) { $('[role=tabpanel]').innerHTML = html; }
function listHeader(title, count, actions, placeholder) {
  return `<header class="view-header"><div class="view-header__top"><div class="view-header__title"><h1>${title}</h1><span class="view-header__count num">${count}</span></div><div class="row">${actions}</div></div><div class="view-header__tools"><label class="search view-header__search">${ICON_SEARCH}<span class="sr-only">Filter</span><input class="input" placeholder="${placeholder}" type="search" value=""><span class="kbd view-header__kbd" aria-hidden="true">/</span></label></div></header>`;
}
function selectRow(text) { $$('tbody tr').forEach(tr => { if (tr.textContent.includes(text)) { tr.setAttribute('aria-selected', 'true'); tr.dataset.cursor = 'true'; } }); }

const roles = [
  ['Administrator', 'All hosts', 'Every permission', '1', 'Can\'t be edited or emptied', true],
  ['Analyst', 'All hosts', '14', '5', 'From the Analyst template'],
  ['Windows lead', 'WindowsServers', String(WINDOWS_LEAD.length), '2', 'From the Team lead template'],
  ['Operator (Lab)', 'Lab', '10', '1', 'Upgraded from Operator'],
  ['Viewer', 'All hosts', '8', '3', 'Upgraded from Viewer'],
];
function rolesView() {
  const rows = roles.map(([n, hosts, perms, people, from, builtin], i) => `<tr data-index="${i}"><td><div class="cell-two"><span>${n}${builtin ? ' <span class="badge badge--plain">Built in</span>' : ''}</span><span class="subtle">${from}</span></div></td><td>${hosts}</td><td class="num">${perms}</td><td class="num">${people}</td></tr>`).join('');
  return `<div class="view">${listHeader('Roles', roles.length, '<button type="button" class="button button--primary button--small">+ New role</button>', 'Filter roles…')}
  <div class="table-wrap"><table class="table" aria-label="Roles"><thead><tr><th aria-sort="ascending"><button type="button">Role</button></th><th style="width:170px">Hosts</th><th style="width:130px" class="num">Permissions</th><th style="width:90px" class="num">People</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

// ---- The role page: a full page, not a panel. ----
function startField(st) {
  const opts = [['Blank', 'No permissions; you choose them all']].concat(TEMPLATES);
  const list = st.open ? `<div class="sel__popup" style="position:absolute;top:calc(100% + 4px);left:0;width:100%;z-index:30"><div class="sel__list" role="listbox">${opts.map(([n, d]) => `<div role="option" data-template="${n}" aria-selected="${n === st.startFrom}" class="${n === st.startFrom ? 'sel__option sel__option--active' : 'sel__option'}"><span class="sel__label"><span>${n}${TEMPLATE_PERMS[n] ? ` <span class="subtle sel__hint">· ${TEMPLATE_PERMS[n].length} permissions</span>` : ''}<br><span class="subtle sel__hint" style="font-size:12.5px">${d}</span></span></span></div>`).join('')}</div></div>` : '';
  return `<div class="field"><div class="sel" style="position:relative"><button type="button" class="select sel__button" style="height:44px;font-size:15px" role="combobox" aria-haspopup="listbox" aria-expanded="${!!st.open}"><span class="sel__value">${st.startFrom === 'Blank' ? 'Blank: no permissions' : st.startFrom + ' template'}</span></button>${list}</div></div>`;
}
function chip(p, st) {
  const [name, label, allOnly] = p;
  const blocked = false;
  const on = !blocked && st.on.has(name);
  const changed = st.changed.has(name);
  const ring = changed ? (on ? 'box-shadow:0 0 0 2px rgba(46,160,67,.55);' : 'box-shadow:0 0 0 2px rgba(207,34,46,.45);') : '';
  const mark = PLATFORM.has(name) && !st._areaPlatform ? infoMark(12) : '';
  return `<button type="button" class="chip" data-perm="${esc(name)}" aria-pressed="${on}" ${blocked ? 'disabled aria-disabled="true" style="opacity:.45;cursor:not-allowed;' + ring + '"' : `style="${ring}"`} title="${esc(name)}${PLATFORM.has(name) ? ' — applies to the whole platform' : ''}${NEEDS[name] ? ' (needs ' + NEEDS[name].join(', ') + ')' : ''}">${mark}${label}</button>`;
}
function matrix(st) {
  const usable = () => true;
  const colOn = (i) => { const ps = ALL_PERMS.filter(p => p[3] === i && usable(p)); return ps.length && ps.every(p => st.on.has(p[0])); };
  const head = `<tr><th style="width:190px">Area</th>${COLUMNS.map((c, i) => `<th><span class="row" style="gap:8px">${c}<button type="button" class="button button--ghost button--small" data-col="${i}" style="height:22px;padding:0 6px;font-size:11.5px" title="${colOn(i) ? 'Turn off' : 'Turn on'} this column in every area">${colOn(i) ? 'none' : 'all'}</button></span></th>`).join('')}<th style="width:70px"></th></tr>`;
  const rows = CATALOGUE.map(([area, ps]) => {
    const n = ps.filter(p => st.on.has(p[0]) && usable(p)).length;
    const areaPlatform = ps.every(p => PLATFORM.has(p[0]));
    st._areaPlatform = areaPlatform;
    const cells = COLUMNS.map((_, i) => { const c = ps.filter(p => p[3] === i); return `<td style="vertical-align:top;padding:10px 12px"><div class="row row--wrap" style="gap:6px">${c.map(p => chip(p, st)).join('') || '<span style="color:var(--text-3);opacity:.5">·</span>'}</div></td>`; }).join('');
    st._areaPlatform = false;
    const all = ps.filter(usable).every(p => st.on.has(p[0]));
    return `<tr><td style="vertical-align:top;padding:12px"><div style="display:grid;gap:2px"><span class="row" style="gap:6px"><strong>${area}</strong>${areaPlatform ? infoMark() : ''}</span><span class="subtle num" style="font-size:12px">${n ? `${n} of ${ps.length} on` : 'none'}</span></div></td>${cells}<td style="vertical-align:top;padding:10px 12px;text-align:right"><button type="button" class="button button--ghost button--small" data-area="${area}">${all ? 'None' : 'All'}</button></td></tr>`;
  }).join('');
  return `<div class="table-wrap" style="margin:0"><table class="table" aria-label="Permissions"><thead>${head}</thead><tbody>${rows}</tbody></table></div>`;
}
const step = (n, title, aside = '') => `<div class="row row--between" style="align-items:baseline"><h2 class="section-title" style="display:flex;gap:10px;align-items:center"><span style="display:inline-grid;place-items:center;width:22px;height:22px;border-radius:50%;background:var(--accent-soft);color:var(--accent);font-size:12px;letter-spacing:0">${n}</span>${title}</h2>${aside}</div>`;
function hostsField(st, n) {
  const q = (st.search || '').toLowerCase();
  const opts = [['All hosts', GROUPS.reduce((n, g) => n + g[1], 0)]].concat(GROUPS).filter(([n]) => n.toLowerCase().includes(q));
  const picked = (n) => n === 'All hosts' ? st.all : st.groups.includes(n);
  const list = st.hostsOpen ? `<div class="sel__popup" style="position:absolute;top:calc(100% + 4px);left:0;width:100%;z-index:30"><div class="sel__list" role="listbox" aria-multiselectable="true">${opts.map(([n, c]) => `<div role="option" data-group="${n}" aria-selected="${picked(n)}" class="sel__option"><span class="sel__label" style="display:flex;justify-content:space-between;width:100%"><span>${n} <span class="subtle sel__hint">· ${c} hosts</span></span>${picked(n) ? `<span style="color:var(--accent);display:inline-flex">${ICON_CHECK}</span>` : ''}</span></div>`).join('') || '<div class="sel__empty subtle">No group matches</div>'}</div></div>` : '';
  const chipFor = (g) => `<span class="chip" aria-pressed="true" style="gap:4px;padding-right:4px">${g}<button type="button" class="icon-button" data-untag="${g}" aria-label="Remove ${g}" title="Remove ${g}" style="width:20px;height:20px;min-width:20px">${ICON_X}</button></span>`;
  const chosen = st.all ? chipFor('All hosts') : st.groups.map(chipFor).join('');
  const note = st.all ? 'Its host permissions apply to every host, now and later.' : st.groups.length ? `Its host permissions apply only to hosts in ${st.groups.length === 1 ? 'this group' : 'these groups'}.` : 'Its host permissions reach no hosts yet. Search for groups, or choose All hosts. Platform permissions work either way.';
  return `<section class="stack" style="gap:10px;margin-bottom:300px">${step(n, 'Hosts')}
    <div style="position:relative"><label class="search" style="width:100%">${ICON_SEARCH}<span class="sr-only">Search groups</span><input class="input" style="height:40px" data-hosts-search placeholder="Search host groups, or choose All hosts" value="${esc(st.search || '')}" autocomplete="off"></label>${list}</div>
    ${chosen ? `<div class="row row--wrap" style="gap:6px">${chosen}</div>` : ''}<p class="subtle" style="margin:0">${note}</p></section>`;
}
function rolePage(st) {
  const count = ALL_PERMS.filter(p => st.on.has(p[0])).length;
  const compare = st.changed.size ? `<span class="subtle" style="font-size:12.5px"><span style="display:inline-block;width:9px;height:9px;border-radius:50%;box-shadow:0 0 0 2px rgba(46,160,67,.7);margin-right:4px"></span>added by ${st.startFrom} &nbsp; <span style="display:inline-block;width:9px;height:9px;border-radius:50%;box-shadow:0 0 0 2px rgba(207,34,46,.6);margin-right:4px"></span>taken away, compared with ${st.from}</span>` : '';
  const notice = st.notice ? `<div class="callout" style="margin:0;background:var(--accent-soft);color:var(--text)"><span style="color:var(--accent);display:inline-flex">${ICON_INFO}</span><span>${st.notice}</span></div>` : '';
  const tpl = TEMPLATES.find(([n]) => n === st.startFrom);
  const hasStart = st.startFrom !== undefined;
  const k = hasStart ? 1 : 0;
  const startBlock = hasStart ? `<section class="stack" style="gap:10px">${step(2, 'Start from')}<div>${startField(st)}</div><p class="subtle" style="margin:0">${tpl ? tpl[1] : 'Blank: no permissions. Pick a template to fill them in, and switch between templates to compare.'}</p></section>` : '';
  const hostsLabel = st.all ? 'All hosts' : st.groups.length ? st.groups.join(', ') : 'no hosts yet';
  const summary = `<strong>${esc(st.name || 'Unnamed role')}</strong><span class="subtle">· ${count} permission${count === 1 ? '' : 's'} · ${esc(hostsLabel)}</span>`;
  return `<div class="view">
    <div>
    <header class="view-header"><div class="view-header__top"><div class="view-header__title" style="display:grid;gap:2px"><span class="subtle"><a href="#">Settings</a> › <a href="#">Roles</a></span><h1>${st.title}</h1></div></div></header>
    ${st.note || ''}
    <div class="view-pad stack" style="gap:32px">
      <div style="display:grid;grid-template-columns:${hasStart ? '1fr 1fr' : '1fr'};gap:32px;align-items:start">
      <section class="stack" style="gap:10px">${step(1, 'Name')}<input class="input" style="font-size:18px;height:44px;width:100%" value="${esc(st.name)}" placeholder="e.g. Windows lead" aria-label="Name"><p class="subtle" style="margin:0">With single sign-on, people in the identity-provider group of this name get the role.</p></section>
      ${startBlock}
      </div>
      <section class="stack" style="gap:10px">${step(2 + k, `Permissions <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">${count} of ${ALL_PERMS.length}</span>`, compare)}
        ${notice}
        ${matrix(st)}
        <p class="subtle" style="margin:0;font-size:12.5px"><span style="display:inline-flex;vertical-align:-2px">${infoMark()}</span> Applies to the whole platform: the role's Hosts don't limit it (next to an area: the whole area). Everything else applies only to the hosts chosen in step ${3 + k}. Turning a permission on also turns on what it needs (hover a chip to see it); turning one off turns off what depends on it.</p></section>
      ${hostsField(st, 3 + k)}
    </div>
    </div>
    <div style="position:sticky;bottom:0;margin-top:24px;z-index:20;background:var(--surface);border-top:1px solid var(--line);box-shadow:0 -6px 16px rgba(0,0,0,.05);padding:12px 24px"><div style="display:flex;align-items:center;gap:12px"><span class="row grow" style="gap:8px;min-width:0">${summary}</span>${st.actions(st)}</div></div>
  </div>`;
}
const LABEL = Object.fromEntries(CATALOGUE.flatMap(([a, ps]) => ps.map(p => [p[0], p[0]])));
function withNeeds(st, name, added) { (NEEDS[name] || []).forEach(n => { if (!st.on.has(n)) { st.on.add(n); added.push(n); } withNeeds(st, n, added); }); }
function withoutDependents(st, name, removed) { Object.entries(NEEDS).forEach(([d, ns]) => { if (ns.includes(name) && st.on.has(d)) { st.on.delete(d); removed.push(d); withoutDependents(st, d, removed); } }); }
function livePage(st) {
  const render = () => {
    const v = $('.view-area'); const top = v.scrollTop; const focused = document.activeElement?.dataset?.hostsSearch !== undefined;
    v.innerHTML = rolePage(st); v.scrollTop = top;
    if (focused) { const i = $('[data-hosts-search]'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }
  };
  render();
  document.addEventListener('input', (e) => { if (e.target.dataset.hostsSearch !== undefined) { st.search = e.target.value; st.hostsOpen = true; render(); } });
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-template],.sel__button,[data-perm],[data-area],[data-col],[data-group],[data-untag],[data-hosts-search]');
    if (!t || !t.closest('.view-area')) { if (st.hostsOpen || st.open) { st.hostsOpen = false; st.open = false; render(); } return; }
    const prev = new Set(st.on); st.notice = '';
    if (t.dataset.hostsSearch !== undefined) { st.hostsOpen = true; st.open = false; render(); return; }
    if (t.matches('.sel__button')) { st.open = !st.open; st.hostsOpen = false; }
    else if (t.dataset.template) {
      const n = t.dataset.template;
      if (!st.name || Object.keys(TEMPLATE_PERMS).includes(st.name)) st.name = n === 'Blank' ? '' : n;
      st.from = st.startFrom; st.startFrom = n; st.open = false; st.on = new Set(TEMPLATE_PERMS[n] || []);
      st.changed = new Set([...prev, ...st.on].filter(x => prev.has(x) !== st.on.has(x)));
    } else if (t.dataset.group) {
      const g = t.dataset.group; st.search = '';
      if (g === 'All hosts') { st.all = !st.all; if (st.all) st.groups = []; }
      else { st.all = false; st.groups = st.groups.includes(g) ? st.groups.filter(x => x !== g) : st.groups.concat(g); }
    } else if (t.dataset.untag) {
      const g = t.dataset.untag; if (g === 'All hosts') st.all = false; else st.groups = st.groups.filter(x => x !== g);
    } else if (t.dataset.perm && !t.disabled) {
      const n = t.dataset.perm, changes = [];
      if (st.on.has(n)) { st.on.delete(n); withoutDependents(st, n, changes); if (changes.length) st.notice = `Also turned off, because they need ${n}: ${changes.join(', ')}.`; }
      else { st.on.add(n); withNeeds(st, n, changes); if (changes.length) st.notice = `Also turned on, because ${n} needs it: ${changes.join(', ')}.`; }
    } else if (t.dataset.area || t.dataset.col) {
      const ps = (t.dataset.area ? CATALOGUE.find(([a]) => a === t.dataset.area)[1] : ALL_PERMS.filter(p => p[3] === Number(t.dataset.col)))
        .map(p => p[0]);
      const all = ps.every(n => st.on.has(n)), changes = [];
      ps.forEach(n => { if (all) { st.on.delete(n); withoutDependents(st, n, changes); } else { st.on.add(n); withNeeds(st, n, changes); } });
      const extra = changes.filter(n => !ps.includes(n));
      if (extra.length) st.notice = all ? `Also turned off, because they need these: ${extra.join(', ')}.` : `Also turned on, because these need them: ${extra.join(', ')}.`;
    }
    render();
  });
}
"""

SCREENS = []


def screen(slug, base, caption, script):
    SCREENS.append((slug, base, caption, script))


screen(
    "1-roles", "settings-access",
    "<b>1 · Settings › Roles.</b> Settings is always in the menu; its tabs follow your permissions. Your roles, with where each came from.",
    "settingsTabs('Roles'); tabPanel(rolesView());",
)

NEW = r"""
const st = { title: 'New role', name: START === 'Blank' ? '' : START, all: false, groups: [], on: new Set(TEMPLATE_PERMS[START] || []),
  startFrom: START, from: FROM, open: OPEN, changed: CHANGED,
  actions: (st) => '<button type="button" class="button">Cancel</button>' + (st.name ? '<button type="button" class="button button--primary">Create role</button>' : '<button type="button" class="button button--primary" disabled title="Give it a name first">Create role</button>') };
livePage(st);
"""
screen(
    "2-new-role", "settings-access",
    "<b>2 · + New role</b> opens a full page; it starts blank. <b>Try it:</b> pick templates in Start from; search and tick groups in Hosts; click Assign under Cases and View cases comes with it.",
    "const START = 'Blank', FROM = 'Blank', OPEN = false, CHANGED = new Set();" + NEW,
)
screen(
    "3-start-from", "settings-access",
    "<b>3 · Start from.</b> Blank and the six templates. A template has no members and is never a role by itself; picking one fills in the matrix.",
    "const START = 'Blank', FROM = 'Blank', OPEN = true, CHANGED = new Set();" + NEW,
)
screen(
    "4-compare", "settings-access",
    "<b>4 · Comparing.</b> Switched from Analyst to Team lead: outlined green is what Team lead adds, red what it takes away. A template never picks hosts.",
    "const START = 'Team lead', FROM = 'Analyst', OPEN = false; const CHANGED = new Set(TEMPLATE_PERMS['Team lead'].filter(n => !TEMPLATE_PERMS['Analyst'].includes(n)));" + NEW,
)
screen(
    "5-team-role", "settings-access",
    "<b>5 · Editing a role limited to some groups.</b> Windows lead's host permissions (view, triage, labels…) apply only to WindowsServers; any permission can be added.",
    r"""
livePage({ title: 'Windows lead', name: 'Windows lead', all: false, groups: ['WindowsServers'], on: new Set(WINDOWS_LEAD), changed: new Set(),
  note: `<div class="view-pad"><div class="callout" style="background:var(--accent-soft);color:var(--text);max-width:720px"><span style="color:var(--accent);display:inline-flex">${ICON_INFO}</span><span>2 people have this role. It was made from the Team lead template. Changes apply at their next request.</span></div></div>`,
  actions: () => '<button type="button" class="button button--ghost">Delete role</button><button type="button" class="button">Cancel</button><button type="button" class="button button--primary">Save</button>' });
""",
)

PEOPLE = r"""
// ---- People ----
const ROLE_DEFS = {
  'Administrator': { all: true, groups: [], perms: ALL_PERMS.map(p => p[0]) },
  'Analyst': { all: true, groups: [], perms: TEMPLATE_PERMS['Analyst'] },
  'Windows lead': { all: false, groups: ['WindowsServers'], perms: WINDOWS_LEAD },
  'Operator (Lab)': { all: false, groups: ['Lab'], perms: ['View alarms', 'View findings', 'View vulnerabilities', 'View hosts', 'Label hosts', 'View rule sets and versions', 'View where sets run', 'View ATT&CK coverage', 'View rule contents', 'View cases'] },
  'Viewer': { all: true, groups: [], perms: TEMPLATE_PERMS['Viewer'] },
};
const scopeOf = (r) => ROLE_DEFS[r].all ? 'All hosts' : ROLE_DEFS[r].groups.join(', ');
const PEOPLE = [
  ['Alex Admin', 'admin', ['Administrator'], 'Active', '2 min ago'],
  ['Priya Patel', 'priya.patel@corp.example', ['Analyst'], 'Active', '20 min ago', 'Entra ID'],
  ['Wendy Ward', 'wendy', ['Windows lead', 'Viewer'], 'Active', '1 h ago'],
  ['Sam Analyst', 'sam', ['Analyst'], 'Active', 'yesterday'],
  ['Lab operator', 'lab-ops', ['Operator (Lab)'], 'Active', '3 days ago'],
  ['Vic Viewer', 'vic', ['Viewer'], 'Active', '2 weeks ago'],
  ['Dana Doe', 'dana', [], 'Disabled', '4 months ago'],
];
function reach(roles) {
  const g = [...new Set(roles.flatMap(r => ROLE_DEFS[r].groups))];
  if (roles.some(r => ROLE_DEFS[r].all)) return g.length ? `All hosts <span class="subtle">· more on ${g.join(', ')}</span>` : 'All hosts';
  return g.length ? g.join(', ') : '<span class="subtle">No hosts</span>';
}
function peopleView() {
  const rows = PEOPLE.map(([n, u, roles, status, seen, sso], i) => `<tr data-index="${i}"><td><div class="cell-two"><span>${n}</span><span class="mono subtle">${u}</span></div></td>
    <td><span class="row row--wrap" style="gap:6px">${roles.map(r => `<span class="badge badge--accent badge--plain">${r}<span style="font-weight:400;opacity:.8"> · ${scopeOf(r)}</span></span>`).join('') || '<span class="subtle">No roles</span>'}</span></td><td>${sso ? `<span class="badge badge--plain">SSO · ${sso}</span>` : '<span class="subtle">Password</span>'}</td><td><span class="badge ${status === 'Active' ? 'badge--ok' : 'badge--plain'}">${status}</span></td><td class="subtle">${seen}</td></tr>`).join('');
  return `<div class="view">${listHeader('People', PEOPLE.length, '<button type="button" class="button button--primary button--small">+ New user</button>', 'Filter people or roles…')}
  <div class="table-wrap"><table class="table" aria-label="People"><thead><tr><th aria-sort="ascending"><button type="button">Person</button></th><th>Roles <span class="subtle" style="font-weight:400">· where each applies</span></th><th style="width:150px">Signs in with</th><th style="width:110px">Status</th><th style="width:140px">Last sign-in</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}
// The read-only "what can this person do" matrix: each granted permission says where it applies.
function effective(roles) {
  const out = {};
  roles.forEach(r => ROLE_DEFS[r].perms.forEach(n => { (out[n] = out[n] || []).push(r); }));
  return out;
}
function whereFor(n, rs) {
  if (rs.some(r => ROLE_DEFS[r].all)) return 'All hosts';
  return [...new Set(rs.flatMap(r => ROLE_DEFS[r].groups))].join(', ');
}
function effectiveMatrix(roles) {
  const eff = effective(roles);
  const head = `<tr><th style="width:190px">Area</th>${COLUMNS.map(c => `<th>${c}</th>`).join('')}</tr>`;
  const rows = CATALOGUE.map(([area, ps]) => {
    const cells = COLUMNS.map((_, i) => { const c = ps.filter(p => p[3] === i && eff[p[0]]);
      return `<td style="vertical-align:top;padding:10px 12px"><div class="stack" style="gap:6px">${c.map(p => `<span class="row" style="gap:6px;flex-wrap:nowrap"><span class="chip" aria-pressed="true" style="cursor:default" title="From ${eff[p[0]].join(', ')}">${p[1]}</span><span class="subtle" style="font-size:12px;white-space:nowrap">${whereFor(p[0], eff[p[0]])}</span></span>`).join('') || '<span style="color:var(--text-3);opacity:.5">·</span>'}</div></td>`; }).join('');
    return `<tr><td style="vertical-align:top;padding:12px"><strong>${area}</strong></td>${cells}</tr>`;
  }).join('');
  return `<div class="table-wrap" style="margin:0"><table class="table" aria-label="What this person can do"><thead>${head}</thead><tbody>${rows}</tbody></table></div>`;
}
function rolePicker(st) {
  const q = (st.search || '').toLowerCase();
  const opts = Object.keys(ROLE_DEFS).filter(r => !st.roles.includes(r) && r.toLowerCase().includes(q));
  const list = st.open ? `<div class="sel__popup" style="position:absolute;top:calc(100% + 4px);left:0;width:100%;z-index:30"><div class="sel__list" role="listbox">${opts.map(r => `<div role="option" data-addrole="${r}" class="sel__option"><span class="sel__label"><span>${r} <span class="subtle sel__hint">· ${scopeOf(r)} · ${ROLE_DEFS[r].perms.length} permissions</span></span></span></div>`).join('') || '<div class="sel__empty subtle">No other role matches</div>'}</div></div>` : '';
  return `<div style="position:relative"><label class="search" style="width:100%">${ICON_SEARCH}<span class="sr-only">Add a role</span><input class="input" style="height:40px" data-role-search placeholder="Add a role: search by name" value="${esc(st.search || '')}" autocomplete="off"></label>${list}</div>`;
}
const LOCK = '<span title="Managed by single sign-on" style="display:inline-flex;color:var(--text-3)"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 11h14v10H5z"></path><path d="M8 11V7a4 4 0 0 1 8 0v4"></path></svg></span>';
function initials(n) { return n.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase(); }
// Access grouped by where it applies: platform-wide, all hosts, then each set of groups.
function accessBuckets(roles) {
  const eff = effective(roles), buckets = new Map();
  const put = (key, title, sub, p, from) => { if (!buckets.has(key)) buckets.set(key, { title, sub, perms: [], from: new Set() }); const b = buckets.get(key); b.perms.push(p); from.forEach(r => b.from.add(r)); };
  ALL_PERMS.forEach(p => { const rs = eff[p[0]]; if (!rs) return;
    if (PLATFORM.has(p[0])) return put('platform', 'Platform-wide', 'Not limited by hosts', p, rs);
    const allRoles = rs.filter(r => ROLE_DEFS[r].all);
    if (allRoles.length) return put('all', 'On all hosts', '', p, allRoles);
    const gs = [...new Set(rs.flatMap(r => ROLE_DEFS[r].groups))].sort();
    put('g:' + gs.join(','), 'Only on ' + gs.join(', '), '', p, rs);
  });
  const order = (k) => k === 'all' ? 0 : k === 'platform' ? 2 : 1;
  return [...buckets.entries()].sort((x, y) => order(x[0]) - order(y[0])).map(([, b]) => b);
}
function accessView(roles) {
  const bs = accessBuckets(roles);
  if (!bs.length) return '<p class="subtle">No access: without roles this person can sign in but sees nothing.</p>';
  return bs.map(b => {
    const byArea = CATALOGUE.map(([area, ps]) => [area, b.perms.filter(p => ps.includes(p))]).filter(([, ps]) => ps.length);
    return `<section class="card" style="overflow:hidden"><div class="row row--between" style="padding:14px 20px;border-bottom:1px solid var(--line)"><div class="row" style="gap:8px"><strong style="font-size:15px">${b.title}</strong>${b.title === 'Platform-wide' ? infoMark() : ''}<span class="subtle num">· ${b.perms.length} permission${b.perms.length === 1 ? '' : 's'}</span></div><span class="subtle" style="font-size:12.5px">From ${[...b.from].join(', ')}</span></div>
      <div style="display:grid;grid-template-columns:180px 1fr;row-gap:10px;padding:14px 20px">${byArea.map(([area, ps]) => `<span class="subtle">${area}</span><span class="row row--wrap" style="gap:6px">${ps.map(p => `<span class="chip" aria-pressed="true" style="cursor:default" title="${esc(p[0])}">${p[1]}</span>`).join('')}</span>`).join('')}</div></section>`;
  }).join('');
}
function roleCards(st) {
  return st.roles.map(r => { const fromSso = (st.ssoRoles || []).includes(r); const d = ROLE_DEFS[r];
    const where = d.all ? '<span class="chip" aria-pressed="true" style="cursor:default">All hosts</span>' : d.groups.map(g => `<span class="chip" aria-pressed="true" style="cursor:default">${g}</span>`).join('');
    return `<div style="display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;padding:10px 12px;border:1px solid var(--line);border-radius:var(--r-2)"><div class="stack" style="gap:6px"><div class="row" style="gap:8px"><strong>${r}</strong>${fromSso ? `<span class="badge badge--plain">From ${st.sso} group</span>` : ''}</div><div class="row row--wrap" style="gap:6px"><span class="subtle" style="margin-right:2px">Applies to</span>${where}<span class="subtle">· ${d.perms.length} permissions</span></div></div>
      <div class="row" style="gap:6px"><a class="button button--ghost button--small" href="#">Open role</a>${fromSso ? `<span class="row subtle" style="gap:4px;font-size:12.5px">${LOCK} Set in ${st.sso}</span>` : `<button type="button" class="button button--small" data-removerole="${r}">Remove</button>`}</div></div>`; }).join('') || '<p class="subtle">No roles yet: this person can sign in but sees nothing.</p>';
}
function personPage(st) {
  const sso = st.sso;
  const edit = (label, value, mono) => `<label class="field"><span>${label}</span><input class="input${mono ? ' mono' : ''}" value="${esc(value)}"></label>`;
  const kv = (k, v) => `<dt>${k}</dt><dd>${v}</dd>`;
  const detailsBody = st.editing && !sso
    ? `<div class="stack" style="gap:10px">${edit('Name', st.name)}${edit('Email', st.email)}${edit('Username', st.user, true)}<div class="row" style="gap:8px"><button type="button" class="button button--primary button--small" data-edit>Save</button><button type="button" class="button button--small" data-edit>Cancel</button></div></div>`
    : `<dl class="kv" style="margin:0;row-gap:10px;grid-template-columns:118px minmax(0,1fr)">${kv('Email', esc(st.email))}${kv('Username', `<span class="mono">${st.user}</span>`)}${kv('Signs in with', sso ? `Single sign-on · ${sso} ${LOCK}` : 'Password')}${kv('Status', '<span class="badge badge--ok">Active</span>')}${kv('Last sign-in', st.seen)}${kv('Created', sso ? 'At first sign-in, 3 Mar 2026' : '4 Oct 2026 by Alex Admin')}${sso ? kv('Removed after', '90 days without signing in') : kv('Password changed', '12 days ago')}</dl>`;
  const notice = st.notice ? `<div class="callout" style="margin:0;background:var(--accent-soft);color:var(--text)"><span style="color:var(--accent);display:inline-flex">${ICON_INFO}</span><span>${st.notice}</span></div>` : '';
  const ssoNote = sso ? `<div class="callout" style="margin:0;background:var(--accent-soft);color:var(--text)"><span style="color:var(--accent);display:inline-flex">${ICON_INFO}</span><span>Managed by ${sso}: name, email and roles from ${sso} groups are changed there.</span></div>` : '';
  const menu = st.menu ? `<div role="menu" style="position:absolute;right:0;top:calc(100% + 6px);z-index:30;min-width:200px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-2);box-shadow:var(--shadow-2);padding:6px">${sso ? '' : '<button type="button" role="menuitem" class="menu__item" style="display:block;width:100%;text-align:left">Reset password…</button>'}<button type="button" role="menuitem" class="menu__item" style="display:block;width:100%;text-align:left;color:var(--bad)">${sso ? 'Disable in OpenVIBES…' : 'Disable user…'}</button></div>` : '';
  const actions = `${sso ? '' : `<button type="button" class="button" data-edit>${st.editing ? 'Stop editing' : 'Edit details'}</button>`}<span style="position:relative"><button type="button" class="button" data-menu aria-haspopup="menu" aria-expanded="${!!st.menu}" aria-label="More actions">⋯</button>${menu}</span>`;
  const count = Object.keys(effective(st.roles)).length;
  const activity = [['Approved a suppression', 'curl from cron · WindowsServers', '20 min ago'], ['Triaged 3 alarms', 'Mitigated', '1 h ago'], ['Added label backup-target', 'win-file-07', 'yesterday'], ['Signed in', 'from 10.0.4.17', 'yesterday']];
  const card = (title, aside, body) => `<section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">${title}</h2>${aside || ''}</div><div style="padding:14px 16px">${body}</div></section>`;
  return `<div class="view"><div>
    <div class="view-pad" style="padding-top:20px"><span class="subtle"><a href="#">Settings</a> › <a href="#">People</a></span></div>
    <header class="view-pad" style="display:flex;gap:16px;align-items:center;padding-top:8px;padding-bottom:16px">
      <span style="position:relative;width:64px;height:64px;flex:none">
        <span style="display:grid;place-items:center;width:64px;height:64px;border-radius:50%;background:var(--accent-soft);color:var(--accent);font-weight:650;font-size:22px">${initials(st.name)}</span>
        <button type="button" data-photo aria-label="Change profile picture" title="Change profile picture" style="position:absolute;right:-4px;bottom:-4px;display:grid;place-items:center;width:28px;height:28px;border-radius:50%;background:var(--surface);border:1px solid var(--line-strong);color:var(--text-2);cursor:pointer;box-shadow:var(--shadow-1)"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3z"></path><path d="M9 13a3 3 0 1 0 6 0a3 3 0 1 0-6 0"></path></svg></button>
        ${st.photo ? `<div role="menu" style="position:absolute;left:0;top:calc(100% + 8px);z-index:30;min-width:240px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-2);box-shadow:var(--shadow-2);padding:6px"><button type="button" role="menuitem" class="menu__item" style="display:block;width:100%;text-align:left;text-transform:none">Upload picture…</button><button type="button" role="menuitem" class="menu__item" style="display:block;width:100%;text-align:left;text-transform:none">Remove picture</button><p class="subtle" style="margin:6px 8px 4px;font-size:12px">Square JPG, PNG or WebP, up to 1 MB. Shown here, in People and in the top bar.${sso ? ` Without one, the picture from ${sso} is used.` : ''}</p></div>` : ''}
      </span>
      <div class="stack grow" style="gap:4px"><div class="row" style="gap:10px"><h1 style="margin:0">${st.name}</h1><span class="badge badge--ok">Active</span>${sso ? `<span class="badge badge--plain">SSO · ${sso}</span>` : ''}</div>
        <span class="subtle">${st.roles.length} role${st.roles.length === 1 ? '' : 's'} · ${count} permissions · last signed in ${st.seen}</span></div>
      <div class="row" style="gap:8px">${actions}</div></header>
    <div class="view-pad" style="display:grid;grid-template-columns:380px minmax(0,1fr);gap:24px;align-items:start;margin-bottom:300px">
      <div class="stack" style="gap:16px">
        ${ssoNote}
        ${card('Details', '', detailsBody)}
        ${card('Recent activity', '<a href="#" style="font-size:12.5px">Audit log</a>', `<ul class="list list--plain" style="margin:0">${activity.map(([a, d, w]) => `<li style="display:grid;gap:2px;padding:6px 0;border-bottom:1px solid var(--line)"><span>${a}</span><span class="subtle" style="font-size:12.5px">${d} · ${w}</span></li>`).join('')}</ul>`)}
      </div>
      <div class="stack" style="gap:16px">
        ${notice}
        ${card(`Roles <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">${st.roles.length}</span>`, st.adding ? '' : '<button type="button" class="button button--primary button--small" data-adding>+ Add role</button>',
          `${st.adding ? `<div style="position:relative;margin-bottom:12px">${rolePicker(st)}</div>` : ''}<div class="stack" style="gap:8px">${roleCards(st)}</div>`)}
        <div class="row row--between" style="margin-top:8px"><h2 class="section-title" style="margin:0">Access <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">${count} of ${ALL_PERMS.length}</span></h2><span class="subtle" style="font-size:12.5px">What these roles add up to, by where it applies.</span></div>
        ${accessView(st.roles)}
      </div>
    </div></div>
  </div>`;
}
function livePerson(st) {
  st.tab = st.tab || 'roles';
  const render = () => { const v = $('.view-area'); const top = v.scrollTop; const f = document.activeElement?.dataset?.roleSearch !== undefined;
    v.innerHTML = personPage(st); v.scrollTop = top; const i = $('[data-role-search]'); if (i && (f || st.focusSearch)) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); st.focusSearch = false; } };
  render();
  document.addEventListener('input', (e) => { if (e.target.dataset.roleSearch !== undefined) { st.search = e.target.value; st.open = true; render(); } });
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-role-search],[data-addrole],[data-removerole],[data-tab],[data-edit],[data-menu],[data-adding],[data-photo]');
    if (!t) { if (st.open || st.menu || st.adding || st.photo) { st.open = false; st.menu = false; st.adding = false; st.photo = false; render(); } return; }
    st.notice = '';
    if (t.dataset.roleSearch !== undefined) { st.open = true; render(); return; }
    if (t.dataset.tab) st.tab = t.dataset.tab;
    if (t.dataset.edit !== undefined) st.editing = !st.editing;
    if (t.dataset.menu !== undefined) st.menu = !st.menu;
    if (t.dataset.photo !== undefined) st.photo = !st.photo;
    if (t.dataset.adding !== undefined) { st.adding = true; st.open = true; st.focusSearch = true; }
    if (t.dataset.addrole) { st.roles = st.roles.concat(t.dataset.addrole); st.open = false; st.adding = false; st.search = ''; st.notice = `${st.first} now has ${t.dataset.addrole} (${scopeOf(t.dataset.addrole)}). It applies at the next request.`; }
    if (t.dataset.removerole) { st.roles = st.roles.filter(r => r !== t.dataset.removerole); st.notice = `${t.dataset.removerole} removed. It applies at the next request.`; }
    render();
  });
}
"""
screen(
    "6-people", "settings-access",
    "<b>6 · Settings › People.</b> Everyone with each role and where it applies, how they sign in, status and last sign-in. A team admin sees only the people inside their share.",
    PEOPLE + "settingsTabs('People'); tabPanel(peopleView());",
)
WENDY = "livePerson({ name: 'Wendy Ward', first: 'Wendy', user: 'wendy', email: 'wendy.ward@corp.example', seen: '1 h ago', roles: ['Windows lead', 'Viewer'], open: OPEN, adding: OPEN, tab: TAB, search: '' });"
screen(
    "7-person", "settings-access",
    "<b>7 · A person's page.</b> Everything on one page: details and recent activity on the left; roles and what they add up to on the right. <b>Try it:</b> the camera on the picture, + Add role, Remove, Edit details, ⋯.",
    PEOPLE + "const OPEN = false, TAB = 'roles';" + WENDY,
)

UPLOAD = r"""
// ---- Profile picture upload: crop, previews, what happens on the server ----
const PHOTO = 'data:image/svg+xml;utf8,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="900" height="600" viewBox="0 0 900 600"><defs><linearGradient id="s" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#7cc4f2"/><stop offset="1" stop-color="#f6d7a7"/></linearGradient></defs><rect width="900" height="600" fill="url(#s)"/><circle cx="700" cy="140" r="70" fill="#ffd36b"/><path d="M0 470 Q200 380 420 450 T900 430 V600 H0z" fill="#5a8f5a"/><circle cx="450" cy="250" r="95" fill="#c98f6b"/><path d="M300 600 Q300 380 450 360 Q600 380 600 600z" fill="#2f5d8a"/><path d="M360 230 Q380 120 460 140 Q560 140 545 245 Q520 180 455 190 Q395 185 360 230z" fill="#3b2a20"/></svg>');
function uploadDialog(u) {
  const t = `translate(${u.x}px, ${u.y}px) scale(${u.zoom})`;
  const crop = 300;
  const preview = (size) => `<span style="display:grid;gap:4px;justify-items:center"><span style="width:${size}px;height:${size}px;border-radius:50%;overflow:hidden;position:relative;border:1px solid var(--line)"><img src="${PHOTO}" alt="" style="position:absolute;left:50%;top:50%;width:${900 * size / crop}px;max-width:none;transform:translate(-50%,-50%) translate(${u.x * size / crop}px, ${u.y * size / crop}px) scale(${u.zoom})"></span><span class="subtle" style="font-size:11.5px">${size} px</span></span>`;
  return `<div style="position:fixed;inset:0;z-index:50;background:rgba(10,20,30,.45);display:grid;place-items:center">
    <div role="dialog" aria-modal="true" aria-labelledby="up-title" class="card" style="width:min(760px,94vw);padding:0;overflow:hidden;box-shadow:var(--shadow-2)">
      <div class="row row--between" style="padding:16px 20px;border-bottom:1px solid var(--line)"><h2 id="up-title" style="margin:0;font-size:17px">Profile picture</h2><button type="button" class="icon-button" aria-label="Close">${ICON_X}</button></div>
      <div style="display:grid;grid-template-columns:${crop}px 1fr;gap:24px;padding:20px">
        <div class="stack" style="gap:10px">
          <div data-crop style="width:${crop}px;height:${crop}px;position:relative;overflow:hidden;border-radius:var(--r-2);background:#111;cursor:grab;touch-action:none">
            <img src="${PHOTO}" alt="Your picture" draggable="false" style="position:absolute;left:50%;top:50%;width:900px;max-width:none;transform:translate(-50%,-50%) ${t};transform-origin:center;user-select:none">
            <div aria-hidden="true" style="position:absolute;inset:0;background:radial-gradient(circle at center, transparent ${crop / 2 - 1}px, rgba(0,0,0,.55) ${crop / 2}px)"></div>
            <div aria-hidden="true" style="position:absolute;inset:0;border-radius:50%;box-shadow:inset 0 0 0 2px rgba(255,255,255,.85)"></div>
          </div>
          <label class="row" style="gap:10px"><span class="subtle">Zoom</span><input type="range" data-zoom min="0.33" max="1.5" step="0.01" value="${u.zoom}" style="flex:1"></label>
          <span class="subtle" style="font-size:12.5px">Drag the picture to place it in the circle.</span>
        </div>
        <div class="stack" style="gap:16px">
          <div class="stack" style="gap:4px"><strong>me-at-the-beach.gif</strong><span class="subtle">GIF · animated, 42 frames · 1.8 MB · 900 × 600</span><span><span class="badge badge--ok">Stays animated</span></span></div>
          <div class="stack" style="gap:8px"><span class="subtle">How it looks</span><div class="row" style="gap:18px;align-items:end">${preview(64)}${preview(32)}${preview(24)}</div></div>
          <div class="callout" style="margin:0;background:var(--surface-2);color:var(--text-2);align-items:flex-start"><span style="display:inline-flex;margin-top:1px">${ICON_INFO}</span><span>Checked and re-encoded on the server: only the cropped picture is kept, as WebP, and the original is discarded with its metadata (camera, location). JPEG, PNG, GIF, WebP, AVIF, BMP or TIFF, up to 10 MB.</span></div>
          <button type="button" class="button button--ghost" style="justify-self:start">Choose another file…</button>
        </div>
      </div>
      <div class="row" style="gap:8px;justify-content:flex-end;padding:14px 20px;border-top:1px solid var(--line)"><button type="button" class="button">Cancel</button><button type="button" class="button button--primary">Save picture</button></div>
    </div></div>`;
}
function liveUpload(person) {
  const u = { x: 0, y: -40, zoom: 0.62 };
  const layer = document.createElement('div'); document.body.append(layer);
  const draw = () => { layer.innerHTML = uploadDialog(u); };
  livePerson(person); draw();
  let drag = null;
  document.addEventListener('pointerdown', (e) => { if (e.target.closest('[data-crop]')) { drag = { x: e.clientX - u.x, y: e.clientY - u.y }; e.preventDefault(); } });
  document.addEventListener('pointermove', (e) => { if (drag) { u.x = e.clientX - drag.x; u.y = e.clientY - drag.y; draw(); } });
  document.addEventListener('pointerup', () => { drag = null; });
  document.addEventListener('input', (e) => { if (e.target.dataset.zoom !== undefined) { u.zoom = Number(e.target.value); const v = e.target.value; draw(); const r = layer.querySelector('[data-zoom]'); r.value = v; r.focus(); } });
}
"""
screen(
    "7c-upload-picture", "settings-access",
    "<b>7c · Uploading a picture.</b> Crop to the circle (drag, zoom), see it at the sizes the console uses, and save. GIFs stay animated. The server checks and re-encodes every picture.",
    PEOPLE + UPLOAD + "liveUpload({ name: 'Wendy Ward', first: 'Wendy', user: 'wendy', email: 'wendy.ward@corp.example', seen: '1 h ago', roles: ['Windows lead', 'Viewer'], open: false, tab: 'roles', search: '' });",
)
screen(
    "7b-sso-person", "settings-access",
    "<b>7b · A single sign-on user.</b> Details and roles from Entra ID groups are locked; extra roles can be added. Removed after a set time without signing in.",
    PEOPLE + "livePerson({ name: 'Priya Patel', first: 'Priya', user: 'priya.patel@corp.example', email: 'priya.patel@corp.example', seen: '20 min ago', roles: ['Analyst'], ssoRoles: ['Analyst'], sso: 'Entra ID', open: false, tab: 'roles', search: '' });",
)
screen(
    "8-add-role", "settings-access",
    "<b>8 · Adding a role.</b> Search by name; each role shows where it applies and how many permissions it has. A team admin is offered only roles inside their share.",
    PEOPLE + "const OPEN = true, TAB = 'roles';" + WENDY,
)

HOSTGROUPS = r"""
// ---- Host groups: rule groups (automatic or yours) and manual groups ----
// What each host reports (agent facts); labels never count.
const HOSTS = [
  { name: 'win-dc-01', family: 'Windows', distro: 'Windows Server 2022', ip: '10.0.1.10', labels: ['hq'], seen: '1 min ago', online: true, alarms: 0, crit: 1 },
  { name: 'win-dc-02', family: 'Windows', distro: 'Windows Server 2022', ip: '10.0.1.11', labels: ['hq'], seen: '1 min ago', online: true, alarms: 0, crit: 1 },
  { name: 'win-file-07', family: 'Windows', distro: 'Windows Server 2019', ip: '10.0.2.17', labels: ['hq'], seen: '2 min ago', online: true, alarms: 2, crit: 0 },
  { name: 'win-file-08', family: 'Windows', distro: 'Windows Server 2019', ip: '10.8.2.18', labels: ['branch'], seen: '3 h ago', online: false, alarms: 0, crit: 0 },
  { name: 'win-app-03', family: 'Windows', distro: 'Windows Server 2022', ip: '10.0.3.3', labels: ['hq'], seen: '1 min ago', online: true, alarms: 1, crit: 2 },
  { name: 'win-test-01', family: 'Windows', distro: 'Windows 11', ip: '10.9.0.21', labels: ['lab'], seen: '5 min ago', online: true, alarms: 0, crit: 0 },
  { name: 'mx-01', family: 'Linux', distro: 'Debian 12', ip: '10.0.4.1', labels: ['hq'], seen: '1 min ago', online: true, alarms: 0, crit: 0 },
  { name: 'mx-backup-03', family: 'Linux', distro: 'Ubuntu 24.04', ip: '10.7.4.3', labels: ['dr', 'backup'], seen: '2 min ago', online: true, alarms: 1, crit: 0 },
  { name: 'web-01', family: 'Linux', distro: 'Fedora 44', ip: '10.0.5.1', labels: ['hq'], seen: '1 min ago', online: true, alarms: 3, crit: 1 },
  { name: 'db-02', family: 'Linux', distro: 'Debian 12', ip: '10.0.6.2', labels: ['hq'], seen: '1 min ago', online: true, alarms: 0, crit: 0 },
  { name: 'lab-ws-04', family: 'Linux', distro: 'Fedora 44', ip: '10.9.0.44', labels: ['lab'], seen: '2 days ago', online: false, alarms: 0, crit: 0 },
];
const FIELDS = { 'OS family': h => h.family, 'Distribution': h => h.distro, 'Hostname': h => h.name, 'IP address': h => h.ip };
const glob = (pat, v) => new RegExp('^' + pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$').test(v);
const test = (h, [f, op, v]) => { const x = FIELDS[f](h); return op === 'is' ? x === v : op === 'is not' ? x !== v : op === 'matches' ? glob(v, x) : op === 'does not match' ? !glob(v, x) : op === 'is in' ? x.startsWith(v.replace(/\.0\.0\/16$/, '.').replace(/\.0\/24$/, '.')) : false; };
// kind: auto (made by OpenVIBES), rule (yours), manual (hand-picked)
const HG = [
  { name: 'Windows', kind: 'auto', rule: [['OS family', 'is', 'Windows']], roles: [], desc: 'Every host that reports Windows. Kept up to date by OpenVIBES.' },
  { name: 'Linux', kind: 'auto', rule: [['OS family', 'is', 'Linux']], roles: [], desc: 'Every host that reports Linux. Kept up to date by OpenVIBES.' },
  { name: 'Debian 12', kind: 'auto', rule: [['Distribution', 'is', 'Debian 12']], roles: [], desc: 'Hosts running Debian 12.' },
  { name: 'Fedora 44', kind: 'auto', rule: [['Distribution', 'is', 'Fedora 44']], roles: [], desc: 'Hosts running Fedora 44.' },
  { name: 'Windows Server 2022', kind: 'auto', rule: [['Distribution', 'is', 'Windows Server 2022']], roles: [], desc: 'Hosts running Windows Server 2022.' },
  { name: 'WindowsServers', kind: 'rule', rule: [['OS family', 'is', 'Windows'], ['Hostname', 'does not match', '*test*']], roles: ['Windows lead'], desc: 'Windows servers the Windows team runs; test machines left out.', changed: '3 days ago by Alex Admin' },
  { name: 'HQ network', kind: 'rule', rule: [['IP address', 'is in', '10.0.0.0/16']], roles: [], desc: 'Everything on the head-office network.', changed: '2 weeks ago by Alex Admin' },
  { name: 'Lab', kind: 'rule', rule: [['IP address', 'is in', '10.9.0.0/16']], roles: ['Operator (Lab)'], desc: 'Test machines on the lab network; nothing here is production.', changed: '1 week ago by Alex Admin' },
  { name: 'Production', kind: 'manual', hosts: ['win-dc-01', 'win-dc-02', 'win-app-03', 'web-01', 'db-02', 'mx-01'], roles: [], desc: 'Upgraded from the Production asset group (it used the env=prod tag): the same hosts, now hand-picked. Turn it into a rule when you can.', changed: 'Upgraded from an asset group' },
  { name: 'Pilot hosts', kind: 'manual', hosts: ['web-01', 'win-app-03', 'mx-backup-03'], roles: [], desc: 'Hand-picked hosts that try new rule sets first.', changed: '5 days ago by Alex Admin' },
];
const PEOPLE_IN_ROLE = { 'Windows lead': ['Wendy Ward', 'Tom Tanaka'], 'Operator (Lab)': ['Lab operator'] };
const membersOf = (g) => g.kind === 'manual' ? HOSTS.filter(h => g.hosts.includes(h.name)) : HOSTS.filter(h => g.rule.every(c => test(h, c)));
const ruleChip = ([f, op, v]) => `<span class="tag" style="white-space:pre;font-family:inherit">${f} ${op} <b>${v}</b></span>`;
const KIND = { auto: '<span class="badge badge--plain">Automatic</span>', rule: '<span class="badge badge--accent badge--plain">Rule</span>', manual: '<span class="badge" style="border:1px solid var(--line-strong);background:transparent;color:var(--text-2)">Manual</span>' };
const problems = (hs) => { const a = hs.reduce((n, h) => n + h.alarms, 0), c = hs.reduce((n, h) => n + h.crit, 0);
  const out = [a ? `<span class="badge badge--high">${a} alarm${a === 1 ? '' : 's'}</span>` : '', c ? `<span class="badge badge--critical">${c} critical</span>` : ''].filter(Boolean).join(' ');
  return out ? `<span class="row" style="gap:4px;flex-wrap:nowrap;white-space:nowrap">${out}</span>` : '<span class="subtle">None open</span>'; };
const groupIcon = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"></path></svg>';
function groupsView() {
  const rows = HG.map((g, i) => { const hs = membersOf(g); const online = hs.filter(h => h.online).length; const people = g.roles.flatMap(r => PEOPLE_IN_ROLE[r] || []).length;
    return `<tr data-index="${i}"><td><div class="cell-two"><span class="row" style="gap:8px"><strong>${g.name}</strong>${KIND[g.kind]}</span><span class="subtle" style="white-space:normal">${g.desc}</span></div></td>
    <td><span class="row row--wrap" style="gap:6px">${g.kind === 'manual' ? `<span class="subtle">${g.hosts.length} hosts picked by hand</span>` : g.rule.map(ruleChip).join('<span class="subtle">and</span>')}</span></td>
    <td><div class="cell-two"><span class="num">${hs.length} hosts</span><span class="subtle">${online} online</span></div></td>
    <td>${problems(hs)}</td>
    <td><div class="cell-two"><span>${g.roles.map(r => `<span class="badge badge--accent badge--plain">${r}</span>`).join(' ') || '<span class="subtle">No role yet</span>'}</span><span class="subtle">${people ? `${people} ${people === 1 ? 'person' : 'people'}` : 'Nobody reaches it'}</span></div></td></tr>`; }).join('');
  return `<div class="view">${listHeader('Host groups', HG.length, '<button type="button" class="button button--primary button--small">+ New group</button>', 'Filter groups, rules or hosts…')}
  <p class="view-pad subtle" style="margin:0 0 8px"><b>Automatic</b> groups are made by OpenVIBES from what agents report (OS, distribution) and appear as new kinds of hosts arrive. <b>Rule</b> groups are yours, built from what agents report (OS, distribution, hostname, IP address); both stay up to date by themselves. <b>Manual</b> groups hold hand-picked hosts and never change by themselves.</p>
  <div class="table-wrap"><table class="table" aria-label="Host groups"><thead><tr><th aria-sort="ascending"><button type="button">Group</button></th><th style="width:380px">Membership</th><th style="width:110px">Hosts</th><th style="width:200px">Open problems</th><th style="width:210px">Who reaches it</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}
function groupPage(st) {
  const g = st.g, inGroup = membersOf(g), savedNames = membersOf(st.saved).map(h => h.name), now = inGroup.map(h => h.name);
  const plus = now.filter(n => !savedNames.includes(n)), minus = savedNames.filter(n => !now.includes(n));
  const online = inGroup.filter(h => h.online).length, people = g.roles.flatMap(r => PEOPLE_IN_ROLE[r] || []);
  const card = (title, aside, body, pad = true) => `<section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">${title}</h2>${aside || ''}</div><div style="${pad ? 'padding:14px 16px' : ''}">${body}</div></section>`;
  const kv = (k, v) => `<dt>${k}</dt><dd>${v}</dd>`;
  const sel = (v, w) => `<span class="select" style="width:${w}px;display:inline-flex;align-items:center;padding:0 10px">${v}</span>`;
  const conds = g.kind !== 'manual' ? g.rule.map((c, i) => `<div class="row" style="gap:8px">${i ? '<span class="subtle" style="width:44px">and</span>' : '<span class="subtle" style="width:44px">Where</span>'}${sel(c[0], 150)}${sel(c[1], 140)}${st.editing ? `<input class="input" style="width:190px" value="${esc(c[2])}">` : sel(c[2], 190)}${st.editing ? `<button type="button" class="icon-button" data-dropcond="${i}" aria-label="Remove this condition">${ICON_X}</button>` : ''}</div>`).join('') : '';
  const impact = st.editing && (plus.length || minus.length) ? `<div class="callout callout--warn" style="margin:0"><span style="display:inline-flex">${ICON_INFO}</span><span>If you save: ${[plus.length ? `<b>+${plus.length}</b> (${plus.join(', ')})` : '', minus.length ? `<b>−${minus.length}</b> (${minus.join(', ')})` : ''].filter(Boolean).join(', ')}.${people.length ? ` ${people.join(', ')} ${plus.length && minus.length ? 'gain and lose access accordingly' : plus.length ? 'gain access to them' : 'lose access to them'}.` : ''}</span></div>` : '';
  const autoNote = g.kind === 'auto' ? `<div class="callout" style="margin:0;background:var(--accent-soft);color:var(--text)"><span style="color:var(--accent);display:inline-flex">${ICON_INFO}</span><span>Made by OpenVIBES from what agents report. Editing it makes it yours: OpenVIBES won't change it again. Deleting it is remembered; it won't come back.</span></div>` : '';
  const membership = g.kind === 'manual'
    ? `<div class="stack" style="gap:10px"><span class="subtle">Hosts picked by hand. New hosts are never added by themselves.</span><div class="row row--wrap" style="gap:6px">${g.hosts.map(n => `<span class="chip" aria-pressed="true" style="gap:4px;${st.editing ? 'padding-right:4px' : 'cursor:default'}">${n}${st.editing ? `<button type="button" class="icon-button" data-drophost="${n}" aria-label="Remove ${n}" style="width:20px;height:20px;min-width:20px">${ICON_X}</button>` : ''}</span>`).join('') || '<span class="subtle">No hosts yet</span>'}</div>${st.editing ? `<label class="search" style="width:100%">${ICON_SEARCH}<input class="input" placeholder="Search hosts to add"></label>` : ''}${impact}${st.editing ? '<div class="row" style="gap:8px"><button type="button" class="button button--primary button--small" data-edit>Save changes</button><button type="button" class="button button--small" data-cancel>Cancel</button></div>' : ''}</div>`
    : `<div class="stack" style="gap:10px">${autoNote}${conds}${st.editing ? '<div><button type="button" class="button button--ghost button--small">+ Add condition</button></div>' : ''}<span class="subtle" style="font-size:12.5px">Rules use what agents report: OS family, distribution, hostname and IP address. Labels never count. Hosts join and leave by themselves as they change.</span>${impact}${st.editing ? '<div class="row" style="gap:8px"><button type="button" class="button button--primary button--small" data-edit>Save changes</button><button type="button" class="button button--small" data-cancel>Cancel</button></div>' : ''}</div>`;
  const hostRows = inGroup.map(h => `<tr><td><div class="cell-two"><span class="mono">${h.name}</span><span class="subtle">${h.distro}</span></div></td><td class="mono">${h.ip}</td><td><span class="row row--wrap" style="gap:4px">${h.labels.map(l => `<span class="chip" style="cursor:default;height:22px">${l}</span>`).join('')}</span></td><td><span class="${h.online ? '' : 'warn-text'}">${h.seen}</span></td><td>${problems([h])}</td></tr>`).join('');
  const menu = st.menu ? `<div role="menu" style="position:absolute;right:0;top:calc(100% + 6px);z-index:30;min-width:180px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-2);box-shadow:var(--shadow-2);padding:6px"><button type="button" role="menuitem" class="menu__item" style="display:block;width:100%;text-align:left;text-transform:none">Duplicate…</button><button type="button" role="menuitem" class="menu__item" style="display:block;width:100%;text-align:left;text-transform:none;color:var(--bad)">Delete group…</button></div>` : '';
  const activity = g.kind === 'auto' ? [['Created automatically', 'OpenVIBES · when the first host reported it']] : g.kind === 'manual' ? [['Added mx-backup-03', 'Alex Admin · 5 days ago'], ['Group created', 'Alex Admin · 2 weeks ago']] : [['Rule changed: added Hostname does not match *test*', 'Alex Admin · 3 days ago'], ['Windows lead started using this group', 'Alex Admin · 2 weeks ago'], ['Group created', 'Alex Admin · 2 weeks ago']];
  const membershipWords = g.kind === 'manual' ? `${g.hosts.length} hosts picked by hand` : 'Hosts where ' + g.rule.map(([f, op, v]) => `${f.toLowerCase()} ${op} <b>${v}</b>`).join(' and ');
  return `<div class="view"><div>
    <div class="view-pad" style="padding-top:20px"><span class="subtle"><a href="#">Settings</a> › <a href="#">Host groups</a></span></div>
    <header class="view-pad" style="display:flex;gap:16px;align-items:center;padding-top:8px;padding-bottom:16px">
      <span style="display:grid;place-items:center;width:56px;height:56px;border-radius:14px;background:var(--accent-soft);color:var(--accent)">${groupIcon}</span>
      <div class="stack grow" style="gap:4px"><div class="row" style="gap:10px"><h1 style="margin:0">${g.name}</h1>${KIND[g.kind]}</div><span class="subtle">${inGroup.length} hosts · ${online} online · used by ${g.roles.length} role${g.roles.length === 1 ? '' : 's'} · ${people.length} ${people.length === 1 ? 'person' : 'people'} reach it</span></div>
      <div class="row" style="gap:8px"><button type="button" class="button" data-edit>${st.editing ? 'Stop editing' : 'Edit'}</button><span style="position:relative"><button type="button" class="button" data-menu aria-haspopup="menu" aria-label="More actions">⋯</button>${menu}</span></div></header>
    <div class="view-pad" style="display:grid;grid-template-columns:380px minmax(0,1fr);gap:24px;align-items:start;margin-bottom:60px">
      <div class="stack" style="gap:16px">
        ${card('Details', '', `<p style="margin:0 0 12px">${g.desc}</p><dl class="kv" style="margin:0;row-gap:10px;grid-template-columns:118px minmax(0,1fr)">${kv('Kind', g.kind === 'auto' ? 'Automatic: made by OpenVIBES' : g.kind === 'rule' ? 'Rule: stays up to date' : 'Manual: hand-picked')}${kv('Membership', membershipWords)}${kv('Open problems', problems(inGroup))}${kv('Changed', g.changed || 'Never by hand')}</dl>`)}
        ${card('Who reaches it', '', g.roles.length ? g.roles.map(r => `<div class="stack" style="gap:6px;padding:4px 0 10px"><div class="row row--between"><a href="#"><strong>${r}</strong></a><span class="subtle num">${ROLE_DEFS[r].perms.length} permissions</span></div><div class="row row--wrap" style="gap:6px">${(PEOPLE_IN_ROLE[r] || []).map(n => `<span class="chip" style="cursor:default;gap:6px"><span style="display:grid;place-items:center;width:18px;height:18px;border-radius:50%;background:var(--accent-soft);color:var(--accent);font-size:9.5px;font-weight:650">${initials(n)}</span>${n}</span>`).join('')}</div></div>`).join('') : '<span class="subtle">No role uses this group yet. Choose it in a role\'s Hosts.</span>')}
        ${card('Recent changes', '<a href="#" style="font-size:12.5px">Audit log</a>', `<ul class="list list--plain" style="margin:0">${activity.map(([a, d]) => `<li style="display:grid;gap:2px;padding:6px 0;border-bottom:1px solid var(--line)"><span>${a}</span><span class="subtle" style="font-size:12.5px">${d}</span></li>`).join('')}</ul>`)}
      </div>
      <div class="stack" style="gap:16px">
        ${card(g.kind === 'manual' ? 'Hosts picked by hand' : 'Rule', st.editing ? '<span class="badge badge--accent badge--plain">Editing</span>' : '', membership)}
        ${card(`Hosts in this group <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">${inGroup.length}</span>`, `<label class="search" style="width:240px">${ICON_SEARCH}<input class="input" placeholder="Filter hosts…"></label>`,
          `<div class="table-wrap" style="margin:0;border:0;border-radius:0"><table class="table" aria-label="Hosts in this group"><thead><tr><th style="width:220px">Host</th><th style="width:130px">IP address</th><th>Labels</th><th style="width:110px">Last seen</th><th style="width:200px">Open problems</th></tr></thead><tbody>${hostRows || '<tr><td colspan="5" class="subtle">No host matches yet.</td></tr>'}</tbody></table></div>`, false)}
      </div>
    </div></div>
  </div>`;
}
function liveGroup(name) {
  const st = { g: JSON.parse(JSON.stringify(HG.find(g => g.name === name))) };
  st.saved = JSON.parse(JSON.stringify(st.g));
  const render = () => { const v = $('.view-area'); const top = v.scrollTop; v.innerHTML = groupPage(st); v.scrollTop = top; };
  render();
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-dropcond],[data-drophost],[data-edit],[data-cancel],[data-menu]');
    if (!t) { if (st.menu) { st.menu = false; render(); } return; }
    if (t.dataset.edit !== undefined) { if (st.editing) st.saved = JSON.parse(JSON.stringify(st.g)); st.editing = !st.editing; }
    if (t.dataset.cancel !== undefined) { st.g = JSON.parse(JSON.stringify(st.saved)); st.editing = false; }
    if (t.dataset.menu !== undefined) st.menu = !st.menu;
    if (t.dataset.dropcond) st.g.rule = st.g.rule.filter((_, i) => i !== Number(t.dataset.dropcond));
    if (t.dataset.drophost) st.g.hosts = st.g.hosts.filter(n => n !== t.dataset.drophost);
    render();
  });
}
"""
screen(
    "9-host-groups", "settings-access",
    "<b>9 · Settings › Host groups.</b> Automatic groups made by OpenVIBES (OS, distribution), your rule groups, and manual groups. Rule and automatic groups stay up to date by themselves.",
    HOSTGROUPS + "settingsTabs('Host groups'); tabPanel(groupsView());",
)
screen(
    "10-host-group", "settings-access",
    "<b>10 · A rule group.</b> WindowsServers: its rule (built from what agents report), who reaches it, and its hosts. <b>Try it:</b> Edit, remove a condition, see who would join or leave before saving.",
    PEOPLE + HOSTGROUPS + "liveGroup('WindowsServers');",
)
screen(
    "10b-manual-group", "settings-access",
    "<b>10b · A manual group.</b> Pilot hosts: picked by hand, never changes by itself. <b>Try it:</b> Edit and remove a host.",
    PEOPLE + HOSTGROUPS + "liveGroup('Pilot hosts');",
)
screen(
    "10c-automatic-group", "settings-access",
    "<b>10c · An automatic group.</b> Debian 12, made by OpenVIBES when the first Debian 12 host reported in. Editing it makes it yours.",
    PEOPLE + HOSTGROUPS + "liveGroup('Debian 12');",
)

GENERAL = r"""
// ---- General ----
const sw2 = (on, label) => `<button type="button" role="switch" aria-checked="${on}" aria-label="${label}" class="switch" data-toggle style="width:auto"><span class="switch__track" aria-hidden="true"><span class="switch__knob"></span></span></button>`;
function settingRow(title, text, control, extra, saved) {
  return `<div style="display:grid;grid-template-columns:minmax(0,1fr) auto;gap:24px;align-items:start;padding:16px">
    <div class="stack" style="gap:4px"><strong>${title}</strong><span class="subtle">${text}</span>${extra || ''}${saved ? `<span class="row" style="gap:6px;font-size:12.5px;color:var(--ok)"><span style="display:inline-flex">${ICON_CHECK}</span>Saved · recorded in the audit log</span>` : ''}</div>
    <div style="padding-top:2px">${control}</div></div>`;
}
function generalView(st) {
  const card = (id, title, body) => `<section class="card" id="${id}" style="overflow:hidden"><div style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">${title}</h2></div>${body}</section>`;
  const approvers = st.approval ? `<div class="callout" style="margin:6px 0 0;background:var(--accent-soft);color:var(--text)"><span style="color:var(--accent);display:inline-flex">${ICON_INFO}</span><span>Approvers: anyone with <b>Approve suppressions</b>, on the hosts their role covers: <a href="#">Windows lead</a> (WindowsServers), <a href="#">Administrator</a> (all hosts). Nobody approves their own request.</span></div>` : '';
  const days = `<span class="row" style="gap:8px"><input class="input num" data-days style="width:72px;text-align:right" value="${st.days}" aria-label="Days"><span class="subtle">days</span>${st.daysDirty ? '<button type="button" class="button button--primary button--small" data-savedays>Save</button>' : ''}</span>`;
  const toc = [['alarms', 'Alarm suppressions', '1 setting'], ['sso', 'Single sign-on', '1 setting']];
  const changes = [['Suppressions need approval: on', 'Alex Admin · 2 days ago'], ['Inactive SSO users: 90 days', 'Alex Admin · 1 month ago']];
  return `<div class="view">
    <header class="view-pad" style="padding-top:20px;padding-bottom:16px"><h1 style="margin:0">General</h1><span class="subtle">Settings for the whole platform · each one saves as soon as you change it</span></header>
    <div class="view-pad" style="display:grid;grid-template-columns:300px minmax(0,1fr);gap:24px;align-items:start;padding-bottom:40px">
      <div class="stack" style="gap:16px">
        <section class="card" style="overflow:hidden"><div style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">On this page</h2></div>
          <ul class="list list--plain" style="margin:0;padding:6px 0">${toc.map(([id, t, n]) => `<li><a href="#${id}" class="row row--between" style="padding:8px 16px;text-decoration:none;color:inherit"><span>${t}</span><span class="subtle" style="font-size:12.5px">${n}</span></a></li>`).join('')}</ul></section>
        <section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">Recent changes</h2><a href="#" style="font-size:12.5px">Audit log</a></div>
          <ul class="list list--plain" style="margin:0;padding:6px 16px">${changes.map(([a, d]) => `<li style="display:grid;gap:2px;padding:6px 0;border-bottom:1px solid var(--line)"><span>${a}</span><span class="subtle" style="font-size:12.5px">${d}</span></li>`).join('')}</ul></section>
      </div>
      <div class="stack" style="gap:16px">
        ${card('alarms', 'Alarm suppressions', settingRow('Suppressions need approval', st.approval ? 'A suppression waits under Alarm suppressions until someone allowed to approve it says yes. Until then, matching alarms keep arriving.' : 'Off: a suppression works as soon as it is made, with its reason. Turn on to have a second person approve every suppression.', sw2(st.approval, 'Suppressions need approval'), approvers, st.saved === 'approval'))}
        ${card('sso', 'Single sign-on', settingRow('Remove inactive single sign-on users', 'A person who signs in through single sign-on and then stops is removed after this many days without signing in. Their audit history stays; local users are never removed. Takes effect once single sign-on is set up.', days, '', st.saved === 'days'))}
      </div>
    </div></div>`;
}
function liveGeneral(st) {
  st.days = st.days || 90;
  const render = (focus) => { tabPanel(generalView(st)); if (focus) { const i = $('[data-days]'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); } };
  settingsTabs('General'); render();
  document.addEventListener('input', (e) => { if (e.target.dataset.days !== undefined) { st.days = e.target.value; st.daysDirty = true; st.saved = ''; render(true); } });
  document.addEventListener('click', (e) => {
    if (e.target.closest('[data-toggle]')) { st.approval = !st.approval; st.saved = 'approval'; render(); }
    if (e.target.closest('[data-savedays]')) { st.daysDirty = false; st.saved = 'days'; render(); }
  });
}
"""
screen(
    "11-general", "settings-access",
    "<b>11 · Settings › General.</b> Sections on the left, their settings on the right; each saves when changed. <b>Try it:</b> switch on approvals; change the days and Save.",
    GENERAL + "liveGeneral({ approval: false });",
)

ALARMS = r"""
// ---- Suppressing with a reason, and approvals ----
const ICON_APPROVE = '<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M2 12a10 10 0 1 0 20 0a10 10 0 1 0-20 0"></path><path d="m8 12 3 3 5-6"></path></svg>';
function approvalsRail(active) {
  const supp = $('a.rail__item[href="/alarm-suppressions"]'); if (!supp) return;
  if (active) { $$('a.rail__item[aria-current]').forEach(a => a.removeAttribute('aria-current')); }
  supp.after(h(`<a class="rail__item" href="/approvals" aria-label="Approvals" ${active ? 'aria-current="page"' : ''}>${ICON_APPROVE}<span class="rail__count" title="2 waiting">2</span><span class="rail__label">Approvals</span><span class="rail__short" aria-hidden="true">Approvals</span><span class="rail__tip" aria-hidden="true">Approvals</span></a>`));
}
function suppressForm(st) {
  if (st.sent) return `<div class="callout callout--warn" style="margin:0;align-items:flex-start"><span style="display:inline-flex;margin-top:1px">${ICON_INFO}</span><span><b>Suppression requested, waiting for approval.</b> Until someone allowed to approve on Lab says yes, these alarms keep arriving. It is listed under Alarm suppressions, where approvers see it with Approve and Reject. <a href="#">Withdraw request</a></span></div>`;
  return `<section class="card" style="padding:14px 16px;display:grid;gap:12px">
    <div class="row row--between"><strong>Suppress this alarm</strong><span class="subtle" style="font-size:12.5px">New matches are closed as false positives</span></div>
    <div class="field"><span>What</span>${seg('What', ['This program', 'This exact command'], st.what)}<span class="mono subtle" style="font-size:12px">${st.what === 'This program' ? '/usr/bin/sh started by /usr/sbin/nginx' : 'sh -c /usr/local/bin/healthcheck'}</span></div>
    <div class="field"><span>Where</span>${seg('Where', ['This host', 'Lab'], st.where)}<span class="subtle" style="font-size:12px">Only hosts your role covers can be chosen.</span></div>
    <div class="field"><span>For</span>${seg('For', ['7 days', '30 days', 'Until removed'], st.for)}</div>
    <label class="field"><span>Reason <span class="subtle">(required)</span></span><textarea class="textarea" rows="3" data-reason placeholder="Why is this safe to quiet? e.g. our health check runs this every minute">${esc(st.reason)}</textarea></label>
    <div class="callout" style="margin:0;background:var(--accent-soft);color:var(--text)"><span style="color:var(--accent);display:inline-flex">${ICON_INFO}</span><span>Suppressions need approval on this platform: this waits under Alarm suppressions until someone allowed to approve on Lab says yes.</span></div>
    <div class="row" style="gap:8px"><button type="button" class="button button--primary" data-send ${st.reason.trim().length < 10 ? 'disabled title="Give a reason first"' : ''}>Request suppression</button><button type="button" class="button">Cancel</button>${st.reason.trim().length < 10 ? '<span class="subtle" style="font-size:12.5px">A reason of at least a few words is needed.</span>' : ''}</div>
  </section>`;
}
function liveSuppress(st) {
  const quiet = $('[aria-label^="Quiet"]').closest('.row');
  const box = document.createElement('div'); quiet.replaceWith(box);
  const render = () => { box.innerHTML = suppressForm(st); const t = box.querySelector('[data-reason]'); if (t && st.focus) { t.focus(); t.setSelectionRange(t.value.length, t.value.length); } };
  render();
  document.addEventListener('input', (e) => { if (e.target.dataset.reason !== undefined) { st.reason = e.target.value; st.focus = true; render(); } });
  document.addEventListener('click', (e) => {
    const o = e.target.closest('.seg__opt'); const send = e.target.closest('[data-send]');
    if (o && o.closest('.card')) { const g = o.closest('.seg').getAttribute('aria-label'); st[g === 'What' ? 'what' : g === 'Where' ? 'where' : 'for'] = o.textContent; st.focus = false; render(); }
    if (send && !send.disabled) { st.sent = true; render(); }
  });
}
const REQUESTS = [
  { id: 1, who: 'Lab operator', when: '12 min ago', what: 'This program', detail: '/usr/bin/sh started by /usr/sbin/nginx', where: 'Lab', for: '30 days', reason: 'Our health check script runs through sh every minute on the k8s lab nodes. Reviewed with the platform team.', matches: 41, sample: ['k8s-node-02.lab · 2 min ago', 'k8s-node-01.lab · 6 min ago', 'k8s-node-03.lab · 9 min ago'] },
  { id: 2, who: 'Wendy Ward', when: '1 h ago', what: 'This exact command', detail: 'powershell.exe -File C:\\ops\\backup.ps1', where: 'WindowsServers', for: 'Until removed', reason: 'Nightly backup job on the file servers; signed script, runs 02:00.', matches: 14, sample: ['win-file-07 · yesterday 02:00', 'win-file-08 · yesterday 02:00'] },
];
function approvalsPage(st) {
  const list = st.tab === 'waiting' ? REQUESTS.filter(r => !st.done[r.id]) : REQUESTS.filter(r => st.done[r.id]);
  const card = (r) => {
    const done = st.done[r.id];
    const rejecting = st.rejecting === r.id;
    const actions = done ? `<span class="badge ${done.ok ? 'badge--ok' : 'badge--bad'}">${done.ok ? 'Approved by you' : 'Rejected by you'}</span>${done.reason ? `<span class="subtle">“${esc(done.reason)}”</span>` : ''}`
      : rejecting ? `<div class="stack" style="gap:8px;width:100%"><label class="field"><span>Why reject? <span class="subtle">(required, ${r.who} sees it)</span></span><textarea class="textarea" rows="2" data-rejectreason>${esc(st.rejectReason)}</textarea></label><div class="row" style="gap:8px"><button type="button" class="button button--danger" data-confirmreject="${r.id}" ${st.rejectReason.trim().length < 5 ? 'disabled' : ''} style="background:var(--bad);color:#fff;border-color:var(--bad)">Reject</button><button type="button" class="button" data-cancelreject>Cancel</button></div></div>`
      : `<button type="button" class="button button--primary" data-approve="${r.id}">Approve</button><button type="button" class="button" data-reject="${r.id}">Reject…</button>`;
    return `<section class="card" style="overflow:hidden"><div style="display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:20px;padding:16px 20px">
      <div class="stack" style="gap:10px">
        <div class="row" style="gap:10px"><strong style="font-size:15px">Suppress “A web server started a shell”</strong></div>
        <div class="row row--wrap" style="gap:6px"><span class="chip" aria-pressed="true" style="cursor:default">${r.what}</span><span class="chip" aria-pressed="true" style="cursor:default">${r.where}</span><span class="chip" aria-pressed="true" style="cursor:default">${r.for}</span></div>
        <span class="mono subtle" style="font-size:12.5px">${r.detail}</span>
        <blockquote style="margin:0;padding:8px 12px;border-left:3px solid var(--accent);background:var(--surface-2);border-radius:var(--r-1)">${esc(r.reason)}</blockquote>
        <span class="subtle" style="font-size:12.5px">Asked by <b>${r.who}</b> · ${r.when}</span>
      </div>
      <div class="stack" style="gap:8px"><span class="subtle">Would have closed <b class="num">${r.matches}</b> alarms in the last 7 days, for example:</span><ul class="list list--plain" style="margin:0">${r.sample.map(x => `<li class="mono" style="font-size:12.5px;padding:3px 0">${x}</li>`).join('')}</ul><a href="#" style="font-size:12.5px">See all matching alarms</a></div>
    </div><div class="row" style="gap:8px;padding:12px 20px;border-top:1px solid var(--line);background:var(--surface-2)">${actions}</div></section>`;
  };
  const waiting = REQUESTS.filter(r => !st.done[r.id]).length;
  return `<div class="view"><header class="view-header"><div class="view-header__top"><div class="view-header__title"><h1>Approvals</h1><span class="view-header__count num">${waiting}</span></div></div></header>
    <p class="view-pad subtle" style="margin:0">Suppression requests on hosts you may approve for. You never see your own requests here.</p>
    <div class="tabs" role="tablist" style="margin-top:12px"><button type="button" role="tab" data-atab="waiting" aria-selected="${st.tab === 'waiting'}">Waiting <span class="subtle num">${waiting}</span></button><button type="button" role="tab" data-atab="decided" aria-selected="${st.tab === 'decided'}">Decided</button></div>
    <div class="view-pad stack" style="gap:16px;padding-top:20px">${list.map(card).join('') || `<div class="empty"><h3>${st.tab === 'waiting' ? 'Nothing waiting' : 'Nothing decided yet'}</h3><p>${st.tab === 'waiting' ? 'New suppression requests on your hosts appear here.' : 'Approved and rejected requests appear here.'}</p></div>`}</div></div>`;
}
function liveApprovals(st) {
  approvalsRail(true); $('.topbar__title').textContent = 'Approvals';
  const render = () => { const v = $('.view-area'); v.innerHTML = approvalsPage(st); const t = v.querySelector('[data-rejectreason]'); if (t && st.focus) { t.focus(); t.setSelectionRange(t.value.length, t.value.length); } };
  render();
  document.addEventListener('input', (e) => { if (e.target.dataset.rejectreason !== undefined) { st.rejectReason = e.target.value; st.focus = true; render(); } });
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-approve],[data-reject],[data-confirmreject],[data-cancelreject],[data-atab]'); if (!t) return;
    st.focus = false;
    if (t.dataset.atab) st.tab = t.dataset.atab;
    if (t.dataset.approve) st.done[t.dataset.approve] = { ok: true };
    if (t.dataset.reject) { st.rejecting = Number(t.dataset.reject); st.rejectReason = ''; st.focus = true; }
    if (t.dataset.cancelreject !== undefined) st.rejecting = null;
    if (t.dataset.confirmreject && !t.disabled) { st.done[t.dataset.confirmreject] = { ok: false, reason: st.rejectReason }; st.rejecting = null; }
    render();
  });
}
function suppressionsList() {
  // Approvals live here: the menu count is on Alarm suppressions.
  const supp = $('a.rail__item[href="/alarm-suppressions"]');
  if (supp && !supp.querySelector('.rail__count')) supp.querySelector('.rail__label').before(h('<span class="rail__count" title="2 waiting">2</span>'));
  const st = { items: [
    { id: 1, st: 'waiting', cmd: '/usr/bin/sh started by /usr/sbin/nginx', what: 'This program', where: 'Lab', for: '30 days after approval', who: 'Lab operator', when: '12 min ago', why: 'Our health check script runs through sh every minute on the k8s lab nodes.', matches: 41 },
    { id: 2, st: 'waiting', cmd: '/usr/bin/python3 started by /usr/sbin/cron', what: 'This program', where: 'This host · db-02', for: '7 days', who: 'You', when: '5 min ago', why: 'Database maintenance script while we migrate; runs nightly.', matches: 6, mine: true },
    { id: 3, st: 'active', cmd: 'powershell.exe -File C:\\ops\\backup.ps1', what: 'This exact command', where: 'WindowsServers', for: 'Until removed', who: 'Wendy Ward', when: '1 h ago', why: 'Nightly backup job on the file servers; signed script, runs 02:00.', note: 'Approved by Alex Admin · 40 min ago · closed 14 alarms since' },
    { id: 4, st: 'rejected', cmd: '/usr/bin/curl started by cron', what: 'This program', where: 'web-01', for: '7 days', who: 'Sam Analyst', when: 'yesterday', why: 'Monitoring ping.', note: 'Rejected by Alex Admin: “Too broad: use the exact command instead.”' },
  ], rejecting: null, reason: '' };
  const T = { waiting: ['Waiting for approval', 'badge--warn'], active: ['Active', 'badge--ok'], rejected: ['Rejected', 'badge--bad'] };
  const chips = (x) => [x.what, x.where, x.for].map(c => `<span class="chip" aria-pressed="true" style="cursor:default">${c}</span>`).join('');
  const actions = (x) => {
    if (x.st === 'waiting' && x.mine) return '<button type="button" class="button button--small">Withdraw</button>';
    if (x.st === 'waiting') return `<button type="button" class="button button--primary button--small" data-approve="${x.id}">Approve</button><button type="button" class="button button--small" data-reject="${x.id}">Reject…</button>`;
    return x.st === 'active' ? '<button type="button" class="button button--small">Remove…</button>' : '<button type="button" class="button button--small">Ask again…</button>';
  };
  const note = (x) => x.st === 'waiting' ? (x.mine ? 'waiting for someone allowed to approve on db-02 (you can\'t approve your own)' : `would have closed <b>${x.matches}</b> alarms in the last 7 days · <a href="#">see them</a>`) : x.note;
  const rejectBox = (x) => st.rejecting === x.id ? `<div class="stack" style="gap:8px;grid-column:1 / -1"><label class="field"><span>Why reject? <span class="subtle">(required, ${x.who} sees it)</span></span><textarea class="textarea" rows="2" data-rejectreason>${esc(st.reason)}</textarea></label><div class="row" style="gap:8px"><button type="button" class="button button--small" data-confirmreject="${x.id}" ${st.reason.trim().length < 5 ? 'disabled' : ''} style="background:var(--bad);color:#fff;border-color:var(--bad)">Reject</button><button type="button" class="button button--small" data-cancelreject>Cancel</button></div></div>` : '';
  const row = (x) => `<div style="display:grid;grid-template-columns:minmax(0,1fr) auto;gap:16px 24px;align-items:start;padding:16px;border-top:1px solid var(--line)">
    <div class="stack" style="gap:8px"><span class="mono">${x.cmd}</span><div class="row row--wrap" style="gap:6px">${chips(x)}</div>
      <blockquote style="margin:0;padding:6px 12px;border-left:3px solid var(--accent);background:var(--surface-2);border-radius:var(--r-1)">${x.why}</blockquote>
      <span class="subtle" style="font-size:12.5px">Asked by <b>${x.who}</b> · ${x.when} · ${note(x)}</span></div>
    <div class="stack" style="gap:8px;justify-items:end;align-items:end"><span class="badge ${T[x.st][1]}">${T[x.st][0]}</span><div class="row" style="gap:6px"><a class="button button--ghost button--small" href="#">Open alarm</a>${st.rejecting === x.id ? '' : actions(x)}</div></div>${rejectBox(x)}</div>`;
  const render = () => {
    const sections = ['waiting', 'active', 'rejected'].map(k => [k, st.items.filter(x => x.st === k)]);
    const count = (k) => st.items.filter(x => x.st === k).length;
    const card = (k, xs) => `<section class="card" id="s-${k}" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px"><h2 class="section-title" style="margin:0">${T[k][0]} <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">${xs.length}</span></h2>${k === 'waiting' ? '<span class="subtle" style="font-size:12.5px">You can approve requests on hosts your role covers, never your own</span>' : ''}</div>${xs.map(row).join('') || '<p class="subtle" style="margin:0;padding:16px;border-top:1px solid var(--line)">None.</p>'}</section>`;
    const changes = [['Wendy Ward\'s backup suppression approved', 'Alex Admin · 40 min ago'], ['Lab operator asked to suppress sh from nginx', '12 min ago'], ['Sam Analyst\'s curl suppression rejected', 'Alex Admin · yesterday']];
    const v = $('.view-area'); const top = v.scrollTop;
    v.innerHTML = `<div class="view">
    <header class="view-pad" style="padding-top:20px;padding-bottom:16px"><h1 style="margin:0">Alarm suppressions</h1><span class="subtle">${st.items.length} suppressions · ${count('waiting')} waiting · ${count('active')} active · ${count('rejected')} rejected · new suppressions are made from an alarm</span></header>
    <div class="view-pad" style="display:grid;grid-template-columns:300px minmax(0,1fr);gap:24px;align-items:start;padding-bottom:40px">
      <div class="stack" style="gap:16px">
        <section class="card" style="overflow:hidden"><div style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">By status</h2></div>
          <ul class="list list--plain" style="margin:0;padding:6px 0">${sections.map(([k, xs]) => `<li><a href="#s-${k}" class="row row--between" style="padding:8px 16px;text-decoration:none;color:inherit"><span>${T[k][0]}</span><span class="badge ${T[k][1]}">${xs.length}</span></a></li>`).join('')}</ul></section>
        <section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">Recent changes</h2><a href="#" style="font-size:12.5px">Audit log</a></div>
          <ul class="list list--plain" style="margin:0;padding:6px 16px">${changes.map(([a, d]) => `<li style="display:grid;gap:2px;padding:6px 0;border-bottom:1px solid var(--line)"><span>${a}</span><span class="subtle" style="font-size:12.5px">${d}</span></li>`).join('')}</ul></section>
      </div>
      <div class="stack" style="gap:16px">${sections.map(([k, xs]) => card(k, xs)).join('')}</div>
    </div></div>`;
    v.scrollTop = top;
    const t = v.querySelector('[data-rejectreason]'); if (t && st.focus) { t.focus(); t.setSelectionRange(t.value.length, t.value.length); }
  };
  render();
  document.addEventListener('input', (e) => { if (e.target.dataset.rejectreason !== undefined) { st.reason = e.target.value; st.focus = true; render(); } });
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-approve],[data-reject],[data-confirmreject],[data-cancelreject]'); if (!t) return;
    const find = (id) => st.items.find(x => x.id === Number(id));
    st.focus = false;
    if (t.dataset.approve) { const x = find(t.dataset.approve); x.st = 'active'; x.note = 'Approved by you · just now'; }
    if (t.dataset.reject) { st.rejecting = Number(t.dataset.reject); st.reason = ''; st.focus = true; }
    if (t.dataset.cancelreject !== undefined) st.rejecting = null;
    if (t.dataset.confirmreject && !t.disabled) { const x = find(t.dataset.confirmreject); x.st = 'rejected'; x.note = `Rejected by you: “${esc(st.reason)}”`; st.rejecting = null; }
    render();
  });
}
"""
screen(
    "12-suppress", "alarm-panel",
    "<b>12 · Suppressing an alarm.</b> What, where (only hosts your role covers), for how long, and a required reason. <b>Try it:</b> type a reason, then Request: with approvals on it waits for a yes.",
    ALARMS + "liveSuppress({ what: 'This program', where: 'Lab', for: '30 days', reason: '', sent: false });",
)
screen(
    "14-suppressions", "suppressions",
    "<b>14 · Alarm suppressions</b> (approvals live here). Waiting requests come first with Approve / Reject…; your own show Withdraw. <b>Try it:</b> Approve or Reject… (with a reason) the Lab operator's request.",
    ALARMS + "suppressionsList();",
)

HOSTSUI = r"""
// ---- Hosts list with filters, and the host page ----
const AGENT = { 'win-dc-01': '0.2.8', 'win-dc-02': '0.2.8', 'win-file-07': '0.2.7', 'win-file-08': '0.2.6', 'win-app-03': '0.2.8', 'win-test-01': '0.2.8', 'mx-01': '0.2.8', 'mx-backup-03': '0.2.8', 'web-01': '0.2.8', 'db-02': '0.2.7', 'lab-ws-04': '0.2.6' };
const LATEST_AGENT = '0.2.8';
const groupsOf = (h) => HG.filter(g => membersOf(g).some(x => x.name === h.name)).map(g => g.name);
function hostsActive(rail) { $$('a.rail__item[aria-current]').forEach(a => a.removeAttribute('aria-current')); const a = $(`a.rail__item[href="${rail}"]`); if (a) a.setAttribute('aria-current', 'page'); $('.topbar__title').textContent = 'Hosts'; }
const FILTERS = {
  Status: { opts: ['Online', 'Offline'], test: (h, v) => (v === 'Online') === h.online },
  OS: { opts: ['Windows', 'Linux'], test: (h, v) => h.family === v },
  Group: { opts: () => HG.map(g => g.name), test: (h, v) => groupsOf(h).includes(v) },
  Label: { opts: () => [...new Set(HOSTS.flatMap(h => h.labels))], test: (h, v) => h.labels.includes(v) },
  Problems: { opts: ['Has critical', 'Has open alarms', 'None open'], test: (h, v) => v === 'Has critical' ? h.crit > 0 : v === 'Has open alarms' ? h.alarms > 0 : !h.crit && !h.alarms },
  Agent: { opts: ['Older than the latest', 'Latest'], test: (h, v) => (AGENT[h.name] !== LATEST_AGENT) === (v === 'Older than the latest') },
};
function hostsList(st) {
  const rows = HOSTS.filter(h => Object.entries(st.filters).every(([k, v]) => FILTERS[k].test(h, v)) && (!st.q || h.name.includes(st.q)));
  const opts = (k) => typeof FILTERS[k].opts === 'function' ? FILTERS[k].opts() : FILTERS[k].opts;
  const count = (k, v) => HOSTS.filter(h => FILTERS[k].test(h, v)).length;
  const fbtn = (k) => { const on = st.filters[k];
    const menu = st.open === k ? `<div role="menu" style="position:absolute;left:0;top:calc(100% + 6px);z-index:30;min-width:220px;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-2);box-shadow:var(--shadow-2);padding:6px">${opts(k).map(v => `<button type="button" role="menuitemradio" aria-checked="${on === v}" class="menu__item" data-fset="${k}|${v}" style="display:flex;width:100%;justify-content:space-between;text-transform:none;gap:16px"><span>${v}</span><span class="subtle num">${count(k, v)}</span></button>`).join('')}</div>` : '';
    return `<span style="position:relative">${on ? `<span class="chip" aria-pressed="true" style="gap:4px;padding-right:4px">${k}: ${on}<button type="button" class="icon-button" data-fclear="${k}" aria-label="Clear ${k}" style="width:20px;height:20px;min-width:20px">${ICON_X}</button></span>` : `<button type="button" class="chip" data-fopen="${k}">${k} <span aria-hidden="true">▾</span></button>`}${menu}</span>`; };
  const tr = rows.map(h => { const gs = groupsOf(h); const old = AGENT[h.name] !== LATEST_AGENT;
    return `<tr data-host="${h.name}" style="cursor:pointer"><td><div class="cell-two"><span class="mono">${h.name}</span><span class="subtle">${h.ip}</span></div></td><td><div class="cell-two"><span>${h.distro}</span><span class="subtle">${h.family}</span></div></td>
      <td><span class="row row--wrap" style="gap:4px">${gs.slice(0, 2).map(g => `<span class="badge badge--accent badge--plain">${g}</span>`).join('')}${gs.length > 2 ? `<span class="subtle" style="font-size:12px">+${gs.length - 2}</span>` : ''}</span></td>
      <td><span class="row row--wrap" style="gap:4px">${h.labels.map(l => `<span class="chip" style="cursor:default;height:22px">${l}</span>`).join('')}</span></td>
      <td>${problems([h])}</td><td><div class="cell-two"><span class="${h.online ? '' : 'warn-text'}">${h.seen}</span><span class="subtle">${h.online ? 'Online' : 'Offline'}</span></div></td><td><span class="mono ${old ? 'warn-text' : ''}" title="${old ? 'Older than the latest agent release (' + LATEST_AGENT + ')' : 'The latest agent release'}">${AGENT[h.name]}</span></td></tr>`; }).join('');
  return `<div class="view">
    <header class="view-pad" style="padding-top:20px;padding-bottom:8px"><div class="row row--between"><div><h1 style="margin:0">Hosts <span class="subtle num" style="font-size:16px;font-weight:500">${rows.length}${rows.length !== HOSTS.length ? ' of ' + HOSTS.length : ''}</span></h1><span class="subtle">${HOSTS.filter(h => h.online).length} online · ${HOSTS.filter(h => AGENT[h.name] !== LATEST_AGENT).length} with an older agent · ${HOSTS.filter(h => h.crit).length} with critical vulnerabilities</span></div><button type="button" class="button button--primary button--small">+ Add a host</button></div></header>
    <div class="view-pad row row--wrap" style="gap:8px;padding-bottom:12px"><label class="search" style="width:280px">${ICON_SEARCH}<input class="input" data-q placeholder="Search host name or IP…" value="${esc(st.q)}"></label>${Object.keys(FILTERS).map(fbtn).join('')}${Object.keys(st.filters).length ? '<button type="button" class="button button--ghost button--small" data-fclearall>Clear all</button>' : ''}<span class="grow"></span><button type="button" class="button button--ghost button--small">Save view</button><button type="button" class="button button--ghost button--small">Columns</button></div>
    <div class="table-wrap" style="margin:0 24px 40px"><table class="table" aria-label="Hosts"><thead><tr><th style="width:190px">Host</th><th style="width:190px">OS</th><th>Groups</th><th style="width:170px">Labels</th><th style="width:190px">Open problems</th><th style="width:130px">Last heartbeat</th><th style="width:80px">Agent</th></tr></thead><tbody>${tr || '<tr><td colspan="7" class="subtle">No host matches these filters.</td></tr>'}</tbody></table></div></div>`;
}
function liveHosts(st) {
  hostsActive('/agents');
  const render = (focus) => { const v = $('.view-area'); v.innerHTML = hostsList(st); if (focus) { const i = $('[data-q]'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); } };
  render();
  document.addEventListener('input', (e) => { if (e.target.dataset.q !== undefined) { st.q = e.target.value; render(true); } });
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-fopen],[data-fset],[data-fclear],[data-fclearall]');
    if (!t && !st.open && e.target.closest('tr[data-host]')) { location.href = '17-host.html'; return; }
    if (!t) { if (st.open) { st.open = null; render(); } return; }
    if (t.dataset.fopen) st.open = st.open === t.dataset.fopen ? null : t.dataset.fopen;
    if (t.dataset.fset) { const [k, v] = t.dataset.fset.split('|'); st.filters[k] = v; st.open = null; }
    if (t.dataset.fclear) delete st.filters[t.dataset.fclear];
    if (t.dataset.fclearall !== undefined) st.filters = {};
    render();
  });
}
const GKIND = { Windows: 'automatic', Linux: 'automatic', 'Debian 12': 'automatic', 'Fedora 44': 'automatic', 'Windows Server 2022': 'automatic', 'Pilot hosts': 'rule', Lab: 'rule', WindowsServers: 'rule', 'HQ network': 'rule', Production: 'manual' };
function groupsLabels(h, st) {
  const chipX = (l) => `<span class="chip" aria-pressed="true" style="gap:4px;padding-right:4px">${esc(l)}<button type="button" class="icon-button" data-droplabel="${esc(l)}" aria-label="Remove label ${esc(l)}" style="width:20px;height:20px;min-width:20px">${ICON_X}</button></span>`;
  return `<div class="stack" style="gap:12px">
    <div class="stack" style="gap:6px"><span class="subtle" style="font-size:12.5px">Groups</span><span class="row row--wrap" style="gap:6px">${groupsOf(h).map(g => `<a href="#" class="chip" style="text-decoration:none">${g} <span class="subtle" style="font-size:11px">${GKIND[g] || 'rule'}</span></a>`).join('')}</span></div>
    <div class="stack" style="gap:6px"><span class="subtle" style="font-size:12.5px">Labels</span><span class="row row--wrap" style="gap:6px">${st.labels.map(chipX).join('')}<input class="input" data-newlabel placeholder="Add a label" style="height:28px;width:130px;font-size:12.5px" value="${esc(st.draft)}"></span>
      <span class="subtle" style="font-size:12px">For filtering and finding hosts. Labels never change who can see a host.</span></div></div>`;
}
function liveHost(name) {
  const h = HOSTS.find(x => x.name === name); const st = { labels: [...h.labels, 'owner:platform-team'], draft: '' };
  hostsActive('/agents'); $('.view-area').innerHTML = hostPage(h);
  const render = (focus) => { $('[data-gl]').innerHTML = groupsLabels(h, st); if (focus) { const i = $('[data-newlabel]'); i.focus(); } };
  render();
  document.addEventListener('input', (e) => { if (e.target.dataset.newlabel !== undefined) st.draft = e.target.value; });
  document.addEventListener('keydown', (e) => { if (e.target.dataset.newlabel !== undefined && e.key === 'Enter' && st.draft.trim()) { if (!st.labels.includes(st.draft.trim())) st.labels.push(st.draft.trim()); st.draft = ''; render(true); } });
  document.addEventListener('click', (e) => { const t = e.target.closest('[data-droplabel]'); if (t) { st.labels = st.labels.filter(l => l !== t.dataset.droplabel); render(); } });
}
function hostPage(h) {
  const card = (title, aside, body, pad = true) => `<section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">${title}</h2>${aside || ''}</div><div style="${pad ? 'padding:14px 16px' : ''}">${body}</div></section>`;
  const kv = (rows) => `<dl class="kv" style="margin:0;row-gap:10px;grid-template-columns:118px minmax(0,1fr)">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const tile = (label, value, sub, tone) => `<a href="#" class="card card__body" style="display:grid;gap:4px;text-decoration:none;color:inherit"><span class="subtle">${label}</span><span style="font-size:26px;font-weight:650;${tone ? `color:var(--${tone})` : ''}">${value}</span><span class="subtle" style="font-size:12.5px">${sub}</span></a>`;
  const table = (cols, rows) => `<div class="table-wrap" style="margin:0;border:0;border-radius:0"><table class="table"><thead><tr>${cols.map(([c, w]) => `<th${w ? ` style="width:${w}px"` : ''}>${c}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  const more = (n, what) => `<a href="#" style="font-size:12.5px">Show all ${n} ${what}</a>`;
  const sev = (x) => `<span class="badge badge--${x === 'Critical' ? 'critical' : x === 'High' ? 'high' : 'medium'}">${x}</span>`;
  const gs = groupsOf(h);
  return `<div class="view"><div>
    <div class="view-pad" style="padding-top:20px"><span class="subtle"><a href="#">Hosts</a></span></div>
    <header class="view-pad" style="display:flex;gap:16px;align-items:center;padding-top:8px;padding-bottom:16px">
      <span style="display:grid;place-items:center;width:56px;height:56px;border-radius:14px;background:var(--accent-soft);color:var(--accent);font-weight:700">${h.family === 'Linux' ? 'LX' : 'WIN'}</span>
      <div class="stack grow" style="gap:4px"><div class="row" style="gap:10px"><h1 style="margin:0;font-size:24px"><span class="mono" style="font-size:inherit">${h.name}</span></h1><span class="badge ${h.online ? 'badge--ok' : 'badge--plain'}">${h.online ? 'Online' : 'Offline'}</span></div>
        <span class="subtle">agent-00012 · ${h.distro} · ${h.ip} · agent ${AGENT[h.name]}${AGENT[h.name] === LATEST_AGENT ? ' (latest)' : ' <span class="warn-text">(older)</span>'} · heartbeat ${h.seen} · enrolled 23 Jul 2026</span></div>
      <div class="row" style="gap:8px"><button type="button" class="button">Compare</button><button type="button" class="button">Export</button><button type="button" class="button">Add to case</button><button type="button" class="button">Ask about this</button><button type="button" class="button" aria-label="More actions" title="Revoke…">⋯</button></div></header>
    <div class="view-pad" style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;padding-bottom:16px">
      ${tile('Open alarms', 3, '1 high · 2 medium', 'bad')}${tile('Compliance failing', 7, '2 critical · 5 medium', 'warn')}${tile('Vulnerabilities', 12, '1 critical · 2 exploited', 'crit')}${tile('Software', 412, '3 with fixes available', '')}
    </div>
    <div class="view-pad" style="display:grid;grid-template-columns:380px minmax(0,1fr);gap:24px;align-items:start;margin-bottom:60px">
      <div class="stack" style="gap:16px">
        ${card('Details', '', kv([['Agent ID', '<span class="mono">agent-00012</span>'], ['System', `${h.distro} · x86_64`], ['Kernel', '6.12.9'], ['IP address', `<span class="mono">${h.ip}</span>`], ['Enrolled', '23 Jul 2026 by Alex Admin'], ['Capabilities', '<span class="row row--wrap" style="gap:4px"><span class="tag">findings</span><span class="tag">heartbeat</span><span class="tag">inventory</span></span>']]))}
        ${card('Protection', '', kv([['Threat alarms', 'On <span class="subtle">(eBPF)</span>'], ['Hardening', 'L1 on · L2 off'], ['Last test', '<span class="badge badge--ok">Alarm OK · 2 min ago</span>'], ['', '<span class="subtle" style="font-size:12.5px">Finding test not seen yet</span>']]))}
        ${card('Rule sets', '', kv([['baseline', 'v14 <span class="subtle">· expires Sep 2028</span>'], ['baseline-alarms', 'v6'], ['hardening-linux-l1', 'v4']]))}
        ${card('Groups and labels', '', '<div data-gl></div>')}
        ${card('Certificates', '', kv([['Current', 'expires in 11 months'], ['Issued by', 'OpenVIBES intermediate']]))}
      </div>
      <div class="stack" style="gap:16px">
        ${card('Open alarms <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">3</span>', more(3, 'alarms'), table([['Alarm'], ['Severity', 110], ['Last seen', 120]], [['A web server started a shell <span class="subtle mono">nginx → sh</span>', sev('High'), '2 min ago'], ['A shell downloaded a program <span class="subtle mono">bash → curl</span>', sev('Medium'), '1 h ago'], ['Unexpected listening port 8081', sev('Medium'), 'yesterday']]), false)}
        ${card('Vulnerabilities <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">12</span>', more(12, 'vulnerabilities'), table([['Advisory'], ['Package', 180], ['Severity', 110], ['Fix', 120]], [['CVE-2026-10037 <span class="badge badge--bad">Exploited</span>', '<span class="mono">openssl 3.0.13</span>', sev('Critical'), 'Available'], ['CVE-2026-10042 <span class="badge badge--bad">Exploited</span>', '<span class="mono">curl 8.5.0</span>', sev('High'), 'Available'], ['CVE-2026-10079', '<span class="mono">glibc 2.39</span>', sev('High'), 'Not yet']]), false)}
        ${card('Compliance failing <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">7</span>', more(7, 'findings'), table([['Check'], ['Rule set', 170], ['Severity', 110]], [['SSH allows root login', 'hardening-linux-l1', sev('Critical')], ['Password maximum age too long', 'hardening-linux-l1', sev('Critical')], ['Unattended upgrades off', 'baseline', sev('Medium')]]), false)}
        ${card('Software, ports and services', '', `<div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px"><div class="stack" style="gap:6px"><strong>412 packages</strong><span class="subtle" style="font-size:12.5px">3 with fixes available</span>${more(412, 'packages')}</div><div class="stack" style="gap:6px"><strong>9 open ports</strong><span class="subtle mono" style="font-size:12.5px">22, 80, 443, 8081 …</span>${more(9, 'ports')}</div><div class="stack" style="gap:6px"><strong>23 services</strong><span class="subtle" style="font-size:12.5px">nginx, sshd, postgres …</span>${more(23, 'services')}</div></div>`)}
      </div>
    </div></div></div>`;
}
"""
screen(
    "16-hosts", "suppressions",
    "<b>16 · Hosts.</b> Search plus filters (Status, OS, Group, Label, Problems, Agent), and more in the table. <b>Try it:</b> open a filter, pick a value, combine them, clear them; click a host to open its page.",
    PEOPLE + HOSTGROUPS + HOSTSUI + "liveHosts({ filters: {}, q: '', open: null });",
)
screen(
    "17-host", "suppressions",
    "<b>17 · A host's page.</b> Everything from the old detail view, in one tidy page: summary tiles, then details, protection, rule sets, groups and labels, certificates; and its alarms, vulnerabilities, compliance and software. <b>Try it:</b> add a label (type and Enter) or remove one.",
    PEOPLE + HOSTGROUPS + HOSTSUI + "liveHost('web-01');",
)

SHARE = r"""
// ---- Dashboard sharing ----
function shareDialog(st) {
  const opt = (id, title, text, extra = '', disabled = '') => `<label class="card" style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px;padding:14px 16px;cursor:${disabled ? 'not-allowed' : 'pointer'};${st.who === id ? 'border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)' : ''};${disabled ? 'opacity:.6' : ''}">
    <input type="radio" name="who" value="${id}" data-who ${st.who === id ? 'checked' : ''} ${disabled ? 'disabled' : ''} style="margin-top:3px"><strong>${title}</strong><span></span><span class="subtle">${disabled || text}</span>${extra ? `<span></span><div>${extra}</div>` : ''}</label>`;
  const mine = ['Analyst', 'Windows lead'];
  const roles = `<div class="row row--wrap" style="gap:6px;margin-top:6px">${mine.map(r => `<button type="button" class="chip" data-role="${r}" aria-pressed="${st.roles.includes(r)}">${st.roles.includes(r) ? '✓ ' : ''}${r}</button>`).join('')}</div><span class="subtle" style="font-size:12px">Only roles you hold. ${st.roles.length ? `<b>${st.roles.length === 2 ? 14 : st.roles.includes('Analyst') ? 9 : 6} people</b> will see it.` : 'Pick at least one.'}</span>`;
  return `<div style="position:fixed;inset:0;z-index:50;background:rgba(10,20,30,.45);display:grid;place-items:center">
    <div role="dialog" aria-modal="true" aria-labelledby="sh-title" class="card" style="width:min(580px,94vw);padding:0;overflow:hidden;box-shadow:var(--shadow-2)">
      <div class="row row--between" style="padding:16px 20px;border-bottom:1px solid var(--line)"><h2 id="sh-title" style="margin:0;font-size:17px">Share “Windows morning check”</h2><button type="button" class="icon-button" aria-label="Close" data-close>${ICON_X}</button></div>
      <div class="stack" style="gap:10px;padding:20px">
        <span class="subtle" style="font-size:12.5px">Who can see this dashboard</span>
        ${opt('me', 'Only me', 'Nobody else sees it.')}
        ${opt('roles', 'People with these roles', 'Everyone holding one of the roles, now and later.', st.who === 'roles' ? roles : '')}
        ${opt('all', 'Everyone', 'Every person who signs in to OpenVIBES.', '', st.canPublish ? '' : 'Needs the “Publish dashboards” permission, which none of your roles give.')}
        <div class="callout" style="margin:6px 0 0;background:var(--accent-soft);color:var(--text)"><span style="color:var(--accent);display:inline-flex">${ICON_INFO}</span><span>Each person sees the widgets counted on <b>their own</b> hosts and permissions. Sharing never shows anyone data they couldn't see already. Only you can edit it; others can make their own copy.</span></div>
      </div>
      <div class="row" style="gap:8px;justify-content:flex-end;padding:14px 20px;border-top:1px solid var(--line)"><button type="button" class="button" data-close>Cancel</button><button type="button" class="button button--primary" data-save ${st.who === 'roles' && !st.roles.length ? 'disabled' : ''}>Save</button></div>
    </div></div>`;
}
function liveShare(st) {
  const h1 = $('.view-area h1'); h1.textContent = 'Windows morning check';
  h1.nextElementSibling.textContent = 'Your dashboard';
  const bar = $('.view-area .view-header__top .row');
  const badge = h('<span data-sharebadge></span>'); h1.parentElement.append(badge);
  const btn = h(`<button type="button" class="button" data-openshare>Share</button>`); bar.prepend(btn);
  const layer = document.createElement('div'); document.body.append(layer);
  const label = () => st.saved === 'me' ? 'Only you' : st.saved === 'all' ? 'Everyone' : 'Shared with ' + st.savedRoles.join(', ');
  const render = () => { layer.innerHTML = st.open ? shareDialog(st) : '';
    badge.innerHTML = `<span class="badge ${st.saved === 'me' ? 'badge--plain' : 'badge--accent'}" style="margin-top:6px">${label()}</span>`; };
  render();
  document.addEventListener('change', (e) => { if (e.target.dataset.who !== undefined) { st.who = e.target.value; render(); } });
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-openshare],[data-close],[data-save],[data-role]'); if (!t) return;
    if (t.dataset.openshare !== undefined) st.open = true;
    if (t.dataset.close !== undefined) st.open = false;
    if (t.dataset.role) { const r = t.dataset.role; st.roles = st.roles.includes(r) ? st.roles.filter(x => x !== r) : [...st.roles, r]; }
    if (t.dataset.save !== undefined && !t.disabled) { st.saved = st.who; st.savedRoles = [...st.roles]; st.open = false; }
    render();
  });
}
"""
screen(
    "18-share-dashboard", "dashboards",
    "<b>18 · Sharing a dashboard.</b> Only me, people with roles you hold, or everyone (needs Publish dashboards). Viewers always see counts from their own access. <b>Try it:</b> pick roles, Save; reopen with Share.",
    SHARE + "liveShare({ open: true, who: 'roles', roles: ['Windows lead'], canPublish: false, saved: 'me', savedRoles: [] });",
)

PORTSUI = r"""
// ---- Ports list with filters, and a port's page ----
const LINUX = HOSTS.filter(h => h.family === 'Linux').map(h => h.name), WIN = HOSTS.filter(h => h.family === 'Windows').map(h => h.name);
const PORTS = [
  { port: '22/tcp', name: 'SSH', svc: ['sshd.service'], hosts: LINUX, local: ['db-02'] },
  { port: '25/tcp', name: 'SMTP', svc: ['postfix.service'], hosts: ['mx-01', 'mx-backup-03'], local: [] },
  { port: '53/udp', name: 'DNS', svc: ['systemd-resolved.service'], hosts: LINUX, local: LINUX },
  { port: '80/tcp', name: 'HTTP', svc: ['nginx.service'], hosts: ['web-01'], local: [] },
  { port: '443/tcp', name: 'HTTPS', svc: ['nginx.service', 'haproxy.service'], hosts: ['web-01', 'mx-01'], local: [] },
  { port: '5432/tcp', name: 'PostgreSQL', svc: ['postgresql.service'], hosts: ['db-02'], local: [], risk: 'Database reachable from the network' },
  { port: '8081/tcp', name: '', svc: ['api.service'], hosts: ['web-01'], local: [], fresh: ['web-01'], risk: 'New this week, not a usual port' },
  { port: '445/tcp', name: 'SMB file sharing', svc: ['LanmanServer'], hosts: ['win-dc-01', 'win-dc-02', 'win-file-07', 'win-file-08', 'win-app-03'], local: [] },
  { port: '3389/tcp', name: 'Remote Desktop', svc: ['TermService'], hosts: WIN, local: [], fresh: ['win-test-01'] },
  { port: '5985/tcp', name: 'WinRM', svc: ['WinRM'], hosts: WIN, local: ['win-test-01'] },
];
const exposedOn = (x) => x.hosts.filter(n => !x.local.includes(n));
const PFILTERS = {
  Exposure: { opts: ['Exposed somewhere', 'Local only'], test: (x, v) => (exposedOn(x).length > 0) === (v === 'Exposed somewhere') },
  Protocol: { opts: ['TCP', 'UDP'], test: (x, v) => x.port.endsWith('/' + v.toLowerCase()) },
  Group: { opts: () => HG.map(g => g.name), test: (x, v) => membersOf(HG.find(g => g.name === v)).some(h => x.hosts.includes(h.name)) },
  Service: { opts: () => [...new Set(PORTS.flatMap(x => x.svc))].sort(), test: (x, v) => x.svc.includes(v) },
  Changes: { opts: ['New this week', 'Needs a look'], test: (x, v) => v === 'New this week' ? !!x.fresh : !!x.risk },
};
function filterBar(F, st, items, placeholder) {
  const opts = (k) => typeof F[k].opts === 'function' ? F[k].opts() : F[k].opts;
  const count = (k, v) => items.filter(x => F[k].test(x, v)).length;
  const fbtn = (k) => { const on = st.filters[k];
    const menu = st.open === k ? `<div role="menu" style="position:absolute;left:0;top:calc(100% + 6px);z-index:30;min-width:220px;max-height:340px;overflow:auto;background:var(--surface);border:1px solid var(--line);border-radius:var(--r-2);box-shadow:var(--shadow-2);padding:6px">${opts(k).map(v => `<button type="button" role="menuitemradio" aria-checked="${on === v}" class="menu__item" data-fset="${k}|${v}" style="display:flex;width:100%;justify-content:space-between;text-transform:none;gap:16px"><span>${v}</span><span class="subtle num">${count(k, v)}</span></button>`).join('')}</div>` : '';
    return `<span style="position:relative">${on ? `<span class="chip" aria-pressed="true" style="gap:4px;padding-right:4px">${k}: ${on}<button type="button" class="icon-button" data-fclear="${k}" aria-label="Clear ${k}" style="width:20px;height:20px;min-width:20px">${ICON_X}</button></span>` : `<button type="button" class="chip" data-fopen="${k}">${k} <span aria-hidden="true">▾</span></button>`}${menu}</span>`; };
  return `<div class="view-pad row row--wrap" style="gap:8px;padding-bottom:12px"><label class="search" style="width:280px">${ICON_SEARCH}<input class="input" data-q placeholder="${placeholder}" value="${esc(st.q)}"></label>${Object.keys(F).map(fbtn).join('')}${Object.keys(st.filters).length ? '<button type="button" class="button button--ghost button--small" data-fclearall>Clear all</button>' : ''}<span class="grow"></span><button type="button" class="button button--ghost button--small">Save view</button><button type="button" class="button button--ghost button--small">Columns</button></div>`;
}
function liveFilters(st, render, onRow) {
  document.addEventListener('input', (e) => { if (e.target.dataset.q !== undefined) { st.q = e.target.value; render(true); } });
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-fopen],[data-fset],[data-fclear],[data-fclearall]');
    if (!t && !st.open && onRow && e.target.closest('tr[data-row]')) { onRow(e.target.closest('tr[data-row]').dataset.row); return; }
    if (!t) { if (st.open) { st.open = null; render(); } return; }
    if (t.dataset.fopen) st.open = st.open === t.dataset.fopen ? null : t.dataset.fopen;
    if (t.dataset.fset) { const [k, v] = t.dataset.fset.split('|'); st.filters[k] = v; st.open = null; }
    if (t.dataset.fclear) delete st.filters[t.dataset.fclear];
    if (t.dataset.fclearall !== undefined) st.filters = {};
    render();
  });
}
function portsList(st) {
  const rows = PORTS.filter(x => Object.entries(st.filters).every(([k, v]) => PFILTERS[k].test(x, v)) && (!st.q || (x.port + ' ' + x.name + ' ' + x.svc.join(' ')).toLowerCase().includes(st.q.toLowerCase())));
  const groupsFor = (x) => HG.filter(g => g.kind !== 'manual' && membersOf(g).some(h => x.hosts.includes(h.name))).map(g => g.name);
  const tr = rows.map(x => { const ex = exposedOn(x).length; const gs = groupsFor(x);
    return `<tr data-row="${x.port}" style="cursor:pointer"><td><div class="cell-two"><span class="mono">${x.port}</span><span class="subtle">${x.name || 'Not a well-known port'}</span></div></td>
      <td class="num">${x.hosts.length} <span class="subtle">of ${HOSTS.length}</span></td>
      <td>${ex ? `<span class="badge badge--warn">${ex === x.hosts.length ? 'All ' + ex : ex + ' of ' + x.hosts.length}</span>` : '<span class="subtle">Local only</span>'}</td>
      <td><span class="mono" style="font-size:12.5px">${x.svc.join(', ')}</span></td>
      <td><span class="row" style="gap:4px;flex-wrap:nowrap;white-space:nowrap">${gs.slice(0, 2).map(g => `<span class="badge badge--accent badge--plain">${g}</span>`).join('')}${gs.length > 2 ? `<span class="subtle" style="font-size:12px">+${gs.length - 2}</span>` : ''}</span></td>
      <td>${x.fresh ? `<span class="badge badge--accent">+${x.fresh.length} host this week</span>` : '<span class="subtle">No change</span>'}</td>
      <td>${x.risk ? `<span class="row" style="gap:6px;color:var(--warn);font-size:12.5px">⚠ ${x.risk}</span>` : ''}</td></tr>`; }).join('');
  return `<div class="view">
    <header class="view-pad" style="padding-top:20px;padding-bottom:8px"><h1 style="margin:0">Ports <span class="subtle num" style="font-size:16px;font-weight:500">${rows.length}${rows.length !== PORTS.length ? ' of ' + PORTS.length : ''}</span></h1><span class="subtle">${PORTS.filter(x => exposedOn(x).length).length} exposed on some host · ${PORTS.filter(x => x.fresh).length} with new hosts this week · ${PORTS.filter(x => x.risk).length} need a look · from ${HOSTS.length} hosts' last reports</span></header>
    ${filterBar(PFILTERS, st, PORTS, 'Search port, name or service…')}
    <div class="table-wrap" style="margin:0 24px 40px"><table class="table" aria-label="Ports"><thead><tr><th style="width:170px">Port</th><th style="width:90px">Hosts</th><th style="width:110px">Exposed on</th><th>Services</th><th style="width:250px">Groups</th><th style="width:160px">This week</th><th style="width:230px">Needs a look</th></tr></thead><tbody>${tr || '<tr><td colspan="7" class="subtle">No port matches these filters.</td></tr>'}</tbody></table></div></div>`;
}
function livePorts(st) {
  hostsActive('/ports'); $('.topbar__title').textContent = 'Ports';
  const render = (focus) => { $('.view-area').innerHTML = portsList(st); if (focus) { const i = $('[data-q]'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); } };
  render(); liveFilters(st, render, () => { location.href = '20-port.html'; });
}
function portPage(x, st) {
  const card = (title, aside, body, pad = true) => `<section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">${title}</h2>${aside || ''}</div><div style="${pad ? 'padding:14px 16px' : ''}">${body}</div></section>`;
  const kv = (rows) => `<dl class="kv" style="margin:0;row-gap:10px;grid-template-columns:110px minmax(0,1fr)">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const tile = (label, value, sub, tone) => `<div class="card card__body" style="display:grid;gap:4px"><span class="subtle">${label}</span><span style="font-size:26px;font-weight:650;${tone ? `color:var(--${tone})` : ''}">${value}</span><span class="subtle" style="font-size:12.5px">${sub}</span></div>`;
  const hs = HOSTS.filter(h => x.hosts.includes(h.name));
  const shown = hs.filter(h => st.show === 'all' || (st.show === 'exposed') !== x.local.includes(h.name));
  const bound = (h) => x.local.includes(h.name) ? '127.0.0.1' : '0.0.0.0, ::';
  const byGroup = HG.filter(g => g.kind !== 'manual').map(g => [g.name, membersOf(g).filter(h => x.hosts.includes(h.name)).length, membersOf(g).length]).filter(r => r[1]);
  const seg = (id, label, n) => `<button type="button" class="chip" data-show="${id}" aria-pressed="${st.show === id}">${label} <span class="subtle num">${n}</span></button>`;
  return `<div class="view"><div>
    <div class="view-pad" style="padding-top:20px"><span class="subtle"><a href="19-ports.html">Ports</a></span></div>
    <header class="view-pad" style="display:flex;gap:16px;align-items:center;padding-top:8px;padding-bottom:16px">
      <span style="display:grid;place-items:center;width:56px;height:56px;border-radius:14px;background:var(--accent-soft);color:var(--accent);font-weight:700;font-size:13px">TCP</span>
      <div class="stack grow" style="gap:4px"><div class="row" style="gap:10px"><h1 style="margin:0;font-size:24px"><span class="mono" style="font-size:inherit">${x.port}</span></h1><span class="subtle" style="font-size:18px">${x.name}</span></div>
        <span class="subtle">Listening on ${hs.length} of ${HOSTS.length} hosts · exposed on ${exposedOn(x).length} · ${x.svc.join(', ')} · first seen 23 Jul 2026</span></div>
      <div class="row" style="gap:8px"><button type="button" class="button">Export</button><button type="button" class="button">Add to case</button><button type="button" class="button">Ask about this</button></div></header>
    <div class="view-pad" style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;padding-bottom:16px">
      ${tile('Hosts listening', hs.length, `of ${HOSTS.length} hosts`, '')}${tile('Exposed', exposedOn(x).length, 'reachable from the network', 'warn')}${tile('Local only', x.local.length, 'bound to 127.0.0.1', '')}${tile('This week', '0', 'no host started or stopped', '')}
    </div>
    <div class="view-pad" style="display:grid;grid-template-columns:380px minmax(0,1fr);gap:24px;align-items:start;margin-bottom:60px">
      <div class="stack" style="gap:16px">
        ${card('Details', '', kv([['Protocol', 'TCP'], ['Usual use', 'SSH: remote shell and file copy'], ['Services', `<span class="mono">${x.svc.join(', ')}</span>`], ['Programs', '<span class="mono">sshd</span>'], ['First seen', '23 Jul 2026 on web-01']]))}
        ${card('By group', '', `<div class="stack" style="gap:10px">${byGroup.map(([g, n, of]) => `<div class="stack" style="gap:4px"><span class="row row--between"><a href="#">${g}</a><span class="subtle num">${n} of ${of}</span></span><span style="height:6px;border-radius:3px;background:var(--surface-2);overflow:hidden"><span style="display:block;height:100%;width:${Math.round(100 * n / of)}%;background:var(--accent)"></span></span></div>`).join('')}</div>`)}
        ${card('Recent changes', '<a href="#" style="font-size:12.5px">History</a>', `<ul class="list list--plain" style="margin:0;padding:0">${[['db-02 now listens only locally', '2 days ago'], ['lab-ws-04 stopped reporting', '2 days ago'], ['mx-backup-03 started listening', '3 weeks ago']].map(([a, d]) => `<li style="display:grid;gap:2px;padding:6px 0;border-bottom:1px solid var(--line)"><span>${a}</span><span class="subtle" style="font-size:12.5px">${d}</span></li>`).join('')}</ul>`)}
      </div>
      <div class="stack" style="gap:16px">
        ${card(`Hosts <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">${hs.length}</span>`, `<span class="row" style="gap:6px">${seg('all', 'All', hs.length)}${seg('exposed', 'Exposed', exposedOn(x).length)}${seg('local', 'Local only', x.local.length)}</span>`,
          `<div class="table-wrap" style="margin:0;border:0;border-radius:0"><table class="table"><thead><tr><th>Host</th><th style="width:150px">Bound to</th><th style="width:190px">Service · program</th><th style="width:120px">Exposure</th><th style="width:120px">Last report</th></tr></thead><tbody>${shown.map(h => `<tr><td><div class="cell-two"><a href="17-host.html" class="mono">${h.name}</a><span class="subtle">${h.distro} · ${h.ip}</span></div></td><td class="mono">${bound(h)}</td><td><span class="mono" style="font-size:12.5px">sshd.service · sshd</span></td><td>${x.local.includes(h.name) ? '<span class="subtle">Local only</span>' : '<span class="badge badge--warn">Exposed</span>'}</td><td class="${h.online ? '' : 'warn-text'}">${h.seen}</td></tr>`).join('')}</tbody></table></div>`, false)}
        ${card('Related', '', `<div class="stack" style="gap:10px">
          <div class="row row--between"><span><b>Compliance:</b> SSH allows root login</span><span class="row" style="gap:8px"><span class="badge badge--critical">Failing on 2 hosts</span><a href="#" style="font-size:12.5px">Show</a></span></div>
          <div class="row row--between"><span><b>Compliance:</b> SSH password login allowed</span><span class="row" style="gap:8px"><span class="badge badge--high">Failing on 1 host</span><a href="#" style="font-size:12.5px">Show</a></span></div>
          <div class="row row--between"><span><b>Vulnerabilities:</b> openssh</span><span class="row" style="gap:8px"><span class="badge badge--medium">1 open on 3 hosts</span><a href="#" style="font-size:12.5px">Show</a></span></div>
          <div class="row row--between"><span><b>Alarms</b> on these hosts mentioning sshd</span><span class="row" style="gap:8px"><span class="subtle">None open</span></span></div></div>`)}
      </div>
    </div></div></div>`;
}
function livePort(port) {
  const x = PORTS.find(p => p.port === port); const st = { show: 'all' };
  hostsActive('/ports'); $('.topbar__title').textContent = 'Ports';
  const render = () => { $('.view-area').innerHTML = portPage(x, st); };
  render();
  document.addEventListener('click', (e) => { const t = e.target.closest('[data-show]'); if (t) { st.show = t.dataset.show; render(); } });
}
"""
screen(
    "19-ports", "ports",
    "<b>19 · Ports.</b> Search plus filters (Exposure, Protocol, Group, Service, Changes), and more in the table: the port's usual name, how many hosts, where it's exposed, groups, what changed this week, and what needs a look. <b>Try it:</b> filter, then click a port.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + "livePorts({ filters: {}, q: '', open: null });",
)
screen(
    "20-port", "ports",
    "<b>20 · A port's page.</b> 22/tcp in the shared layout: details, spread by group and recent changes on the left; its hosts (all, exposed, local only) and related findings, vulnerabilities and alarms on the right. <b>Try it:</b> switch Exposed / Local only.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + "livePort('22/tcp');",
)

SERVICESUI = r"""
// ---- Services list with filters, and a service's page ----
const SERVICES = [
  { unit: 'sshd.service', desc: 'OpenSSH server', hosts: LINUX, user: 'root', programs: ['sshd'], ports: ['22/tcp'], pkg: 'openssh-server' },
  { unit: 'chronyd.service', desc: 'Time synchronisation', hosts: LINUX, user: 'chrony', programs: ['chronyd'], ports: [], pkg: 'chrony' },
  { unit: 'systemd-resolved.service', desc: 'Name resolution', hosts: LINUX, user: 'systemd-resolve', programs: ['systemd-resolved'], ports: ['53/udp'], pkg: 'systemd' },
  { unit: 'postfix.service', desc: 'Mail server', hosts: ['mx-01', 'mx-backup-03'], user: 'root', programs: ['master', 'qmgr', 'pickup'], ports: ['25/tcp'], pkg: 'postfix' },
  { unit: 'nginx.service', desc: 'Web server', hosts: ['web-01', 'mx-01'], user: 'root, www-data', programs: ['nginx'], ports: ['80/tcp', '443/tcp'], pkg: 'nginx', risk: 'Open alarm: a web server started a shell' },
  { unit: 'haproxy.service', desc: 'Load balancer', hosts: ['mx-01'], user: 'haproxy', programs: ['haproxy'], ports: ['443/tcp'], pkg: 'haproxy' },
  { unit: 'postgresql.service', desc: 'PostgreSQL database', hosts: ['db-02'], user: 'postgres', programs: ['postgres'], ports: ['5432/tcp'], pkg: 'postgresql-16', risk: 'Its port is reachable from the network' },
  { unit: 'api.service', desc: 'No description', hosts: ['web-01'], user: 'root', programs: ['node'], ports: ['8081/tcp'], pkg: '', fresh: ['web-01'], risk: 'New this week, runs as root, not from a package' },
  { unit: 'TermService', desc: 'Remote Desktop Services', hosts: WIN, user: 'NETWORK SERVICE', programs: ['svchost.exe'], ports: ['3389/tcp'], pkg: 'Windows', fresh: ['win-test-01'] },
  { unit: 'LanmanServer', desc: 'File and printer sharing', hosts: ['win-dc-01', 'win-dc-02', 'win-file-07', 'win-file-08', 'win-app-03'], user: 'SYSTEM', programs: ['svchost.exe'], ports: ['445/tcp'], pkg: 'Windows' },
  { unit: 'WinRM', desc: 'Windows Remote Management', hosts: WIN, user: 'NETWORK SERVICE', programs: ['svchost.exe'], ports: ['5985/tcp'], pkg: 'Windows' },
];
const portOf = (p) => PORTS.find(x => x.port === p);
const svcExposed = (x) => x.ports.some(p => exposedOn(portOf(p)).length);
const SFILTERS = {
  'Runs as': { opts: ['root or SYSTEM', 'Another user'], test: (x, v) => /root|SYSTEM/.test(x.user) === (v === 'root or SYSTEM') },
  Listens: { opts: ['On an exposed port', 'Local only', 'No ports'], test: (x, v) => v === 'No ports' ? !x.ports.length : x.ports.length > 0 && svcExposed(x) === (v === 'On an exposed port') },
  Group: { opts: () => HG.map(g => g.name), test: (x, v) => membersOf(HG.find(g => g.name === v)).some(h => x.hosts.includes(h.name)) },
  Package: { opts: ['From a package', 'Not from a package'], test: (x, v) => !!x.pkg === (v === 'From a package') },
  Changes: { opts: ['New this week', 'Needs a look'], test: (x, v) => v === 'New this week' ? !!x.fresh : !!x.risk },
};
function servicesList(st) {
  const rows = SERVICES.filter(x => Object.entries(st.filters).every(([k, v]) => SFILTERS[k].test(x, v)) && (!st.q || (x.unit + ' ' + x.desc + ' ' + x.programs.join(' ')).toLowerCase().includes(st.q.toLowerCase())));
  const tr = rows.map(x => `<tr data-row="${x.unit}" style="cursor:pointer"><td><div class="cell-two"><span class="mono">${x.unit}</span><span class="subtle">${x.desc}</span></div></td>
      <td class="num">${x.hosts.length} <span class="subtle">of ${HOSTS.length}</span></td>
      <td><span class="mono ${/root|SYSTEM/.test(x.user) ? 'warn-text' : ''}" style="font-size:12.5px">${x.user}</span></td>
      <td><span class="row" style="gap:4px;flex-wrap:nowrap">${x.ports.map(p => `<a href="20-port.html" class="badge ${exposedOn(portOf(p)).length ? 'badge--warn' : 'badge--plain'}" style="text-decoration:none">${p}</a>`).join('') || '<span class="subtle">None</span>'}</span></td>
      <td><div class="cell-two"><span class="mono" style="font-size:12.5px">${x.programs.join(', ')}</span><span class="subtle">${x.pkg ? 'package ' + x.pkg : '<span class="warn-text">not from a package</span>'}</span></div></td>
      <td>${x.fresh ? `<span class="badge badge--accent">+${x.fresh.length} host this week</span>` : '<span class="subtle">No change</span>'}</td>
      <td>${x.risk ? `<span style="color:var(--warn);font-size:12.5px">⚠ ${x.risk}</span>` : ''}</td></tr>`).join('');
  return `<div class="view">
    <header class="view-pad" style="padding-top:20px;padding-bottom:8px"><h1 style="margin:0">Services <span class="subtle num" style="font-size:16px;font-weight:500">${rows.length}${rows.length !== SERVICES.length ? ' of ' + SERVICES.length : ''}</span></h1><span class="subtle">${SERVICES.filter(svcExposed).length} listen on an exposed port · ${SERVICES.filter(x => !x.pkg).length} not from a package · ${SERVICES.filter(x => x.fresh).length} with new hosts this week · ${SERVICES.filter(x => x.risk).length} need a look</span></header>
    ${filterBar(SFILTERS, st, SERVICES, 'Search service or program…')}
    <div class="table-wrap" style="margin:0 24px 40px"><table class="table" aria-label="Services"><thead><tr><th style="width:230px">Service</th><th style="width:90px">Hosts</th><th style="width:150px">Runs as</th><th style="width:170px">Ports</th><th>Programs</th><th style="width:160px">This week</th><th style="width:250px">Needs a look</th></tr></thead><tbody>${tr || '<tr><td colspan="7" class="subtle">No service matches these filters.</td></tr>'}</tbody></table></div></div>`;
}
function liveServices(st) {
  hostsActive('/services'); $('.topbar__title').textContent = 'Services';
  const render = (focus) => { $('.view-area').innerHTML = servicesList(st); if (focus) { const i = $('[data-q]'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); } };
  render(); liveFilters(st, render, () => { location.href = '22-service.html'; });
}
function servicePage(x, st) {
  const card = (title, aside, body, pad = true) => `<section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">${title}</h2>${aside || ''}</div><div style="${pad ? 'padding:14px 16px' : ''}">${body}</div></section>`;
  const kv = (rows) => `<dl class="kv" style="margin:0;row-gap:10px;grid-template-columns:110px minmax(0,1fr)">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const tile = (label, value, sub, tone) => `<div class="card card__body" style="display:grid;gap:4px"><span class="subtle">${label}</span><span style="font-size:26px;font-weight:650;${tone ? `color:var(--${tone})` : ''}">${value}</span><span class="subtle" style="font-size:12.5px">${sub}</span></div>`;
  const hs = HOSTS.filter(h => x.hosts.includes(h.name));
  const per = { 'web-01': ['1.26.2', 5, '80, 443'], 'mx-01': ['1.22.1', 3, '80'] };
  const byGroup = HG.filter(g => g.kind !== 'manual').map(g => [g.name, membersOf(g).filter(h => x.hosts.includes(h.name)).length, membersOf(g).length]).filter(r => r[1]);
  return `<div class="view"><div>
    <div class="view-pad" style="padding-top:20px"><span class="subtle"><a href="21-services.html">Services</a></span></div>
    <header class="view-pad" style="display:flex;gap:16px;align-items:center;padding-top:8px;padding-bottom:16px">
      <span style="display:grid;place-items:center;width:56px;height:56px;border-radius:14px;background:var(--accent-soft);color:var(--accent);font-weight:700;font-size:13px">SVC</span>
      <div class="stack grow" style="gap:4px"><div class="row" style="gap:10px"><h1 style="margin:0;font-size:24px"><span class="mono" style="font-size:inherit">${x.unit}</span></h1><span class="subtle" style="font-size:18px">${x.desc}</span></div>
        <span class="subtle">Running on ${hs.length} of ${HOSTS.length} hosts · 8 processes · runs as ${x.user} · listens on ${x.ports.join(', ')} · package ${x.pkg}</span></div>
      <div class="row" style="gap:8px"><button type="button" class="button">Export</button><button type="button" class="button">Add to case</button><button type="button" class="button">Ask about this</button></div></header>
    <div class="view-pad" style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;padding-bottom:16px">
      ${tile('Hosts running it', hs.length, `of ${HOSTS.length} hosts`, '')}${tile('Open alarms', 1, 'on web-01 · high', 'bad')}${tile('Vulnerabilities', 2, 'in the nginx package · 1 high', 'crit')}${tile('Versions', 2, '1.26.2 and 1.22.1', '')}
    </div>
    <div class="view-pad" style="display:grid;grid-template-columns:380px minmax(0,1fr);gap:24px;align-items:start;margin-bottom:60px">
      <div class="stack" style="gap:16px">
        ${card('Details', '', kv([['Unit', `<span class="mono">${x.unit}</span>`], ['Description', x.desc], ['Programs', `<span class="mono">${x.programs.join(', ')}</span>`], ['Runs as', `<span class="mono">${x.user}</span> <span class="subtle">(main process as root)</span>`], ['Package', `<a href="#" class="mono">${x.pkg}</a>`], ['First seen', '23 Jul 2026 on web-01']]))}
        ${card('Ports', '', `<div class="stack" style="gap:8px">${x.ports.map(p => { const o = portOf(p); return `<div class="row row--between"><a href="20-port.html" class="mono">${p}</a><span class="row" style="gap:8px"><span class="subtle">${o.name}</span><span class="badge ${exposedOn(o).length ? 'badge--warn' : 'badge--plain'}">${exposedOn(o).length ? 'Exposed' : 'Local only'}</span></span></div>`; }).join('')}</div>`)}
        ${card('By group', '', `<div class="stack" style="gap:10px">${byGroup.map(([g, n, of]) => `<div class="stack" style="gap:4px"><span class="row row--between"><a href="#">${g}</a><span class="subtle num">${n} of ${of}</span></span><span style="height:6px;border-radius:3px;background:var(--surface-2);overflow:hidden"><span style="display:block;height:100%;width:${Math.round(100 * n / of)}%;background:var(--accent)"></span></span></div>`).join('')}</div>`)}
        ${card('Recent changes', '<a href="#" style="font-size:12.5px">History</a>', `<ul class="list list--plain" style="margin:0;padding:0">${[['web-01 updated nginx to 1.26.2', '4 days ago'], ['mx-01 started running it', '3 weeks ago']].map(([a, d]) => `<li style="display:grid;gap:2px;padding:6px 0;border-bottom:1px solid var(--line)"><span>${a}</span><span class="subtle" style="font-size:12.5px">${d}</span></li>`).join('')}</ul>`)}
      </div>
      <div class="stack" style="gap:16px">
        ${card(`Hosts <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">${hs.length}</span>`, '',
          `<div class="table-wrap" style="margin:0;border:0;border-radius:0"><table class="table"><thead><tr><th>Host</th><th style="width:110px">Version</th><th style="width:110px">Processes</th><th style="width:130px">Ports</th><th style="width:140px">Problems</th><th style="width:120px">Last report</th></tr></thead><tbody>${hs.map(h => `<tr><td><div class="cell-two"><a href="17-host.html" class="mono">${h.name}</a><span class="subtle">${h.distro} · ${h.ip}</span></div></td><td class="mono">${per[h.name][0]}</td><td class="num">${per[h.name][1]}</td><td class="mono">${per[h.name][2]}</td><td>${h.name === 'web-01' ? '<span class="badge badge--bad">1 alarm</span>' : '<span class="subtle">None open</span>'}</td><td>${h.seen}</td></tr>`).join('')}</tbody></table></div>`, false)}
        ${card('Related', '', `<div class="stack" style="gap:10px">
          <div class="row row--between"><span><b>Alarm:</b> A web server started a shell <span class="subtle mono">nginx → sh</span> on web-01</span><span class="row" style="gap:8px"><span class="badge badge--high">High · 2 min ago</span><a href="#" style="font-size:12.5px">Open</a></span></div>
          <div class="row row--between"><span><b>Vulnerability:</b> CVE-2026-10112 in nginx 1.22.1</span><span class="row" style="gap:8px"><span class="badge badge--high">High · mx-01</span><a href="#" style="font-size:12.5px">Open</a></span></div>
          <div class="row row--between"><span><b>Vulnerability:</b> CVE-2026-10118 in nginx</span><span class="row" style="gap:8px"><span class="badge badge--medium">Medium · 2 hosts</span><a href="#" style="font-size:12.5px">Open</a></span></div>
          <div class="row row--between"><span><b>Compliance:</b> checks about nginx</span><span class="row" style="gap:8px"><span class="subtle">All passing</span></span></div></div>`)}
      </div>
    </div></div></div>`;
}
"""
screen(
    "21-services", "services",
    "<b>21 · Services.</b> Search plus filters (Runs as, Listens, Group, Package, Changes), and more in the table: what it is, how many hosts, who it runs as, its ports (exposed in amber), programs and package, this week, and what needs a look. <b>Try it:</b> filter, then click a service.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + SERVICESUI + "liveServices({ filters: {}, q: '', open: null });",
)
screen(
    "22-service", "services",
    "<b>22 · A service's page.</b> nginx.service in the shared layout: details, its ports, spread by group and recent changes on the left; its hosts (version, processes, ports, problems) and the alarms, vulnerabilities and checks that concern it on the right.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + SERVICESUI + "hostsActive('/services'); $('.topbar__title').textContent = 'Services'; $('.view-area').innerHTML = servicePage(SERVICES.find(x => x.unit === 'nginx.service'));",
)

SOFTWAREUI = r"""
// ---- Software list with filters, and a package's page ----
const SW = [
  { name: 'openssl', type: 'deb, rpm', desc: 'TLS and crypto library', hosts: LINUX, versions: ['3.0.13', '3.0.15', '3.2.2'], worst: 'Critical', n: 2, exploited: true, fix: 2, used: ['nginx', 'sshd', 'postfix', 'haproxy'], week: 'Updated on 2 hosts' },
  { name: 'curl', type: 'deb, rpm', desc: 'URL transfer tool and library', hosts: LINUX, versions: ['8.5.0', '8.9.1'], worst: 'High', n: 3, exploited: true, fix: 3, used: [], week: '' },
  { name: 'glibc', type: 'deb, rpm', desc: 'GNU C library', hosts: LINUX, versions: ['2.39', '2.40'], worst: 'High', n: 1, exploited: false, fix: 0, used: ['everything'], week: '' },
  { name: 'nginx', type: 'deb, rpm', desc: 'Web server', hosts: ['web-01', 'mx-01'], versions: ['1.22.1', '1.26.2'], worst: 'High', n: 2, exploited: false, fix: 1, used: ['nginx.service'], week: 'Updated on web-01' },
  { name: 'openssh-server', type: 'deb, rpm', desc: 'OpenSSH server', hosts: LINUX, versions: ['9.6p1'], worst: 'Medium', n: 1, exploited: false, fix: 0, used: ['sshd.service'], week: '' },
  { name: 'postgresql-16', type: 'deb', desc: 'PostgreSQL database', hosts: ['db-02'], versions: ['16.4'], worst: '', n: 0, exploited: false, fix: 0, used: ['postgresql.service'], week: '' },
  { name: 'bash', type: 'deb, rpm', desc: 'GNU shell', hosts: LINUX, versions: ['5.2.37'], worst: '', n: 0, exploited: false, fix: 0, used: [], week: '' },
  { name: 'nodejs', type: 'rpm', desc: 'JavaScript runtime', hosts: ['web-01'], versions: ['22.11.0'], worst: 'Medium', n: 1, exploited: false, fix: 1, used: ['api.service'], week: 'New on web-01' },
  { name: 'Microsoft Edge', type: 'Windows', desc: 'Web browser', hosts: WIN, versions: ['141.0.3537', '140.0.3485'], worst: 'High', n: 2, exploited: true, fix: 2, used: [], week: 'Updated on 4 hosts' },
  { name: '7-Zip', type: 'Windows', desc: 'File archiver', hosts: ['win-file-07', 'win-file-08', 'win-test-01'], versions: ['23.01', '24.08'], worst: 'High', n: 1, exploited: false, fix: 2, used: [], week: '' },
];
const SWF = {
  Vulnerabilities: { opts: ['Exploited', 'Critical or high', 'Any', 'None'], test: (x, v) => v === 'Exploited' ? x.exploited : v === 'Critical or high' ? ['Critical', 'High'].includes(x.worst) : v === 'Any' ? x.n > 0 : x.n === 0 },
  Fix: { opts: ['Fix available', 'No fix yet'], test: (x, v) => v === 'Fix available' ? x.fix > 0 : x.n > 0 && x.fix === 0 },
  Versions: { opts: ['One version', 'Several versions'], test: (x, v) => (x.versions.length > 1) === (v === 'Several versions') },
  Group: { opts: () => HG.map(g => g.name), test: (x, v) => membersOf(HG.find(g => g.name === v)).some(h => x.hosts.includes(h.name)) },
  Type: { opts: ['deb', 'rpm', 'Windows'], test: (x, v) => x.type.includes(v) },
  Changes: { opts: ['Changed this week'], test: (x) => !!x.week },
};
const sevBadge = (x) => x.worst ? `<span class="badge badge--${x.worst === 'Critical' ? 'critical' : x.worst === 'High' ? 'high' : 'medium'}">${x.worst}</span>` : '';
function softwareList(st) {
  const rows = SW.filter(x => Object.entries(st.filters).every(([k, v]) => SWF[k].test(x, v)) && (!st.q || (x.name + ' ' + x.desc).toLowerCase().includes(st.q.toLowerCase())));
  const tr = rows.map(x => `<tr data-row="${x.name}" style="cursor:pointer"><td><div class="cell-two"><span class="mono">${x.name}</span><span class="subtle">${x.desc} · ${x.type}</span></div></td>
      <td class="num">${x.hosts.length} <span class="subtle">of ${HOSTS.length}</span></td>
      <td><div class="cell-two"><span class="mono" style="font-size:12.5px">${x.versions.length > 1 ? x.versions[0] + ' … ' + x.versions[x.versions.length - 1] : x.versions[0]}</span><span class="subtle">${x.versions.length > 1 ? x.versions.length + ' versions' : '1 version'}</span></div></td>
      <td>${x.n ? `<span class="row" style="gap:6px;flex-wrap:nowrap">${sevBadge(x)}<span class="subtle">${x.n} advisor${x.n > 1 ? 'ies' : 'y'}</span>${x.exploited ? '<span class="badge badge--bad">Exploited</span>' : ''}</span>` : '<span class="subtle">None open</span>'}</td>
      <td>${x.fix ? `<span class="badge badge--warn">Update on ${x.fix} host${x.fix > 1 ? 's' : ''}</span>` : x.n ? '<span class="subtle">No fix yet</span>' : '<span class="subtle">—</span>'}</td>
      <td><span class="mono" style="font-size:12.5px">${x.used.join(', ') || '<span class="subtle">—</span>'}</span></td>
      <td>${x.week ? `<span class="badge badge--accent">${x.week}</span>` : '<span class="subtle">No change</span>'}</td></tr>`).join('');
  return `<div class="view">
    <header class="view-pad" style="padding-top:20px;padding-bottom:8px"><h1 style="margin:0">Software <span class="subtle num" style="font-size:16px;font-weight:500">${rows.length}${rows.length !== SW.length ? ' of ' + SW.length : ''}</span></h1><span class="subtle">${SW.filter(x => x.exploited).length} with exploited vulnerabilities · ${SW.filter(x => x.fix).length} with an update that fixes something · ${SW.filter(x => x.versions.length > 1).length} in several versions · ${SW.filter(x => x.week).length} changed this week</span></header>
    ${filterBar(SWF, st, SW, 'Search package or description…')}
    <div class="table-wrap" style="margin:0 24px 40px"><table class="table" aria-label="Software"><thead><tr><th style="width:260px">Package</th><th style="width:90px">Hosts</th><th style="width:170px">Versions</th><th style="width:270px">Vulnerabilities</th><th style="width:160px">Fix</th><th>Used by</th><th style="width:180px">This week</th></tr></thead><tbody>${tr || '<tr><td colspan="7" class="subtle">No package matches these filters.</td></tr>'}</tbody></table></div></div>`;
}
function liveSoftware(st) {
  hostsActive('/software'); $('.topbar__title').textContent = 'Software';
  const render = (focus) => { $('.view-area').innerHTML = softwareList(st); if (focus) { const i = $('[data-q]'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); } };
  render(); liveFilters(st, render, () => { location.href = '24-package.html'; });
}
function packagePage(st) {
  const card = (title, aside, body, pad = true) => `<section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">${title}</h2>${aside || ''}</div><div style="${pad ? 'padding:14px 16px' : ''}">${body}</div></section>`;
  const kv = (rows) => `<dl class="kv" style="margin:0;row-gap:10px;grid-template-columns:110px minmax(0,1fr)">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const tile = (label, value, sub, tone) => `<div class="card card__body" style="display:grid;gap:4px"><span class="subtle">${label}</span><span style="font-size:26px;font-weight:650;${tone ? `color:var(--${tone})` : ''}">${value}</span><span class="subtle" style="font-size:12.5px">${sub}</span></div>`;
  const ver = { 'web-01': ['3.0.13', 'nginx, sshd'], 'db-02': ['3.0.13', 'sshd, postgres'], 'mx-01': ['3.0.15', 'postfix, nginx, haproxy, sshd'], 'mx-backup-03': ['3.0.15', 'postfix, sshd'], 'lab-ws-04': ['3.2.2', 'sshd'] };
  const hs = HOSTS.filter(h => ver[h.name]);
  const needs = (h) => ver[h.name][0] === '3.0.13';
  const shown = hs.filter(h => st.show === 'all' || (st.show === 'update') === needs(h));
  const versions = [['3.0.13', 2, 'Vulnerable: CVE-2026-10037, CVE-2026-10051', 'crit'], ['3.0.15', 2, 'Fixed', 'ok'], ['3.2.2', 1, 'Fixed', 'ok']];
  const seg = (id, label, n) => `<button type="button" class="chip" data-show="${id}" aria-pressed="${st.show === id}">${label} <span class="subtle num">${n}</span></button>`;
  return `<div class="view"><div>
    <div class="view-pad" style="padding-top:20px"><span class="subtle"><a href="23-software.html">Software</a></span></div>
    <header class="view-pad" style="display:flex;gap:16px;align-items:center;padding-top:8px;padding-bottom:16px">
      <span style="display:grid;place-items:center;width:56px;height:56px;border-radius:14px;background:var(--accent-soft);color:var(--accent);font-weight:700;font-size:13px">PKG</span>
      <div class="stack grow" style="gap:4px"><div class="row" style="gap:10px"><h1 style="margin:0;font-size:24px"><span class="mono" style="font-size:inherit">openssl</span></h1><span class="subtle" style="font-size:18px">TLS and crypto library</span></div>
        <span class="subtle">Installed on 5 of ${HOSTS.length} hosts · 3 versions · deb and rpm · used by nginx, sshd, postfix, haproxy</span></div>
      <div class="row" style="gap:8px"><button type="button" class="button">Export</button><button type="button" class="button">Add to case</button><button type="button" class="button">Ask about this</button></div></header>
    <div class="view-pad" style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;padding-bottom:16px">
      ${tile('Hosts', 5, `of ${HOSTS.length} hosts`, '')}${tile('Vulnerabilities', 2, '1 critical · exploited', 'crit')}${tile('Need an update', 2, 'to 3.0.15 or later', 'warn')}${tile('Versions', 3, 'oldest 3.0.13', '')}
    </div>
    <div class="view-pad" style="display:grid;grid-template-columns:380px minmax(0,1fr);gap:24px;align-items:start;margin-bottom:60px">
      <div class="stack" style="gap:16px">
        ${card('Details', '', kv([['Package', '<span class="mono">openssl, libssl3</span>'], ['Description', 'TLS and crypto library'], ['Types', 'deb (Debian, Ubuntu), rpm (Fedora)'], ['Source', '<span class="mono">openssl</span>'], ['First seen', '23 Jul 2026']]))}
        ${card('Versions', '', `<div class="stack" style="gap:12px">${versions.map(([v, n, note, tone]) => `<div class="stack" style="gap:4px"><span class="row row--between"><span class="mono">${v}</span><span class="subtle num">${n} host${n > 1 ? 's' : ''}</span></span><span style="height:6px;border-radius:3px;background:var(--surface-2);overflow:hidden"><span style="display:block;height:100%;width:${n * 20}%;background:var(--${tone === 'crit' ? 'crit' : 'accent'})"></span></span><span class="subtle" style="font-size:12.5px;${tone === 'crit' ? 'color:var(--crit)' : ''}">${note}</span></div>`).join('')}</div>`)}
        ${card('Used by', '', `<div class="stack" style="gap:8px">${[['nginx.service', 2], ['sshd.service', 5], ['postfix.service', 2], ['haproxy.service', 1], ['postgresql.service', 1]].map(([u, n]) => `<div class="row row--between"><a href="22-service.html" class="mono">${u}</a><span class="subtle">${n} host${n > 1 ? 's' : ''}</span></div>`).join('')}</div>`)}
        ${card('Recent changes', '<a href="#" style="font-size:12.5px">History</a>', `<ul class="list list--plain" style="margin:0;padding:0">${[['mx-01 updated 3.0.13 → 3.0.15', '2 days ago'], ['mx-backup-03 updated 3.0.13 → 3.0.15', '2 days ago'], ['CVE-2026-10037 marked exploited', '5 days ago']].map(([a, d]) => `<li style="display:grid;gap:2px;padding:6px 0;border-bottom:1px solid var(--line)"><span>${a}</span><span class="subtle" style="font-size:12.5px">${d}</span></li>`).join('')}</ul>`)}
      </div>
      <div class="stack" style="gap:16px">
        ${card('Vulnerabilities <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">2</span>', '<a href="#" style="font-size:12.5px">Show in Vulnerabilities</a>',
          `<div class="table-wrap" style="margin:0;border:0;border-radius:0"><table class="table"><thead><tr><th>Advisory</th><th style="width:110px">Severity</th><th style="width:150px">Affects</th><th style="width:120px">Fixed in</th><th style="width:100px">Hosts</th></tr></thead><tbody>
          <tr><td>CVE-2026-10037 <span class="badge badge--bad">Exploited</span><div class="subtle" style="font-size:12.5px">Memory corruption in TLS 1.3 handshake</div></td><td><span class="badge badge--critical">Critical</span></td><td class="mono">< 3.0.15</td><td class="mono">3.0.15</td><td class="num">2</td></tr>
          <tr><td>CVE-2026-10051<div class="subtle" style="font-size:12.5px">Timing side channel in RSA decryption</div></td><td><span class="badge badge--medium">Medium</span></td><td class="mono">< 3.0.15</td><td class="mono">3.0.15</td><td class="num">2</td></tr></tbody></table></div>`, false)}
        ${card(`Hosts <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">${hs.length}</span>`, `<span class="row" style="gap:6px">${seg('all', 'All', hs.length)}${seg('update', 'Need an update', hs.filter(needs).length)}${seg('ok', 'Up to date', hs.filter(h => !needs(h)).length)}</span>`,
          `<div class="table-wrap" style="margin:0;border:0;border-radius:0"><table class="table"><thead><tr><th>Host</th><th style="width:110px">Version</th><th style="width:170px">Status</th><th>Used by</th><th style="width:120px">Last report</th></tr></thead><tbody>${shown.map(h => `<tr><td><div class="cell-two"><a href="17-host.html" class="mono">${h.name}</a><span class="subtle">${h.distro} · ${h.ip}</span></div></td><td class="mono">${ver[h.name][0]}</td><td>${needs(h) ? '<span class="badge badge--warn">Update to 3.0.15</span>' : '<span class="badge badge--ok">Up to date</span>'}</td><td class="mono" style="font-size:12.5px">${ver[h.name][1]}</td><td class="${h.online ? '' : 'warn-text'}">${h.seen}</td></tr>`).join('')}</tbody></table></div>`, false)}
      </div>
    </div></div></div>`;
}
function livePackage() {
  const st = { show: 'all' };
  hostsActive('/software'); $('.topbar__title').textContent = 'Software';
  const render = () => { $('.view-area').innerHTML = packagePage(st); };
  render();
  document.addEventListener('click', (e) => { const t = e.target.closest('[data-show]'); if (t) { st.show = t.dataset.show; render(); } });
}
"""
screen(
    "23-software", "software",
    "<b>23 · Software.</b> Search plus filters (Vulnerabilities, Fix, Versions, Group, Type, Changes), and one line per package: what it is, hosts, version range, worst advisory (exploited flagged), where an update fixes something, what uses it, and this week. <b>Try it:</b> filter, then click a package.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + SOFTWAREUI + "liveSoftware({ filters: {}, q: '', open: null });",
)
screen(
    "24-package", "software",
    "<b>24 · A package's page.</b> openssl in the shared layout: details, versions (which are vulnerable), what uses it and recent changes on the left; its vulnerabilities and its hosts (need an update / up to date) on the right. <b>Try it:</b> switch Need an update / Up to date.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + SOFTWAREUI + "livePackage();",
)

VULNSUI = r"""
// ---- Vulnerabilities list with filters, and an advisory's page ----
const V = [
  { id: 'CVE-2026-10037', title: 'openssl: memory corruption in the TLS 1.3 handshake', sev: 'Critical', ex: true, pkg: 'openssl', fixv: '3.0.15', open: 2, of: 5, cvss: 9.8, epss: 87.9, due: '30 Oct', dueSoon: true, who: '' },
  { id: 'CVE-2026-10042', title: 'curl: heap overflow in SOCKS5 proxy handshake', sev: 'High', ex: true, pkg: 'curl', fixv: '8.9.1', open: 3, of: 5, cvss: 8.6, epss: 63.1, due: '6 Nov', dueSoon: true, who: 'Sam Analyst' },
  { id: 'CVE-2026-10079', title: 'glibc: buffer overflow in iconv', sev: 'High', ex: false, pkg: 'glibc', fixv: '', open: 5, of: 5, cvss: 7.8, epss: 4.2, due: '', who: '' },
  { id: 'CVE-2026-10112', title: 'nginx: request smuggling with HTTP/2', sev: 'High', ex: false, pkg: 'nginx', fixv: '1.26.2', open: 1, of: 2, cvss: 7.5, epss: 12.0, due: '', who: 'Wendy Ward' },
  { id: 'CVE-2026-20871', title: 'Microsoft Edge: type confusion in V8', sev: 'High', ex: true, pkg: 'Microsoft Edge', fixv: '141.0.3537', open: 2, of: 6, cvss: 8.8, epss: 41.0, due: '13 Nov', who: 'Wendy Ward' },
  { id: 'CVE-2026-10118', title: 'nginx: memory disclosure in the mp4 module', sev: 'Medium', ex: false, pkg: 'nginx', fixv: '1.26.3', open: 2, of: 2, cvss: 5.9, epss: 1.1, due: '', who: '' },
  { id: 'CVE-2026-10051', title: 'openssl: timing side channel in RSA decryption', sev: 'Medium', ex: false, pkg: 'openssl', fixv: '3.0.15', open: 2, of: 5, cvss: 5.3, epss: 0.8, due: '', who: '' },
  { id: 'CVE-2026-10140', title: 'openssh: information leak in agent forwarding', sev: 'Medium', ex: false, pkg: 'openssh-server', fixv: '', open: 5, of: 5, cvss: 5.0, epss: 0.4, due: '', who: '' },
  { id: 'CVE-2026-20430', title: '7-Zip: directory traversal when extracting', sev: 'High', ex: false, pkg: '7-Zip', fixv: '24.08', open: 2, of: 3, cvss: 7.0, epss: 2.6, due: '', who: '' },
  { id: 'CVE-2026-10155', title: 'nodejs: path traversal in the permission model', sev: 'Medium', ex: false, pkg: 'nodejs', fixv: '22.11.1', open: 1, of: 1, cvss: 6.5, epss: 0.9, due: '', who: '' },
];
const VF = {
  Severity: { opts: ['Critical', 'High', 'Medium'], test: (x, v) => x.sev === v },
  State: { opts: ['Open', 'Mitigated', 'Risk accepted', 'False positive', 'Resolved'], test: (x, v) => v === 'Open' ? x.open > 0 : v === 'Resolved' ? x.open < x.of : false },
  Signals: { opts: ['Known exploited', 'Due within 30 days', 'No fix yet', 'Reboot needed', 'Lower confidence'], test: (x, v) => v === 'Known exploited' ? x.ex : v === 'Due within 30 days' ? !!x.due : v === 'No fix yet' ? !x.fixv : false },
  Package: { opts: () => [...new Set(V.map(x => x.pkg))].sort(), test: (x, v) => x.pkg === v },
  Group: { opts: () => HG.map(g => g.name), test: (x, v) => true },
  Assignee: { opts: ['Unassigned', 'Sam Analyst', 'Wendy Ward', 'Me'], test: (x, v) => v === 'Unassigned' ? !x.who : x.who === v },
};
const sevB = (s) => `<span class="badge badge--${s === 'Critical' ? 'critical' : s === 'High' ? 'high' : 'medium'}">${s}</span>`;
function vulnsList(st) {
  const rows = V.filter(x => Object.entries(st.filters).every(([k, v]) => VF[k].test(x, v)) && (!st.q || (x.id + ' ' + x.title + ' ' + x.pkg).toLowerCase().includes(st.q.toLowerCase())));
  const tr = rows.map(x => `<tr data-row="${x.id}" style="cursor:pointer"><td><input type="checkbox" aria-label="Select ${x.id}" data-sel="${x.id}" ${st.sel.includes(x.id) ? 'checked' : ''}></td><td>${sevB(x.sev)}</td>
      <td><div class="cell-two"><span>${x.title} ${x.ex ? '<span class="badge badge--bad">Exploited</span>' : ''}</span><span class="subtle mono" style="font-size:12px">${x.id}</span></div></td>
      <td><div class="cell-two"><span class="mono" style="font-size:12.5px">${x.pkg}</span><span class="subtle">${x.fixv ? 'fixed in ' + x.fixv : '<span class="warn-text">no fix yet</span>'}</span></div></td>
      <td class="num">${x.cvss.toFixed(1)}</td><td class="num">${x.epss.toFixed(1)}%</td>
      <td><div class="stack" style="gap:4px"><span class="num"><b>${x.open}</b> <span class="subtle">open of ${x.of}</span></span><span style="height:5px;border-radius:3px;background:var(--surface-2);overflow:hidden;width:110px"><span style="display:block;height:100%;width:${Math.round(100 * (x.of - x.open) / x.of)}%;background:var(--ok)"></span></span></div></td>
      <td>${x.due ? `<span class="${x.dueSoon ? 'warn-text' : ''}">${x.due}</span>` : '<span class="subtle">—</span>'}</td>
      <td>${x.who ? x.who : '<span class="subtle">Unassigned</span>'}</td></tr>`).join('');
  const bulk = st.sel.length ? `<div class="view-pad" style="padding-bottom:10px"><div class="card row" style="gap:10px;padding:8px 12px;background:var(--accent-soft)"><b>${st.sel.length} selected</b><button type="button" class="button button--small">Set state ▾</button><button type="button" class="button button--small">Assign ▾</button><button type="button" class="button button--small">Add to case</button><span class="grow"></span><button type="button" class="button button--ghost button--small" data-selnone>Clear</button></div></div>` : '';
  return `<div class="view">
    <header class="view-pad" style="padding-top:20px;padding-bottom:8px"><h1 style="margin:0">Vulnerabilities <span class="subtle num" style="font-size:16px;font-weight:500">${rows.length}${rows.length !== V.length ? ' of ' + V.length : ''}</span></h1><span class="subtle">${V.length} open advisories on ${HOSTS.length} hosts · ${V.filter(x => x.ex).length} known exploited · ${V.filter(x => x.due).length} with a due date · ${V.filter(x => !x.fixv).length} without a fix · ${V.filter(x => !x.who).length} unassigned</span></header>
    ${filterBar(VF, st, V, 'Search CVE, advisory or package…')}${bulk}
    <div class="table-wrap" style="margin:0 24px 40px"><table class="table" aria-label="Vulnerabilities"><thead><tr><th style="width:36px"><input type="checkbox" aria-label="Select all" data-selall></th><th style="width:100px">Severity</th><th>Advisory</th><th style="width:170px">Package</th><th style="width:70px">CVSS</th><th style="width:80px">EPSS</th><th style="width:140px">Hosts</th><th style="width:90px">Due</th><th style="width:130px">Assignee</th></tr></thead><tbody>${tr || '<tr><td colspan="9" class="subtle">No advisory matches these filters.</td></tr>'}</tbody></table></div></div>`;
}
function liveVulns(st) {
  hostsActive('/vulnerabilities'); $('.topbar__title').textContent = 'Vulnerabilities';
  const render = (focus) => { $('.view-area').innerHTML = vulnsList(st); if (focus) { const i = $('[data-q]'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); } };
  document.addEventListener('click', (e) => {
    const c = e.target.closest('[data-sel]'); if (c) { e.stopImmediatePropagation(); st.sel = c.checked ? [...st.sel, c.dataset.sel] : st.sel.filter(x => x !== c.dataset.sel); render(); return; }
    if (e.target.closest('[data-selall]')) { e.stopImmediatePropagation(); st.sel = e.target.checked ? V.map(x => x.id) : []; render(); return; }
    if (e.target.closest('[data-selnone]')) { e.stopImmediatePropagation(); st.sel = []; render(); }
  }, true);
  render(); liveFilters(st, render, () => { location.href = '26-advisory.html'; });
}
function advisoryPage(st) {
  const card = (title, aside, body, pad = true) => `<section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">${title}</h2>${aside || ''}</div><div style="${pad ? 'padding:14px 16px' : ''}">${body}</div></section>`;
  const kv = (rows) => `<dl class="kv" style="margin:0;row-gap:10px;grid-template-columns:110px minmax(0,1fr)">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const tile = (label, value, sub, tone) => `<div class="card card__body" style="display:grid;gap:4px"><span class="subtle">${label}</span><span style="font-size:26px;font-weight:650;${tone ? `color:var(--${tone})` : ''}">${value}</span><span class="subtle" style="font-size:12.5px">${sub}</span></div>`;
  const H = [['web-01', '8.5.0-1.fc44', 'Open', 'Sam Analyst', 'Fedora: FEDORA-2026-3a245276'], ['db-02', '7.88.1-10', 'Open', 'Sam Analyst', 'Debian: DSA-5891-1'], ['mx-backup-03', '8.5.0-2ubuntu10', 'Open', '—', 'Ubuntu: USN-7102-1'], ['lab-ws-04', '8.5.0-1.fc44', 'Mitigated', 'Sam Analyst', 'Fedora: FEDORA-2026-3a245276'], ['mx-01', '7.88.1-10+deb12u8', 'Resolved', '—', 'Debian: DSA-5891-1']];
  const stB = (x) => `<span class="badge ${x === 'Open' ? 'badge--bad' : x === 'Resolved' ? 'badge--ok' : 'badge--plain'}">${x}</span>`;
  const shown = H.filter(r => st.show === 'all' || r[2] === st.show);
  const seg = (id, label) => `<button type="button" class="chip" data-show="${id}" aria-pressed="${st.show === id}">${label} <span class="subtle num">${id === 'all' ? H.length : H.filter(r => r[2] === id).length}</span></button>`;
  return `<div class="view"><div>
    <div class="view-pad" style="padding-top:20px"><span class="subtle"><a href="25-vulnerabilities.html">Vulnerabilities</a></span></div>
    <header class="view-pad" style="display:flex;gap:16px;align-items:center;padding-top:8px;padding-bottom:12px">
      <span style="display:grid;place-items:center;width:56px;height:56px;border-radius:14px;background:var(--accent-soft);color:var(--accent);font-weight:700;font-size:13px">CVE</span>
      <div class="stack grow" style="gap:4px"><div class="row" style="gap:10px"><h1 style="margin:0;font-size:22px">curl: heap overflow in SOCKS5 proxy handshake</h1>${sevB('High')}<span class="badge badge--bad">Known exploited</span></div>
        <span class="subtle"><span class="mono">CVE-2026-10042</span> · package curl · fixed in 8.9.1 · open on 3 of 5 hosts · assigned to Sam Analyst</span></div>
      <div class="row" style="gap:8px"><button type="button" class="button">Set state ▾</button><button type="button" class="button">Assign ▾</button><button type="button" class="button">Add to case</button><button type="button" class="button" aria-label="More actions">⋯</button></div></header>
    <div class="view-pad" style="padding-bottom:16px"><div class="callout" style="margin:0;background:var(--crit-soft, #fde8ef);color:var(--text)"><span style="color:var(--crit)">⏱</span><span>Known exploited: CISA asks for remediation by <b>6 Nov 2026</b> (in 21 days).</span></div></div>
    <div class="view-pad" style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;padding-bottom:16px">
      ${tile('Open on', 3, 'of 5 hosts with curl', 'bad')}${tile('Fix available', 3, 'update curl to 8.9.1', 'warn')}${tile('EPSS', '63.1%', 'chance of exploitation in 30 days', '')}${tile('CVSS', '8.6', 'network, no privileges needed', '')}
    </div>
    <div class="view-pad" style="display:grid;grid-template-columns:380px minmax(0,1fr);gap:24px;align-items:start;margin-bottom:60px">
      <div class="stack" style="gap:16px">
        ${card('What to do', '', `<div class="stack" style="gap:10px"><span>Update <a href="24-package.html" class="mono">curl</a> to <b class="mono">8.9.1</b> or the fixed distribution build:</span><div class="stack" style="gap:6px">${[['Fedora 44', '8.9.1-3.fc44'], ['Debian 12', '7.88.1-10+deb12u8'], ['Ubuntu 24.04', '8.5.0-2ubuntu10.5']].map(([d, v]) => `<span class="row row--between"><span>${d}</span><span class="mono" style="font-size:12.5px">${v}</span></span>`).join('')}</div><span class="subtle" style="font-size:12.5px">No reboot needed.</span></div>`)}
        ${card('Details', '', kv([['Advisories', '<span class="stack" style="gap:2px"><a href="#">FEDORA-2026-3a245276</a><a href="#">DSA-5891-1</a><a href="#">USN-7102-1</a></span>'], ['Published', '9 Oct 2026'], ['Confidence', '98% <span class="subtle">· package version from inventory</span>'], ['Vector', '<span class="mono" style="font-size:12px">AV:N/AC:L/PR:N/UI:R</span>']]))}
        ${card('History', '<a href="#" style="font-size:12.5px">All</a>', `<ul class="list list--plain" style="margin:0;padding:0">${[['Sam Analyst assigned to themself', '2 h ago'], ['lab-ws-04 marked Mitigated: “outbound SOCKS blocked at the firewall”', 'yesterday'], ['mx-01 resolved by updating curl', '2 days ago'], ['Added to the CISA known-exploited list', '5 days ago']].map(([a, d]) => `<li style="display:grid;gap:2px;padding:6px 0;border-bottom:1px solid var(--line)"><span>${a}</span><span class="subtle" style="font-size:12.5px">${d}</span></li>`).join('')}</ul>`)}
      </div>
      <div class="stack" style="gap:16px">
        ${card('Hosts <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">5</span>', `<span class="row" style="gap:6px">${seg('all', 'All')}${seg('Open', 'Open')}${seg('Mitigated', 'Mitigated')}${seg('Resolved', 'Resolved')}</span>`,
          `<div class="table-wrap" style="margin:0;border:0;border-radius:0"><table class="table"><thead><tr><th style="width:36px"><input type="checkbox" aria-label="Select all"></th><th>Host</th><th style="width:170px">Installed</th><th style="width:110px">State</th><th style="width:130px">Assignee</th><th style="width:210px">Advisory</th></tr></thead><tbody>${shown.map(([n, v, s, w, a]) => { const h = HOSTS.find(x => x.name === n); return `<tr><td><input type="checkbox" aria-label="Select ${n}"></td><td><div class="cell-two"><a href="17-host.html" class="mono">${n}</a><span class="subtle">${h.distro} · ${h.ip}</span></div></td><td class="mono" style="font-size:12.5px">${v}</td><td>${stB(s)}</td><td>${w === '—' ? '<span class="subtle">—</span>' : w}</td><td class="subtle" style="font-size:12.5px">${a}</td></tr>`; }).join('')}</tbody></table></div>`, false)}
        ${card('Related', '', `<div class="stack" style="gap:10px">
          <div class="row row--between"><span><b>Alarm:</b> A shell downloaded a program <span class="subtle mono">bash → curl</span> on web-01</span><span class="row" style="gap:8px"><span class="badge badge--medium">Medium · 1 h ago</span><a href="#" style="font-size:12.5px">Open</a></span></div>
          <div class="row row--between"><span><b>Case:</b> Outbound downloads from web servers</span><span class="row" style="gap:8px"><span class="badge badge--plain">Open · Sam Analyst</span><a href="#" style="font-size:12.5px">Open</a></span></div>
          <div class="row row--between"><span><b>Same package:</b> 2 more curl advisories</span><span class="row" style="gap:8px"><span class="subtle">Medium, Low</span><a href="#" style="font-size:12.5px">Show</a></span></div></div>`)}
      </div>
    </div></div></div>`;
}
function liveAdvisory() {
  const st = { show: 'all' };
  hostsActive('/vulnerabilities'); $('.topbar__title').textContent = 'Vulnerabilities';
  const render = () => { $('.view-area').innerHTML = advisoryPage(st); };
  render();
  document.addEventListener('click', (e) => { const t = e.target.closest('[data-show]'); if (t) { st.show = t.dataset.show; render(); } });
}
"""
screen(
    "25-vulnerabilities", "vulns",
    "<b>25 · Vulnerabilities.</b> The nine toggles become filters (Severity, State, Signals, Package, Group, Assignee); each row adds the package and its fix, hosts open with progress, the due date and the assignee. Selecting rows shows the bulk bar. <b>Try it:</b> tick two rows; filter; click an advisory.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + VULNSUI + "liveVulns({ filters: {}, q: '', open: null, sel: [] });",
)
screen(
    "26-advisory", "vulns",
    "<b>26 · An advisory's page.</b> CVE-2026-10042 in the shared layout: triage in the header, the CISA due date, what to do per distribution, details and history on the left; its hosts (open, mitigated, resolved) and related alarms and cases on the right. <b>Try it:</b> switch the host states.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + VULNSUI + "liveAdvisory();",
)

COMPLIANCEUI = r"""
// ---- Compliance list with filters, and a check's page ----
const C = [
  { title: 'Docker API exposed without TLS', id: 'port.docker_api.exposed', set: 'baseline', area: 'Network exposure', sev: 'Critical', open: 1, mit: 0, acc: 0, checked: 11, since: '10 Sep', who: '' },
  { title: 'SSH allows root login', id: 'ssh.permit_root_login', set: 'hardening-linux-l1', area: 'SSH', sev: 'Critical', open: 2, mit: 0, acc: 0, checked: 5, since: '23 Jul', who: 'Sam Analyst' },
  { title: 'Password maximum age too long', id: 'accounts.pass_max_days', set: 'hardening-linux-l1', area: 'Accounts', sev: 'Critical', open: 2, mit: 0, acc: 1, checked: 5, since: '23 Jul', who: '' },
  { title: 'SSH password login allowed', id: 'ssh.password_authentication', set: 'hardening-linux-l1', area: 'SSH', sev: 'High', open: 1, mit: 0, acc: 0, checked: 5, since: '2 Aug', who: '' },
  { title: 'Redis exposed to the network', id: 'port.redis.exposed', set: 'baseline', area: 'Network exposure', sev: 'High', open: 1, mit: 0, acc: 0, checked: 11, since: '10 Sep', who: '' },
  { title: 'PostgreSQL exposed to the network', id: 'port.postgresql.exposed', set: 'baseline', area: 'Network exposure', sev: 'Medium', open: 1, mit: 0, acc: 0, checked: 11, since: '10 Sep', who: 'Wendy Ward' },
  { title: 'SMB exposed to the network', id: 'port.smb.exposed', set: 'baseline', area: 'Network exposure', sev: 'Medium', open: 3, mit: 2, acc: 0, checked: 11, since: '10 Sep', who: 'Wendy Ward' },
  { title: 'Unattended upgrades off', id: 'packages.auto_updates', set: 'baseline', area: 'Packages', sev: 'Medium', open: 3, mit: 0, acc: 1, checked: 5, since: '23 Jul', who: '' },
  { title: 'IP forwarding enabled', id: 'kernel.ip_forward', set: 'hardening-linux-l1', area: 'Kernel', sev: 'Medium', open: 1, mit: 0, acc: 0, checked: 5, since: '5 Oct', who: '' },
  { title: 'telnet-server installed', id: 'package.telnet_server.installed', set: 'baseline', area: 'Packages', sev: 'Low', open: 1, mit: 0, acc: 0, checked: 5, since: '23 Jul', who: '' },
];
const CF = {
  Severity: { opts: ['Critical', 'High', 'Medium', 'Low'], test: (x, v) => x.sev === v },
  State: { opts: ['Open', 'Mitigated', 'Risk accepted', 'False positive', 'Resolved'], test: (x, v) => v === 'Open' ? x.open > 0 : v === 'Mitigated' ? x.mit > 0 : v === 'Risk accepted' ? x.acc > 0 : false },
  'Rule set': { opts: ['baseline', 'hardening-linux-l1'], test: (x, v) => x.set === v },
  Area: { opts: () => [...new Set(C.map(x => x.area))].sort(), test: (x, v) => x.area === v },
  Group: { opts: () => HG.map(g => g.name), test: () => true },
  Assignee: { opts: ['Unassigned', 'Sam Analyst', 'Wendy Ward', 'Me'], test: (x, v) => v === 'Unassigned' ? !x.who : x.who === v },
};
const sevC = (s) => `<span class="badge badge--${s === 'Critical' ? 'critical' : s === 'High' ? 'high' : s === 'Medium' ? 'medium' : 'low'}">${s}</span>`;
const stateBar = (x) => { const pass = x.checked - x.open - x.mit - x.acc; const seg = (n, c) => n ? `<span style="width:${100 * n / x.checked}%;background:var(--${c})"></span>` : '';
  return `<div class="stack" style="gap:4px"><span style="display:flex;height:6px;width:130px;border-radius:3px;overflow:hidden;background:var(--surface-2)">${seg(x.open, 'bad')}${seg(x.mit, 'ok')}${seg(x.acc, 'muted, #8a94a6')}</span><span class="subtle" style="font-size:12px">${x.open} open${x.mit ? ` · ${x.mit} mitigated` : ''}${x.acc ? ` · ${x.acc} accepted` : ''} · ${pass} pass</span></div>`; };
function complianceList(st) {
  const rows = C.filter(x => Object.entries(st.filters).every(([k, v]) => CF[k].test(x, v)) && (!st.q || (x.title + ' ' + x.id + ' ' + x.set).toLowerCase().includes(st.q.toLowerCase())));
  const tr = rows.map(x => `<tr data-row="${x.id}" style="cursor:pointer"><td><input type="checkbox" aria-label="Select ${x.title}" data-sel="${x.id}" ${st.sel.includes(x.id) ? 'checked' : ''}></td><td>${sevC(x.sev)}</td>
      <td><div class="cell-two"><span>${x.title}</span><span class="subtle" style="font-size:12px"><span class="mono">${x.id}</span> · ${x.set}</span></div></td>
      <td>${x.area}</td>
      <td class="num"><b>${x.open}</b> <span class="subtle">of ${x.checked}</span></td>
      <td>${stateBar(x)}</td><td>${x.since}</td>
      <td>${x.who ? x.who : '<span class="subtle">Unassigned</span>'}</td></tr>`).join('');
  const bulk = st.sel.length ? `<div class="view-pad" style="padding-bottom:10px"><div class="card row" style="gap:10px;padding:8px 12px;background:var(--accent-soft)"><b>${st.sel.length} selected</b><button type="button" class="button button--small">Set state ▾</button><button type="button" class="button button--small">Assign ▾</button><button type="button" class="button button--small">Add to case</button><span class="grow"></span><button type="button" class="button button--ghost button--small" data-selnone>Clear</button></div></div>` : '';
  return `<div class="view">
    <header class="view-pad" style="padding-top:20px;padding-bottom:8px"><h1 style="margin:0">Compliance <span class="subtle num" style="font-size:16px;font-weight:500">${rows.length}${rows.length !== C.length ? ' of ' + C.length : ''}</span></h1><span class="subtle">${C.length} checks failing on ${HOSTS.length} hosts · ${C.filter(x => x.sev === 'Critical').length} critical · ${C.filter(x => !x.who).length} unassigned · baseline ${C.filter(x => x.set === 'baseline').length}, hardening-linux-l1 ${C.filter(x => x.set !== 'baseline').length}</span></header>
    ${filterBar(CF, st, C, 'Search check, rule or rule set…')}${bulk}
    <div class="table-wrap" style="margin:0 24px 40px"><table class="table" aria-label="Compliance"><thead><tr><th style="width:36px"><input type="checkbox" aria-label="Select all" data-selall></th><th style="width:100px">Severity</th><th>Check</th><th style="width:150px">Area</th><th style="width:90px">Failing</th><th style="width:220px">Hosts</th><th style="width:80px">Since</th><th style="width:130px">Assignee</th></tr></thead><tbody>${tr || '<tr><td colspan="8" class="subtle">No check matches these filters.</td></tr>'}</tbody></table></div></div>`;
}
function liveCompliance(st) {
  hostsActive('/compliance'); $('.topbar__title').textContent = 'Compliance';
  const render = (focus) => { $('.view-area').innerHTML = complianceList(st); if (focus) { const i = $('[data-q]'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); } };
  document.addEventListener('click', (e) => {
    const c = e.target.closest('[data-sel]'); if (c) { e.stopImmediatePropagation(); st.sel = c.checked ? [...st.sel, c.dataset.sel] : st.sel.filter(x => x !== c.dataset.sel); render(); return; }
    if (e.target.closest('[data-selall]')) { e.stopImmediatePropagation(); st.sel = e.target.checked ? C.map(x => x.id) : []; render(); return; }
    if (e.target.closest('[data-selnone]')) { e.stopImmediatePropagation(); st.sel = []; render(); }
  }, true);
  render(); liveFilters(st, render, () => { location.href = '28-check.html'; });
}
function checkPage(st) {
  const card = (title, aside, body, pad = true) => `<section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">${title}</h2>${aside || ''}</div><div style="${pad ? 'padding:14px 16px' : ''}">${body}</div></section>`;
  const kv = (rows) => `<dl class="kv" style="margin:0;row-gap:10px;grid-template-columns:110px minmax(0,1fr)">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const tile = (label, value, sub, tone) => `<div class="card card__body" style="display:grid;gap:4px"><span class="subtle">${label}</span><span style="font-size:26px;font-weight:650;${tone ? `color:var(--${tone})` : ''}">${value}</span><span class="subtle" style="font-size:12.5px">${sub}</span></div>`;
  const H = [['web-01', 'Open', '<span class="mono">PermitRootLogin yes</span> in /etc/ssh/sshd_config line 32', 'Sam Analyst', '1 min ago'], ['mx-backup-03', 'Open', '<span class="mono">PermitRootLogin yes</span> in /etc/ssh/sshd_config.d/50-cloud.conf', 'Sam Analyst', '2 min ago'], ['mx-01', 'Passing', '<span class="mono">PermitRootLogin no</span>', '', '1 min ago'], ['db-02', 'Passing', '<span class="mono">PermitRootLogin prohibit-password</span>', '', '1 min ago'], ['lab-ws-04', 'Passing', '<span class="mono">PermitRootLogin no</span>', '', '2 days ago']];
  const stB = (x) => `<span class="badge ${x === 'Open' ? 'badge--bad' : x === 'Passing' ? 'badge--ok' : 'badge--plain'}">${x}</span>`;
  const shown = H.filter(r => st.show === 'all' || r[1] === st.show);
  const seg = (id, label) => `<button type="button" class="chip" data-show="${id}" aria-pressed="${st.show === id}">${label} <span class="subtle num">${id === 'all' ? H.length : H.filter(r => r[1] === id).length}</span></button>`;
  const spark = [3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2];
  return `<div class="view"><div>
    <div class="view-pad" style="padding-top:20px"><span class="subtle"><a href="27-compliance.html">Compliance</a></span></div>
    <header class="view-pad" style="display:flex;gap:16px;align-items:center;padding-top:8px;padding-bottom:16px">
      <span style="display:grid;place-items:center;width:56px;height:56px;border-radius:14px;background:var(--accent-soft);color:var(--accent);font-weight:700;font-size:13px">CHK</span>
      <div class="stack grow" style="gap:4px"><div class="row" style="gap:10px"><h1 style="margin:0;font-size:22px">SSH allows root login</h1>${sevC('Critical')}</div>
        <span class="subtle"><span class="mono">ssh.permit_root_login</span> · hardening-linux-l1 v4 · SSH · failing on 2 of 5 hosts checked · assigned to Sam Analyst</span></div>
      <div class="row" style="gap:8px"><button type="button" class="button">Set state ▾</button><button type="button" class="button">Assign ▾</button><button type="button" class="button">Add to case</button><button type="button" class="button">Ask about this</button></div></header>
    <div class="view-pad" style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;padding-bottom:16px">
      ${tile('Failing on', 2, 'of 5 hosts checked', 'bad')}${tile('Passing', 3, 'checked within the last day', 'ok')}${tile('First seen', '23 Jul', 'on web-01', '')}
      <div class="card card__body" style="display:grid;gap:4px"><span class="subtle">Last 14 days</span><span style="display:flex;align-items:flex-end;gap:3px;height:34px">${spark.map(n => `<span style="flex:1;height:${n * 10}px;background:var(--bad);opacity:.75;border-radius:2px"></span>`).join('')}</span><span class="subtle" style="font-size:12.5px">3 → 2 hosts failing</span></div>
    </div>
    <div class="view-pad" style="display:grid;grid-template-columns:380px minmax(0,1fr);gap:24px;align-items:start;margin-bottom:60px">
      <div class="stack" style="gap:16px">
        ${card('Why it matters', '', '<p style="margin:0">Logging in as root over SSH means one stolen password or key gives full control, and the audit trail cannot tell people apart. Log in as yourself and use sudo.</p>')}
        ${card('How to fix', '', `<div class="stack" style="gap:8px"><span>In <span class="mono">/etc/ssh/sshd_config</span> (and any file in <span class="mono">sshd_config.d/</span>), set:</span><pre class="mono" style="margin:0;padding:10px 12px;background:var(--surface-2);border-radius:var(--r-1);font-size:12.5px">PermitRootLogin no</pre><span>Then reload SSH: <span class="mono">systemctl reload sshd</span>. Fixed hosts pass on their next scan.</span></div>`)}
        ${card('Details', '', kv([['Rule', '<span class="mono">ssh.permit_root_login</span> · version 3'], ['Rule set', '<a href="#">hardening-linux-l1</a> v4'], ['Applies to', 'Linux hosts running sshd'], ['Reference', 'CIS Linux 5.2.10']]))}
        ${card('History', '<a href="#" style="font-size:12.5px">All</a>', `<ul class="list list--plain" style="margin:0;padding:0">${[['db-02 passes after a config change', '6 days ago'], ['Sam Analyst assigned to themself', '1 week ago'], ['Rule set hardening-linux-l1 v4 published', '3 weeks ago']].map(([a, d]) => `<li style="display:grid;gap:2px;padding:6px 0;border-bottom:1px solid var(--line)"><span>${a}</span><span class="subtle" style="font-size:12.5px">${d}</span></li>`).join('')}</ul>`)}
      </div>
      <div class="stack" style="gap:16px">
        ${card('Hosts <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">5</span>', `<span class="row" style="gap:6px">${seg('all', 'All')}${seg('Open', 'Failing')}${seg('Passing', 'Passing')}</span>`,
          `<div class="table-wrap" style="margin:0;border:0;border-radius:0"><table class="table"><thead><tr><th style="width:36px"><input type="checkbox" aria-label="Select all"></th><th style="width:200px">Host</th><th style="width:100px">State</th><th>Evidence</th><th style="width:120px">Assignee</th><th style="width:110px">Checked</th></tr></thead><tbody>${shown.map(([n, s, ev, w, t]) => { const h = HOSTS.find(x => x.name === n); return `<tr><td><input type="checkbox" aria-label="Select ${n}"></td><td><div class="cell-two"><a href="17-host.html" class="mono">${n}</a><span class="subtle">${h.distro}</span></div></td><td>${stB(s)}</td><td style="font-size:12.5px">${ev}</td><td>${w || '<span class="subtle">—</span>'}</td><td class="${h.online ? '' : 'warn-text'}">${t}</td></tr>`; }).join('')}</tbody></table></div>`, false)}
        ${card('Related', '', `<div class="stack" style="gap:10px">
          <div class="row row--between"><span><b>Port:</b> 22/tcp SSH, exposed on 4 hosts</span><a href="20-port.html" style="font-size:12.5px">Open</a></div>
          <div class="row row--between"><span><b>Service:</b> sshd.service</span><a href="#" style="font-size:12.5px">Open</a></div>
          <div class="row row--between"><span><b>Same area:</b> SSH password login allowed</span><span class="row" style="gap:8px"><span class="badge badge--high">High · 1 host</span><a href="#" style="font-size:12.5px">Open</a></span></div></div>`)}
      </div>
    </div></div></div>`;
}
function liveCheck() {
  const st = { show: 'all' };
  hostsActive('/compliance'); $('.topbar__title').textContent = 'Compliance';
  const render = () => { $('.view-area').innerHTML = checkPage(st); };
  render();
  document.addEventListener('click', (e) => { const t = e.target.closest('[data-show]'); if (t) { st.show = t.dataset.show; render(); } });
}
"""
screen(
    "27-compliance", "compliance",
    "<b>27 · Compliance.</b> Each check gets a short name (the explanation moves to its page); filters (Severity, State, Rule set, Area, Group, Assignee); the colour bar gets words (open · mitigated · accepted · pass). Bulk selection stays. <b>Try it:</b> tick rows; filter by Area; click a check.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + COMPLIANCEUI + "liveCompliance({ filters: {}, q: '', open: null, sel: [] });",
)
screen(
    "28-check", "compliance",
    "<b>28 · A check's page.</b> SSH allows root login in the shared layout: why it matters, how to fix, details and history on the left; each host with its evidence (the exact config line) and related port, service and checks on the right. <b>Try it:</b> switch Failing / Passing.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + COMPLIANCEUI + "liveCheck();",
)

ALARMSUI = r"""
// ---- Alarms list with filters, and an alarm's page ----
const A = [
  { id: 'a1', title: 'A web server started a shell', chain: 'nginx → sh', host: 'web-01', sev: 'High', count: 41, first: 'today 08:12', last: '2 min ago', state: 'Open', who: 'Sam Analyst', kase: 'C-104', tech: 'T1505.003', supp: false },
  { id: 'a2', title: 'A database server started a shell', chain: 'postgres → bash', host: 'db-02', sev: 'Critical', count: 1, first: '2 h ago', last: '2 h ago', state: 'Open', who: '', kase: 'C-103', tech: 'T1059.004', supp: false },
  { id: 'a3', title: 'A shell downloaded a program and ran it', chain: 'bash → curl', host: 'web-01', sev: 'Medium', count: 1, first: '1 h ago', last: '1 h ago', state: 'Open', who: '', kase: '', tech: 'T1105', supp: false },
  { id: 'a4', title: 'Unexpected listening port 8081', chain: 'node', host: 'web-01', sev: 'Medium', count: 1, first: 'yesterday', last: 'yesterday', state: 'Open', who: '', kase: '', tech: 'T1571', supp: false },
  { id: 'a5', title: 'PowerShell downloaded and ran a script', chain: 'powershell.exe → iex', host: 'win-file-07', sev: 'High', count: 2, first: '3 h ago', last: '40 min ago', state: 'Open', who: 'Wendy Ward', kase: '', tech: 'T1059.001', supp: false },
  { id: 'a6', title: 'An Office app started a command shell', chain: 'winword.exe → cmd.exe', host: 'win-app-03', sev: 'High', count: 1, first: '5 h ago', last: '5 h ago', state: 'Open', who: '', kase: '', tech: 'T1204.002', supp: false },
  { id: 'a7', title: 'A shell downloaded a program and ran it', chain: 'bash → curl', host: 'mx-backup-03', sev: 'Medium', count: 3, first: 'yesterday', last: '6 h ago', state: 'Mitigated', who: 'Sam Analyst', kase: '', tech: 'T1105', supp: false },
  { id: 'a8', title: 'A backup job started PowerShell', chain: 'backup.exe → powershell.exe', host: 'win-file-07', sev: 'Low', count: 14, first: 'last week', last: '02:00', state: 'Open', who: '', kase: '', tech: 'T1059.001', supp: true },
];
const AF = {
  Severity: { opts: ['Critical', 'High', 'Medium', 'Low'], test: (x, v) => x.sev === v },
  State: { opts: ['Open', 'Mitigated', 'Risk accepted', 'False positive', 'Resolved'], test: (x, v) => x.state === v },
  Suppressed: { opts: ['Hide suppressed', 'Only suppressed'], test: (x, v) => x.supp === (v === 'Only suppressed') },
  Host: { opts: () => [...new Set(A.map(x => x.host))].sort(), test: (x, v) => x.host === v },
  Group: { opts: () => HG.map(g => g.name), test: (x, v) => membersOf(HG.find(g => g.name === v)).some(h => h.name === x.host) },
  Technique: { opts: () => [...new Set(A.map(x => x.tech))].sort(), test: (x, v) => x.tech === v },
  Case: { opts: ['In a case', 'Not in a case'], test: (x, v) => !!x.kase === (v === 'In a case') },
  Assignee: { opts: ['Unassigned', 'Sam Analyst', 'Wendy Ward', 'Me'], test: (x, v) => v === 'Unassigned' ? !x.who : x.who === v },
};
const sevA = (s) => `<span class="badge badge--${s === 'Critical' ? 'critical' : s === 'High' ? 'high' : s === 'Medium' ? 'medium' : 'low'}">${s}</span>`;
const stA = (s) => `<span class="badge ${s === 'Open' ? 'badge--bad' : 'badge--plain'}">${s}</span>`;
function alarmsList(st) {
  const rows = A.filter(x => Object.entries(st.filters).every(([k, v]) => AF[k].test(x, v)) && (st.filters.Suppressed || !x.supp) && (!st.q || (x.title + ' ' + x.chain + ' ' + x.host).toLowerCase().includes(st.q.toLowerCase())));
  const tr = rows.map(x => { const h = HOSTS.find(y => y.name === x.host);
    return `<tr data-row="${x.id}" style="cursor:pointer"><td><input type="checkbox" aria-label="Select ${x.title}" data-sel="${x.id}" ${st.sel.includes(x.id) ? 'checked' : ''}></td><td>${sevA(x.sev)}</td>
      <td><div class="cell-two"><span>${x.title} ${x.supp ? '<span class="badge badge--plain">Suppressed</span>' : ''}</span><span class="subtle" style="font-size:12px"><span class="mono">${x.chain}</span> · ${x.tech}</span></div></td>
      <td><div class="cell-two"><a href="17-host.html" class="mono">${x.host}</a><span class="subtle">${h.distro}</span></div></td>
      <td class="num"><b>${x.count}</b>×</td>
      <td><div class="cell-two"><span>${x.last}</span><span class="subtle">first ${x.first}</span></div></td>
      <td>${stA(x.state)}</td><td>${x.who || '<span class="subtle">Unassigned</span>'}</td>
      <td>${x.kase ? `<a href="#" class="badge badge--accent" style="text-decoration:none">${x.kase}</a>` : '<span class="subtle">—</span>'}</td></tr>`; }).join('');
  const bulk = st.sel.length ? `<div class="view-pad" style="padding-bottom:10px"><div class="card row" style="gap:10px;padding:8px 12px;background:var(--accent-soft)"><b>${st.sel.length} selected</b><button type="button" class="button button--small">Set state ▾</button><button type="button" class="button button--small">Assign ▾</button><button type="button" class="button button--small">Add to case</button><button type="button" class="button button--small">Suppress…</button><span class="grow"></span><button type="button" class="button button--ghost button--small" data-selnone>Clear</button></div></div>` : '';
  const live = A.filter(x => !x.supp);
  return `<div class="view">
    <header class="view-pad" style="padding-top:20px;padding-bottom:8px"><h1 style="margin:0">Alarms <span class="subtle num" style="font-size:16px;font-weight:500">${rows.length}</span></h1><span class="subtle">${live.filter(x => x.state === 'Open').length} open on ${new Set(live.filter(x => x.state === 'Open').map(x => x.host)).size} hosts · ${live.filter(x => x.sev === 'Critical' || x.sev === 'High').length} critical or high · ${live.filter(x => !x.who && x.state === 'Open').length} unassigned · ${A.filter(x => x.supp).length} suppressed (hidden) · new ones appear live</span></header>
    ${filterBar(AF, st, A, 'Search alarm, program or host…')}${bulk}
    <div class="table-wrap" style="margin:0 24px 40px"><table class="table" aria-label="Alarms"><thead><tr><th style="width:36px"><input type="checkbox" aria-label="Select all" data-selall></th><th style="width:100px">Severity</th><th>Alarm</th><th style="width:150px">Host</th><th style="width:70px">Count</th><th style="width:140px">Last seen</th><th style="width:110px">State</th><th style="width:130px">Assignee</th><th style="width:80px">Case</th></tr></thead><tbody>${tr || '<tr><td colspan="9" class="subtle">No alarm matches these filters.</td></tr>'}</tbody></table></div></div>`;
}
function liveAlarms(st) {
  hostsActive('/alarms'); $('.topbar__title').textContent = 'Alarms';
  const render = (focus) => { $('.view-area').innerHTML = alarmsList(st); if (focus) { const i = $('[data-q]'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); } };
  document.addEventListener('click', (e) => {
    const c = e.target.closest('[data-sel]'); if (c) { e.stopImmediatePropagation(); st.sel = c.checked ? [...st.sel, c.dataset.sel] : st.sel.filter(x => x !== c.dataset.sel); render(); return; }
    if (e.target.closest('[data-selall]')) { e.stopImmediatePropagation(); st.sel = e.target.checked ? A.map(x => x.id) : []; render(); return; }
    if (e.target.closest('[data-selnone]')) { e.stopImmediatePropagation(); st.sel = []; render(); }
  }, true);
  render(); liveFilters(st, render, () => { location.href = '30-alarm.html'; });
}
function alarmPage() {
  const card = (title, aside, body, pad = true) => `<section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">${title}</h2>${aside || ''}</div><div style="${pad ? 'padding:14px 16px' : ''}">${body}</div></section>`;
  const kv = (rows) => `<dl class="kv" style="margin:0;row-gap:10px;grid-template-columns:110px minmax(0,1fr)">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const tile = (label, value, sub, tone) => `<div class="card card__body" style="display:grid;gap:4px"><span class="subtle">${label}</span><span style="font-size:26px;font-weight:650;${tone ? `color:var(--${tone})` : ''}">${value}</span><span class="subtle" style="font-size:12.5px">${sub}</span></div>`;
  const hours = [0, 0, 2, 2, 2, 2, 2, 2, 2, 3, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 2, 2, 2, 2];
  const proc = (exe, cmd, meta, alarm) => `<div style="padding:10px 14px;border-radius:var(--r-1);background:var(--surface-2);${alarm ? 'border-left:3px solid var(--bad)' : ''}"><div class="mono" style="font-weight:600">${exe}</div><div class="mono subtle" style="font-size:12.5px">${cmd}</div><div class="subtle" style="font-size:12px">${meta}</div></div>`;
  return `<div class="view"><div>
    <div class="view-pad" style="padding-top:20px"><span class="subtle"><a href="29-alarms.html">Alarms</a></span></div>
    <header class="view-pad" style="display:flex;gap:16px;align-items:center;padding-top:8px;padding-bottom:16px">
      <span style="display:grid;place-items:center;width:56px;height:56px;border-radius:14px;background:var(--bad-soft, #fde2e1);color:var(--bad);font-weight:700;font-size:13px">ALM</span>
      <div class="stack grow" style="gap:4px"><div class="row" style="gap:10px"><h1 style="margin:0;font-size:22px">A web server started a shell</h1>${sevA('High')}${stA('Open')}<span class="badge badge--plain">41×</span></div>
        <span class="subtle">on <a href="17-host.html" class="mono">web-01</a> · <span class="mono">nginx → sh</span> · rule web-server-spawns-shell · baseline · ATT&CK T1505.003 · assigned to Sam Analyst · in case <a href="#">C-104</a></span></div>
      <div class="row" style="gap:8px"><button type="button" class="button">Set state ▾</button><button type="button" class="button">Assign ▾</button><button type="button" class="button">Suppress…</button><button type="button" class="button">Ask about this</button><button type="button" class="button" aria-label="More actions">⋯</button></div></header>
    <div class="view-pad" style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;padding-bottom:16px">
      ${tile('Starts matched', 41, 'last 2 min ago', 'bad')}${tile('Different commands', 2, '1 seen only once', 'warn')}${tile('First seen', '08:12', 'today', '')}${tile('Confidence', '80', 'web server parent, shell child', '')}
    </div>
    <div class="view-pad" style="display:grid;grid-template-columns:380px minmax(0,1fr);gap:24px;align-items:start;margin-bottom:60px">
      <div class="stack" style="gap:16px">
        ${card('What happened', '', '<div class="stack" style="gap:8px"><p style="margin:0">nginx, a web server, started a shell. Web servers rarely need one; it is how a web shell or an exploited bug usually runs commands.</p><p style="margin:0"><b>Check:</b> is the command expected (a health check, a script you know)? If it is, suppress that exact command. If not, isolate the host and look at the web logs around the first time it ran.</p></div>')}
        ${card('Details', '', kv([['Rule', '<span class="mono">web-server-spawns-shell</span> · v1'], ['Rule set', 'baseline v4'], ['Technique', '<a href="#">T1505.003 Web shell</a>'], ['Host', '<a href="17-host.html" class="mono">web-01</a> · Fedora 44'], ['User', '<span class="mono">www-data</span> (uid 33)']]))}
        ${card('History', '<a href="#" style="font-size:12.5px">All</a>', `<ul class="list list--plain" style="margin:0;padding:0">${[['Added to case C-104 by Sam Analyst', '1 h ago'], ['Assigned to Sam Analyst', '1 h ago'], ['First seen', 'today 08:12']].map(([a, d]) => `<li style="display:grid;gap:2px;padding:6px 0;border-bottom:1px solid var(--line)"><span>${a}</span><span class="subtle" style="font-size:12.5px">${d}</span></li>`).join('')}</ul>`)}
      </div>
      <div class="stack" style="gap:16px">
        ${card('Commands seen <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">2</span>', '<span class="subtle" style="font-size:12.5px">Each distinct command line, with how often it ran</span>',
          `<div class="table-wrap" style="margin:0;border:0;border-radius:0"><table class="table"><thead><tr><th>Command</th><th style="width:80px">Count</th><th style="width:150px">Last</th><th style="width:170px"></th></tr></thead><tbody>
          <tr><td class="mono" style="font-size:12.5px">sh -c /usr/local/bin/healthcheck</td><td class="num">40×</td><td>2 min ago</td><td><button type="button" class="button button--small">Suppress this command…</button></td></tr>
          <tr style="background:var(--warn-soft, #fff4dc)"><td class="mono" style="font-size:12.5px">sh -c id; uname -a <span class="badge badge--warn" style="font-family:inherit">Seen once</span></td><td class="num">1×</td><td>today 08:12</td><td><button type="button" class="button button--small">Add to case</button></td></tr></tbody></table></div>`, false)}
        ${card('Process chain', '<span class="subtle" style="font-size:12.5px">At the first time it ran</span>', `<div class="stack" style="gap:8px">${proc('/usr/lib/systemd/systemd', 'systemd --system', 'pid 1 · root')}${proc('/usr/sbin/nginx', 'nginx: worker process', 'pid 1102 · user www-data (33) · in /')}${proc('/usr/bin/sh', 'sh -c id; uname -a', 'pid 50877 · user www-data (33) · in /var/www', true)}</div>`)}
        ${card('Last 24 hours', '', `<div class="stack" style="gap:6px"><span style="display:flex;align-items:flex-end;gap:3px;height:48px">${hours.map(n => `<span style="flex:1;height:${n * 14 + 2}px;background:var(--bad);opacity:${n ? .75 : .15};border-radius:2px"></span>`).join('')}</span><span class="row row--between subtle" style="font-size:12px"><span>yesterday 15:00</span><span>about twice an hour since 08:12</span><span>now</span></span></div>`)}
        ${card('Related', '', `<div class="stack" style="gap:10px">
          <div class="row row--between"><span><b>Same host:</b> A shell downloaded a program <span class="subtle mono">bash → curl</span></span><span class="row" style="gap:8px"><span class="badge badge--medium">Medium · 1 h ago</span><a href="#" style="font-size:12.5px">Open</a></span></div>
          <div class="row row--between"><span><b>Same host:</b> Unexpected listening port 8081</span><span class="row" style="gap:8px"><span class="badge badge--medium">Medium · yesterday</span><a href="20-port.html" style="font-size:12.5px">Open</a></span></div>
          <div class="row row--between"><span><b>Vulnerability:</b> nginx request smuggling (CVE-2026-10112)</span><span class="row" style="gap:8px"><span class="badge badge--high">High · mx-01</span><a href="#" style="font-size:12.5px">Open</a></span></div>
          <div class="row row--between"><span><b>Same rule elsewhere:</b> none in the last 30 days</span></div></div>`)}
      </div>
    </div></div></div>`;
}
"""
screen(
    "29-alarms", "alarms",
    "<b>29 · Alarms.</b> Filters (Severity, State, Suppressed, Host, Group, Technique, Case, Assignee); each row adds the ATT&CK technique, the host's OS, first and last seen, assignee and case. The per-row Quiet… menu moves to the bulk bar (Suppress…) and the alarm's page. <b>Try it:</b> tick rows; filter; click an alarm.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + ALARMSUI + "liveAlarms({ filters: {}, q: '', open: null, sel: [] });",
)
screen(
    "30-alarm", "alarms",
    "<b>30 · An alarm's page.</b> In the shared layout: what happened and what to check, details and history on the left; every distinct command with its count (a rare one stands out, and the usual one can be suppressed right there), the process chain, the last 24 hours and related alarms and vulnerabilities on the right.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + ALARMSUI + "hostsActive('/alarms'); $('.topbar__title').textContent = 'Alarms'; $('.view-area').innerHTML = alarmPage();",
)

CASESUI = r"""
// ---- Cases list with filters, and a case's page ----
const K = [
  { id: 'C-104', title: 'Shells started by nginx on web-01', by: 'Sam Analyst', opened: '1 h ago', sev: 'High', status: 'Investigating', who: 'Sam Analyst', hosts: ['web-01'], items: { alarms: 2, vulns: 1, findings: 0 }, done: 1, total: 3, updated: '12 min ago', note: 'One command is the health check; sh -c id is not ours.' },
  { id: 'C-103', title: 'PostgreSQL started a shell on db-02', by: 'Sam Analyst', opened: '2 h ago', sev: 'Critical', status: 'Open', who: '', hosts: ['db-02'], items: { alarms: 1, vulns: 0, findings: 1 }, done: 0, total: 2, updated: '45 min ago', note: '' },
  { id: 'C-102', title: 'openssl known exploited on 2 hosts', by: 'Alex Admin', opened: 'yesterday', sev: 'Critical', status: 'Investigating', who: 'Wendy Ward', hosts: ['web-01', 'db-02'], items: { alarms: 0, vulns: 2, findings: 0 }, done: 1, total: 2, updated: '5 h ago', note: 'Update scheduled tonight for db-02.' },
  { id: 'C-101', title: 'PowerShell downloads on the file servers', by: 'Wendy Ward', opened: '3 days ago', sev: 'High', status: 'Open', who: 'Wendy Ward', hosts: ['win-file-07', 'win-file-08'], items: { alarms: 2, vulns: 0, findings: 1 }, done: 0, total: 3, updated: '1 day ago', note: '' },
  { id: 'C-100', title: 'Root SSH login on mail servers', by: 'Sam Analyst', opened: 'last week', sev: 'Medium', status: 'Closed', who: 'Sam Analyst', hosts: ['mx-01', 'mx-backup-03'], items: { alarms: 0, vulns: 0, findings: 2 }, done: 2, total: 2, updated: '2 days ago', note: 'Fixed on both; closed.' },
];
const KF = {
  Status: { opts: ['Open', 'Investigating', 'Closed'], test: (x, v) => x.status === v },
  Severity: { opts: ['Critical', 'High', 'Medium', 'Low'], test: (x, v) => x.sev === v },
  Assignee: { opts: ['Me', 'Unassigned', 'Sam Analyst', 'Wendy Ward'], test: (x, v) => v === 'Unassigned' ? !x.who : v === 'Me' ? false : x.who === v },
  Contains: { opts: ['Alarms', 'Vulnerabilities', 'Compliance findings'], test: (x, v) => (v === 'Alarms' ? x.items.alarms : v === 'Vulnerabilities' ? x.items.vulns : x.items.findings) > 0 },
  Host: { opts: () => [...new Set(K.flatMap(x => x.hosts))].sort(), test: (x, v) => x.hosts.includes(v) },
  Group: { opts: () => HG.map(g => g.name), test: (x, v) => membersOf(HG.find(g => g.name === v)).some(h => x.hosts.includes(h.name)) },
  Updated: { opts: ['Today', 'This week', 'Quiet for 7 days or more'], test: (x, v) => v === 'Today' ? /min|h ago/.test(x.updated) : v === 'This week' ? !/week/.test(x.updated) : /week/.test(x.updated) },
};
const sevK = (s) => `<span class="badge badge--${s === 'Critical' ? 'critical' : s === 'High' ? 'high' : s === 'Medium' ? 'medium' : 'low'}">${s}</span>`;
const stK = (s) => `<span class="badge ${s === 'Open' ? 'badge--bad' : s === 'Investigating' ? 'badge--warn' : 'badge--plain'}">${s}</span>`;
function casesList(st) {
  const rows = K.filter(x => Object.entries(st.filters).every(([k, v]) => KF[k].test(x, v)) && (st.filters.Status || x.status !== 'Closed') && (!st.q || (x.id + ' ' + x.title + ' ' + x.who).toLowerCase().includes(st.q.toLowerCase())));
  const kinds = (i) => [[i.alarms, 'alarm'], [i.vulns, 'vulnerability', 'vulnerabilities'], [i.findings, 'finding']].filter(([n]) => n).map(([n, a, b]) => `${n} ${n > 1 ? (b || a + 's') : a}`).join(' · ');
  const tr = rows.map(x => `<tr data-row="${x.id}" style="cursor:pointer"><td class="mono">${x.id}</td>
      <td><div class="cell-two"><span>${x.title}</span><span class="subtle">Opened by ${x.by}, ${x.opened}${x.note ? ` · <i>“${x.note}”</i>` : ''}</span></div></td>
      <td>${sevK(x.sev)}</td><td>${stK(x.status)}</td><td>${x.who || '<span class="subtle">Unassigned</span>'}</td>
      <td style="white-space:nowrap">${x.hosts.slice(0, 2).map(h => `<a href="17-host.html" class="mono" style="font-size:12.5px">${h}</a>`).join(', ')}</td>
      <td><div class="stack" style="gap:4px"><span style="font-size:12.5px;white-space:nowrap">${kinds(x.items)}</span><span class="row" style="gap:6px"><span style="height:5px;width:80px;border-radius:3px;background:var(--surface-2);overflow:hidden"><span style="display:block;height:100%;width:${100 * x.done / x.total}%;background:var(--ok)"></span></span><span class="subtle" style="font-size:12px;white-space:nowrap">${x.done}/${x.total} with an outcome</span></span></div></td>
      <td>${x.updated}</td></tr>`).join('');
  const live = K.filter(x => x.status !== 'Closed');
  return `<div class="view">
    <header class="view-pad" style="padding-top:20px;padding-bottom:8px"><div class="row row--between"><div><h1 style="margin:0">Cases <span class="subtle num" style="font-size:16px;font-weight:500">${rows.length}</span></h1><span class="subtle">${live.filter(x => x.status === 'Open').length} open · ${live.filter(x => x.status === 'Investigating').length} investigating · ${live.filter(x => !x.who).length} unassigned · ${live.reduce((n, x) => n + x.total - x.done, 0)} items need an outcome · closed cases hidden</span></div><button type="button" class="button button--primary button--small">+ New case</button></div></header>
    ${filterBar(KF, st, K, 'Search case, title or assignee…')}
    <div class="table-wrap" style="margin:0 24px 40px"><table class="table" aria-label="Cases"><thead><tr><th style="width:70px">Case</th><th>Title</th><th style="width:95px">Severity</th><th style="width:125px">Status</th><th style="width:120px">Assignee</th><th style="width:200px">Hosts</th><th style="width:240px">Items</th><th style="width:110px">Updated</th></tr></thead><tbody>${tr || '<tr><td colspan="8" class="subtle">No case matches these filters.</td></tr>'}</tbody></table></div></div>`;
}
function liveCases(st) {
  hostsActive('/cases'); $('.topbar__title').textContent = 'Cases';
  const render = (focus) => { $('.view-area').innerHTML = casesList(st); if (focus) { const i = $('[data-q]'); i.focus(); i.setSelectionRange(i.value.length, i.value.length); } };
  render(); liveFilters(st, render, () => { location.href = '32-case.html'; });
}
function casePage(st) {
  const card = (title, aside, body, pad = true) => `<section class="card" style="overflow:hidden"><div class="row row--between" style="padding:12px 16px;border-bottom:1px solid var(--line)"><h2 class="section-title" style="margin:0">${title}</h2>${aside || ''}</div><div style="${pad ? 'padding:14px 16px' : ''}">${body}</div></section>`;
  const kv = (rows) => `<dl class="kv" style="margin:0;row-gap:10px;grid-template-columns:110px minmax(0,1fr)">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
  const tile = (label, value, sub, tone) => `<div class="card card__body" style="display:grid;gap:4px"><span class="subtle">${label}</span><span style="font-size:26px;font-weight:650;${tone ? `color:var(--${tone})` : ''}">${value}</span><span class="subtle" style="font-size:12.5px">${sub}</span></div>`;
  const outcome = (i) => `<select class="input" data-outcome="${i}" style="height:30px;font-size:12.5px;width:170px">${['Needs an outcome', 'Confirmed malicious', 'Expected activity', 'False positive', 'Fixed'].map(o => `<option ${st.out[i] === o ? 'selected' : ''}>${o}</option>`).join('')}</select>`;
  const items = [['Alarm', 'A web server started a shell', '<span class="mono">nginx → sh</span> · 41×', 'High', '30-alarm.html'], ['Alarm', 'A shell downloaded a program and ran it', '<span class="mono">bash → curl</span> · 1×', 'Medium', '#'], ['Vulnerability', 'curl: heap overflow in SOCKS5 proxy handshake', 'CVE-2026-10042 · Exploited', 'High', '26-advisory.html']];
  const need = items.filter((_, i) => st.out[i] === 'Needs an outcome').length;
  const tl = [...st.notes.map(n => ['You', 'added a note', 'just now', n]), ['Sam Analyst', 'set the shell alarm to Confirmed malicious for sh -c id', '12 min ago', ''], ['Sam Analyst', 'added a note', '20 min ago', 'One command is the health check; sh -c id is not ours. Isolating web-01 from the internet while we look.'], ['Sam Analyst', 'added vulnerability CVE-2026-10042', '50 min ago', ''], ['Sam Analyst', 'started investigating', '55 min ago', ''], ['Sam Analyst', 'opened the case with 2 alarms', '1 h ago', '']];
  return `<div class="view"><div>
    <div class="view-pad" style="padding-top:20px"><span class="subtle"><a href="31-cases.html">Cases</a></span></div>
    <header class="view-pad" style="display:flex;gap:16px;align-items:center;padding-top:8px;padding-bottom:16px">
      <span style="display:grid;place-items:center;width:56px;height:56px;border-radius:14px;background:var(--accent-soft);color:var(--accent);font-weight:700;font-size:13px">C-104</span>
      <div class="stack grow" style="gap:4px"><div class="row" style="gap:10px"><h1 style="margin:0;font-size:22px">Shells started by nginx on web-01</h1>${sevK('High')}${stK('Investigating')}</div>
        <span class="subtle">Opened by Sam Analyst 1 h ago · assigned to Sam Analyst · 3 items on 1 host · updated 12 min ago</span></div>
      <div class="row" style="gap:8px"><button type="button" class="button">Edit</button><button type="button" class="button">Assign ▾</button><button type="button" class="button">Ask about this</button><button type="button" class="button button--primary">Close case…</button><button type="button" class="button" aria-label="More actions">⋯</button></div></header>
    <div class="view-pad" style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;padding-bottom:16px">
      ${tile('Items', 3, '2 alarms · 1 vulnerability', '')}${tile('Need an outcome', need, need ? 'set one on each item to close' : 'ready to close', need ? 'warn' : 'ok')}${tile('Hosts', 1, 'web-01', '')}${tile('Open for', '1 h', 'since 08:40', '')}
    </div>
    <div class="view-pad" style="display:grid;grid-template-columns:380px minmax(0,1fr);gap:24px;align-items:start;margin-bottom:60px">
      <div class="stack" style="gap:16px">
        ${card('Details', '', kv([['Case', '<span class="mono">C-104</span>'], ['Severity', sevK('High')], ['Status', stK('Investigating')], ['Assignee', 'Sam Analyst'], ['Opened', 'today 08:40 by Sam Analyst']]))}
        ${card('Hosts in this case', '', `<div class="stack" style="gap:10px"><div class="row row--between"><span class="stack" style="gap:2px"><a href="17-host.html" class="mono">web-01</a><span class="subtle" style="font-size:12.5px">Fedora 44 · 10.0.5.1 · online</span></span><span class="row" style="gap:6px"><span class="badge badge--bad">3 alarms</span><span class="badge badge--critical">1 critical</span></span></div></div>`)}
        ${card('Who can see it', '', '<span class="subtle">Everyone who can see web-01 (its alarms or vulnerabilities), plus the people it is assigned to.</span>')}
      </div>
      <div class="stack" style="gap:16px">
        ${card('Items <span class="subtle num" style="text-transform:none;letter-spacing:0;font-weight:500">3</span>', '<button type="button" class="button button--small">+ Add item</button>',
          `<div class="table-wrap" style="margin:0;border:0;border-radius:0"><table class="table"><thead><tr><th style="width:110px">Kind</th><th>Item</th><th style="width:100px">Severity</th><th style="width:100px">Host</th><th style="width:190px">Outcome</th><th style="width:40px"></th></tr></thead><tbody>${items.map(([k, t, sub, sv, href], i) => `<tr><td><span class="badge badge--plain">${k}</span></td><td><div class="cell-two"><a href="${href}">${t}</a><span class="subtle" style="font-size:12px">${sub}</span></div></td><td>${sevK(sv)}</td><td><a href="17-host.html" class="mono" style="font-size:12.5px">web-01</a></td><td>${outcome(i)}</td><td><button type="button" class="icon-button" aria-label="Remove from case" title="Remove from case">${ICON_X}</button></td></tr>`).join('')}</tbody></table></div>`, false)}
        ${card('Notes and timeline', '', `<div class="stack" style="gap:12px">
          <div class="stack" style="gap:8px"><textarea class="textarea" rows="2" data-note placeholder="What you found or decided. Everyone who can see this case can read it.">${esc(st.draft)}</textarea><div class="row" style="justify-content:flex-end"><button type="button" class="button button--primary button--small" data-addnote ${st.draft.trim() ? '' : 'disabled'}>Add note</button></div></div>
          <ul class="list list--plain" style="margin:0;padding:0">${tl.map(([w, a, d, note]) => `<li style="display:grid;gap:4px;padding:10px 0;border-top:1px solid var(--line)"><span><b>${w}</b> ${a} <span class="subtle" style="font-size:12.5px">· ${d}</span></span>${note ? `<div style="padding:8px 12px;background:var(--surface-2);border-radius:var(--r-1)">${esc(note)}</div>` : ''}</li>`).join('')}</ul></div>`)}
      </div>
    </div></div></div>`;
}
function liveCase() {
  const st = { out: ['Confirmed malicious', 'Needs an outcome', 'Needs an outcome'], draft: '', notes: [] };
  hostsActive('/cases'); $('.topbar__title').textContent = 'Cases';
  const render = (focus) => { const v = $('.view-area'); const top = v.scrollTop; v.innerHTML = casePage(st); v.scrollTop = top; if (focus) { const t = $('[data-note]'); t.focus(); t.setSelectionRange(t.value.length, t.value.length); } };
  render();
  document.addEventListener('change', (e) => { if (e.target.dataset.outcome) { st.out[Number(e.target.dataset.outcome)] = e.target.value; render(); } });
  document.addEventListener('input', (e) => { if (e.target.dataset.note !== undefined) { st.draft = e.target.value; render(true); } });
  document.addEventListener('click', (e) => { if (e.target.closest('[data-addnote]') && st.draft.trim()) { st.notes.unshift(st.draft.trim()); st.draft = ''; render(); } });
}
"""
screen(
    "31-cases", "cases",
    "<b>31 · Cases.</b> The eleven toggles become filters (Status, Severity, Assignee, Contains, Host, Group, Updated; closed hidden by default); each row adds the latest note, the hosts, what the items are and how many have an outcome. <b>Try it:</b> filter, then click a case.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + CASESUI + "liveCases({ filters: {}, q: '', open: null });",
)
screen(
    "32-case", "cases",
    "<b>32 · A case's page.</b> C-104 in the shared layout: details, its hosts and who can see it on the left; items with an outcome each, and notes with the timeline on the right. <b>Try it:</b> set an outcome on each item (the tile counts down), add a note.",
    PEOPLE + HOSTGROUPS + HOSTSUI + PORTSUI + CASESUI + "liveCase();",
)

slugs = [s[0] for s in SCREENS]
for i, (slug, base, caption, script) in enumerate(SCREENS):
    back = f'<a href="/files/{slugs[i-1]}.html">← Back</a>' if i else '<span style="opacity:.4">← Back</span>'
    nxt = f'<a href="/files/{slugs[i+1]}.html">Next →</a>' if i + 1 < len(slugs) else '<span style="opacity:.4">Next →</span>'
    bar = f'<span style="flex:1">{caption}</span><span style="white-space:nowrap;display:flex;gap:14px">{back}{nxt}</span>'
    doc = f"""<!DOCTYPE html><html lang="en" data-theme-preference="system"><head><meta charset="utf-8"><title>{slug}</title>
<style>{CSS}</style>
<style>.mock-caption{{display:flex;gap:18px;align-items:center;position:fixed;left:0;right:0;bottom:0;z-index:9999;background:#0b3a57;color:#e8f4ff;font:14px/1.45 system-ui,sans-serif;padding:10px 18px;border-top:2px solid #4fb3e8}} .mock-caption a{{color:#9fdcff;font-weight:600;text-decoration:none}} .view-area,.inspector__scroll{{padding-bottom:44px}} .chip{{white-space:nowrap}} .input:disabled{{background:var(--surface-2);color:var(--text-2);cursor:not-allowed}}</style>
</head><body>{BASES[base]}
<div class="mock-caption">{bar}</div>
<script>const CATALOGUE = {json.dumps(CATALOGUE)}; const COLUMNS = {json.dumps(COLUMNS)}; const TEMPLATE_PERMS = {json.dumps(TEMPLATE_PERMS)}; const TEMPLATES = {json.dumps(TEMPLATES)}; const WINDOWS_LEAD = {json.dumps(WINDOWS_LEAD)}; const NEEDS = {json.dumps(NEEDS)}; const ICON_SEARCH = {json.dumps(ICONS['search'])}; const ICON_X = {json.dumps(ICONS['x'])}; const ICON_INFO = {json.dumps(ICONS['info'])}; const ICON_CHECK = {json.dumps(ICONS['check'])}; const GROUPS = {json.dumps(GROUPS)}; const PLATFORM = new Set({json.dumps(PLATFORM)});
{HELPERS}
{script}
</script></body></html>"""
    for out in outs:
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{slug}.html").write_text(doc)
print(f"{len(SCREENS)} screens")
