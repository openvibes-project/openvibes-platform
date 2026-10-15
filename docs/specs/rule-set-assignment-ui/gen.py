#!/usr/bin/env python3
"""Rule-set assignment console mockups: real console pages (captured from the
demo build) with the new parts edited in by a small script per screen.

Usage: gen.py BASE_DIR OUT_DIR [OUT_DIR...]
BASE_DIR holds base-settings-rulesets.json and base-host-details.json
(captured body HTML) and console.css (the demo build's stylesheet)."""
import json
import sys
from pathlib import Path

base_dir = Path(sys.argv[1])
outs = [Path(p) for p in sys.argv[2:]]
host = json.loads((base_dir / "base-host-details.json").read_text())
settings = json.loads((base_dir / "base-settings-rulesets.json").read_text())
CSS = (base_dir / "console.css").read_text()


def inline_brand(html):
    """The logos load from the console's /brand/; embed them so the pages stand alone."""
    import base64
    for svg in (base_dir / "brand").glob("*.svg"):
        uri = "data:image/svg+xml;base64," + base64.b64encode(svg.read_bytes()).decode()
        html = html.replace(f'src="/brand/{svg.name}"', f'src="{uri}"')
    return html


host["html"] = inline_brand(host["html"])
settings["html"] = inline_brand(settings["html"])  # the built stylesheet, verbatim

# Shared helpers available to every screen's edit script.
HELPERS = r"""
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const h = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; };
const sw = (label, on, extra = '') => `<button type="button" role="switch" aria-checked="${on}" class="switch" ${extra}><span class="switch__label">${label}</span><span class="switch__track" aria-hidden="true"><span class="switch__knob"></span></span></button>`;
const swOnly = (on, label) => `<button type="button" role="switch" aria-checked="${on}" aria-label="${label}" class="switch" style="width:auto"><span class="switch__track" aria-hidden="true"><span class="switch__knob"></span></span></button>`;
function ruleSetsTable() {
  const t = $('table[aria-label="Rule sets"]');
  $$('td .mono', t).forEach(e => e.classList.add('nowrap'));
  const head = $('thead tr', t);
  head.lastElementChild.before(h('<th style="width: 170px;">Runs on</th>'));
  const rows = {
    'baseline': ['All hosts'],
    'baseline-alarms': ['Linux'],
    'site': ['Hosts that trust its key'],
  };
  $$('tbody tr', t).forEach(tr => {
    const id = tr.querySelector('td .mono').textContent;
    tr.lastElementChild.before(h(`<td>${rows[id][0]}</td>`));
  });
  const alarms = $$('tbody tr', t).find(tr => tr.textContent.includes('baseline-alarms'));
  const site = $$('tbody tr', t).find(tr => tr.textContent.includes('site'));
  site.before(h(`<tr data-index="2"><td><span class="mono nowrap">hardening-linux-l1</span></td><td class="num"><span class="num">4</span></td><td><span class="mono subtle">openvibes-1</span></td><td><span class="subtle"><time class="nowrap">in 11 mo</time></span></td><td class="nowrap">Linux <span class="subtle">· 1 group off</span></td><td><span class="badge badge--ok">Active</span></td></tr>`));
  site.before(h(`<tr data-index="3"><td><span class="mono nowrap">hardening-linux-l2</span></td><td class="num"><span class="subtle">—</span></td><td><span class="subtle">—</span></td><td><span class="subtle">—</span></td><td class="nowrap">Off <span class="subtle">· 1 group on</span></td><td><span class="badge badge--plain">Not published</span></td></tr>`));
  $$('.view-header__title').forEach(e => { if (e.querySelector('h1')?.textContent === 'Rule sets') e.querySelector('.view-header__count').textContent = '5'; });
  return t;
}
function select(id) {
  $$('table[aria-label="Rule sets"] tbody tr').forEach(tr => {
    const on = tr.querySelector('td .mono').textContent === id;
    if (on) { tr.setAttribute('aria-selected', 'true'); tr.setAttribute('data-cursor', 'true'); }
    else { tr.removeAttribute('aria-selected'); tr.removeAttribute('data-cursor'); }
  });
}
function rulePanel({ id, badges, kv, note, where }) {
  $('.crumbs__current').textContent = id;
  $('.panel-header__title').textContent = id;
  $('.panel-header__badges').innerHTML = badges;
  const body = $('.inspector .panel-body');
  body.innerHTML = `<dl class="kv">${kv}</dl>` + (note ? `<p class="subtle">${note}</p>` : '');
  const versions = $('.inspector .panel-section--flush');
  body.append(h(`<section class="panel-section"><div class="panel-section__head"><h3 class="section-title">Where it runs</h3></div>${where}</section>`));
  if (id.endsWith('l2')) versions.remove();
  else $('tbody', versions).innerHTML = `<tr><td class="num">4<span class="badge badge--ok" style="margin-left: 8px;">Current</span></td><td><time class="nowrap">3 days ago</time></td><td>setup</td><td class="num subtle">21.3 KiB</td></tr>`;
}
const overrides = (rows, extra = '') => `<table class="table table--compact" aria-label="Group overrides"><thead><tr><th>Group</th><th>Matches</th><th class="num">Hosts</th><th class="num">Runs</th></tr></thead><tbody>${rows}${extra}</tbody></table>`;
const ovRow = (name, sel, hosts, on) => `<tr><td>${name}</td><td><span class="tag">${sel}</span></td><td class="num subtle">${hosts}</td><td class="num"><span class="row" style="justify-content:flex-end;gap:6px">${swOnly(on, name + ': runs ' + (on ? 'on' : 'off'))}<button type="button" class="icon-button" aria-label="Remove ${name}" title="Remove: ${name} follows the default again"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"><path d="M18 6 6 18M6 6l12 12"></path></svg></button></span></td></tr>`;
function hostPanel({ name, agent, tags, hardening, hardeningNote, sets }) {
  $$('.crumbs__current').forEach(e => e.textContent = name);
  $('.panel-header__title').textContent = name;
  $$('dd').forEach(dd => { if (dd.textContent === 'api-01.lab.example.test') dd.textContent = name; });
  $$('dd').forEach(dd => { if (dd.textContent === 'agent-00001') dd.textContent = agent; });
  $$('.panel-header + *, .mono').forEach(e => { if (e.textContent === 'agent-00001' && !e.closest('table')) e.textContent = agent; });
  $$('tbody tr').forEach(tr => {
    const on = tr.textContent.includes(name);
    if (on) { tr.setAttribute('aria-selected', 'true'); tr.setAttribute('data-cursor', 'true'); }
    else { tr.removeAttribute('aria-selected'); tr.removeAttribute('data-cursor'); }
  });
  const ta = $$('dt').find(d => d.textContent === 'Threat alarms');
  ta.nextElementSibling.after(h(`<dt>Hardening</dt>`), h(`<dd>${hardening}</dd>`));
  const dd2 = ta.nextElementSibling.nextElementSibling.nextElementSibling;
  if (hardeningNote) dd2.after(h(`<dd style="grid-column: 1 / -1">${hardeningNote}</dd>`));
  const list = $('ul[aria-label="Rule sets on this host"]');
  list.innerHTML = sets;
  const tagIn = $('input[aria-label="Tags as key=value pairs"]'); if (tagIn) tagIn.value = tags;
}
"""

SCREENS = []


def screen(slug, base, caption, script, scroll=None):
    SCREENS.append((slug, base, caption, script, scroll))


L1_KV = '<dt>Signed by</dt><dd class="mono">openvibes-1</dd><dt>Expires</dt><dd><time class="nowrap">in 11 mo</time> · 9 Oct 2027</dd><dt>Source</dt><dd>OpenVIBES rules package <span class="subtle">(43 checks, Level 1)</span></dd>'
L2_KV = '<dt>Source</dt><dd>OpenVIBES rules package <span class="subtle">(Level 2: stricter, may affect services)</span></dd>'
EXPLAIN = '<p class="subtle">A host runs it when any of its groups has it on; otherwise when the default is on. Hosts follow on their next scan. Switching it off ends that host\'s findings from this set (their triage stays).</p>'

screen(
    "1-rule-sets", settings,
    "1 · Settings › Rule sets. The two hardening sets are listed, with a new <b>Runs on</b> column. Click <b>hardening-linux-l1</b>.",
    "ruleSetsTable(); select(''); $('aside.inspector').remove();",
)
screen(
    "2-l1-panel", settings,
    "2 · Clicked hardening-linux-l1. New section <b>Where it runs</b>: the default switch, then groups that differ from it. Production has it off.",
    "ruleSetsTable(); select('hardening-linux-l1'); rulePanel({id:'hardening-linux-l1', badges:'<span class=\"badge badge--accent badge--plain\">version 4</span>', kv:L1_KV, note:'', where:"
    "`<div class=\"stack\">${sw('On for Linux hosts by default', true)}<p class=\"subtle\">Runs on <b>162</b> Linux hosts · off on <b>24</b>.</p>${overrides(ovRow('Production','env=prod',24,false))}<div class=\"row\"><button class=\"button button--small\" type=\"button\">+ Add group</button></div>${EXPLAIN}</div>`});",
)
L2_NOTE = '<div style="display:block;border:1px solid var(--line-strong);border-radius:8px;padding:10px 12px"><b>Not available yet.</b> <span class="subtle">This platform has no L2 set yet: it comes with a later rules package. Switches you set now are kept and apply when it is published.</span></div>'
screen(
    "3-l2-panel", settings,
    "3 · Clicked hardening-linux-l2. It is not published yet: the panel says so, and the switches can be set ahead. Default off. Click <b>+ Add group</b>.",
    "ruleSetsTable(); select('hardening-linux-l2'); rulePanel({id:'hardening-linux-l2', badges:'<span class=\"badge badge--plain\">Not published</span>', kv:L2_KV, note:'', where:"
    "`<div class=\"stack\">" + L2_NOTE.replace('`', '') + "${sw('On for Linux hosts by default', false)}<p class=\"subtle\">No group differs from the default.</p><div class=\"row\"><button class=\"button button--small\" type=\"button\">+ Add group</button></div>${EXPLAIN}</div>`});",
)
ADD_FORM = ('<tr><td><select class="select select--small" aria-label="Group"><option>Lab</option><option>Production</option></select></td>'
            '<td><span class="tag">env=lab</span></td><td class="num subtle">31</td>'
            '<td class="num"><div class="seg" role="radiogroup" aria-label="Runs"><button class="seg__opt" role="radio" aria-checked="true" type="button">On</button><button class="seg__opt" role="radio" aria-checked="false" type="button">Off</button></div></td></tr>')
screen(
    "4-add-group", settings,
    "4 · Clicked + Add group. A new row: pick the group (only groups not listed yet), On or Off (the opposite of the default is preselected). Click <b>Add</b>.",
    "ruleSetsTable(); select('hardening-linux-l2'); rulePanel({id:'hardening-linux-l2', badges:'<span class=\"badge badge--plain\">Not published</span>', kv:L2_KV, note:'', where:"
    "`<div class=\"stack\">" + L2_NOTE + "${sw('On for Linux hosts by default', false)}${overrides('', '" + ADD_FORM + "')}<div class=\"row\"><button class=\"button button--small button--primary\" type=\"button\">Add</button><button class=\"button button--small\" type=\"button\">Cancel</button></div>${EXPLAIN}</div>`});",
)
screen(
    "5-added", settings,
    "5 · Added. Lab now has L2 on (it will run there once published). The change is in the audit log. Each row's switch changes it in place; × removes the row, so that group follows the default again.",
    "ruleSetsTable(); select('hardening-linux-l2'); rulePanel({id:'hardening-linux-l2', badges:'<span class=\"badge badge--plain\">Not published</span>', kv:L2_KV, note:'', where:"
    "`<div class=\"stack\">" + L2_NOTE + "${sw('On for Linux hosts by default', false)}${overrides(ovRow('Lab','env=lab',31,true))}<div class=\"row\"><button class=\"button button--small\" type=\"button\">+ Add group</button></div>${EXPLAIN}</div>`});"
    "$('.toasts').style.bottom = '64px'; $('.toasts').innerHTML = '<div class=\"toast\">hardening-linux-l2 is now on for Lab</div>';",
)
SETS_PROD = ('<li class="list__row list__row--static"><span class="mono">baseline</span><span class="grow"></span><span class="mono subtle nowrap">v14</span><span class="subtle nowrap">expires 14 Nov 2026</span></li>'
             '<li class="list__row list__row--static"><span class="mono">baseline-alarms</span><span class="grow"></span><span class="mono subtle nowrap">v10</span><span class="subtle nowrap">expires 4 Dec 2026</span></li>'
             '<li class="list__row list__row--static"><span class="mono">hardening-linux-l1</span><span class="grow"></span><span class="badge badge--plain" title="Switched off for Production">Not assigned</span><span class="subtle nowrap">off for Production</span></li>')
screen(
    "6-host-prod", host,
    "6 · Hosts › a Production host › Details. New line <b>Hardening</b> beside Threat alarms. L1 is off here because Production has it off; its rule-set row says <b>Not assigned</b>, and its findings have ended.",
    "hostPanel({name:'api-02.prod.example.test', agent:'agent-00015', tags:'env=prod role=web', hardening:'L1 off <span class=\"subtle\">(Production)</span> · L2 off', sets:`" + SETS_PROD + "`});",
    485,
)
SETS_LAB = ('<li class="list__row list__row--static"><span class="mono">baseline</span><span class="grow"></span><span class="mono subtle nowrap">v14</span><span class="subtle nowrap">expires 14 Nov 2026</span></li>'
            '<li class="list__row list__row--static"><span class="mono">baseline-alarms</span><span class="grow"></span><span class="mono subtle nowrap">v10</span><span class="subtle nowrap">expires 4 Dec 2026</span></li>'
            '<li class="list__row list__row--static"><span class="mono">hardening-linux-l1</span><span class="grow"></span><span class="mono subtle nowrap">v4</span><span class="subtle nowrap">expires 9 Oct 2027</span></li>')
screen(
    "7-host-lab", host,
    "7 · A Lab host. L1 runs by default; L2 is on for Lab but not published yet, so the line says it waits. (Right after a switch, before the host's next scan, it says <b>pending</b> instead.)",
    "hostPanel({name:'api-01.lab.example.test', agent:'agent-00001', tags:'env=lab', hardening:'L1 on · L2 on <span class=\"subtle\">(Lab) · waits until published</span>', sets:`" + SETS_LAB + "`});",
    485,
)
FACTS_NOTE = '<span class="badge badge--warn badge--plain">Hardening facts unavailable</span> <span class="subtle">The agent\'s root-facts helper has not reported for 3 days (openvibes-agent-facts.timer), so checks that read root-only files show as unavailable, not failed.</span>'
screen(
    "8-host-facts", host,
    "8 · A host whose root-facts helper stopped. The Hardening line keeps the state and adds why some checks cannot run.",
    "hostPanel({name:'api-04.lab.example.test', agent:'agent-00043', tags:'env=lab', hardening:'L1 on · L2 on <span class=\"subtle\">(Lab) · waits until published</span>', hardeningNote:`" + FACTS_NOTE + "`, sets:`" + SETS_LAB + "`});",
    485,
)

slugs = [x[0] for x in SCREENS]
for i, (slug, base, caption, script, scroll) in enumerate(SCREENS):
    back = f'<a href="/files/{slugs[i-1]}.html">← Back</a>' if i else '<span style="opacity:.4">← Back</span>'
    nxt = f'<a href="/files/{slugs[i+1]}.html">Next →</a>' if i + 1 < len(slugs) else '<span style="opacity:.4">Next →</span>'
    caption = f'<span style="flex:1">{caption}</span><span style="white-space:nowrap;display:flex;gap:14px">{back}{nxt}</span>'
    scroll_js = f"const s=document.querySelector('.inspector__scroll'); if(s) s.scrollTop={scroll};" if scroll else ""
    doc = f"""<!DOCTYPE html><html lang="en" data-theme-preference="system"><head><meta charset="utf-8"><title>{slug}</title>
<style>{CSS}</style>
<style>.mock-caption{{display:flex;gap:18px;align-items:center;position:fixed;left:0;right:0;bottom:0;z-index:9999;background:#0b3a57;color:#e8f4ff;font:14px/1.45 system-ui,sans-serif;padding:10px 18px;border-top:2px solid #4fb3e8}} .mock-caption a{{color:#9fdcff;font-weight:600;text-decoration:none}}</style>
</head><body>{base['html']}
<div class="mock-caption">{caption}</div>
<script>{HELPERS}
const L1_KV = {json.dumps(L1_KV)}; const L2_KV = {json.dumps(L2_KV)}; const EXPLAIN = {json.dumps(EXPLAIN)};
{script}
{scroll_js}
</script></body></html>"""
    for out in outs:
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{slug}.html").write_text(doc)
print(f"{len(SCREENS)} screens")
