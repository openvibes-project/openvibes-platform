import sys

sys.path.insert(0, sys.argv[1])
from gen import ask, bar, page, screen  # noqa: E402

home = screen("limebox · v0.2.8", [
    "",
    "        {g}●{/} All 8 services running   {y}▲{/} Certificate expires in 21 days",
    "",
    "",
    "     {s}▸  Status          health, services, logs              {/}",
    "",
    "        Settings        {d}how each service works{/}",
    "",
    "        Agents          {d}hosts, routers, enrollment{/}",
    "",
    "        Maintenance     {d}update, repair, backup, database{/}",
    "",
    "        Quit",
], bar("{k} Enter {/} Open", "{k} q {/} Quit  {k} ? {/}"))

status = screen("Status", [
    "",
    "   {b}Needs attention{/}",
    " {s}▸ {y}▲{/}{s} Certificate for limebox expires in 21 days                    {/}",
    "",
    "   {b}Services{/}                                            {d}8 of 8 running{/}",
    "   {g}●{/} ingest          running   ready    {d}since 18:40{/}",
    "   {g}●{/} console         running   ready    {d}since 18:40{/}",
    "   {g}●{/} vulns           running   ready    {d}since 18:40{/}",
    "   {g}●{/} netlog          running   ready    {d}since 18:40{/}",
    "   {g}●{/} distribution    running   ready    {d}since 18:40{/}",
    "   {d}… 3 more{/}",
    "",
    "   {b}Checks{/}   {g}●{/} disk 41%   {g}●{/} rules v4   {g}●{/} feeds   {g}●{/} database",
], bar("{k} Enter {/} Renew certificate"))

ingest = screen("Status › ingest", [
    "",
    "   {g}●{/} {b}ingest{/}  running · ready · since 18:40 · starts at boot",
    "     {d}Agent connections on port 18423 · 12 agents online{/}",
    "",
    "   {b}Recent log{/}                                         {d}newest at the bottom{/}",
    "   {d}18:40:02{/}  INFO  listening on 0.0.0.0:18423",
    "   {d}18:40:02{/}  INFO  database ready, schema 46",
    "   {d}19:12:44{/}  {y}WARN{/}  agent web-02: certificate renewal refused",
    "   {d}20:14:09{/}  INFO  delivered 340 findings from 12 agents",
], bar("{k} r {/} Restart  {k} s {/} Stop  {k} b {/} Not at boot  {k} l {/} Full log"))

ingest_confirm = screen("Status › ingest", [
    "",
    "   {g}●{/} {b}ingest{/}  running · ready · since 18:40 · starts at boot",
    "     {d}Agent connections on port 18423 · 12 agents online{/}",
    "",
    "   {b}Recent log{/}                                         {d}newest at the bottom{/}",
    "   {d}18:40:02{/}  INFO  listening on 0.0.0.0:18423",
    "   {d}18:40:02{/}  INFO  database ready, schema 46",
    "   {d}19:12:44{/}  {y}WARN{/}  agent web-02: certificate renewal refused",
    "   {d}20:14:09{/}  INFO  delivered 340 findings from 12 agents",
], ask("Restart ingest?", "Agents reconnect within a minute"))

settings = screen("Settings", [
    "",
    "",
    "     {s}▸  Console              web address, sign-in, assistant      {/}",
    "",
    "        Agent connections    {d}limits, timeouts, how long kept{/}",
    "",
    "        Rule distribution    {d}limits, timeouts{/}",
    "",
    "        Vulnerabilities      {d}feeds, proxy, how often to check{/}",
    "",
    "        Network devices      {d}port, how alarms are grouped{/}",
    "",
    "        Admin                {d}database connection{/}",
], bar("{k} Enter {/} Open"))

vulns = screen("Settings › Vulnerabilities", [
    "",
    "   {b}Feeds{/}",
    "     How often to check         every 60 minutes",
    "     Fedora mirror list         {d}mirrors.fedoraproject.org/…{/}",
    " {s}▸   Proxy                      none                                    {/}",
    "     NVD API key                {d}not set (slower lookups){/}",
    "",
    "   {b}Enrichment{/}",
    "     Known exploited (CISA)     on",
    "     Exploit likelihood (EPSS)  on",
    "",
    "   {d}Proxy for every feed download, e.g. http://proxy.example:3128.{/}",
    "   {d}Empty: connect directly.{/}",
], bar("{k} Enter {/} Change"))

vulns_edit = screen("Settings › Vulnerabilities", [
    "",
    "   {b}Feeds{/}",
    "     How often to check         every 60 minutes",
    "     Fedora mirror list         {d}mirrors.fedoraproject.org/…{/}",
    " {s}▸   Proxy                      http://proxy.lan:3128█                  {/}",
    "     NVD API key                {d}not set (slower lookups){/}",
    "",
    "   {b}Enrichment{/}",
    "     Known exploited (CISA)     on",
    "     Exploit likelihood (EPSS)  on",
    "",
    "   {d}Proxy for every feed download, e.g. http://proxy.example:3128.{/}",
    "   {d}Empty: connect directly.{/}",
], bar("{b}Editing Proxy{/}  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False))

vulns_save = screen("Settings › Vulnerabilities", [
    "",
    "   {b}Feeds{/}",
    "     How often to check         every 60 minutes",
    "     Fedora mirror list         {d}mirrors.fedoraproject.org/…{/}",
    " {s}▸ {y}*{/}{s} Proxy                      http://proxy.lan:3128                   {/}",
    "     NVD API key                {d}not set (slower lookups){/}",
    "",
    "   {b}Enrichment{/}",
    "     Known exploited (CISA)     on",
    "     Exploit likelihood (EPSS)  on",
    "",
    "   {y}1 unsaved change:{/} Proxy  none → http://proxy.lan:3128",
], bar("{k} w {/} Save and restart vulns  {k} u {/} Undo"))

print(page(
    "TUI mockups: full screens at real size (80×24)",
    "1–4 are the screens you already said yes to, now drawn properly. "
    "5–8 are new: Settings. Tell me in the terminal: yes, or what to change, per number.",
    [
        ("Home (approved)", "After install. ↑↓ moves the highlight.", home),
        ("Status (approved)", "Problems first; Enter on the highlighted line acts on it.", status),
        ("Status › ingest (approved)", "Enter on a service.", ingest),
        ("Restart question (approved)", "After pressing r: the bar asks.", ingest_confirm),
        ("Settings (new)", "One entry per service, in plain words.", settings),
        ("Settings › Vulnerabilities (new)", "Grouped settings with plain names; the help for the highlighted one below.", vulns),
        ("Editing a setting (new)", "Enter: the value is edited in place.", vulns_edit),
        ("After a change (new)", "The bar offers to save and restart in one step; * marks the changed setting.", vulns_save),
    ]))
