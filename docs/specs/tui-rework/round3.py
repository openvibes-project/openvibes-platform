import sys

sys.path.insert(0, sys.argv[1])
from gen import ask, bar, page, screen  # noqa: E402


def status(sel):
    """Status with the highlight on row `sel` (0 = certificate, 1.. = services)."""
    services = [("ingest", ""), ("console", ""), ("vulns", ""), ("netlog", ""), ("distribution", "")]
    rows = []
    cert = "   {y}▲{/} Certificate for limebox expires in 21 days"
    rows.append(" {s}▸ {y}▲{/}{s} Certificate for limebox expires in 21 days                    {/}" if sel == 0 else cert)
    body = ["", "   {b}Needs attention{/}", rows[0], "",
            "   {b}Services{/}                                            {d}8 of 8 running{/}"]
    for i, (name, note) in enumerate(services, 1):
        text = f"{name:<15} running   ready    since 18:40   {note:<10}"
        if i == sel:
            body.append(" {s}▸ {g}●{/}{s} " + text + "        {/}")
        else:
            body.append("   {g}●{/} " + text.replace("since 18:40", "{d}since 18:40{/}"))
    body.append("   {d}… 3 more{/}")
    return body


status_cert = screen("limebox · Status", status(0), bar("{k} Enter {/} Renew certificate"))
status_ingest = screen("limebox · Status", status(1),
                       bar("{k} Enter {/} Open  {k} r {/} Restart  {k} s {/} Stop"))
status_stop = screen("limebox · Status", status(1),
                     ask("Stop ingest?", "Agents keep their findings until it runs"))
status_stopped = screen("limebox · Status", [
    "", "   {b}Needs attention{/}",
    " {s}▸ {r}■{/}{s} ingest is stopped · agents cannot deliver                      {/}",
    "   {y}▲{/} Certificate for limebox expires in 21 days",
    "", "   {b}Services{/}                                            {d}7 of 8 running{/}",
    "   {r}■{/} ingest          {r}stopped{/}   –        {d}since 20:31{/}",
    "   {g}●{/} console         running   ready    {d}since 18:40{/}",
    "   {g}●{/} vulns           running   ready    {d}since 18:40{/}",
    "   {d}… 5 more{/}",
], bar("{k} Enter {/} Start ingest"))

ingest = screen("limebox · Status › ingest", [
    "",
    "   {t}━━{/} {b}Service: ingest{/} {t}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{/}",
    "   {g}●{/} running · ready · since 18:40",
    "   {d}Agent connections on port 18423 · 12 agents online{/}",
    "",
    "   {b}Recent log{/}                                         {d}newest at the bottom{/}",
    "   {d}18:40:02{/}  INFO  listening on 0.0.0.0:18423",
    "   {d}18:40:02{/}  INFO  database ready, schema 46",
    "   {d}19:12:44{/}  {y}WARN{/}  agent web-02: certificate renewal refused",
    "   {d}20:14:09{/}  INFO  delivered 340 findings from 12 agents",
], bar("{k} l {/} Full log"))

print(page(
    "Status and a service: your changes",
    "Service actions now live on Status, in the bar, when a service is highlighted. "
    "The service screen only shows the service. No boot switch anywhere.",
    [
        ("Status: highlight on the certificate", "The bar offers what this line can do.", status_cert),
        ("Status: highlight on ingest", "Moved down one: the bar changes to the service's actions.", status_ingest),
        ("Status: after pressing s", "Stop asks first and says what stops working.", status_stop),
        ("Status: ingest stopped", "A stopped service is a problem at the top, with Enter to start it.", status_stopped),
        ("Service: ingest (after Enter)", "A clear header says which service you are in; only its log and Back.", ingest),
    ]))
