import sys

sys.path.insert(0, sys.argv[1])
from gen import ask, bar, header, menu, page, screen  # noqa: E402

ACTS = [("Restart", "agents reconnect within a minute"),
        ("Stop", "agents keep their findings until it runs"),
        ("Full log", "every line, newest at the bottom")]
LOG = ["    {b}Recent log{/}",
       "    {d}19:12:44{/}  {y}WARN{/}  agent web-02: certificate renewal refused",
       "    {d}20:14:09{/}  INFO  delivered 340 findings from 12 agents"]


def svc(sel, bar_lines):
    body = [header("Service: ingest"), "",
            "    {g}●{/} running · ready · since 18:40 · 12 agents online", ""] + menu(ACTS, sel) + [""] + LOG
    return screen("limebox · Status › ingest", body, bar_lines)


def status():
    body = [header("Status"), "",
            "    {y}▲{/} Certificate for limebox expires in 21 days", "",
            "    {b}Services{/}                                           {d}8 of 8 running{/}",
            "  {s}▸ {g}●{/}{s} ingest          running   ready    since 18:40                      {/}", "",
            "    {g}●{/} console         running   ready    since 18:40", "",
            "    {g}●{/} vulns           running   ready    since 18:40",
            "    {d}↓ 5 more{/}"]
    return screen("limebox · Status", body, bar("{k} Enter {/} Open ingest"))


print(page("A service's actions on its own screen",
           "No pop-up box: Enter on a service opens its screen; the actions are entries there. "
           "Reply per number: yes, or what to change.", [
    ("Status: highlight on ingest", "As before.", status()),
    ("Enter: Service: ingest", "Its state, its actions as entries, its latest log lines.",
     svc(0, bar("{k} Enter {/} Restart ingest"))),
    ("↓ once: Stop", "The bar follows the highlight.", svc(1, bar("{k} Enter {/} Stop ingest"))),
    ("Enter on Restart: the question", "←→ Yes / No, Enter to answer.",
     svc(0, ask("Restart ingest?", "agents reconnect"))),
]))
