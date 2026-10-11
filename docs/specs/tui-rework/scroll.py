import sys

sys.path.insert(0, sys.argv[1])
from gen import bar, page, screen  # noqa: E402

SERVICES = [("ingest", "running", "ready"), ("console", "running", "ready"),
            ("vulns", "running", "ready"), ("netlog", "running", "ready"),
            ("distribution", "running", "ready"), ("signer", "running", "ready"),
            ("llm", "idle", "–"), ("maintenance", "waiting", "–")]
SHOWN = 5


def status(sel, top):
    """Highlight on service `sel`; the list shows SHOWN rows from `top`."""
    body = ["", "   {b}Needs attention{/}",
            "   {y}▲{/} Certificate for limebox expires in 21 days", "",
            "   {b}Services{/}                                            {d}8 of 8 running{/}"]
    body.append(f"   {{d}}↑ {top} more{{/}}" if top else "")
    for i in range(top, top + SHOWN):
        name, state, ready = SERVICES[i]
        since = "since 18:40" if state == "running" else ("starts on use" if name == "llm" else "next 03:00")
        text = f"{name:<15} {state:<9} {ready:<8} "
        if i == sel:
            body.append(" {s}▸ {g}●{/}{s} " + text + f"{since:<14}" + " " * 18 + "{/}")
        else:
            body.append("   {g}●{/} " + text + "{d}" + since + "{/}")
    rest = len(SERVICES) - top - SHOWN
    body.append(f"   {{d}}↓ {rest} more{{/}}" if rest else "")
    return body


def shot(sel, top):
    return screen("limebox · Status", status(sel, top),
                  bar("{k} Enter {/} Open  {k} r {/} Restart  {k} s {/} Stop"))


print(page(
    "Status: the list scrolls as you move",
    "“↓ 3 more” only tells you there is more; pressing ↓ at the bottom row scrolls. "
    "“↑ 2 more” appears when rows are above. Nothing to press Enter on.",
    [
        ("Highlight on distribution (last visible row)", "↓ 3 more below, nothing above.", shot(4, 0)),
        ("↓ once", "One row scrolls: ↑ 1 more above, ↓ 2 more below.", shot(5, 1)),
        ("↓ again", "↑ 2 more above, ↓ 1 more below.", shot(6, 2)),
        ("↓ again: the end", "↑ 3 more above, nothing below: you have seen every service.", shot(7, 3)),
        ("↑ back up to the top row", "Going up scrolls back the same way; the counts follow.", shot(2, 2)),
    ]))
