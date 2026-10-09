#!/usr/bin/env python3
"""Builds crates/openvibes-console/data/attack-enterprise.json from MITRE's
Enterprise ATT&CK STIX bundle (spec 2026-10-09-attack-coverage-design.md §2).

    curl -fLO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json
    python3 -I scripts/attack-data.py enterprise-attack-19.2.json 19.2 > crates/openvibes-console/data/attack-enterprise.json

(run from the repository root; the bundle must be a .json file under it)

Keeps tactics in matrix order and live techniques (no revoked or deprecated
ones), each with its tactic ids. Run offline at build time; the console
never fetches ATT&CK.
"""
import json
import sys
from pathlib import Path

NOTICE = ("MITRE ATT&CK, (c) The MITRE Corporation. This work is reproduced and "
          "distributed with the permission of The MITRE Corporation.")


def mitre_id(obj):
    return next((r["external_id"] for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"), None)


def live(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def bundle_path(arg):
    """The STIX bundle, which must be a .json file under the current directory."""
    base = Path.cwd().resolve()
    path = (base / arg).resolve()
    if not path.is_relative_to(base) or path.suffix != ".json" or not path.is_file():
        sys.exit(f"attack-data: want a .json file under {base}, not {arg}")
    return path


def main(arg, version):
    with bundle_path(arg).open(encoding="utf-8") as f:
        objects = json.load(f)["objects"]
    tactics = {o["id"]: o for o in objects if o["type"] == "x-mitre-tactic" and live(o)}
    [matrix] = [o for o in objects if o["type"] == "x-mitre-matrix" and live(o)]
    ordered = [tactics[ref] for ref in matrix["tactic_refs"] if ref in tactics]
    by_short = {t["x_mitre_shortname"]: mitre_id(t) for t in ordered}
    techniques = []
    for o in objects:
        if o["type"] != "attack-pattern" or not live(o):
            continue
        ids = [by_short[p["phase_name"]] for p in o.get("kill_chain_phases", [])
               if p.get("kill_chain_name") == "mitre-attack" and p["phase_name"] in by_short]
        if ids:
            techniques.append({"id": mitre_id(o), "name": o["name"], "tactics": ids})
    techniques.sort(key=lambda t: t["id"])
    out = {
        "version": version,
        "notice": NOTICE,
        "tactics": [{"id": mitre_id(t), "name": t["name"]} for t in ordered],
        "techniques": techniques,
    }
    json.dump(out, sys.stdout, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
