"""Known-vulnerability check of the Aeria dependencies against the OSV database (osv.dev).

    python scripts/osv_scan.py --maven aeria-iot-sensors=deps-iot.txt --maven aeria-backoffice=deps-bo.txt \
        --pypi aeria-forecast=../aeria-forecast/requirements.txt --pypi aeria-data-pipeline=pipeline-freeze.txt \
        --out docs/audit/raw/11-osv.json

Maven input: output of `mvn dependency:list -DincludeScope=runtime -DoutputFile=...`.
PyPI input: pinned requirements (name==version). Only package names and versions are sent to osv.dev.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"


def maven_packages(path: Path) -> list[tuple[str, str]]:
    pkgs = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = re.match(r"\s*([\w.\-]+):([\w.\-]+):jar(?::[\w.\-]+)?:([\w.\-]+):(compile|runtime)", line)
        if m:
            pkgs.append((f"{m.group(1)}:{m.group(2)}", m.group(3)))
    return sorted(set(pkgs))


def pypi_packages(path: Path) -> list[tuple[str, str]]:
    pkgs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?==([\w.\-]+)", line)
        if m:
            pkgs.append((m.group(1).lower(), m.group(2)))
    return sorted(set(pkgs))


def severity(vuln: dict) -> str:
    for s in vuln.get("database_specific", {}), :
        if isinstance(s, dict) and s.get("severity"):
            return str(s["severity"]).upper()
    for aff in vuln.get("affected", []):
        sev = aff.get("ecosystem_specific", {}).get("severity") or aff.get("database_specific", {}).get("severity")
        if sev:
            return str(sev).upper()
    return "UNKNOWN"


def scan(ecosystem: str, pkgs: list[tuple[str, str]]) -> list[dict]:
    queries = [{"package": {"name": n, "ecosystem": ecosystem}, "version": v} for n, v in pkgs]
    results = []
    for i in range(0, len(queries), 500):
        r = requests.post(OSV_BATCH, json={"queries": queries[i:i + 500]}, timeout=60)
        r.raise_for_status()
        results += r.json()["results"]
    found = []
    for (name, version), res in zip(pkgs, results):
        for v in res.get("vulns", []):
            detail = requests.get(OSV_VULN.format(v["id"]), timeout=60).json()
            fixed = sorted({e["fixed"] for a in detail.get("affected", [])
                            if a.get("package", {}).get("name", "").lower() == name.lower()
                            for rng in a.get("ranges", []) for e in rng.get("events", []) if "fixed" in e})
            found.append({"package": name, "version": version, "id": v["id"],
                          "aliases": detail.get("aliases", []), "summary": detail.get("summary", ""),
                          "severity": severity(detail), "fixed_in": fixed})
    return found


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--maven", action="append", default=[], help="module=dependency-list.txt")
    p.add_argument("--pypi", action="append", default=[], help="module=requirements.txt")
    p.add_argument("--out", required=True)
    a = p.parse_args()
    report = {"collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "source": "osv.dev",
              "modules": {}}
    for spec, eco, reader in [(m, "Maven", maven_packages) for m in a.maven] + [(m, "PyPI", pypi_packages) for m in a.pypi]:
        module, path = spec.split("=", 1)
        pkgs = reader(Path(path))
        vulns = scan(eco, pkgs)
        report["modules"][module] = {"ecosystem": eco, "packages": len(pkgs), "vulnerabilities": vulns}
        print(f"{module}: {len(pkgs)} {eco} packages, {len(vulns)} known vulnerabilities")
        for v in vulns:
            print(f"   {v['package']} {v['version']}: {v['id']} {v['severity']} fixed in {', '.join(v['fixed_in']) or '-'}")
    Path(a.out).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
