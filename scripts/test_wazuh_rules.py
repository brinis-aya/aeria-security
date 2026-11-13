"""Test the Aeria decoders and rules on a real Wazuh manager with wazuh-logtest.

    python scripts/test_wazuh_rules.py --container aeria-wazuh-test [--report docs/audit/raw/10-wazuh-logtest.txt]

The decoders and rules are copied into the container, then every scenario of wazuh/tests/scenarios.json
is played in a fresh logtest session (so frequency rules start from zero). Exit code 1 if one fails.
Use a disposable manager: the files stay installed in the target container.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def docker(*args: str, stdin: str | None = None) -> str:
    # wazuh-logtest prints its results on stderr: both streams are read together
    out = subprocess.run(["docker", *args], input=stdin, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, encoding="utf-8", timeout=180)
    if out.returncode != 0:
        raise RuntimeError(out.stdout)
    return out.stdout


def wait_ready(container: str, timeout: int = 240) -> None:
    """A freshly started manager needs a minute or two before wazuh-logtest answers."""
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if "Phase 1" in docker("exec", "-i", container, "/var/ossec/bin/wazuh-logtest", stdin="ping\n"):
                return
        except RuntimeError:
            pass
        print("waiting for the Wazuh manager to start...", flush=True)
        time.sleep(10)
    raise RuntimeError(f"wazuh-logtest did not answer within {timeout} s in {container}")


def install(container: str) -> None:
    wait_ready(container)
    docker("cp", str(ROOT / "wazuh/decoders/aeria_decoders.xml"), f"{container}:/var/ossec/etc/decoders/aeria_decoders.xml")
    docker("cp", str(ROOT / "wazuh/rules/aeria_rules.xml"), f"{container}:/var/ossec/etc/rules/aeria_rules.xml")
    docker("exec", container, "chown", "wazuh:wazuh", "/var/ossec/etc/decoders/aeria_decoders.xml",
           "/var/ossec/etc/rules/aeria_rules.xml")


def logtest(container: str, lines: list[str]) -> list[dict]:
    """Return, for each line, the decoder, fields and rule id reported by wazuh-logtest."""
    raw = docker("exec", "-i", container, "/var/ossec/bin/wazuh-logtest", stdin="\n".join(lines) + "\n")
    if "error when connecting" in raw:
        raise RuntimeError("wazuh-analysisd is not reachable in " + container)
    if "Wazuh-logtest error" in raw:  # invalid decoder/rule: the session cannot even start
        raise RuntimeError(raw.strip())
    events = []
    for block in raw.split("**Phase 1: Completed pre-decoding.")[1:]:
        rule = re.search(r"\*\*Phase 3: Completed filtering \(rules\)\.\s+id: '(\d+)'\s+level: '(\d+)'", block)
        decoder = re.search(r"name: '([^']+)'", block.split("**Phase 2")[1]) if "**Phase 2" in block else None
        fields = dict(re.findall(r"\n\t([\w.]+): '([^']*)'", block.split("**Phase 3")[0].split("**Phase 2")[-1]))
        events.append({"rule": rule.group(1) if rule else None, "level": int(rule.group(2)) if rule else None,
                       "decoder": decoder.group(1) if decoder else None, "fields": fields,
                       "alert": "**Alert to be generated." in block})
    return events


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--container", required=True)
    p.add_argument("--report")
    a = p.parse_args()
    install(a.container)
    scenarios = json.loads((ROOT / "wazuh/tests/scenarios.json").read_text(encoding="utf-8"))
    lines_out, failures = [], 0
    for sc in scenarios:
        lines = []
        if "before" in sc:
            lines += [sc["before"]["line"]] * sc["before"]["repeat"]
        lines += [sc["line"]] * sc["repeat"]
        events = logtest(a.container, lines)
        last = events[-1] if events else {}
        problems = []
        if last.get("rule") != sc["expect"]:
            problems.append(f"rule {last.get('rule')} instead of {sc['expect']}")
        if sc.get("decoder") and last.get("decoder") != sc["decoder"]:
            problems.append(f"decoder {last.get('decoder')} instead of {sc['decoder']}")
        for k, v in sc.get("fields", {}).items():
            if last.get("fields", {}).get(k) != v:
                problems.append(f"field {k}={last.get('fields', {}).get(k)!r} instead of {v!r}")
        status = "PASS" if not problems else "FAIL"
        failures += bool(problems)
        line = (f"{status}  {sc['name']}: rule {last.get('rule')} level {last.get('level')}"
                f"{' (alert)' if last.get('alert') else ''}" + (f" -- {'; '.join(problems)}" if problems else ""))
        print(line)
        lines_out.append(line)
    summary = f"{len(scenarios) - failures}/{len(scenarios)} scenarios pass"
    print(summary)
    if a.report:
        version = docker("exec", a.container, "/var/ossec/bin/wazuh-control", "info").splitlines()[0]
        Path(a.report).write_text(f"wazuh-logtest - {version}\n\n" + "\n".join(lines_out) + f"\n\n{summary}\n",
                                  encoding="utf-8")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
