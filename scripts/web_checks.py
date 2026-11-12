"""Application-level checks of the Aeria web services (own platform, local deployment only).

    python scripts/web_checks.py --backoffice http://127.0.0.1:8084 --forecast http://127.0.0.1:8083 \
        --out docs/audit/raw/06-web-avant.json

Checks: security headers, cookie flags, technology disclosure, exposed endpoints, error leakage, and
resistance of the login form to password guessing (20 wrong passwords on the demo account).
"""
from __future__ import annotations

import argparse
import json
import re
import time
from datetime import datetime, timezone

import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "limits injected scripts (XSS)",
    "X-Frame-Options": "clickjacking",
    "X-Content-Type-Options": "MIME sniffing",
    "Referrer-Policy": "URL leakage to third parties",
    "Strict-Transport-Security": "forces HTTPS (only meaningful over TLS)",
    "Permissions-Policy": "browser features (camera, geolocation...)",
}


def headers_report(resp: requests.Response) -> dict:
    present = {h: resp.headers.get(h) for h in SECURITY_HEADERS}
    return {
        "status": resp.status_code,
        "missing": [h for h, v in present.items() if v is None],
        "present": {h: v for h, v in present.items() if v is not None},
        "server_banner": resp.headers.get("Server"),
        "tls": resp.url.startswith("https://"),
    }


def cookie_flags(resp: requests.Response) -> list[dict]:
    out = []
    for raw in resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []:
        name = raw.split("=", 1)[0]
        low = raw.lower()
        out.append({"cookie": name, "httponly": "httponly" in low, "secure": "secure" in low,
                    "samesite": (re.search(r"samesite=(\w+)", low) or [None, None])[1]})
    return out


def check_backoffice(base: str, demo_password: str | None = None) -> dict:
    s = requests.Session()
    r = {"base": base}
    login = s.get(f"{base}/login", timeout=10)
    r["login_page"] = headers_report(login) | {"cookies": cookie_flags(login)}
    r["anonymous_root"] = s.get(f"{base}/", allow_redirects=False, timeout=10).status_code
    r["anonymous_api"] = s.get(f"{base}/api/capteurs", timeout=10).status_code
    # no redirects: an anonymous request redirected to /login must not count as "exposed"
    r["actuator"] = {p: requests.get(f"{base}{p}", timeout=10, allow_redirects=False).status_code
                     for p in ("/actuator", "/actuator/health", "/actuator/env", "/actuator/heapdump")}
    err = requests.get(f"{base}/capteurs/%2e%2e", timeout=10, allow_redirects=False)
    r["error_page"] = {"status": err.status_code, "stack_trace_leak": "Exception" in err.text or "at org." in err.text}

    # password guessing: 20 wrong passwords, then check the account is still usable (no lockout, no delay)
    token = re.search(r'name="_csrf" value="([^"]+)"', login.text)
    timings, statuses = [], []
    for i in range(20):
        t0 = time.perf_counter()
        resp = s.post(f"{base}/login", data={"username": "responsable", "password": f"wrong-{i}",
                                              "_csrf": token.group(1) if token else ""},
                      allow_redirects=False, timeout=10)
        timings.append(round(time.perf_counter() - t0, 3))
        statuses.append(resp.headers.get("Location", str(resp.status_code)))
        page = s.get(f"{base}/login", timeout=10)
        token = re.search(r'name="_csrf" value="([^"]+)"', page.text)
    r["bruteforce"] = {"attempts": 20, "all_rejected": all("error" in x for x in statuses),
                       "median_response_s": sorted(timings)[10], "max_response_s": max(timings),
                       "throttling_observed": max(timings) > 2.0}
    if demo_password:
        # lockout check: right after the failures, the right (demo) password must be refused too
        ok = s.post(f"{base}/login", data={"username": "responsable", "password": demo_password,
                                            "_csrf": token.group(1) if token else ""},
                    allow_redirects=False, timeout=10)
        r["bruteforce"]["locked_after_failures"] = "error" in ok.headers.get("Location", "")
    return r


def check_forecast(base: str) -> dict:
    r = {"base": base}
    try:
        h = requests.get(f"{base}/health", timeout=10)
    except requests.RequestException as exc:
        return r | {"reachable": False, "error": str(exc)}
    r["health"] = headers_report(h)
    r["openapi_docs_public"] = requests.get(f"{base}/docs", timeout=10).status_code == 200
    r["model_card_public"] = requests.get(f"{base}/model", timeout=10).status_code == 200
    burst = [requests.get(f"{base}/health", timeout=10).status_code for _ in range(50)]
    r["rate_limit_on_50_requests"] = any(s == 429 for s in burst)
    bad = requests.get(f"{base}/forecast", params={"issue_date": "not-a-date"}, timeout=10)
    r["validation_error"] = {"status": bad.status_code, "leaks_trace": "Traceback" in bad.text}
    return r


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--backoffice")
    p.add_argument("--forecast")
    p.add_argument("--demo-password", help="password of the demo account, to verify the lockout")
    p.add_argument("--out", required=True)
    a = p.parse_args()
    report = {"collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if a.backoffice:
        report["backoffice"] = check_backoffice(a.backoffice, a.demo_password)
    if a.forecast:
        report["forecast"] = check_forecast(a.forecast)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
