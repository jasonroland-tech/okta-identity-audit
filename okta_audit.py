"""Read only Okta identity audit.

Finds accounts that are a risk or an audit finding:
  NEVER_LOGGED_IN   active, created over N days ago, never signed in
  INACTIVE          active, no sign in for N days
  STALE_PENDING     staged or provisioned (never activated) for over N days
  SUSPENDED         suspended or locked out, worth a review
  SERVICE_NO_OWNER  service account with no named owner
  ADMIN             holds an Okta admin role

Usage:
  python okta_audit.py --mock                 # sample data, no Okta needed
  OKTA_ORG_URL=https://integrator-123.okta.com OKTA_API_TOKEN=... python okta_audit.py --check-admins

The script only sends GET requests. Use a token from a Read Only Administrator.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
SERVICE_PREFIXES = ("svc-", "svc.", "svc_")


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_service_account(user: dict) -> bool:
    profile = user.get("profile", {})
    login = profile.get("login", "").lower()
    return login.startswith(SERVICE_PREFIXES) or profile.get("userType", "").lower() == "service"


def classify(user: dict, now: datetime, inactive_days: int = 90, pending_days: int = 30,
             admin_roles: list[str] | None = None) -> list[str]:
    """Return the finding codes for one user. Pure function so it is easy to test."""
    findings: list[str] = []
    status = user.get("status", "")
    created = parse_time(user.get("created"))
    last_login = parse_time(user.get("lastLogin"))
    profile = user.get("profile", {})

    if status == "ACTIVE":
        if last_login is None:
            if created and now - created > timedelta(days=pending_days):
                findings.append("NEVER_LOGGED_IN")
        elif now - last_login > timedelta(days=inactive_days):
            findings.append("INACTIVE")
    elif status in ("STAGED", "PROVISIONED"):
        if created and now - created > timedelta(days=pending_days):
            findings.append("STALE_PENDING")
    elif status in ("SUSPENDED", "LOCKED_OUT"):
        findings.append("SUSPENDED")

    if is_service_account(user) and not (profile.get("manager") or profile.get("owner")):
        findings.append("SERVICE_NO_OWNER")

    if admin_roles:
        findings.append("ADMIN")

    return findings


class OktaClient:
    def __init__(self, org_url: str, token: str):
        import requests  # imported here so --mock and tests need no extra packages

        self.base = org_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
        })

    def _get(self, url: str, params: dict | None = None):
        while True:
            resp = self.session.get(url, params=params, timeout=30)
            if resp.status_code == 429:  # rate limited: wait until the window resets
                reset = int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 5))
                time.sleep(max(1, reset - int(time.time())))
                continue
            resp.raise_for_status()
            return resp

    def list_users(self) -> list[dict]:
        users: list[dict] = []
        url, params = f"{self.base}/api/v1/users", {"limit": 200}
        while url:
            resp = self._get(url, params)
            users.extend(resp.json())
            url = resp.links.get("next", {}).get("url")
            params = None  # the next link already carries the cursor
        return users

    def admin_roles(self, user_id: str) -> list[str]:
        resp = self._get(f"{self.base}/api/v1/users/{user_id}/roles")
        return [r.get("type") or r.get("label", "CUSTOM") for r in resp.json()]


def load_mock() -> tuple[list[dict], dict[str, list[str]]]:
    users = json.loads((HERE / "sample_data" / "users.json").read_text())
    admins = json.loads((HERE / "sample_data" / "admin_roles.json").read_text())
    return users, admins


def run(users: list[dict], admins: dict[str, list[str]], now: datetime,
        inactive_days: int, pending_days: int) -> list[dict]:
    rows = []
    for u in users:
        roles = admins.get(u["id"], [])
        findings = classify(u, now, inactive_days, pending_days, roles)
        if not findings:
            continue
        p = u.get("profile", {})
        rows.append({
            "login": p.get("login", ""),
            "status": u.get("status", ""),
            "last_login": u.get("lastLogin") or "never",
            "created": u.get("created", ""),
            "admin_roles": ";".join(roles),
            "findings": ";".join(findings),
        })
    return rows


def write_reports(rows: list[dict], total: int, out_dir: Path, stamp: str) -> tuple[Path, Path]:
    out_dir.mkdir(exist_ok=True)
    csv_path = out_dir / f"okta_audit_{stamp}.csv"
    md_path = out_dir / f"okta_audit_{stamp}.md"

    fields = ["login", "status", "last_login", "created", "admin_roles", "findings"]
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    counts: dict[str, int] = {}
    for r in rows:
        for code in r["findings"].split(";"):
            counts[code] = counts.get(code, 0) + 1

    lines = [f"# Okta identity audit ({stamp})", "",
             f"Users scanned: **{total}**. Users with findings: **{len(rows)}**.", "",
             "| Finding | Count |", "| --- | --- |"]
    lines += [f"| {k} | {v} |" for k, v in sorted(counts.items())]
    lines += ["", "| Login | Status | Last login | Findings |", "| --- | --- | --- | --- |"]
    lines += [f"| {r['login']} | {r['status']} | {r['last_login'][:10]} | {r['findings']} |" for r in rows]
    md_path.write_text("\n".join(lines) + "\n")
    return csv_path, md_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Read only Okta identity audit")
    ap.add_argument("--mock", action="store_true", help="use sample_data instead of a live org")
    ap.add_argument("--check-admins", action="store_true", help="look up admin roles (one call per active user)")
    ap.add_argument("--inactive-days", type=int, default=90)
    ap.add_argument("--pending-days", type=int, default=30)
    ap.add_argument("--now", help="override the current time (ISO 8601), used for repeatable runs")
    ap.add_argument("--out", default=str(HERE / "reports"))
    args = ap.parse_args(argv)

    now = parse_time(args.now) if args.now else datetime.now(timezone.utc)

    if args.mock:
        users, admins = load_mock()
    else:
        org, token = os.environ.get("OKTA_ORG_URL"), os.environ.get("OKTA_API_TOKEN")
        if not org or not token:
            print("Set OKTA_ORG_URL and OKTA_API_TOKEN, or use --mock.", file=sys.stderr)
            return 2
        if not re.match(r"^https://[\w.-]+$", org.rstrip("/")):
            print("OKTA_ORG_URL should look like https://integrator-1234567.okta.com", file=sys.stderr)
            return 2
        client = OktaClient(org, token)
        users = client.list_users()
        admins = {}
        if args.check_admins:
            for u in users:
                if u.get("status") == "ACTIVE":
                    roles = client.admin_roles(u["id"])
                    if roles:
                        admins[u["id"]] = roles

    rows = run(users, admins, now, args.inactive_days, args.pending_days)
    stamp = now.strftime("%Y%m%d")
    csv_path, md_path = write_reports(rows, len(users), Path(args.out), stamp)
    print(f"Scanned {len(users)} users, {len(rows)} with findings.")
    print(f"Wrote {csv_path} and {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
