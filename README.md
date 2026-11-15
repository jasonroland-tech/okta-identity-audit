# Okta Identity Audit (Python)

> **Loom walkthrough:** _link coming soon_

A read only Python script that scans an Okta org through the Management API and flags the accounts auditors and attackers both look for. It writes a CSV and a Markdown report, ships with sample data and tests, and runs in CI.

## What it flags

| Finding | Rule | Why it matters |
| --- | --- | --- |
| `NEVER_LOGGED_IN` | Active, created over 30 days ago, never signed in | Unclaimed accounts are easy targets |
| `INACTIVE` | Active, no sign in for 90 days | Leavers missed by offboarding |
| `STALE_PENDING` | Staged or provisioned over 30 days | Provisioning that never finished |
| `SUSPENDED` | Suspended or locked out | Should be resolved or deprovisioned |
| `SERVICE_NO_OWNER` | `svc-` login or userType Service, no manager or owner | Machine accounts nobody is accountable for |
| `ADMIN` | Holds an Okta admin role | Privileged access to review |

## What this proves

| Skill | Evidence |
| --- | --- |
| Python and REST APIs | Okta Management API with pagination and rate limit handling ([`okta_audit.py`](okta_audit.py)) |
| Least privilege automation | Token from a Read-only Administrator; the script only sends GET requests |
| Non-human identity governance | Service accounts must have an owner |
| Audit evidence | CSV plus Markdown report, and a before and after remediation run |
| Testing and CI | 7 pytest tests on sample data, run by GitHub Actions |

## Sample output (mock data)

| Finding | Count |
| --- | --- |
| ADMIN | 2 |
| INACTIVE | 1 |
| NEVER_LOGGED_IN | 1 |
| SERVICE_NO_OWNER | 1 |
| STALE_PENDING | 1 |
| SUSPENDED | 1 |

## Run it

```bash
pip install -r requirements.txt
python3 okta_audit.py --mock                       # no Okta needed
OKTA_ORG_URL=https://<org>.okta.com OKTA_API_TOKEN=<read only token> python3 okta_audit.py --check-admins
```

Full walkthrough: [LAB-GUIDE.md](LAB-GUIDE.md).

## Next steps

- Run on a schedule (GitHub Actions cron or Okta Workflows) and open a ticket per finding.
- Add OAuth for Okta (service app with `okta.users.read`) instead of an SSWS token.
