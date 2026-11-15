import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import okta_audit  # noqa: E402

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)


def user(status="ACTIVE", created="2026-01-01T00:00:00Z", last=None, **profile):
    profile.setdefault("login", "x@lakeviewhealth.example")
    return {"id": "1", "status": status, "created": created, "lastLogin": last, "profile": profile}


def test_recent_user_is_clean():
    assert okta_audit.classify(user(last="2026-11-10T00:00:00Z"), NOW) == []


def test_inactive_user():
    assert okta_audit.classify(user(last="2026-05-01T00:00:00Z"), NOW) == ["INACTIVE"]


def test_never_logged_in_only_after_grace_period():
    assert okta_audit.classify(user(created="2026-08-01T00:00:00Z"), NOW) == ["NEVER_LOGGED_IN"]
    assert okta_audit.classify(user(created="2026-11-10T00:00:00Z"), NOW) == []


def test_stale_pending():
    assert okta_audit.classify(user(status="STAGED", created="2026-07-01T00:00:00Z"), NOW) == ["STALE_PENDING"]


def test_service_account_needs_owner():
    svc = user(last="2026-11-14T00:00:00Z", login="svc-reporting@lakeviewhealth.example")
    assert okta_audit.classify(svc, NOW) == ["SERVICE_NO_OWNER"]
    owned = user(last="2026-11-14T00:00:00Z", login="svc-backup@lakeviewhealth.example", manager="cara.diaz")
    assert okta_audit.classify(owned, NOW) == []


def test_admin_flag():
    assert okta_audit.classify(user(last="2026-11-14T00:00:00Z"), NOW, admin_roles=["SUPER_ADMIN"]) == ["ADMIN"]


def test_mock_run_end_to_end(tmp_path):
    rc = okta_audit.main(["--mock", "--now", "2026-11-15T00:00:00Z", "--out", str(tmp_path)])
    assert rc == 0
    report = (tmp_path / "okta_audit_20261115.md").read_text()
    assert "Users scanned: **8**" in report
    assert "ben.cruz" in report and "INACTIVE;ADMIN" in report
    assert "ava.adams" not in report
