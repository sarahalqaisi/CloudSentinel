from __future__ import annotations

from fastapi.testclient import TestClient

from app.database import SessionLocal, init_db
from app.main import app
from app.services.policies import import_policies
from app.services.seed import seed_demo
from app.services.analytics import repository_score


def prepare():
    init_db()
    with SessionLocal() as db:
        import_policies(db)
        seed_demo(db)


def test_health_dashboard_and_api_routes():
    prepare()
    with TestClient(app) as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["service"] == "CloudSentinel"
        for path in ["/", "/scans", "/findings", "/resources", "/iam-graph", "/compliance", "/policies", "/repository-security", "/audit", "/docs"]:
            response = client.get(path)
            assert response.status_code == 200, path
        stats = client.get("/api/stats").json()
        assert stats["summary"]["policies"] == 35
        assert "latest" not in stats["summary"]
        assert client.get("/reports/scans/1.pdf").status_code == 200
        sarif = client.get("/reports/scans/1.sarif")
        assert sarif.status_code == 200
        assert sarif.json()["version"] == "2.1.0"
        assert sarif.headers["cache-control"] == "no-store"
        assert sarif.headers["x-content-type-options"] == "nosniff"


def test_repository_score_rewards_security_controls():
    base = repository_score({"openssf_score": 0})
    strong = repository_score({"branch_protection": True, "secret_scanning": True, "code_scanning": True, "dependabot": True, "dependency_review": True, "security_policy": True, "actions_pinning": True, "openssf_score": 10})
    assert base == 0
    assert strong == 100


def test_authenticated_session_csrf_upload_flow():
    prepare()
    with TestClient(app) as client:
        page = client.get("/scans/new")
        assert page.status_code == 200
        import re
        match = re.search(r'name="csrf" value="([^"]+)"', page.text)
        assert match
        terraform = b'resource "aws_security_group" "upload" { ingress { from_port = 22\n to_port = 22\n protocol = "tcp"\n cidr_blocks = ["0.0.0.0/0"] } }'
        response = client.post(
            "/scans/upload",
            data={"name": "Upload Test", "csrf": match.group(1)},
            files={"file": ("main.tf", terraform, "text/plain")},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"].startswith("/scans/")


def test_upload_error_does_not_disclose_parser_details():
    prepare()
    with TestClient(app) as client:
        import re
        token = re.search(r'name="csrf" value="([^"]+)"', client.get("/scans/new").text).group(1)
        response = client.post("/scans/upload", data={"name": "bad", "csrf": token}, files={"file": ("bad.json", b"{secret", "application/json")})
        assert response.status_code == 400
        assert "secret" not in response.text
        assert "line" not in response.text
        assert response.headers["cache-control"] == "no-store"
