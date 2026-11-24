import base64
import io
import json
import os
from pathlib import Path
import subprocess
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient
import httpx
import pytest

from backend import github, issue_tracking, main, remediation

REPO = "vinit09-m/testing-crypto"
BASE = "/repos/" + REPO
ISSUES = BASE + "/issues"
FINDINGS = {
    "apps/identity/signing.json": '{"algorithm":"RSA","jwt_algorithm":"RS256"}\n',
    "apps/ledger/sign.go": "rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)\n",
    "platform/tls.yaml": "certificate: RSA\npreferred_key_exchange: X25519\n",
    "platform/public.pem": "RSA PUBLIC KEY\n",
    "docs/usage.md": "RSA is documented here.\n",
}


def fixture_zip(mode):
    external = os.environ.get("CIPHERSETU_TESTING_CRYPTO_FIXTURE")
    if external and mode == "fixture":
        root = Path(external)
        files = {path.relative_to(root).as_posix(): path.read_bytes()
                 for path in root.rglob("*") if path.is_file() and ".git" not in path.parts
                 and not path.name.endswith(".private-key.pem")}
    elif mode == "clean":
        files = {"readme.md": "Synthetic fixture without crypto mentions.\n"}
    else:
        files = dict(FINDINGS)
        if mode == "fixture":
            files[remediation.TARGET] = remediation.ORIGINAL
        elif mode == "lookalike":
            files[remediation.TARGET] = remediation.ORIGINAL + b"\n# Unknown source variation\n"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for filename, contents in files.items():
            archive.writestr("owner-Testing-Crypto-abcdef/" + filename, contents)
    return buffer.getvalue()


class MockGitHub:
    def __init__(self):
        self.issues = []
        self.comments = []
        self.mutations = []
        self.tokens = []
        self.commit = "a" * 40
        self.archive = fixture_zip("fixture")

    def handle(self, request):
        path = request.url.path
        method = request.method
        auth = request.headers.get("authorization", "")
        payload = json.loads(request.content) if request.content else None
        if request.url.host == "codeload.github.com":
            assert not auth
            return httpx.Response(200, content=self.archive)
        assert request.url.host == "api.github.com"
        if path == BASE + "/installation":
            self.verify_jwt(auth)
            return httpx.Response(200, json={"id": 42})
        if path == "/app/installations/42/access_tokens":
            self.verify_jwt(auth)
            assert payload["repositories"] == ["testing-crypto"]
            permissions = payload["permissions"]
            assert permissions in ({"contents": "read"}, {"contents": "read", "issues": "write"})
            self.tokens.append(permissions)
            token = "mock-issues-token" if "issues" in permissions else "mock-read-token"
            return httpx.Response(201, json={"token": token})
        if path == BASE + "/commits/HEAD":
            assert auth in {"", "Bearer mock-reader", "Bearer mock-read-token"}
            return httpx.Response(200, json={"sha": self.commit})
        if path == BASE + "/zipball/" + self.commit:
            return httpx.Response(302, headers={"Location": "https://codeload.github.com/fixture"})
        assert auth == "Bearer mock-issues-token"
        if path == ISSUES and method == "POST":
            self.mutations.append((method, path))
            assert set(payload) == {"title", "body"}
            issue = {**payload, "number": 7 + len(self.issues), "state": "open"}
            self.issues.insert(0, issue)
            return httpx.Response(201, json=issue)
        if path.startswith(ISSUES + "/") and path.endswith("/comments") and method == "POST":
            self.mutations.append((method, path))
            number = int(path.split("/")[-2])
            assert any(issue["number"] == number for issue in self.issues)
            comment = {**payload, "issue_number": number, "id": 1 + len(self.comments)}
            self.comments.append(comment)
            return httpx.Response(201, json=comment)

        raise AssertionError(f"Unexpected mocked endpoint {method} {path}")

    def verify_jwt(self, auth):
        assert auth.startswith("Bearer ")
        header, claims, signature = auth[7:].split(".")

        def decode(value):
            return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

        assert json.loads(decode(header))["alg"] == "RS256"
        assert json.loads(decode(claims))["iss"] == "12345"
        self.app_key.public_key().verify(
            decode(signature), f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256()
        )


@pytest.fixture(scope="session")
def cli(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    exe = tmp_path_factory.mktemp("cli") / ("ciphersetu.exe" if os.name == "nt" else "ciphersetu")
    subprocess.run(
        ["go", "build", "-buildvcs=false", "-o", str(exe), "./cmd/ciphersetu"],
        cwd=root / "migration", check=True, timeout=180,
    )
    return exe


@pytest.fixture
def workflow(tmp_path, monkeypatch, cli):
    service = MockGitHub()
    service.app_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = tmp_path / "app.pem"
    key_path.write_bytes(service.app_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    monkeypatch.setenv("CIPHERSETU_GITHUB_APP_ID", "12345")
    monkeypatch.setenv("CIPHERSETU_GITHUB_APP_KEY_FILE", str(key_path))
    monkeypatch.setenv("CIPHERSETU_CLI", str(cli))
    monkeypatch.setattr(github, "client", lambda: httpx.Client(transport=httpx.MockTransport(service.handle)))
    return TestClient(main.app), service


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB", str(tmp_path / "scans.db"))
    main.initialize_database()


def settings(client, enabled=None, repo=REPO):
    params = {"repo": repo}
    response = client.get("/api/repository-settings", params=params) if enabled is None else client.put(
        "/api/repository-settings", params=params, json={"auto_remediation": enabled}
    )
    assert response.status_code == 200
    return response.json()["auto_remediation"]


def run(client, **arguments):
    response = client.post("/api/scan/github", data={"repo": REPO, **arguments})
    assert response.status_code == 200, response.text
    return response.json()


def test_preview_then_open_fresh_issues_for_identical_scans(workflow):
    client, service = workflow
    assert settings(client) is False
    preview = run(client, token="mock-reader")
    result = preview["remediation"]
    assert result["status"] == "preview_ready"
    assert result["tests"]["status"] == result["rescan"]["status"] == "passed"
    assert result["diff"].startswith("--- a/apps/payments/wrap_key.py")
    usages = {row["usage"] for row in result["needs_review"]}
    assert {"JWT signing or verification", "Signing or verification",
            "TLS key exchange", "TLS certificate authentication"} <= usages
    assert "mock-reader" not in json.dumps(preview)
    assert client.get("/api/scans/" + preview["id"]).json() == preview
    assert not service.tokens and not service.mutations
    assert settings(client, True, "https://github.com/Vinit09-M/Testing-Crypto/") is True
    assert settings(client, repo="vinit09-m/other") is False
    result = run(client, preview_only="true")["remediation"]
    assert result["status"] == "preview_ready" and "issue_status" not in result
    assert not service.mutations
    opened_report = run(client)
    opened = opened_report["remediation"]
    assert opened["issue_status"] == "opened" and opened["issue_number"] == 7
    assert service.mutations == [("POST", ISSUES)]
    body = service.issues[0]["body"]
    assert "Suggested patch" not in body and "Needs review" not in body
    assert "wrap_data_key(hybrid_public_key, data_key, cli=cli_path)" in body
    assert "Criticality | Impact | Remediation and suggested code fix" in body
    findings = opened_report["findings"]
    assert f"### Scan Findings ({len(findings)})" in body
    for finding in findings:
        path = finding["path"].removeprefix("owner-Testing-Crypto-abcdef/")
        assert f"{issue_tracking._location(path)}:{finding['line']}" in body
    assert "mock-issues-token" not in body and "PRIVATE KEY" not in body
    service.issues[0]["body"] += "\n\nDeveloper notes: assign an owner."
    second = run(client)["remediation"]
    assert second["issue_status"] == "opened" and second["issue_number"] == 8
    assert service.mutations == [("POST", ISSUES), ("POST", ISSUES)]
    assert service.issues[1]["body"].endswith("Developer notes: assign an owner.")
    assert service.commit in service.issues[0]["body"]


def test_identical_scan_opens_new_issue_after_previous_issue_closed(workflow):
    client, service = workflow
    service.archive = fixture_zip("unsupported")
    settings(client, True)
    first = run(client)["remediation"]
    service.issues[0]["state"] = "closed"
    second = run(client)["remediation"]
    assert second["issue_status"] == "opened"
    assert second["issue_number"] != first["issue_number"]
    assert service.issues[1]["state"] == "closed"
    assert service.mutations == [("POST", ISSUES), ("POST", ISSUES)]


@pytest.mark.parametrize("mode", ["unsupported", "lookalike"])
def test_automatic_issue_can_track_unsupported_findings(workflow, mode):
    client, service = workflow
    service.archive = fixture_zip(mode)
    settings(client, True)
    result = run(client)["remediation"]
    assert result["status"] == "needs_review" and result["needs_review"]
    assert "diff" not in result and result["issue_status"] == "opened"
    assert "Suggested patch" not in service.issues[0]["body"]


def test_no_findings_does_not_open_an_issue(workflow):
    client, service = workflow
    service.archive = fixture_zip("clean")
    settings(client, True)
    assert "issue_status" not in run(client)["remediation"]
    assert not service.mutations


@pytest.mark.parametrize("gate", ["tests", "rescan"])
def test_failed_validation_is_reported_without_publishing_the_patch(workflow, monkeypatch, gate):
    client, service = workflow
    settings(client, True)
    if gate == "tests":
        monkeypatch.setenv("CIPHERSETU_CLI", str(Path(__file__).resolve()))
    else:
        monkeypatch.setattr(remediation, "_rescan", lambda *_: {"status": "failed"})
    result = run(client)["remediation"]
    assert result["status"] == "validation_blocked"
    assert result[gate]["status"] == "failed"
    assert result["issue_status"] == "opened"
    assert "Complete validation before applying this change" in service.issues[0]["body"]
    assert "Validated patch" not in service.issues[0]["body"]


@pytest.mark.parametrize("line_ending", [b"\n", b"\r\n"])
def test_preview_diff_matches_the_suggested_file(tmp_path, line_ending):
    original = remediation.ORIGINAL.replace(b"\n", line_ending)
    patch = remediation.Patch(original)
    target = tmp_path / remediation.TARGET
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    subprocess.run(
        ["git", "-c", "core.autocrlf=false", "apply", "--whitespace=nowarn", "-"],
        cwd=tmp_path, input=patch.diff.encode(), check=True, timeout=15,
    )
    assert target.read_bytes() == patch.replacement


@pytest.mark.parametrize(("endpoint", "status", "message"), [
    (BASE + "/installation", 404, "could not find this App's installation"),
    (BASE + "/installation", 401, "rejected the App credentials"),
    ("/app/installations/42/access_tokens", 404, "installation token request failed"),
    (ISSUES, 410, "Issues are enabled"),
])
def test_github_failure_identifies_the_step(workflow, monkeypatch, endpoint, status, message):
    client, service = workflow
    settings(client, True)

    def fail_at_stage(request):
        if request.url.path == endpoint:
            return httpx.Response(status, json={"message": "untrusted upstream diagnostics"})
        return service.handle(request)

    monkeypatch.setattr(github, "client", lambda: httpx.Client(transport=httpx.MockTransport(fail_at_stage)))
    result = run(client, token="mock-reader")["remediation"]
    assert result["status"] == "preview_ready"
    assert result["issue_status"] == "blocked"
    assert message in result["issue_message"]
    assert "untrusted upstream diagnostics" not in result["issue_message"]
    assert not service.issues


def test_issue_path_format_escapes_mentions_and_markup():
    assert issue_tracking._location("a`@user\nb") == "`a\\u0060\\u0040user\\u000ab`"


def test_moved_app_key_error_points_to_environment_setting(workflow, monkeypatch, tmp_path):
    client, service = workflow
    settings(client, True)
    missing = tmp_path / "old-location.pem"
    monkeypatch.setenv("CIPHERSETU_GITHUB_APP_KEY_FILE", str(missing))
    result = run(client, token="mock-reader")["remediation"]
    assert result["status"] == "preview_ready"
    assert result["issue_status"] == "blocked"
    assert "CIPHERSETU_GITHUB_APP_KEY_FILE" in result["issue_message"]
    assert str(missing) not in result["issue_message"]
    assert not service.mutations


def test_all_findings_fit_across_each_new_issue_and_its_comments(workflow, monkeypatch):
    client, service = workflow
    settings(client, True)
    monkeypatch.setattr(issue_tracking, "BODY_LIMIT", 4500)
    report = run(client)
    assert report["remediation"]["issue_status"] == "opened"
    assert service.comments
    messages = "\n".join([service.issues[0]["body"], *(row["body"] for row in service.comments)])
    for finding in report["findings"]:
        path = finding["path"].removeprefix("owner-Testing-Crypto-abcdef/")
        assert f"{issue_tracking._location(path)}:{finding['line']}" in messages
    first_number = report["remediation"]["issue_number"]
    first_comments = list(service.comments)
    second = run(client)["remediation"]
    assert second["issue_status"] == "opened" and second["issue_number"] != first_number
    assert service.comments[:len(first_comments)] == first_comments
    assert all(row["issue_number"] == first_number for row in first_comments)
    assert all(row["issue_number"] == second["issue_number"] for row in service.comments[len(first_comments):])
