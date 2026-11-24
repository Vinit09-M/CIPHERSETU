import datetime
import io
import json
import os
from pathlib import Path
import re
import sqlite3
from threading import Lock
import uuid
import zipfile

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, StrictBool

from . import github, issue_tracking, remediation
from .scanner import scan

app = FastAPI(title="CipherSetu", version="0.2.0-alpha")
DB = os.environ.get("CIPHERSETU_DB", "data/scans.db")


def initialize_database():
    Path(DB).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, created TEXT, report TEXT)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS repository_settings(
                repository TEXT PRIMARY KEY, auto_remediation INTEGER NOT NULL
            )
        """)


initialize_database()


# The app runs as one local process. Serialize publication with other scans and
# settings changes so disabling a repository takes effect before the next issue is created.
publication_lock = Lock()


class RepositorySettings(BaseModel):
    auto_remediation: StrictBool


@app.middleware("http")
async def local_only(request: Request, call_next):
    host = request.headers.get("host", "").split(":")[0]
    if host not in ("localhost", "127.0.0.1", "testserver"):
        return JSONResponse({"detail": "Local deployment only"}, 400)
    origin = request.headers.get("origin")
    if origin and origin != "http://" + request.headers.get("host", ""):
        return JSONResponse({"detail": "Origin rejected"}, 403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'"
    return response


def normalize_repository(repo):
    repo = repo.strip().removeprefix("https://github.com/").rstrip("/").removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or any(
        part in (".", "..") for part in repo.split("/")
    ):
        raise HTTPException(400, "Use a GitHub URL or owner/repository.")
    return repo.lower()


def auto_remediation_enabled(repo):
    with sqlite3.connect(DB) as connection:
        row = connection.execute(
            "SELECT auto_remediation FROM repository_settings WHERE repository=?", (repo,)
        ).fetchone()
    return bool(row and row[0])


@app.get("/api/repository-settings")
def read_repository_settings(repo: str):
    repo = normalize_repository(repo)
    return {"repository": repo, "auto_remediation": auto_remediation_enabled(repo)}


@app.put("/api/repository-settings")
def update_repository_settings(repo: str, settings: RepositorySettings):
    repo = normalize_repository(repo)
    with publication_lock, sqlite3.connect(DB) as connection:
        connection.execute(
            "INSERT INTO repository_settings VALUES (?, ?) ON CONFLICT(repository) "
            "DO UPDATE SET auto_remediation=excluded.auto_remediation",
            (repo, settings.auto_remediation),
        )
    return {"repository": repo, "auto_remediation": settings.auto_remediation}


def inspect_archive(data, years):
    if not 0 <= years <= 100:
        raise HTTPException(400, "Retention must be 0–100")
    try:
        return scan(data, years)
    except (ValueError, OSError, zipfile.BadZipFile, NotImplementedError, RuntimeError):
        raise HTTPException(400, "Invalid archive or scan limit exceeded") from None


def persist(report):
    report["id"] = uuid.uuid4().hex
    report["created"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with sqlite3.connect(DB) as connection:
        connection.execute("INSERT INTO scans VALUES (?,?,?)", (
            report["id"], report["created"], json.dumps(report),
        ))
    return report


@app.post("/api/scan/zip")
async def upload(file: UploadFile = File(...), years: int = Form(0)):
    data = await file.read(github.MAX_ARCHIVE + 1)
    if len(data) > github.MAX_ARCHIVE:
        raise HTTPException(413, "ZIP limit 10 MiB")
    return persist(inspect_archive(data, years))


@app.post("/api/scan/github")
def scan_github(
    repo: str = Form(...), token: str = Form(""), ref: str = Form("HEAD"),
    years: int = Form(0), preview_only: bool = Form(False),
):
    repo = normalize_repository(repo)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", ref) or ref in (".", ".."):
        raise HTTPException(400, "Use a simple branch, tag or commit SHA.")
    if not 0 <= years <= 100:
        raise HTTPException(400, "Retention must be 0–100")
    enabled_at_start = auto_remediation_enabled(repo)
    with github.client() as http:
        if enabled_at_start and not token:
            try:
                token = github.installation_token(http, repo)
            except (github.GitHubError, KeyError, ValueError, TypeError):
                pass  # Public scanning remains available.
        try:
            data, sha = github.fetch_archive(http, repo, ref, token)
        except (github.GitHubError, httpx.HTTPError, KeyError, ValueError, TypeError):
            raise HTTPException(
                400, "GitHub fetch failed. Verify the repository, ref, read access, and archive size."
            ) from None
        report = inspect_archive(data, years)
        report.update(github_commit=sha, repository=repo, github_ref=ref)
        prefix = remediation.github_prefix(data)
        result, patch = remediation.plan(data, report, prefix=prefix)
        result.update(auto_remediation=enabled_at_start, preview_only=preview_only)
        report["remediation"] = result
        if patch:
            remediation.validate(data, report, prefix, patch, result)
        if enabled_at_start and not preview_only and (patch or result["needs_review"]):
            with publication_lock:
                if auto_remediation_enabled(repo):
                    try:
                        result.update(issue_tracking.publish_issue(http, repo, report, result, prefix=prefix))
                    except github.GitHubError as error:
                        result.update(issue_status="blocked", issue_message=str(error))
                    except (KeyError, ValueError, TypeError, AttributeError):
                        result.update(issue_status="blocked", issue_message="Unexpected GitHub response.")
                else:
                    result["auto_remediation"] = False
    return persist(report)


@app.post("/api/demo")
def demo():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo.py", 'key = RSA.generate(2048)\nhashlib.md5(data)\ncipher = "AES-256-GCM"\n')
    return persist(inspect_archive(buffer.getvalue(), 10))


@app.get("/api/scans")
def history():
    with sqlite3.connect(DB) as connection:
        return [{"id": scan_id, "created": created} for scan_id, created in connection.execute(
            "SELECT id,created FROM scans ORDER BY created DESC LIMIT 100"
        )]


@app.get("/api/scans/{id}")
def get(id: str):
    with sqlite3.connect(DB) as connection:
        row = connection.execute("SELECT report FROM scans WHERE id=?", (id,)).fetchone()
    if not row:
        raise HTTPException(404)
    return json.loads(row[0])


@app.get("/")
def home():
    return FileResponse("frontend/index.html")


app.mount("/static", StaticFiles(directory="frontend"), name="static")
