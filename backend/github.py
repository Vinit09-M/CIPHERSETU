"""GitHub archive reads and repository-scoped App tokens."""
import base64
import json
import logging
import os
from pathlib import Path
import re
import time
from urllib.parse import quote

import httpx

from .remediation import ROLLBACK, TARGET

API = "https://api.github.com"
SHA = re.compile(r"[0-9a-f]{40}")
MAX_ARCHIVE = 10 * 1024 * 1024
# Private archive redirects can contain a short-lived credential in the URL.
logging.getLogger("httpx").setLevel(logging.WARNING)


class GitHubError(Exception):
    pass


def client():
    return httpx.Client(timeout=30, follow_redirects=False, trust_env=False)


def _headers(token):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers


def request(http, method, path, token="", *, expected=(200,), operation="request", hint="", **kwargs):
    try:
        response = http.request(method, API + path, headers=_headers(token), **kwargs)
    except httpx.HTTPError:
        raise GitHubError(f"GitHub could not be reached during {operation}.") from None

    status = response.status_code
    if status not in expected:
        advice = f" {hint}" if hint and status in {401, 403, 404, 410, 422} else ""
        raise GitHubError(f"GitHub {operation} failed (HTTP {status}).{advice}")
    return response


def _sha(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise GitHubError("GitHub returned an invalid object ID.")
    return value


def fetch_archive(http, repo, ref, token):
    base = f"/repos/{repo}"
    commit = request(http, "GET", f"{base}/commits/{quote(ref, safe='')}", token).json()
    sha = _sha(commit["sha"])
    redirect = request(http, "GET", f"{base}/zipball/{sha}", token, expected=(302,))
    url = httpx.URL(redirect.headers["location"])
    if url.scheme != "https" or url.host != "codeload.github.com" or url.userinfo or url.port:
        raise GitHubError("GitHub returned an unexpected archive location.")
    archive = bytearray()
    with http.stream("GET", url) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            archive.extend(chunk)
            if len(archive) > MAX_ARCHIVE:
                raise GitHubError("GitHub archive exceeds the 10 MiB limit.")
    return bytes(archive), sha


def _app_jwt():
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    issuer = os.environ.get("CIPHERSETU_GITHUB_APP_ID")
    key_path = os.environ.get("CIPHERSETU_GITHUB_APP_KEY_FILE")
    if not issuer or not key_path:
        raise GitHubError("Set CIPHERSETU_GITHUB_APP_ID and CIPHERSETU_GITHUB_APP_KEY_FILE before starting the server.")
    try:
        pem = Path(key_path).read_bytes()
    except FileNotFoundError:
        raise GitHubError(
            "The App PEM file was not found. Point CIPHERSETU_GITHUB_APP_KEY_FILE to its current location "
            "and restart the server from that same shell."
        ) from None
    except OSError:
        raise GitHubError("The server account could not read the App PEM file. Check the file and its permissions.") from None
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise GitHubError("The configured PEM could not be parsed. Use the private key downloaded for this App.") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise GitHubError("The configured PEM must contain the GitHub App RSA private key.")

    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=")

    now = int(time.time())
    header = encode(b'{"alg":"RS256","typ":"JWT"}')
    payload = encode(json.dumps({"iat": now - 60, "exp": now + 480, "iss": issuer}).encode())
    message = header + b"." + payload
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return (message + b"." + encode(signature)).decode()


def installation_token(http, repo, *, track_issues=False):
    jwt = _app_jwt()
    response = request(
        http, "GET", f"/repos/{repo}/installation", jwt,
        operation="App installation lookup", expected=(200, 401, 404),
    )
    if response.status_code == 404:
        raise GitHubError(
            f"GitHub could not find this App's installation on {repo} (HTTP 404). "
            "Check that the configured App is installed on the repository owner's account "
            "and that the installation includes this exact repository."
        )
    if response.status_code == 401:
        raise GitHubError(
            "GitHub rejected the App credentials (HTTP 401). Check that the App ID "
            "and PEM belong to the same App and the server clock is correct."
        )
    installation = response.json()
    installation_id = int(installation["id"])
    permissions = {"contents": "read"}
    if track_issues:
        permissions["issues"] = "write"
    response = request(
        http, "POST", f"/app/installations/{installation_id}/access_tokens", jwt, expected=(201,),
        operation="installation token request",
        hint=("Verify that the repository is selected and the installation has approved "
              "Contents read and Issues read/write access." if track_issues else
              "Verify that the repository is selected and the installation has Contents read access."),
        json={"repositories": [repo.split("/", 1)[1]], "permissions": permissions},
    )
    return response.json()["token"]
