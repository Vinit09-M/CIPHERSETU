"""Conservative source remediation for the vetted Testing-Crypto wrapper."""
from collections import Counter
from dataclasses import dataclass
import difflib
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

from .scanner import scan

ASSETS = Path(__file__).resolve().parent
TARGET = "apps/payments/wrap_key.py"
RULE = "testing-crypto-hybrid-v1"
ORIGINAL = (ASSETS / "testing_crypto_original.py").read_bytes().replace(b"\r\n", b"\n")
PATCHED = (ASSETS / "testing_crypto_patch.py").read_bytes().replace(b"\r\n", b"\n")
ROLLBACK = (
    "Apply the patch after review and deploy the dual reader before switching writes. "
    "After rollout, pause new writes and retain the dual reader and hybrid private key "
    "for records already written. Revert the writer and its configuration only after "
    "confirming continued access to both formats. Keep the legacy key until legacy "
    "records have been retired or migrated."
)
TESTS = (
    "New writes use the CipherSetu hybrid suite",
    "Reader recovers freshly generated legacy OAEP records",
    "Reader recovers hybrid records",
    "Reader rejects tampered hybrid ciphertext",
)


@dataclass(frozen=True)
class Patch:
    original: bytes

    @property
    def replacement(self):
        if b"\r\n" in self.original:
            return PATCHED.replace(b"\n", b"\r\n")
        return PATCHED

    @property
    def fingerprint(self):
        return hashlib.sha256(RULE.encode() + self.original + self.replacement).hexdigest()

    @property
    def diff(self):
        # Both sides are known templates. Preserve line endings for git apply.
        return "".join(difflib.unified_diff(
            self.original.decode().splitlines(keepends=True),
            self.replacement.decode().splitlines(keepends=True),
            fromfile=f"a/{TARGET}", tofile=f"b/{TARGET}",
        ))


def _usage(path, text, line, algorithm):
    if path.endswith((".md", ".rst", ".txt")):
        return "Documentation reference", "Confirm the referenced use with its owner."
    if path.endswith((".pem", ".crt", ".cer", ".pub")):
        return "Public key or certificate reference", "Identify the key owner and consuming protocol."
    if path.endswith(".aegis"):
        return "Archived envelope", "Identify the format and recover the matching key before planning a file migration."
    if re.search(r"jwt|jws|jwt_algorithm", text, re.I):
        return "JWT signing or verification", "Coordinate issuer and verifier changes and key rotation."
    if re.search(r"\btls\b", path + "\n" + text, re.I):
        if re.search(r"exchange|x25519|ecdh", line, re.I):
            return "TLS key exchange", "Check peer support and test group negotiation."
        return "TLS certificate authentication", "Review certificate and trust-chain compatibility with the PKI owner."
    purpose = text if not path.endswith(".csv") else line
    if re.search(r"certificate signing|\bx509\b", purpose, re.I):
        return "Certificate signing", "Review CA, trust store, and relying-party compatibility."
    if re.search(r"SignPSS|VerifyPSS|SignPKCS1|VerifyPKCS1|signature|verify\(|manifest verification", purpose, re.I):
        return "Signing or verification", "Confirm signers and verifiers and plan a compatible algorithm change."
    if re.search(r"wrap[_ -]?(?:data[_ -]?)?key|key[_ -]wrapping|OAEP", purpose, re.I):
        return "Possible data-key wrapping", "Confirm the format, key custody, and reader compatibility before rewriting."
    if algorithm in {"AES-128", "AES-256"}:
        return "Symmetric encryption reference", "Confirm the mode, key size, and how nonces are managed."
    if algorithm == "MD5/SHA1":
        return "Hash reference", "Determine whether the use requires collision resistance."
    if algorithm == "PQC":
        return "Post-quantum algorithm reference", "Confirm the deployed protocol and parameters."
    return "Unconfirmed use", "Inspect the calling code or configuration with its owner."


def _normal_path(name, prefix):
    return name.removeprefix(prefix) if prefix else name


def plan(archive, report, *, prefix):
    paths = {finding["path"] for finding in report["findings"]}
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        entries = [entry for entry in source.infolist() if entry.filename in paths]
        sources = {}
        for entry in entries:
            # The existing scanner has already bounded and decoded these entries.
            if entry.file_size <= 1024 * 1024 and (entry.external_attr >> 16) & 0o170000 != 0o120000:
                sources[entry.filename] = source.read(entry)
    target = prefix + TARGET
    original = sources.get(target, b"")
    patch = None
    if original.replace(b"\r\n", b"\n") == ORIGINAL and sum(e.filename == target for e in entries) == 1:
        patch = Patch(original)
    # Split each file once and bound the context used for purpose hints. These
    # hints are advisory. Only the exact target match can produce a patch.
    contexts = {}
    for path, data in sources.items():
        source = data.decode("utf-8", errors="replace")
        contexts[path] = (source[:4096], source.splitlines())
    review = []
    for finding in report["findings"]:
        path = finding["path"]
        context, lines = contexts.get(path, ("", ()))
        index = finding["line"] - 1
        line = lines[index] if index < len(lines) else ""
        if patch and path == target:
            usage = "RSA-OAEP data-key wrapping"
            next_step = "Deploy the dual reader and provision hybrid keys before switching writes."
        else:
            usage, next_step = _usage(_normal_path(path, prefix), context + "\n" + line[:4096], line[:4096], finding["algorithm"])
            review.append({
                "path": _normal_path(path, prefix), "line": finding["line"],
                "algorithm": finding["algorithm"], "severity": finding["severity"],
                "usage": usage, "next_step": next_step,
            })
        finding["usage"] = usage

    result = {"rule": RULE, "status": "needs_review", "needs_review": review}
    if patch:
        result.update({
            "status": "preview_ready", "files": [TARGET], "diff": patch.diff,
            "rollback": ROLLBACK,
        })
    return result, patch


def github_prefix(archive):
    """GitHub zipballs always have a common root directory."""
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        names = [entry.filename for entry in source.infolist() if not entry.is_dir()]
    roots = {name.partition("/")[0] for name in names}
    if len(roots) == 1 and all("/" in name for name in names):
        return next(iter(roots)) + "/"
    return ""


def _rescan(archive, report, prefix, patch):
    target = prefix + TARGET
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(archive)) as source, zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as patched:
        for entry in source.infolist():
            if entry.filename == target:
                content = patch.replacement
            elif entry.is_dir() or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                # The scanner ignores these entries without expanding their contents.
                content = b""
            else:
                content = source.read(entry)
            patched.writestr(entry, content)
    after = scan(output.getvalue(), report["retention_years"])
    before_rows = report["findings"]
    after_rows = after["findings"]

    def unchanged(rows):
        return Counter((f["path"], f["line"], f["algorithm"], f["severity"]) for f in rows if f["path"] != target)

    target_rows = [f for f in after_rows if f["path"] == target]
    hybrid = any(f["algorithm"] == "ECC" and f["severity"] == "L" for f in target_rows)
    valid = unchanged(before_rows) == unchanged(after_rows) and hybrid
    return {
        "status": "passed" if valid else "failed",
        "before": report["counts"], "after": after["counts"],
        "file_before": [f["algorithm"] for f in before_rows if f["path"] == target],
        "file_after": [f["algorithm"] for f in target_rows],
        "note": "Remaining RSA identifiers in the patched file belong to the legacy reader.",
    }


def validate(archive, report, prefix, patch, result):
    cli_setting = os.environ.get("CIPHERSETU_CLI")
    cli = Path(cli_setting).resolve() if cli_setting else None
    tests = {"status": "unavailable", "checks": list(TESTS)}
    result["tests"] = tests
    if cli and cli.is_file():
        # No repository files, App credentials, PATH-based executables, or test output
        # enter this process. Only the exact vetted baseline and generated code run.
        env = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR") if key in os.environ}
        try:
            with tempfile.TemporaryDirectory(prefix="ciphersetu-validation-") as directory:
                root = Path(directory)
                (root / "original.py").write_bytes(patch.original)
                (root / "patched.py").write_bytes(patch.replacement)
                subprocess.run(
                    [sys.executable, "-I", str(ASSETS / "testing_crypto_validate.py"), str(cli), directory],
                    cwd=directory, env=env, check=True, timeout=90,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            tests["status"] = "passed"
        except (OSError, subprocess.SubprocessError):
            tests["status"] = "failed"
    try:
        result["rescan"] = _rescan(archive, report, prefix, patch)
    except (ValueError, OSError, zipfile.BadZipFile, RuntimeError):
        result["rescan"] = {"status": "failed"}
    if tests["status"] != "passed" or result["rescan"]["status"] != "passed":
        result["status"] = "validation_blocked"
