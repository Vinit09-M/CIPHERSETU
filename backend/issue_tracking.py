"""Publish a developer review issue for a GitHub scan."""
import re

from . import github

TITLE = "CipherSetu cryptography review"
BODY_LIMIT = 60_000
PRIORITIES = {"C": "Critical", "H": "High", "M": "Medium", "L": "Low"}


def _location(path):
    # Render paths as literal inline code, even if they contain Markdown or mentions.
    return "`" + re.sub(
        r"[`@<>|\x00-\x1f\x7f-\x9f\u2028-\u202e\u2066-\u2069]",
        lambda match: f"\\u{ord(match[0]):04x}",
        path,
    ) + "`"


def _counts(counts):
    return ", ".join(f"{name} {counts[code]}" for code, name in PRIORITIES.items())


TABLE = (
    "| File path and line | Finding | Criticality | Impact | Remediation and suggested code fix |\n"
    "| --- | --- | --- | --- | --- |\n"
)

USE_ADVICE = {
    "Documentation reference": (
        "The reference alone does not establish runtime use.",
        "Confirm the linked implementation with its owner. Update documentation after the implementation changes.",
    ),
    "Public key or certificate reference": (
        "This is key or certificate inventory. The impact depends on its consumers and trust chain.",
        "Locate key consumers and coordinate rotation with the owner. Replace the asset through the key provisioning process.",
    ),
    "JWT signing or verification": (
        "If deployed, a compromised signing key could let an attacker forge tokens trusted by the service.",
        "In issuer and verifier code, keep an explicit algorithm allowlist and version the keys with `kid`. Stage an interoperability-tested signing migration on both sides.",
    ),
    "Signing or verification": (
        "If deployed with a compromised signing key, modified records could be accepted as authentic.",
        "Version the signature format and update the signer and verifier together. Evaluate ML-DSA only if the protocol and deployed libraries support it.",
    ),
    "TLS certificate authentication": (
        "Certificate key compromise could enable service impersonation if peers still trust the affected credential.",
        "Update certificate provisioning and the trust chain together after testing client compatibility.",
    ),
    "TLS key exchange": (
        "Standalone classical key exchange can expose recorded traffic to future quantum decryption.",
        "Select a hybrid TLS group supported by both peers in their actual TLS settings. Add a handshake test that asserts the negotiated group.",
    ),
    "Certificate signing": (
        "A compromised issuer signing key could allow forged certificates accepted by relying parties.",
        "Migrate the issuing CA and distribute updated trust anchors through the PKI workflow before changing relying parties.",
    ),
    "Archived envelope": (
        "The record can be opened or migrated only with the matching key and a reader for its format.",
        "Keep the original and recover the matching key. Use an authenticated format-specific migration and verify recovery with a fresh synthetic test first.",
    ),
}

ALGORITHM_FIXES = {
    "DES/RC4": "If writes still use the legacy cipher, use a supported AES-GCM library for new writes with a fresh nonce per key. Keep legacy reads only for the migration.",
    "MD5/SHA1": "For a verified Python non-password checksum that requires collision resistance, use `hashlib.sha256(data).hexdigest()` and migrate stored digests with format versioning. For passwords, use the application’s password KDF.",
    "AES-128": "If the retention policy requires stronger keys, configure the authenticated encryption library for AES-256 and verify old records remain readable.",
    "AES-256": "Retain AES-256 if the mode, keys, and nonce management are correct. Add a test for nonce uniqueness and rejection of modified ciphertext.",
    "PQC": "Verify the deployed library, parameters, and protocol interoperability. Add a round-trip or verification test for the intended suite.",
}


def _advice(finding, result):
    usage = finding.get("usage", "Unconfirmed use")
    algorithm = finding["algorithm"]
    if usage == "RSA-OAEP data-key wrapping":
        impact = "Recovery of an RSA private key could expose protected data keys and the data they encrypt."
        fix = (
            "Deploy the dual reader first. For new writes, use the hybrid adapter from the local preview as "
            "`wrap_data_key(hybrid_public_key, data_key, cli=cli_path)`. Keep the legacy OAEP reader for existing records. "
            f"Local tests: {result['tests']['status']}; rescan: {result['rescan']['status']}. See the local patch preview."
        )
        if result["status"] != "preview_ready":
            fix += " Complete validation before applying this change."
        return impact, fix
    if usage == "Possible data-key wrapping" and algorithm == "RSA":
        return (
            "If this wraps deployed data keys, future RSA key recovery could expose the protected data.",
            "Identify the format and its readers. Version the writer and preserve a legacy read path before switching to a reviewed hybrid wrapping implementation.",
        )
    if usage in USE_ADVICE:
        return USE_ADVICE[usage]
    return finding["quantum_attack"], ALGORITHM_FIXES.get(algorithm, finding["recommendation"])


def _rows(report, result, prefix):
    order = {code: index for index, code in enumerate(PRIORITIES)}
    for finding in sorted(report["findings"], key=lambda row: (order[row["severity"]], row["path"], row["line"], row["algorithm"])):
        path = finding["path"].removeprefix(prefix)
        impact, fix = _advice(finding, result)
        finding_name = finding["algorithm"] + " · " + finding.get("usage", "Unconfirmed use")
        criticality = f"**{PRIORITIES[finding['severity']]}** ({finding['score']}/10)"
        yield f"| {_location(path)}:{finding['line']} | {finding_name} | {criticality} | {impact} | {fix} |\n"


def _snapshot(report, result, prefix):
    rows = list(_rows(report, result, prefix))
    front = "\n".join([
        f"Scanned `{report['github_ref']}` at `{report['github_commit']}`.",
        "",
        f"Scan priorities: {_counts(report['counts'])}.",
        "",
        f"### Scan Findings ({len(rows)})",
        "",
        "Criticality is a triage score. Confirm use and applicability before changing code.",
        "",
        TABLE,
    ])
    parts = [""]
    part_bytes = len(front.encode())
    for row in rows:
        size = len(row.encode())
        if parts[-1] and part_bytes + size > BODY_LIMIT - 1024:
            parts.append("")
            part_bytes = len(TABLE.encode())
        parts[-1] += row
        part_bytes += size

    body = front + parts[0]
    if len(parts) > 1:
        body += f"\nThe remaining findings continue in {len(parts) - 1} comments on this issue.\n"
    comments = [
        f"### Scan Findings continued ({number}/{len(parts) - 1})\n\n{TABLE}{part}"
        for number, part in enumerate(parts[1:], start=1)
    ]
    return body, comments


def publish_issue(http, repo, report, result, *, prefix):
    token = github.installation_token(http, repo, track_issues=True)
    path = f"/repos/{repo}/issues"
    section, comments = _snapshot(report, result, prefix)
    body = "Use this issue to assign owners, record decisions, and coordinate changes.\n\n" + section
    issue = github.request(
        http, "POST", path, token, expected=(201,), operation="review issue creation",
        hint="Check that Issues are enabled and the App has Issues read/write access.",
        json={"title": TITLE, "body": body},
    ).json()
    number = int(issue["number"])
    for comment in comments:
        try:
            github.request(
                http, "POST", f"{path}/{number}/comments", token, expected=(201,),
                operation="scan findings comment creation", json={"body": comment},
            )
        except github.GitHubError as error:
            return {
                "issue_status": "partial", "issue_number": number,
                "issue_message": f"{error} The full findings are available in the scan report.",
            }
    return {"issue_status": "opened", "issue_number": number}
