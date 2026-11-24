const remediationStatus = {
  needs_review: "No supported patch",
  preview_ready: "Patch validated",
  validation_blocked: "Patch validation blocked",
  publication_blocked: "Saved draft PR attempt blocked",
  draft_opened: "Draft pull request opened",
  draft_reused: "Existing draft pull request reused",
};

function renderRemediation(report) {
  const panel = $("remediation-panel");
  const result = report.remediation;
  panel.hidden = !result;
  if (!result) return;

  $("remediation-status").textContent =
    (remediationStatus[result.status] || result.status) +
    (result.message ? " · " + result.message : "");
  const issueStatus = $("remediation-issue-status");
  const issueLabels = {
    opened: "New review issue opened",
    partial: "Review issue opened with incomplete findings comments",
    updated: "Review issue updated",
    reused: "Existing review issue reused",
    closed: "Previous scan found a closed review issue",
    blocked: "GitHub issue tracking blocked",
  };
  issueStatus.hidden = !result.issue_status;
  issueStatus.textContent = (issueLabels[result.issue_status] || "") +
    (result.issue_message ? " · " + result.issue_message : "");

  const link = $("remediation-link");
  link.hidden = !(result.issue_number || result.pr_number);
  if (!link.hidden) {
    const repo = report.repository.split("/").map(encodeURIComponent).join("/");
    const issue = Boolean(result.issue_number);
    const number = Number(result.issue_number || result.pr_number);
    link.href = "https://github.com/" + repo + (issue ? "/issues/" : "/pull/") + number;
    link.textContent = (issue ? "Open review issue #" : "Open draft #") + number;
  }
  $("remediation-diff").textContent = result.diff || "";
  $("remediation-preview").open = false;
  $("remediation-preview").hidden = !result.diff;

  const validation = $("remediation-validation");
  validation.replaceChildren();
  if (result.tests) {
    const tests = document.createElement("p");
    tests.textContent = "Local tests: " + result.tests.status + " · Rescan: " + result.rescan.status;
    validation.append(tests);
    if (result.tests.status === "unavailable") {
      tests.append(" · Configure CIPHERSETU_CLI to run the compatibility checks.");
    }
    if (result.rescan.before && result.rescan.after) {
      const counts = document.createElement("p");
      counts.textContent = ["C", "H", "M", "L"].map(key =>
        key + " " + result.rescan.before[key] + " → " + result.rescan.after[key]
      ).join(" · ");
      validation.append(counts);
    }
    const rollback = document.createElement("p");
    rollback.textContent = result.rollback;
    validation.append(rollback);
  }

  const review = $("remediation-review");
  review.replaceChildren();
  $("remediation-review-title").textContent = "Needs review (" + result.needs_review.length + ")";
  for (const finding of result.needs_review) {
    const entry = document.createElement("li");
    const location = document.createElement("code");
    location.textContent = finding.path + ":" + finding.line;
    entry.append(location, " · " + finding.usage + ". " + finding.next_step);
    review.append(entry);
  }
  $("remediation-review-section").hidden = !result.needs_review.length;
}

function submitGitHubScan(previewOnly) {
  const repository = $("repo").value.trim();
  if (!repository) {
    $("repo").focus();
    notify("Enter a GitHub repository to continue.", true);
    return;
  }
  const form = new FormData();
  for (const field of ["repo", "ref", "token", "years"]) {
    form.append(field, $(field).value.trim());
  }
  form.append("preview_only", String(previewOnly));
  runScan("/api/scan/github", form);
}

async function repositorySettings(method) {
  const repo = $("repo").value.trim();
  const checkbox = $("auto-remediation");
  const status = $("repository-settings-status");
  const endpoint = "/api/repository-settings?repo=" + encodeURIComponent(repo);
  if (!repo) {
    status.textContent = "Enter a repository to manage its setting.";
    return;
  }
  checkbox.disabled = true;
  let restore = checkbox.checked;
  const scanButtons = [$("github"), $("preview-scan")];
  if (method === "PUT") {
    restore = !restore;
    scanButtons.forEach(button => button.disabled = true);
  }
  try {
    const options = { method };
    if (method === "PUT") {
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify({ auto_remediation: checkbox.checked });
    }
    const response = await fetch(endpoint, options);
    const settings = await response.json();
    if (!response.ok) throw new Error(settings.detail);
    if ($("repo").value.trim() !== repo) return;
    checkbox.checked = settings.auto_remediation;
    status.textContent = checkbox.checked
      ? "On for " + settings.repository
      : "Off for " + settings.repository;
  } catch {
    if ($("repo").value.trim() !== repo) return;
    checkbox.checked = restore;
    status.textContent = method === "PUT" ? "Could not save the setting." : "Enter a valid repository to load its setting.";
  } finally {
    if ($("repo").value.trim() === repo) checkbox.disabled = false;
    if (method === "PUT") scanButtons.forEach(button => button.disabled = false);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("repo").addEventListener("input", () => {
    $("auto-remediation").checked = false;
    $("auto-remediation").disabled = true;
    $("repository-settings-status").textContent = "Leave the repository field to load its setting.";
  });
  $("repo").addEventListener("blur", () => repositorySettings("GET"));
  $("auto-remediation").addEventListener("change", () => repositorySettings("PUT"));
  $("preview-scan").addEventListener("click", () => submitGitHubScan(true));
  if ($("repo").value.trim()) repositorySettings("GET");
});
