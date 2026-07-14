#!/usr/bin/env bash
#
# Invokes the Sonar-Trivy Auto Remediation agent via the NVIDIA API.
# Unlike a one-shot "describe what you'd do" call, this script asks the
# model for STRUCTURED PATCHES (JSON: file + full new content), applies
# them to disk itself, validates the build, and — only on success —
# commits and pushes to the CURRENT branch. The model never has direct
# file/git access; it only proposes changes, this script executes them.
#
# Required env:
#   NVDAI_API_KEY      - NVIDIA API key
# Optional env:
#   NVDAI_MODEL        - model id (default: meta/llama-3.1-70b-instruct)
#   NVDAI_MAX_TOKENS   - max tokens (default: 4000)
#   SKIP_PUSH          - set to "true" to commit locally but not push
#   GIT_COMMIT_NAME    - git author name (default: "Sonar-Trivy Auto Remediator")
#   GIT_COMMIT_EMAIL   - git author email (default: "sonar-trivy-remediator@ci")

set -euo pipefail

if [ -z "${NVDAI_API_KEY:-}" ]; then
  echo "::error::NVDAI_API_KEY is not set; cannot invoke the agent." >&2
  exit 1
fi

REPORTS_DIR="${REPORTS_DIR:-reports}"
mkdir -p "$REPORTS_DIR"

# Truncate large files to avoid blowing up the request payload.
truncate -s 10240 "$REPORTS_DIR/trivy-fs.sarif"    2>/dev/null || true
truncate -s 10240 "$REPORTS_DIR/trivy-image.sarif" 2>/dev/null || true
truncate -s 10240 "$REPORTS_DIR/sonar-report.json" 2>/dev/null || true

MODEL="${NVDAI_MODEL:-meta/llama-3.1-70b-instruct}"
MAX_TOKENS="${NVDAI_MAX_TOKENS:-4000}"

echo "📂 Available reports under $REPORTS_DIR/:" >&2
ls -la "$REPORTS_DIR" >&2 || true

# ---------------------------------------------------------------------
# System / user prompts — now asking for STRUCTURED JSON patches, not a
# markdown narrative. The model proposes; this script disposes.
# ---------------------------------------------------------------------
SYSTEM_PROMPT='You are an Enterprise DevSecOps AI Agent named "Sonar-Trivy Auto Remediation Agent".

You do NOT have direct file or git access. You propose changes; a separate
process applies, validates, and commits them. Your entire output MUST be a
single JSON object — no prose, no markdown fences.

RULES (non-negotiable):
1. Process findings in order: Critical -> High -> Medium -> Low -> Info.
2. For dependencies: choose the LOWEST stable version that fixes the
   vulnerability and shares the SAME MAJOR VERSION as the currently
   installed one. If `fixedVersion` is a comma-separated list of
   candidates, pick exactly ONE valid version string from that list —
   never emit the raw comma-separated string. If `fixedVersion` is not a
   real version (e.g. a bare advisory link), do not propose a patch for
   that finding; put it in skipped_findings instead.
3. For SonarQube: propose only safe, behavior-preserving fixes. Never
   disable rules or suppress warnings.
4. For Dockerfile: prefer minimal changes, pin base images, remove
   unnecessary packages.
5. NEVER delete production logic, remove tests, or modify generated
   files / vendor libraries / build outputs.
6. If a fix cannot be safely automated, do not guess — put it in
   skipped_findings with a reason.
7. Prefer minimal code change -> secure solution -> backward
   compatibility -> readability -> maintainability.
8. Cap total patches at 15. Each `new_content` must be the FULL file
   content after the fix, not a diff or hunk.

OUTPUT SCHEMA (return ONLY this JSON):
{
  "patches": [
    {
      "file": "repo-relative/path",
      "new_content": "<FULL file content after the fix>",
      "finding_ref": "<CVE id or Sonar rule id>",
      "description": "<one-line description>"
    }
  ],
  "dependency_updates": [
    {"package": "group:artifact", "old_version": "x.y.z", "new_version": "a.b.c"}
  ],
  "skipped_findings": [
    {"finding_ref": "<id>", "reason": "<why this could not be safely automated>"}
  ],
  "scan_summary": {
    "sonar_issues": <int>, "trivy_findings": <int>,
    "critical": <int>, "high": <int>, "medium": <int>, "low": <int>
  }
}'

USER_PROMPT='Analyze the reports under ./reports/ (contents provided below is truncated to 10KB per file if large) and propose safe, automated remediations as structured JSON patches per the schema in the system prompt.

Return ONLY the JSON object. No commentary, no markdown fences.'

# Write the two prompts to files so python can read them with no shell escaping.
printf '%s' "$SYSTEM_PROMPT" > system-prompt.txt
printf '%s' "$USER_PROMPT"   > user-prompt.txt

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY="python"
fi
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "::error::Neither python3 nor python is available; cannot build payload." >&2
  exit 1
fi

"$PY" - <<PYEOF
import json, os
with open("system-prompt.txt", "r", encoding="utf-8") as f:
    system_content = f.read()
with open("user-prompt.txt", "r", encoding="utf-8") as f:
    user_content = f.read()

# Inline the report contents into the user message so the model has
# actual data to work from (previously these files sat on disk but were
# never attached to the request).
reports_dir = "${REPORTS_DIR}"
attachments = []
for name in ("trivy-fs.sarif", "trivy-image.sarif", "sonar-report.json",
             "trivy-report.json"):
    path = os.path.join(reports_dir, name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()[:10240]
        attachments.append(f"\n===== {name} =====\n{content}\n")

user_content = user_content + "\n" + "\n".join(attachments)

payload = {
    "model": os.environ.get("NVDAI_MODEL", "meta/llama-3.1-70b-instruct"),
    "max_tokens": int(os.environ.get("NVDAI_MAX_TOKENS", "4000")),
    "temperature": 0.1,
    "messages": [
        {"role": "system", "content": system_content},
        {"role": "user",   "content": user_content},
    ],
}
with open("payload.json", "w", encoding="utf-8") as f:
    json.dump(payload, f, ensure_ascii=False)
print("payload.json written:", os.path.getsize("payload.json"), "bytes")
PYEOF

echo "────────────────────────────────────────────"
echo "🤖 Agent - Sonar-Trivy Auto Remediation"
echo "────────────────────────────────────────────"

RESPONSE=$(curl -s https://integrate.api.nvidia.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $NVDAI_API_KEY" \
  -d @payload.json)

echo "$RESPONSE" | jq -r '.choices[0].message.content // "Agent response unavailable"' \
  > "$REPORTS_DIR/agent-raw-response.txt" 2>/dev/null \
  || echo "$RESPONSE" > "$REPORTS_DIR/agent-raw-response.txt"

echo "────────────────────────────────────────────"

# ---------------------------------------------------------------------
# Apply patches, validate, and (on success) commit + push.
# All of this happens in Python for reliable JSON handling.
# ---------------------------------------------------------------------
"$PY" - <<PYEOF
import json, os, re, subprocess, sys

reports_dir = "${REPORTS_DIR}"
raw_path = os.path.join(reports_dir, "agent-raw-response.txt")
with open(raw_path, "r", encoding="utf-8", errors="replace") as f:
    raw = f.read()

def extract_json(text):
    text = re.sub(r"^\`\`\`(?:json)?\s*", "", text.strip())
    text = re.sub(r"\`\`\`\$", "", text.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None

parsed = extract_json(raw)
report = {
    "patches_proposed": 0,
    "patches_applied": 0,
    "files_modified": [],
    "dependency_updates": [],
    "skipped_findings": [],
    "scan_summary": {},
    "build_validated": False,
    "committed": False,
    "commit_sha": None,
    "pushed": False,
    "push_error": None,
}

if not parsed or not isinstance(parsed.get("patches"), list):
    print("::warning::Agent response was not valid structured JSON; no patches to apply.", file=sys.stderr)
    with open(os.path.join(reports_dir, "remediation-result.json"), "w") as f:
        json.dump(report, f, indent=2)
    sys.exit(0)

report["dependency_updates"] = parsed.get("dependency_updates", [])
report["skipped_findings"] = parsed.get("skipped_findings", [])
report["scan_summary"] = parsed.get("scan_summary", {})
report["patches_proposed"] = len(parsed["patches"])

# --- Apply patches to disk (only whitelisted, existing files) ---
_WRITABLE_GLOBS = ("src/main/java/", "src/test/java/", "src/main/resources/",
                    "pom.xml", "Dockerfile")

def is_writable(rel):
    rel = rel.replace("\\\\", "/").lstrip("/")
    if not rel or rel.startswith("/") or ".." in rel.split("/"):
        return False
    return rel == "pom.xml" or rel == "Dockerfile" or any(rel.startswith(g) for g in _WRITABLE_GLOBS)

applied_files = []
for patch in parsed["patches"]:
    rel = (patch.get("file") or "").strip()
    new_content = patch.get("new_content")
    if not rel or not isinstance(new_content, str):
        report["skipped_findings"].append({"finding_ref": patch.get("finding_ref", "?"), "reason": "malformed patch"})
        continue
    if not is_writable(rel):
        report["skipped_findings"].append({"finding_ref": patch.get("finding_ref", "?"), "reason": f"path not whitelisted: {rel}"})
        continue
    if not os.path.exists(rel):
        report["skipped_findings"].append({"finding_ref": patch.get("finding_ref", "?"), "reason": f"file does not exist: {rel}"})
        continue
    with open(rel, "r", encoding="utf-8", errors="replace") as f:
        current = f.read()
    if current == new_content:
        continue
    with open(rel, "w", encoding="utf-8") as f:
        f.write(new_content)
    applied_files.append(rel)

report["files_modified"] = applied_files
report["patches_applied"] = len(applied_files)

with open(os.path.join(reports_dir, "remediation-result.json"), "w") as f:
    json.dump(report, f, indent=2)

if not applied_files:
    print("No patches applied; nothing to validate or commit.", file=sys.stderr)
    sys.exit(0)

# --- Validate build ---
build = subprocess.run(["mvn", "-B", "-ntp", "-DskipTests", "package"],
                        capture_output=True, text=True)
report["build_validated"] = (build.returncode == 0)
if build.returncode != 0:
    print("::error::Build validation failed after applying patches; reverting.", file=sys.stderr)
    print(build.stdout[-4000:], file=sys.stderr)
    print(build.stderr[-4000:], file=sys.stderr)
    subprocess.run(["git", "checkout", "--"] + applied_files, check=False)
    report["files_modified"] = []
    report["patches_applied"] = 0
    with open(os.path.join(reports_dir, "remediation-result.json"), "w") as f:
        json.dump(report, f, indent=2)
    sys.exit(0)

# --- Commit ---
subprocess.run(["git", "config", "user.email", os.environ.get("GIT_COMMIT_EMAIL", "sonar-trivy-remediator@ci")], check=False)
subprocess.run(["git", "config", "user.name", os.environ.get("GIT_COMMIT_NAME", "Sonar-Trivy Auto Remediator")], check=False)
subprocess.run(["git", "add"] + applied_files, check=False)

diff_check = subprocess.run(["git", "diff", "--cached", "--quiet"], check=False)
if diff_check.returncode == 0:
    print("Nothing staged after add (no-op); skipping commit.", file=sys.stderr)
    with open(os.path.join(reports_dir, "remediation-result.json"), "w") as f:
        json.dump(report, f, indent=2)
    sys.exit(0)

msg_lines = [f"fix(security): auto-remediate {len(applied_files)} finding(s)", ""]
for p in parsed["patches"]:
    if p.get("file") in applied_files:
        msg_lines.append(f"- {p.get('finding_ref','?')}: {p.get('description','')}")
msg_lines += ["", "Generated by sonar-trivy-remediator agent"]
commit_msg = "\n".join(msg_lines)

commit = subprocess.run(["git", "commit", "-m", commit_msg], capture_output=True, text=True)
if commit.returncode != 0:
    print("::warning::git commit failed: " + commit.stderr, file=sys.stderr)
    with open(os.path.join(reports_dir, "remediation-result.json"), "w") as f:
        json.dump(report, f, indent=2)
    sys.exit(0)

report["committed"] = True
sha = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
report["commit_sha"] = sha

# --- Push (unless SKIP_PUSH=true) ---
if os.environ.get("SKIP_PUSH", "").lower() != "true":
    push = subprocess.run(["git", "push", "origin", "HEAD"], capture_output=True, text=True)
    if push.returncode == 0:
        report["pushed"] = True
    else:
        report["pushed"] = False
        report["push_error"] = push.stderr.strip()
        print("::warning::git push failed: " + push.stderr, file=sys.stderr)

with open(os.path.join(reports_dir, "remediation-result.json"), "w") as f:
    json.dump(report, f, indent=2)

print("Remediation result:", json.dumps(report, indent=2))
PYEOF

echo "────────────────────────────────────────────"
cat "$REPORTS_DIR/remediation-result.json" 2>/dev/null || true
echo "────────────────────────────────────────────"

# Clean up files that may contain prompt/report content we don't want left around.
rm -f payload.json system-prompt.txt user-prompt.txt
