# Sonar-Trivy Auto Remediation Agent

This agent automates the safe remediation of SonarQube and Trivy findings
on the **currently checked-out branch** in a GitHub Actions runner.

## Files

| File | Purpose |
|---|---|
| `.claude/agents/sonar-trivy-remediator.md` | Agent definition (system prompt, behavior spec, tool list) |
| `.claude/agents/sonar-report-generator.md` | Read-only agent that converts SonarQube JSON artifacts into `reports/sonar-report.md` |
| `scripts/parse-reports.mjs` | Node.js script that discovers and normalizes SARIF/JSON/XML/HTML/TXT reports into a single JSON list of findings |
| `scripts/run-agent.sh` | **Local dry-run** of the auto-remediation agent via the NVIDIA API. Produces a Markdown report; never pushes or commits. |
| `scripts/ai-remediation.py` | **In-CI fix-applier**: same NVIDIA call, but extracts a fenced ` ```diff ` block from the response, validates and applies it, runs `mvn package`, commits, and pushes the fixes back to the same branch. |
| `scripts/run-sonar-report.sh` | Invokes the sonar-report-generator agent via the NVIDIA API |
| `.github/workflows/build-and-security.yml` (job: `ai-remediate`) | Wires `scripts/ai-remediation.py` into CI: downloads the Trivy fs + image SARIF artifacts and the SonarQube Markdown report, runs the agent, and uploads the resulting reports as the `ai-remediation` artifact. |
| `.github/workflows/build-and-security.yml` (job: `sonar-report`) | Wires the sonar-report-generator agent into CI: downloads the `sonar-report` artifact, then runs the agent to produce `reports/sonar-report.md` |

## How it works

1. **CI runs the existing Trivy fs + image scans** (jobs `trivy-fs` and `trivy-image`) and uploads the SARIF reports as artifacts (`trivy-fs-report`, `trivy-image-report`).
2. **The `sonarqube` job** analyzes the source tree, fetches `sonar-issues.json` from SonarCloud, renders it to `sonar-report.md` + `sonar-report.html` via `scripts/generate_sonar_report.py`, and uploads all three files as the `sonarqube-reports` artifact.
3. **The `ai-remediate` job** downloads those three artifacts, flattens them to `reports/{trivy-fs.sarif, trivy-image.sarif, sonar.md}`, and invokes `scripts/ai-remediation.py` with the NVIDIA API. The script:
   - Prompts the LLM with the same three inputs.
   - Extracts a fenced ` ```diff ` block from the response.
   - Runs `git apply --check` against the diff; if the check fails, the script logs the error and skips the apply (no commit, no push).
   - On a clean apply, runs `mvn -B -ntp -DskipTests package`. If the build fails, the script reverts the working tree and skips the commit.
   - On a clean build, commits the working tree as `github-actions[bot]` with the `[ai-remediation]` trailer and pushes to the trigger branch.
4. **Nothing is pushed or committed unless the diff is valid AND the build passes.** The `ai-remediate` job's `if:` guard checks the head commit's message for the `[ai-remediation]` trailer and skips the next run on the auto-generated commit, so the AI never recursively re-applies itself.

## Required secrets

| Secret | Purpose |
|---|---|
| `nvdai_api_key` | NVIDIA API key for the `integrate.api.nvidia.com/v1/chat/completions` endpoint used to invoke the agent |
| `SONAR_TOKEN` | SonarQube/SonarCloud token (used by the `sonarqube` job to fetch `sonar-issues.json`) |
| `GITHUB_TOKEN` | Auto-provided; used by the `ai-remediate` job to check out the trigger ref and to push the AI's commit back to the same branch |

The `ai-remediate` job requires **`nvdai_api_key`**; the absence of any other secret will cause an earlier job to fail, which in turn prevents the agent from running.

## How the agent is invoked

The job runs `scripts/ai-remediation.py`, which:

1. POSTs a chat-completions request to the NVIDIA API (`meta/llama-3.1-70b-instruct`):

   ```bash
   curl -s https://integrate.api.nvidia.com/v1/chat/completions \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $NVDAI_API_KEY" \
     -d @payload.json
   ```

   The payload embeds:
   - a **system** message with the agent's behavior spec (rules, workflow, safety guarantees, the explicit permission to commit + push), and
   - a **user** message instructing the model to return one fenced ` ```diff ` block followed by the Markdown report.

2. Extracts the diff with a non-greedy `re.DOTALL` regex.
3. Validates the diff with `git apply --check`.
4. On a clean check, runs `git apply` and then `mvn -B -ntp -DskipTests package`.
5. On a clean build, commits the working tree as `github-actions[bot]` with the `[ai-remediation]` trailer and pushes to the trigger branch.

If any step fails, the script writes a JSON summary, a Markdown report, and a (possibly empty) `ai-patch.diff`, and exits 0. The job still succeeds; the artifact is uploaded; nothing is committed or pushed.

## Required permissions

The job declares:

```yaml
permissions:
  contents: write
```

`contents: write` is required for the AI's `git push` back to the trigger branch. The job does not need `pull-requests: write` because it does not post PR comments.

## Local invocation

You can run the dry-run agent (`scripts/run-agent.sh`, report only) or the fix-applier (`scripts/ai-remediation.py`, applies + pushes) against this repo. Both expect the three inputs to be present in `reports/`:

```bash
# 1. Generate a Trivy fs SARIF
trivy fs --format sarif --output reports/trivy-fs.sarif --severity CRITICAL,HIGH --ignore-unfixed .

# 2. Drop a SonarQube Markdown report
#    (the simplest way: re-run the sonarqube job and download
#     the sonarqube-reports artifact, then copy sonar-report.md
#     to reports/sonar.md)
cp /path/to/sonar-report.md reports/sonar.md

# 3a. Dry run (report only, no changes)
export NVDAI_API_KEY=...
bash scripts/run-agent.sh

# 3b. Apply + commit + push (same logic the CI job runs)
export NVDAI_API_KEY=...
export BRANCH=my-feature-branch
export GITHUB_TOKEN=$(gh auth token)   # only needed if you want push to work
python3 scripts/ai-remediation.py \
  --repo-root . --reports reports --branch "${BRANCH}"
# Add --no-push for a local apply + commit without the push step.
```

## Safety guarantees

The script enforces these guarantees in code, not just in the prompt:

- `git apply --check` runs before `git apply`; broken diffs are rejected.
- `mvn package` runs after every apply; build failures trigger `git checkout -- .` and the commit step is skipped.
- The push is `git push origin HEAD:<branch>`, never `--force`.
- The re-trigger guard in the workflow's `if:` checks for the `[ai-remediation]` trailer the script adds to every auto-commit, so the AI never recursively re-applies itself.
- The script never raises; every failure path writes a JSON + Markdown summary and exits 0.

If the working tree is dirty for reasons unrelated to the agent, those changes are preserved by the `git checkout -- .` only when the AI's own diff fails to build — otherwise the AI's diff is committed on top of whatever was already there.
