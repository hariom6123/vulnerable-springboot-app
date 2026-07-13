#!/usr/bin/env python3
"""AI auto-remediation orchestrator.

Reads SonarQube (Markdown) and Trivy (SARIF) reports, prompts the
NVIDIA-hosted LLM to propose safe fixes, extracts a fenced unified
diff from the response, validates and applies it, runs the Maven
build, and (if everything succeeds) commits the changes and pushes
them to the same branch.

Inputs (already on disk):
  reports/trivy-fs.sarif
  reports/trivy-image.sarif
  reports/sonar.md

Outputs (written to the reports directory):
  ai-remediation-report.md   - the LLM's report
  ai-patch.diff              - the validated diff (may be empty)
  ai-remediation.json        - machine-readable summary
  changed-files.txt          - files touched by the commit
  llm-prompt.txt             - the JSON payload sent to NVIDIA
  llm-response.txt           - the raw NVIDIA response

Safety properties:
  * Never raises. Every failure degrades to "report only".
  * The diff is `git apply --check`-ed before `git apply` runs.
  * If the build fails after the apply, the working tree is reverted
    and no commit is created.
  * The push is `git push origin HEAD:<branch>`, not `--force` or
    `--mirror`; it will fail safely on protected branches.
  * The commit is authored as `github-actions[bot]`. The commit
    message includes the `[ai-remediation]` trailer so the workflow's
    `if:` guard skips the next run on the auto-generated commit.

Stdlib only. Python 3.8+.

Usage:
  python3 scripts/ai-remediation.py --repo-root . --reports reports
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

NVIDIA_ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
DEFAULT_MODEL = "meta/llama-3.1-70b-instruct"
DEFAULT_MAX_TOKENS = 4000
DEFAULT_TIMEOUT_S = 240

# Per-input truncation caps. Same numbers as scripts/run-agent.sh.
TRUNCATE_BYTES = {
    "trivy-fs.sarif": 10_240,
    "trivy-image.sarif": 10_240,
    "sonar.md": 20_480,
}

# Bot identity for the auto-commit.
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"

# Trailer that the workflow's `if:` guard looks for to break the
# re-trigger loop.
TRAILER = "[ai-remediation]"


# ---------------------------------------------------------------------------
# System + user prompts. Kept in one place so they can be diffed
# against scripts/run-agent.sh easily.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an Enterprise DevSecOps AI Agent named "Sonar-Trivy Auto Remediation Agent".

Your responsibility is to safely remediate SonarQube and Trivy findings in the CURRENT Git branch, \
and to commit and push those fixes back to the same branch. You are executing inside a GitHub Actions runner.

RULES (non-negotiable):
1. Operate ONLY on the currently checked-out branch. Never switch branches, merge, rebase, or reset.
2. Process findings in order: Critical -> High -> Medium -> Low -> Info.
3. For dependencies: choose the LOWEST stable version that fixes the vulnerability. Avoid major version upgrades unless required.
4. For SonarQube: apply only safe, behavior-preserving fixes. Never disable rules or suppress warnings.
5. For Dockerfile: prefer minimal changes, pin base images, remove unnecessary packages.
6. NEVER delete production logic, remove tests, break compilation, or modify generated files / vendor libraries / build outputs.
7. After every modification, the project MUST still build (mvn -B -ntp -DskipTests package must succeed).
8. If a fix cannot be safely automated, skip it and record the reason.
9. Prefer minimal code change -> secure solution -> backward compatibility -> readability -> maintainability.
10. You MAY commit and push the resulting fixes to the current branch. Use `git apply`-compatible unified diff format.

INPUTS (already on disk under reports/):
- trivy-fs.sarif    : Trivy filesystem scan (SARIF v2.1.0)
- trivy-image.sarif : Trivy image scan (SARIF v2.1.0, if present)
- sonar.md          : SonarQube Markdown report (authoritative Sonar input;
                       produced upstream by the sonarqube job).
                       Contains:
                         - Project summary
                         - Security issues
                         - Bugs
                         - Vulnerabilities
                         - Security Hotspots
                         - Code Smells
                         - Rule IDs, severity, file paths, line numbers,
                           descriptions, and (when available) Sonar's
                           suggested remediation.
                       Treat sonar.md as the authoritative SonarQube
                       report. Parse the Markdown directly.

WORKFLOW:
1. Parse the SARIF reports and the sonar.md Markdown.
2. For each finding, decide: FIX, SKIP, or OUT-OF-SCOPE.
3. Emit a unified diff covering every file you propose to change.
4. Emit a single Markdown report in EXACTLY the format below.
"""

USER_PROMPT = """\
Analyze the reports below and apply safe, automated remediations to the current branch. \
The runner will validate, apply, build, commit, and push the changes for you.

INPUTS (already on disk under reports/):
- reports/trivy-fs.sarif
- reports/trivy-image.sarif
- reports/sonar.md

sonar.md is the AUTHORITATIVE SonarQube report (generated upstream by the sonarqube job). \
Parse it directly. From sonar.md, extract for every issue:
  - Rule ID
  - Severity (Critical / High / Medium / Low / Info)
  - File path (as reported)
  - Line number (as reported)
  - Description
  - Suggested remediation (use Sonar's suggestion when present)

PROCESSING GUIDANCE:
- Read EVERY issue from sonar.md; never summarize and stop. After
  extracting issues, ignore summary tables - do not re-emit them.
- Preserve file paths and line numbers exactly as reported.
- Prefer Sonar's suggested remediation when one is provided.
- Correlate Sonar issues with Trivy findings; if both tools flag the
  same file, batch the fixes so multiple issues in one file are
  resolved in a single hunk.
- Process findings in severity order:
  Critical -> High -> Medium -> Low -> Info.
- Never invent issues, never skip Critical issues, and never silently
  drop a finding - if you cannot fix it, list it under Skipped Findings
  with the reason.
- Apply only safe, behavior-preserving remediations.
- Validate that the project still builds
  (mvn -B -ntp -DskipTests package must succeed).

OUTPUT FORMAT (strict):
Return EXACTLY ONE fenced ```diff code block at the TOP of your response, \
followed by the Markdown report. The diff block must contain a valid \
`git apply`-compatible unified diff covering every file you propose to change.

Inside the diff block:
- Each file must start with `diff --git a/<path> b/<path>`.
- Each file must include `--- a/<path>` and `+++ b/<path>` headers.
- Hunks must use the standard `@@ -<old_start>,<old_count> +<new_start>,<new_count> @@` format.
- Context lines must start with a single space; removed lines with `-`; added lines with `+`.
- Use Unix newlines. Do not include the diff stat (`diff --git ... | 5 ++--` is NOT a diff).

If you cannot produce a safe diff for a finding, skip it and list it under Skipped Findings - \
do NOT include it in the diff.

After the diff block, output the report in EXACTLY this format (no extra explanation outside the report):

# Sonar-Trivy Auto Remediation Report

## Scan Summary

SonarQube Issues: <count>
Trivy Findings: <count>

Critical: <count>
High: <count>
Medium: <count>
Low: <count>

## Automatically Fixed
- <one bullet per fixed issue>

## Files Modified
- <repo-relative path>

## Dependency Updates
- <package> : <old version> -> <new version>

## Docker Improvements
- <one bullet per change>

## Skipped Findings
- <issue> -- <reason>

## Remaining Critical Issues
- <list>

## Remaining High Issues
- <list>

## Manual Recommendations
- <list>

## Overall Result
SUCCESS or PARTIAL SUCCESS or MANUAL ACTION REQUIRED
"""


# ---------------------------------------------------------------------------
# Trivial parsers. The LLM does the heavy lifting; these only feed it
# a short summary of each input.
# ---------------------------------------------------------------------------

_SONAR_ISSUE_RE = re.compile(
    r"^- \*\*"
    r"(?P<severity>[A-Z]+)"
    r"\*\*"
    r"(?:\s*\[(?P<type>[A-Z_]+)\])?"
    r"\s*`?(?P<rule>[A-Za-z0-9:._-]+)`?"
    r"\s+at\s+`?"
    r"(?P<file>[^`\s:]+)"
    r"(?::(?P<line>\d+))?"
    r"`?"
    r"\s*[-—]\s*"
    r"(?P<message>.*)$",
    re.MULTILINE,
)


def _read_capped(path: Path, cap: int) -> str:
    if not path.is_file():
        return ""
    with path.open("rb") as fh:
        data = fh.read(cap)
    return data.decode("utf-8", errors="replace")


def _parse_sarif(text: str, source: str) -> list[dict[str, Any]]:
    """Very small SARIF v2.1.0 parser. Sufficient for Trivy output."""
    if not text.strip():
        return []
    try:
        sarif = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[dict[str, Any]] = []
    for run in sarif.get("runs", []):
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation") or {}
            artifact = loc.get("artifactLocation") or {}
            uri = artifact.get("uri")
            line = (loc.get("region") or {}).get("startLine")
            out.append(
                {
                    "source": source,
                    "ruleId": res.get("ruleId"),
                    "level": res.get("level"),
                    "message": (res.get("message") or {}).get("text", ""),
                    "file": uri,
                    "line": line,
                }
            )
    return out


def _parse_sonar_md(text: str) -> list[dict[str, Any]]:
    """Extract issue bullets from the `## Detailed Findings` section."""
    if not text:
        return []
    section = text
    marker = "## Detailed Findings"
    idx = text.find(marker)
    if idx >= 0:
        section = text[idx:]
        # Stop at the next H2.
        next_h2 = section.find("\n## ", len(marker))
        if next_h2 >= 0:
            section = section[:next_h2]
    out: list[dict[str, Any]] = []
    for m in _SONAR_ISSUE_RE.finditer(section):
        try:
            line = int(m.group("line")) if m.group("line") else None
        except ValueError:
            line = None
        out.append(
            {
                "severity": m.group("severity"),
                "type": m.group("type"),
                "rule": m.group("rule"),
                "file": m.group("file"),
                "line": line,
                "message": m.group("message").strip(),
            }
        )
    return out


# ---------------------------------------------------------------------------
# NVIDIA call.
# ---------------------------------------------------------------------------

def _call_nvidia(
    system: str, user: str, *, model: str, api_key: str, max_tokens: int, timeout_s: int
) -> str:
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        NVIDIA_ENDPOINT,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
        raw = resp.read().decode("utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"NVIDIA returned non-JSON ({len(raw)} bytes): {exc}") from exc
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"NVIDIA response missing choices[0].message.content: {raw[:500]}") from exc


# ---------------------------------------------------------------------------
# Diff extraction + application.
# ---------------------------------------------------------------------------

# Non-greedy match of a fenced ```diff ... ``` block anywhere in the
# response.  DOTALL so the diff can span newlines.
_DIFF_FENCE_RE = re.compile(r"```diff\s*\n(.*?)\n```", re.DOTALL)


def _extract_diff(response: str) -> str:
    m = _DIFF_FENCE_RE.search(response)
    if not m:
        return ""
    return m.group(1).rstrip() + "\n"


def _strip_diff(response: str) -> str:
    """Return the response with the fenced diff block removed."""
    return _DIFF_FENCE_RE.sub("", response).strip()


def _run(
    args: list[str], *, cwd: Path, env: dict[str, str] | None = None, check: bool = True
) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        args,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"{' '.join(args)} failed (exit {proc.returncode})\n"
            f"  stdout: {proc.stdout[-2000:]}\n"
            f"  stderr: {proc.stderr[-2000:]}"
        )
    return proc


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

def _log(msg: str) -> None:
    print(f"::group::ai-remediation: {msg}" if False else f"[ai-remediation] {msg}", flush=True)


def _build_summary(trivy: list[dict[str, Any]], sonar: list[dict[str, Any]]) -> str:
    """Build a short summary the user can read in CI logs."""
    lines = [
        f"Trivy findings: {len(trivy)}",
        f"SonarQube issues: {len(sonar)}",
    ]
    if sonar:
        sev_counts: dict[str, int] = {}
        for it in sonar:
            sev_counts[it["severity"]] = sev_counts.get(it["severity"], 0) + 1
        lines.append("Sonar severity breakdown: " + ", ".join(
            f"{k}={v}" for k, v in sorted(sev_counts.items(), reverse=True)
        ))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--branch", default=os.environ.get("BRANCH", ""))
    ap.add_argument("--model", default=os.environ.get("NVDAI_MODEL", DEFAULT_MODEL))
    ap.add_argument(
        "--max-tokens", type=int,
        default=int(os.environ.get("NVDAI_MAX_TOKENS", DEFAULT_MAX_TOKENS)),
    )
    ap.add_argument(
        "--timeout", type=int,
        default=int(os.environ.get("NVDAI_TIMEOUT", DEFAULT_TIMEOUT_S)),
    )
    ap.add_argument(
        "--no-push", action="store_true",
        help="Skip the push step (useful for local smoke tests).",
    )
    args = ap.parse_args()

    repo = Path(args.repo_root).resolve()
    reports = (repo / args.reports).resolve()
    if not reports.is_dir():
        reports = repo / "reports"
        reports.mkdir(exist_ok=True)

    api_key = os.environ.get("NVDAI_API_KEY", "")
    if not api_key:
        _log("NVDAI_API_KEY is not set; cannot invoke the agent.")
        return 1

    # Discover branch from the env, then from `git rev-parse`.
    branch = args.branch.strip()
    if not branch:
        try:
            branch = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=str(repo), text=True, stderr=subprocess.DEVNULL,
            ).strip()
        except Exception:
            branch = ""
    _log(f"target branch: {branch or '(unknown)'}")

    # ---- Load + truncate inputs ---------------------------------------
    inputs: dict[str, str] = {}
    for name, cap in TRUNCATE_BYTES.items():
        text = _read_capped(reports / name, cap)
        inputs[name] = text
        if not text:
            _log(f"missing or empty input: {name}")
    _log(
        f"loaded inputs (bytes): "
        + ", ".join(f"{k}={len(v)}" for k, v in inputs.items())
    )

    trivy = _parse_sarif(inputs["trivy-fs.sarif"], "trivy-fs") + _parse_sarif(
        inputs["trivy-image.sarif"], "trivy-image"
    )
    sonar = _parse_sonar_md(inputs["sonar.md"])
    _log(_build_summary(trivy, sonar))

    # ---- Build the user prompt (inputs are inlined; matches the
    # existing run-sonar-report.sh pattern) -----------------------------
    user_prompt = USER_PROMPT + "\n\n----- BEGIN sonar.md -----\n" + inputs["sonar.md"] + \
        "\n----- END sonar.md -----\n\n" + \
        "----- BEGIN trivy-fs.sarif -----\n" + inputs["trivy-fs.sarif"] + \
        "\n----- END trivy-fs.sarif -----\n\n" + \
        "----- BEGIN trivy-image.sarif -----\n" + inputs["trivy-image.sarif"] + \
        "\n----- END trivy-image.sarif -----\n"

    # ---- Persist the prompt for debugging ------------------------------
    (reports / "llm-prompt.txt").write_text(user_prompt, encoding="utf-8")

    # ---- Call NVIDIA ----------------------------------------------------
    started = time.time()
    try:
        response = _call_nvidia(
            SYSTEM_PROMPT,
            user_prompt,
            model=args.model,
            api_key=api_key,
            max_tokens=args.max_tokens,
            timeout_s=args.timeout,
        )
    except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
        _log(f"NVIDIA call failed: {exc}")
        (reports / "llm-response.txt").write_text(f"ERROR: {exc}\n", encoding="utf-8")
        # Write a minimal JSON summary and exit non-zero.
        (reports / "ai-remediation.json").write_text(json.dumps({
            "branch": branch,
            "pushed": False,
            "has_fixes": False,
            "fixes": [],
            "build_ok": False,
            "error": str(exc),
        }, indent=2), encoding="utf-8")
        (reports / "ai-remediation-report.md").write_text(
            "MANUAL ACTION REQUIRED - NVIDIA call failed: " + str(exc) + "\n",
            encoding="utf-8",
        )
        return 1
    elapsed = time.time() - started
    _log(f"NVIDIA responded in {elapsed:.1f}s, {len(response)} bytes")

    (reports / "llm-response.txt").write_text(response, encoding="utf-8")

    # ---- Extract the diff ---------------------------------------------
    diff_text = _extract_diff(response)
    report_text = _strip_diff(response)
    (reports / "ai-patch.diff").write_text(diff_text, encoding="utf-8")
    (reports / "ai-remediation-report.md").write_text(report_text + "\n", encoding="utf-8")

    summary: dict[str, Any] = {
        "branch": branch,
        "pushed": False,
        "has_fixes": bool(diff_text.strip()),
        "fixes": [],
        "build_ok": False,
        "diff_bytes": len(diff_text),
    }

    if not diff_text.strip():
        _log("no fenced ```diff block in response; skipping apply/commit/push")
        (reports / "ai-remediation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        (reports / "changed-files.txt").write_text("", encoding="utf-8")
        return 0

    # ---- git apply --check -------------------------------------------
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".patch", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(diff_text)
        tmp_path = Path(tmp.name)
    try:
        proc = _run(
            ["git", "apply", "--check", str(tmp_path)],
            cwd=repo, check=False,
        )
        if proc.returncode != 0:
            _log(f"git apply --check failed: {proc.stderr.strip() or proc.stdout.strip()}")
            summary["apply_error"] = (proc.stderr or proc.stdout).strip()[:2000]
            (reports / "ai-remediation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
            (reports / "changed-files.txt").write_text("", encoding="utf-8")
            return 0
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass

    # ---- git apply (for real) ----------------------------------------
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".patch", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(diff_text)
        tmp_path = Path(tmp.name)
    try:
        _run(["git", "apply", str(tmp_path)], cwd=repo)
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass
    _log("applied diff to working tree")

    # ---- mvn package (validate) --------------------------------------
    build = _run(
        ["mvn", "-B", "-ntp", "-DskipTests", "package"],
        cwd=repo, env={**os.environ, "JAVA_HOME": os.environ.get("JAVA_HOME", "")},
        check=False,
    )
    summary["build_ok"] = build.returncode == 0
    if build.returncode != 0:
        _log("mvn package failed; reverting working tree")
        _run(["git", "checkout", "--", "."], cwd=repo, check=False)
        _run(["git", "clean", "-fd"], cwd=repo, check=False)
        (reports / "ai-remediation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        (reports / "changed-files.txt").write_text("", encoding="utf-8")
        return 0

    # ---- Collect changed files (best-effort) -------------------------
    try:
        changed = subprocess.check_output(
            ["git", "diff", "--name-only"],
            cwd=str(repo), text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        changed = ""
    summary["fixes"] = [f for f in changed.splitlines() if f]
    (reports / "changed-files.txt").write_text(changed + "\n", encoding="utf-8")

    # ---- git add + commit -------------------------------------------
    _run(["git", "add", "-A"], cwd=repo, check=False)
    status = _run(["git", "status", "--porcelain"], cwd=repo, check=False)
    if not status.stdout.strip():
        _log("nothing to commit after apply (git apply produced an empty diff)")
        (reports / "ai-remediation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return 0

    commit_env = {
        **os.environ,
        "GIT_AUTHOR_NAME": BOT_NAME,
        "GIT_AUTHOR_EMAIL": BOT_EMAIL,
        "GIT_COMMITTER_NAME": BOT_NAME,
        "GIT_COMMITTER_EMAIL": BOT_EMAIL,
    }
    body = textwrap.dedent(
        f"""\
        {report_text}

        {TRAILER}

        Co-Authored-By: Claude <noreply@anthropic.com>
        """
    )
    commit = _run(
        ["git", "commit", "-m", "chore(ai-remediation): apply safe SonarQube + Trivy fixes",
         "-m", body],
        cwd=repo, env=commit_env, check=False,
    )
    if commit.returncode != 0:
        _log(f"git commit failed: {commit.stderr.strip() or commit.stdout.strip()}")
        summary["commit_error"] = (commit.stderr or commit.stdout).strip()[:2000]
        (reports / "ai-remediation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return 0
    _log("created commit")

    # ---- git push -----------------------------------------------------
    if args.no_push:
        _log("--no-push set; skipping push step")
        (reports / "ai-remediation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return 0
    if not branch:
        _log("no target branch resolved; skipping push")
        (reports / "ai-remediation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return 0

    push = _run(
        ["git", "push", "origin", f"HEAD:{branch}"],
        cwd=repo, check=False,
    )
    summary["pushed"] = push.returncode == 0
    if push.returncode != 0:
        _log(f"git push failed: {push.stderr.strip() or push.stdout.strip()}")
        summary["push_error"] = (push.stderr or push.stdout).strip()[:2000]
    else:
        _log(f"pushed to origin/{branch}")

    (reports / "ai-remediation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
