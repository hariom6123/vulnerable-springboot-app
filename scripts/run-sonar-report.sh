#!/usr/bin/env bash
#
# Invokes the Sonar Report Generator agent via the NVIDIA API.
#
# Reads SonarQube JSON artifacts (issues.json, quality-gate.json,
# measures.json, hotspots.json, project.json, report-metadata.json) from
# ./reports/ and produces a single deterministic Markdown report at
# ./reports/sonar-report.md.
#
# Required env:
#   NVDAI_API_KEY      - NVIDIA API key
# Optional env:
#   NVDAI_MODEL        - model id (default: meta/llama-3.1-70b-instruct)
#   NVDAI_MAX_TOKENS   - max tokens (default: 4000)
#
# This is a READ-ONLY agent. It does not modify any source code; it
# only writes reports/sonar-report.md.

set -euo pipefail

if [ -z "${NVDAI_API_KEY:-}" ]; then
  echo "::error::NVDAI_API_KEY is not set; cannot invoke the agent." >&2
  exit 1
fi

REPORTS_DIR="${REPORTS_DIR:-reports}"
mkdir -p "$REPORTS_DIR"

MODEL="${NVDAI_MODEL:-meta/llama-3.1-70b-instruct}"
MAX_TOKENS="${NVDAI_MAX_TOKENS:-4000}"

echo "📂 SonarQube inputs under $REPORTS_DIR/:" >&2
ls -la "$REPORTS_DIR" >&2 || true

# --- Step 1: Normalize all SonarQube JSONs into a single inlined JSON.
# The agent receives this inline so it can render the report
# deterministically without needing tool access.
echo "📦 Normalizing SonarQube JSON inputs..." >&2
PARSER_STDERR_FILE="$(mktemp)"
set +e
NORMALIZED_JSON="$(node scripts/parse-sonar-report.mjs --root "$REPORTS_DIR" 2>"$PARSER_STDERR_FILE")"
NODE_RC=$?
set -e
# Forward parser warnings to our own stderr.
if [ -s "$PARSER_STDERR_FILE" ]; then
  cat "$PARSER_STDERR_FILE" >&2
fi
rm -f "$PARSER_STDERR_FILE"
if [ "$NODE_RC" -ne 0 ] || [ -z "$NORMALIZED_JSON" ] || [ "${NORMALIZED_JSON:0:1}" != "{" ]; then
  echo "::warning::No SonarQube JSON inputs found under $REPORTS_DIR/. Agent will be invoked with an empty payload." >&2
  NORMALIZED_JSON='{"metadata":null,"project":null,"qualityGate":null,"measures":{},"issues":[],"hotspots":[]}'
fi
# Cap the size to avoid blowing up the request payload (10KB per input, but the
# normalized form is usually smaller — issues array can grow).
NORMALIZED_JSON_LIMIT=60000
if [ "${#NORMALIZED_JSON}" -gt "$NORMALIZED_JSON_LIMIT" ]; then
  echo "::warning::Normalized JSON is ${#NORMALIZED_JSON} bytes; truncating to $NORMALIZED_JSON_LIMIT." >&2
  NORMALIZED_JSON="${NORMALIZED_JSON:0:$NORMALIZED_JSON_LIMIT}"
fi

# --- Step 2: Build the system + user prompts.
SYSTEM_PROMPT='You are the "Sonar Report Generator Agent". Convert the JSON block in the user message into a single deterministic Markdown report at reports/sonar-report.md.

RULES:
1. DO NOT modify source code, fix vulnerabilities, or invent data.
2. Every count and metric MUST come from the JSON. If a field is missing, write "Not Available". Do NOT terminate.
3. Numbers MUST exactly match the JSON. Never estimate.
4. Sort all aggregates before emission: issues within a severity bucket ascending by (file, line); Files-with-Highest-Issues descending by count then ascending by file path; Rule-Frequency descending by count then ascending by rule; OWASP-Mapping descending by count.
5. Output ONLY the Markdown content. No preamble, no closing remarks, no code fences around the whole report. First line MUST be "# SonarQube Security Analysis Report".

REPORT STRUCTURE (exact order, exact field names):

# SonarQube Security Analysis Report

Header table:
| Field | Value |
| --- | --- |
| Project Name | <project.name or "Not Available"> |
| Repository   | <metadata.repository or "Not Available"> |
| Branch       | <metadata.branch or "Not Available"> |
| Commit ID    | <metadata.commit or "Not Available"> |
| Analysis Date| <project.analysisDate or "Not Available"> |
| Sonar Version| "Not Available" |

---

## Executive Summary

| Item | Value |
| --- | --- |
| Quality Gate | <qualityGate.status: PASS / FAIL / NONE> |

### Overall Risk

| Severity | Count |
| --- | ---:|
| Critical | <count of severity=="CRITICAL"> |
| High     | <count of severity=="MAJOR" (Sonar maps MAJOR to "High" risk)> |
| Medium   | <count of severity=="MINOR"> |
| Low      | <count of severity=="INFO"> |

**Total Issues:** <sum>

---

## Dashboard Summary

| Metric | Count |
| --- | ---:|
| Bugs | <measures.bugs or "Not Available"> |
| Vulnerabilities | <measures.vulnerabilities or "Not Available"> |
| Code Smells | <measures.code_smells or "Not Available"> |
| Security Hotspots | <hotspots.length or "Not Available"> |
| Coverage | <measures.coverage + "%" or "Not Available"> |
| Duplicated Code | <measures.duplicated_lines_density + "%" or "Not Available"> |
| Reliability Rating | <measures.reliability_rating or "Not Available"> |
| Security Rating | <measures.security_rating or "Not Available"> |
| Maintainability Rating | <measures.sqale_rating or "Not Available"> |

---

## Severity Summary

| Severity | Count |
| --- | ---:|
| ⚪ BLOCKER | <count> |
| 🔴 CRITICAL | <count> |
| 🟠 MAJOR | <count> |
| 🟡 MINOR | <count> |
| 🔵 INFO | <count> |

---

## Detailed Findings

Group by severity in this exact order: BLOCKER, CRITICAL, MAJOR, MINOR, INFO. Within each, sort ascending by (file, line). For each issue:

### Finding #<n>

| Field | Value |
| --- | --- |
| Issue Number | <key> |
| Issue Type | <type: VULNERABILITY / BUG / CODE_SMELL / SECURITY_HOTSPOT> |
| Severity | <emoji + severity: 🔴 CRITICAL, 🟠 MAJOR, 🟡 MINOR, 🔵 INFO, ⚪ BLOCKER> |
| Rule ID | <rule> |
| Rule Name | <ruleName or "Not Available"> |
| File | <file> |
| Line Number | <line> |
| Component | <component> |
| Status | <status or "Not Available"> |
| Author | <author or "Not Available"> |
| Created Date | <creationDate or "Not Available"> |
| Updated Date | <updateDate or "Not Available"> |
| Technical Debt | <debt or "Not Available"> |
| Description | <message> |
| Recommended Fix | "Not Available" |
| Tags | <tags comma-joined, or "Not Available"> |

---

## Security Hotspots

For each hotspot:

### Hotspot #<n>

| Field | Value |
| --- | --- |
| Key | <key> |
| Rule | <ruleKey> |
| File | <file> |
| Line | <line> |
| Probability | <probability: HIGH/MEDIUM/LOW> |
| Status | <status> |
| Author | <author or "Not Available"> |
| Created | <creationDate or "Not Available"> |
| Message | <message or "Not Available"> |

---

## Bugs

For type=="BUG", one bullet each, sorted ascending by (file, line):
  - `<rule>` — `<message>` — `<file>:<line>`

## Vulnerabilities

Same shape for type=="VULNERABILITY".

## Code Smells

Same shape for type=="CODE_SMELL".

---

## Files With Highest Issues

Aggregate issue counts per file. Sort descending by count, then ascending by file path.

| File | Total Issues |
| --- | ---:|
| <file> | <count> |

## Rule Frequency

Aggregate per rule. Sort descending by count, then ascending by rule.

| Rule | Count |
| --- | ---:|
| <rule> | <count> |

## OWASP Mapping

Aggregate any issue tags matching ^owasp-.

| OWASP Category | Issues |
| --- | ---:|
| <tag> | <count> |

---

## AI Summary

Max 10 bullets: highest priority risks (file+rule), files requiring immediate attention, critical vulnerability count, coverage observations, technical debt observations. NEVER recommend fixes — only summarize.

---

## Report Footer

| Field | Value |
| --- | --- |
| Generated By | Sonar Report Generator Agent |
| Generated On | <UTC ISO 8601 timestamp, e.g. 2026-07-13T08:00:00Z>'

USER_PROMPT='Render the SonarQube Security Analysis Report from the following normalized JSON. Follow the system prompt exactly. If a field is missing, write "Not Available". Do not invent data.

\`\`\`json
'"$NORMALIZED_JSON"'
\`\`\`'

# Write the two prompts to files so python can read them with no shell escaping.
printf '%s' "$SYSTEM_PROMPT" > system-prompt.txt
printf '%s' "$USER_PROMPT"   > user-prompt.txt

# Build payload.json from the prompt files.
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY="python"
fi
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "::error::Neither python3 nor python is available; cannot build payload." >&2
  exit 1
fi
"$PY" - <<'PYEOF'
import json, os
with open("system-prompt.txt", "r", encoding="utf-8") as f:
    system_content = f.read()
with open("user-prompt.txt", "r", encoding="utf-8") as f:
    user_content = f.read()
payload = {
    "model": os.environ.get("NVDAI_MODEL", "meta/llama-3.1-70b-instruct"),
    "max_tokens": int(os.environ.get("NVDAI_MAX_TOKENS", "4000")),
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
echo "🤖 Agent - Sonar Report Generator"
echo "────────────────────────────────────────────"
echo "📡 Sending request to NVIDIA API..." >&2
echo "   model:        $MODEL" >&2
echo "   max_tokens:   $MAX_TOKENS" >&2
echo "   payload size: $(wc -c < payload.json 2>/dev/null || echo 'n/a') bytes" >&2

START_TS=$(date +%s)
RESPONSE=$(curl -sS --max-time 240 https://integrate.api.nvidia.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $NVDAI_API_KEY" \
  -d @payload.json 2>&1) || RESPONSE='{"error":"curl failed"}'
END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
echo "✅ API responded in ${ELAPSED}s" >&2
echo "📥 Response size: $(echo -n "$RESPONSE" | wc -c) bytes" >&2
# Echo a small preview of the response (first 200 chars, then last 200).
RESP_PREVIEW="${RESPONSE:0:200}"
echo "🔎 Response preview (head): $RESP_PREVIEW" >&2

# Persist the report as an artifact.
echo "$RESPONSE" | jq -r '.choices[0].message.content // ""' 2>/dev/null \
  > "$REPORTS_DIR/sonar-report.md"

# Validate the report is non-empty.
if [ ! -s "$REPORTS_DIR/sonar-report.md" ]; then
  echo "::warning::Agent response was empty. Saving raw API response for debugging." >&2
  echo "$RESPONSE" > "$REPORTS_DIR/sonar-report.raw.json" || true
  cat > "$REPORTS_DIR/sonar-report.md" <<'FALLBACK'
# SonarQube Security Analysis Report

| Field | Value |
|---|---|
| Project Name | Not Available |
| Repository | Not Available |
| Branch | Not Available |
| Commit ID | Not Available |
| Analysis Date | Not Available |
| Sonar Version | Not Available |

---

## Executive Summary

| Item | Value |
|---|---|
| Quality Gate | Not Available |

**Total Issues:** Not Available

All other sections: Not Available.

The agent invocation returned an empty response from the upstream API. The raw API response is preserved in `sonar-report.raw.json` for debugging.
FALLBACK
fi

echo "📝 Report written to $REPORTS_DIR/sonar-report.md" >&2
echo "   size: $(wc -c < "$REPORTS_DIR/sonar-report.md" 2>/dev/null || echo 'n/a') bytes" >&2
echo "   lines: $(wc -l < "$REPORTS_DIR/sonar-report.md" 2>/dev/null || echo 'n/a')" >&2

echo "────────────────────────────────────────────"

# Clean up the payload and prompt files.
rm -f payload.json system-prompt.txt user-prompt.txt
