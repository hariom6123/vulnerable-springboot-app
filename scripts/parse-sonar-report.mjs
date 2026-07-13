#!/usr/bin/env node
/**
 * parse-sonar-report.mjs
 *
 * Reads the SonarQube JSON artifacts produced by the `sonarqube` job
 * (under reports/ or sonar-report/) and emits ONE normalized JSON
 * object on stdout. Used by the sonar-report-generator agent so the
 * model receives all the data in-context.
 *
 * Input files (any missing file is treated as empty):
 *   - issues.json
 *   - quality-gate.json
 *   - measures.json
 *   - hotspots.json
 *   - project.json
 *   - report-metadata.json
 *
 * Output (JSON to stdout):
 *   {
 *     "metadata": { project, repository, branch, commit, generated, ... },
 *     "project":  { key, name, organization, visibility, analysisDate, ... },
 *     "qualityGate": { status, conditions: [...] },
 *     "measures":   { "bugs": N, "vulnerabilities": N, ... },
 *     "issues":     [ { key, type, severity, rule, message, file, line, status, author,
 *                       creationDate, updateDate, debt, tags, flows }, ... ],
 *     "hotspots":   [ { key, ruleKey, file, line, probability, status, author,
 *                       creationDate, message }, ... ]
 *   }
 *
 * Usage:
 *   node scripts/parse-sonar-report.mjs [--root <dir>]
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join, basename } from "node:path";

const SEARCH_DIRS = ["reports", "sonar-report", "."];

const FILE_CANDIDATES = {
  issues:          ["issues.json", "sonar-report.json", "sonarqube-report.json"],
  qualityGate:     ["quality-gate.json", "qualitygate.json"],
  measures:        ["measures.json"],
  hotspots:        ["hotspots.json"],
  project:         ["project.json"],
  metadata:        ["report-metadata.json", "metadata.json"],
};

function parseArgs(argv) {
  const args = { root: process.cwd() };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--root") args.root = argv[++i];
  }
  return args;
}

async function readJsonFile(path) {
  try {
    const text = await readFile(path, "utf-8");
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function walk(dir, depth = 0) {
  if (depth > 3) return [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const out = [];
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name === ".git") continue;
      out.push(...(await walk(p, depth + 1)));
    } else if (e.isFile()) {
      out.push(p);
    }
  }
  return out;
}

async function findFile(root, candidates) {
  for (const d of SEARCH_DIRS) {
    const dir = join(root, d);
    try {
      await stat(dir);
    } catch {
      continue;
    }
    // Direct match first.
    for (const name of candidates) {
      const p = join(dir, name);
      try {
        await stat(p);
        return p;
      } catch {
        // continue
      }
    }
    // Recursive one-level-deep search (artifact downloads put files in
    // a subdirectory named after the artifact).
    const files = await walk(dir);
    for (const f of files) {
      const base = basename(f).toLowerCase();
      if (candidates.some((n) => n.toLowerCase() === base)) return f;
    }
  }
  return null;
}

function splitComponent(component) {
  if (!component || typeof component !== "string") return { file: null, component };
  const idx = component.indexOf(":");
  if (idx < 0) return { file: component, component };
  return { file: component.slice(idx + 1), component };
}

function normalizeIssues(j) {
  if (!j) return [];
  const raw = j.issues || [];
  return raw.map((it) => {
    const { file, component } = splitComponent(it.component);
    return {
      key: it.key || null,
      type: it.type || null,
      severity: (it.severity || "INFO").toUpperCase(),
      rule: it.rule || null,
      ruleName: it.ruleName || it.ruleName || null,
      message: it.message || null,
      file,
      line: it.line || null,
      status: it.status || null,
      author: it.author || null,
      creationDate: it.creationDate || null,
      updateDate: it.updateDate || null,
      debt: it.debt || null,
      tags: Array.isArray(it.tags) ? it.tags : [],
      component,
      textRange: it.textRange || null,
    };
  });
}

function normalizeHotspots(j) {
  if (!j) return [];
  const raw = j.hotspots || [];
  return raw.map((h) => {
    const { file, component } = splitComponent(h.component);
    return {
      key: h.key || null,
      ruleKey: h.ruleKey || null,
      message: h.message || null,
      probability: h.vulnerabilityProbability || null,
      status: h.status || null,
      author: h.author || null,
      creationDate: h.creationDate || null,
      file,
      line: h.line || null,
      component,
    };
  });
}

function normalizeMeasures(j) {
  if (!j) return {};
  const component = j.component || {};
  const arr = component.measures || j.measures || [];
  const out = {};
  for (const m of arr) {
    if (!m || !m.metric) continue;
    out[m.metric] = m.value;
  }
  return out;
}

function normalizeQualityGate(j) {
  if (!j) return null;
  const ps = j.projectStatus || j;
  return {
    status: (ps.status || "NONE").toUpperCase(),
    conditions: Array.isArray(ps.conditions) ? ps.conditions : [],
  };
}

function normalizeProject(j) {
  if (!j) return null;
  const c = j.component || j;
  return {
    key: c.key || null,
    name: c.name || null,
    organization: c.organization || null,
    visibility: c.visibility || null,
    analysisDate: c.analysisDate || null,
    version: c.version || null,
    qualifier: c.qualifier || null,
  };
}

function normalizeMetadata(j) {
  if (!j) return null;
  return {
    project: j.project || null,
    repository: j.repository || null,
    branch: j.branch || null,
    commit: j.commit || null,
    generated: j.generated || null,
  };
}

(async () => {
  const args = parseArgs(process.argv.slice(2));
  const root = args.root;

  // Load all six inputs in parallel.
  const findPromises = Object.fromEntries(
    Object.entries(FILE_CANDIDATES).map(([k, names]) => [k, findFile(root, names)])
  );
  const paths = await Promise.all(Object.values(findPromises));
  const pathMap = Object.fromEntries(
    Object.keys(findPromises).map((k, i) => [k, paths[i]])
  );

  const readPromises = Object.entries(pathMap).map(async ([k, p]) => [k, p ? await readJsonFile(p) : null]);
  const raws = Object.fromEntries(await Promise.all(readPromises));

  const out = {
    metadata:      normalizeMetadata(raws.metadata),
    project:       normalizeProject(raws.project),
    qualityGate:   normalizeQualityGate(raws.qualityGate),
    measures:      normalizeMeasures(raws.measures),
    issues:        normalizeIssues(raws.issues),
    hotspots:      normalizeHotspots(raws.hotspots),
    sources: {
      issues:      pathMap.issues,
      qualityGate: pathMap.qualityGate,
      measures:    pathMap.measures,
      hotspots:    pathMap.hotspots,
      project:     pathMap.project,
      metadata:    pathMap.metadata,
    },
  };

  process.stdout.write(JSON.stringify(out, null, 2));
})();
