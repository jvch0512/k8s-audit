#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { auditYaml, rank, SEVERITIES, sortFindings } from "./audit.js";
import type { Finding, Severity } from "./rules.js";

function collect(path: string): string[] {
  const st = statSync(path);
  if (st.isFile()) return [path];
  return readdirSync(path, { withFileTypes: true })
    .filter((e) => !e.isSymbolicLink() && e.name !== "node_modules" && !e.name.startsWith("."))
    .flatMap((e) => (e.isDirectory() ? collect(join(path, e.name)) : /\.ya?ml$/i.test(e.name) ? [join(path, e.name)] : []));
}

function main(argv: string[]): number {
  let failOn: Severity = "medium";
  let json = false;
  const paths: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--json") json = true;
    else if (a === "--fail-on") {
      const v = argv[++i] as Severity;
      if (!SEVERITIES.includes(v)) { console.error("--fail-on expects low|medium|high|critical"); return 2; }
      failOn = v;
    } else if (a.startsWith("-")) { console.error("usage: k8s-audit [--json] [--fail-on LEVEL] <file|dir>..."); return 2; }
    else paths.push(a);
  }
  if (paths.length === 0) { console.error("usage: k8s-audit [--json] [--fail-on LEVEL] <file|dir>..."); return 2; }
  const all: (Finding & { file: string })[] = [];
  let errors = 0;
  for (const p of paths) {
    let files: string[];
    try { files = collect(p); } catch (e) { console.error(`error: ${p}: ${(e as Error).message}`); return 2; }
    for (const f of files) {
      const r = auditYaml(readFileSync(f, "utf8"));
      errors += r.errors.length;
      for (const e of r.errors) console.error(`${f}: ${e.message}`);
      all.push(...sortFindings(r.findings).map((x) => ({ ...x, file: f })));
    }
  }
  if (json) console.log(JSON.stringify(all, null, 2));
  else {
    for (const f of all) {
      console.log(`[${f.severity.toUpperCase().padEnd(8)}] ${f.rule} ${f.kind}/${f.name}${f.container ? ` (${f.container})` : ""}  ${f.file}\n    ${f.message}\n    fix: ${f.fix}`);
    }
    console.log(`${all.length} finding(s)`);
  }
  if (errors > 0) return 2;
  return all.some((f) => rank(f.severity) >= rank(failOn)) ? 1 : 0;
}

process.exitCode = main(process.argv.slice(2));
