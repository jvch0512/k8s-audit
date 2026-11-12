import { parseAllDocuments } from "yaml";
import { auditDocument, Finding, Severity } from "./rules.js";

export const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

export interface ParseError { message: string }

/** Audit a (possibly multi-document) YAML string. Parse problems are returned, not thrown, so one bad file never hides others. */
export function auditYaml(text: string): { findings: Finding[]; errors: ParseError[]; documents: number } {
  const findings: Finding[] = [];
  const errors: ParseError[] = [];
  let documents = 0;
  // maxAliasCount keeps "billion laughs" style alias bombs in untrusted manifests from exhausting memory.
  for (const doc of parseAllDocuments(text, { prettyErrors: true })) {
    if (doc.errors.length > 0) {
      errors.push(...doc.errors.map((e) => ({ message: e.message.split("\n")[0] ?? "invalid YAML" })));
      continue;
    }
    let js: unknown;
    try {
      js = doc.toJS({ maxAliasCount: 100 });
    } catch (e) {
      errors.push({ message: (e as Error).message });
      continue;
    }
    if (js === null || typeof js !== "object" || Array.isArray(js)) continue;
    documents++;
    const obj = js as Record<string, any>;
    if (obj.kind === "List" && Array.isArray(obj.items)) {
      for (const item of obj.items) if (item && typeof item === "object") findings.push(...auditDocument(item));
    } else {
      findings.push(...auditDocument(obj));
    }
  }
  return { findings, errors, documents };
}

export function rank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

export function sortFindings(f: Finding[]): Finding[] {
  return [...f].sort((a, b) => rank(b.severity) - rank(a.severity) || a.rule.localeCompare(b.rule) || a.name.localeCompare(b.name));
}
