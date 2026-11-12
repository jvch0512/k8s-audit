import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditYaml, imageIssue, sortFindings } from "../src/index.js";

const SAMPLES = join(import.meta.dirname, "..", "..", "samples");
const rules = (yaml: string) => auditYaml(yaml).findings.map((f) => f.rule);

const pod = (container: string, podSpec = "") => `
apiVersion: v1
kind: Pod
metadata: { name: p }
spec:
${podSpec}
  containers:
    - name: c
${container}
`;

test("image tag analysis", () => {
  assert.equal(imageIssue("nginx"), "untagged");
  assert.equal(imageIssue("nginx:latest"), "latest");
  assert.equal(imageIssue("registry.local:5000/team/app"), "untagged", "registry port is not a tag");
  assert.equal(imageIssue("registry.local:5000/team/app:1.2"), "ok");
  assert.equal(imageIssue("app@sha256:abc"), "digest");
});

test("privileged, root and capabilities", () => {
  const r = rules(pod(`      image: a:1
      securityContext:
        privileged: true
        runAsUser: 0
        capabilities: { add: [SYS_ADMIN] }`));
  for (const id of ["K8S006", "K8S008", "K8S010"]) assert.ok(r.includes(id), id);
  assert.ok(!r.includes("K8S007"), "privileged already covers escalation");
});

test("pod-level security context is inherited by containers", () => {
  const r = rules(pod(`      image: a@sha256:00
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
      resources: { limits: { cpu: 1, memory: 1Gi } }
      readinessProbe: { tcpSocket: { port: 1 } }`, `  serviceAccountName: x
  securityContext: { runAsNonRoot: true, seccompProfile: { type: RuntimeDefault } }`));
  assert.deepEqual(r, []);
});

test("host namespaces, hostPath severity and hostPort", () => {
  const f = auditYaml(pod(`      image: a:1
      ports: [{ containerPort: 80, hostPort: 80 }]`, `  hostNetwork: true
  hostPID: true
  hostIPC: true
  volumes:
    - { name: a, hostPath: { path: /var/run/docker.sock } }
    - { name: b, hostPath: { path: /data } }`)).findings;
  const ids = f.map((x) => x.rule);
  for (const id of ["K8S001", "K8S002", "K8S003", "K8S018"]) assert.ok(ids.includes(id), id);
  const hp = f.filter((x) => x.rule === "K8S004").map((x) => x.severity).sort();
  assert.deepEqual(hp, ["critical", "medium"]);
});

test("secrets in env: literals flagged, secretKeyRef accepted", () => {
  const r = rules(pod(`      image: a:1
      env:
        - { name: DB_PASSWORD, value: hunter2 }
        - { name: API_TOKEN, valueFrom: { secretKeyRef: { name: s, key: k } } }
        - { name: LOG_LEVEL, value: debug }`));
  assert.equal(r.filter((x) => x === "K8S016").length, 1);
});

test("init containers are audited but need no probes", () => {
  const y = `
apiVersion: apps/v1
kind: Deployment
metadata: { name: d }
spec:
  template:
    spec:
      initContainers:
        - { name: setup, image: "busybox:latest", securityContext: { privileged: true } }
      containers:
        - { name: app, image: "a:1" }
`;
  const f = auditYaml(y).findings;
  const init = f.filter((x) => x.container === "setup (init)");
  assert.ok(init.some((x) => x.rule === "K8S006"));
  assert.ok(!init.some((x) => x.rule === "K8S017"));
});

test("CronJob, List and multi-document inputs", () => {
  const cj = `
apiVersion: batch/v1
kind: CronJob
metadata: { name: nightly }
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers: [{ name: j, image: "x:latest" }]
`;
  assert.ok(rules(cj).includes("K8S013"));
  const list = `
apiVersion: v1
kind: List
items:
  - { apiVersion: v1, kind: Service, metadata: { name: s }, spec: { type: NodePort } }
`;
  assert.deepEqual(rules(list), ["K8S020"]);
  assert.equal(auditYaml(`${cj}\n---\n${list}`).documents, 2);
});

test("RBAC and exposure rules", () => {
  assert.deepEqual(rules("kind: ClusterRoleBinding\nmetadata: { name: b }\nroleRef: { name: cluster-admin }"), ["K8S022"]);
  const r = rules("kind: ClusterRole\nmetadata: { name: r }\nrules:\n  - { verbs: ['*'], resources: ['*'] }\n  - { verbs: [get], resources: [secrets] }");
  assert.deepEqual(r, ["K8S023", "K8S024"]);
  assert.deepEqual(rules("kind: Ingress\nmetadata: { name: i }\nspec: {}"), ["K8S021"]);
  assert.deepEqual(rules("kind: Ingress\nmetadata: { name: i }\nspec: { tls: [{ secretName: s }] }"), []);
});

test("resilience: bad YAML is reported, alias bombs are refused, non-objects ignored", () => {
  const bad = auditYaml("kind: Pod\n  bad: [unclosed");
  assert.ok(bad.errors.length > 0);
  const bomb = "a: &a [x,x,x,x,x,x,x,x,x,x]\n" + Array.from({ length: 10 }, (_, i) => `b${i}: &b${i} [${Array(10).fill(i === 0 ? "*a" : `*b${i - 1}`).join(",")}]`).join("\n");
  const r = auditYaml(bomb);
  assert.ok(r.errors.length > 0 || r.documents === 1, "must not hang or crash");
  assert.deepEqual(auditYaml("- just\n- a list\n").findings, []);
  assert.deepEqual(auditYaml("").findings, []);
});

test("findings are sorted worst first", () => {
  const f = sortFindings(auditYaml(pod(`      image: a:latest
      securityContext: { privileged: true }`)).findings);
  assert.equal(f[0]?.severity, "critical");
});

test("CLI: samples, thresholds, JSON and errors", () => {
  const cli = join(import.meta.dirname, "..", "src", "cli.js");
  const bad = spawnSync("node", [cli, join(SAMPLES, "bad-deployment.yaml")], { encoding: "utf8" });
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /K8S006/);
  assert.match(bad.stdout, /K8S004/);
  const good = spawnSync("node", [cli, join(SAMPLES, "good-deployment.yaml")], { encoding: "utf8" });
  assert.equal(good.status, 0, good.stdout);
  const json = JSON.parse(execFileSync("node", [cli, "--json", "--fail-on", "critical", join(SAMPLES, "good-deployment.yaml")], { encoding: "utf8" }));
  assert.ok(Array.isArray(json));
  const dir = mkdtempSync(join(tmpdir(), "k8s-"));
  writeFileSync(join(dir, "broken.yaml"), "kind: [");
  assert.equal(spawnSync("node", [cli, dir], { encoding: "utf8" }).status, 2);
  assert.equal(spawnSync("node", [cli], { encoding: "utf8" }).status, 2);
  assert.equal(spawnSync("node", [cli, "/no/such/path"], { encoding: "utf8" }).status, 2);
});
