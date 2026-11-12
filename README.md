# k8s-audit

Static **security audit for Kubernetes manifests**, written in TypeScript. Point it at a file or a directory of YAML (plain manifests, rendered Helm output, `kubectl get -o yaml` dumps, `kind: List`) and get findings with a concrete fix for each. One runtime dependency (`yaml`).

> Built with AI assistance (Claude) as a portfolio project. Review the code before relying on it.

## Usage

```bash
npm install && npm run build
node dist/src/cli.js deploy/                    # directory, recursive
helm template ./chart | node dist/src/cli.js /dev/stdin
node dist/src/cli.js --json --fail-on high manifests/
```

Exit code: `0` clean, `1` findings at or above `--fail-on` (default `medium`), `2` unreadable input or invalid YAML.

```
[CRITICAL] K8S006 Deployment/web (app)  samples/bad-deployment.yaml
    privileged container has near-root access to the node
    fix: Remove privileged; add only the specific capabilities needed
```

## Rules

| ID | Severity | Check |
|----|----------|-------|
| K8S001-003 | high | `hostNetwork`, `hostPID`, `hostIPC` |
| K8S004 | medium / critical | `hostPath` volumes; critical for the Docker socket, `/`, `/etc`, `/proc`, kubelet dirs |
| K8S005 | low | default service account with token auto-mounted |
| K8S006 | critical | privileged container |
| K8S007 | medium | `allowPrivilegeEscalation` not false |
| K8S008 | high / medium | UID 0, or no non-root enforcement |
| K8S009 | low | writable root filesystem |
| K8S010-011 | high / low | dangerous capabilities added (SYS_ADMIN, NET_ADMIN, ALL...) / ALL not dropped |
| K8S012 | low | no seccomp profile |
| K8S013-014 | medium / low | `:latest` or untagged image / tag without digest |
| K8S015 | medium | missing CPU or memory limits |
| K8S016 | high | literal secret-looking value in `env` |
| K8S017 | low | no liveness or readiness probe |
| K8S018 | medium | `hostPort` |
| K8S020-021 | medium | LoadBalancer or NodePort service; Ingress without TLS |
| K8S022-024 | high / critical / medium | `cluster-admin` binding, wildcard RBAC rule, RBAC that can read Secrets |

Covers Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, init containers, and pod-level `securityContext` inheritance (a container is not flagged for settings its pod already enforces).

## Design notes

* Findings are data (`rule`, `severity`, `kind`, `name`, `container`, `message`, `fix`), so the library can be reused: `import { auditYaml } from "k8s-audit"`
* Manifests are untrusted input: YAML alias expansion is capped (`maxAliasCount`) so an alias bomb produces an error instead of exhausting memory, and a broken file is reported without hiding results from the others
* Image parsing understands registry ports (`registry:5000/app` is untagged, not tag `5000/app`)
* Not a substitute for admission control (Kyverno, Gatekeeper, Pod Security Admission) or for tools such as kube-linter or Trivy; this one is small, readable and easy to extend

## Development

```bash
npm ci && npm test
```

MIT licensed.
