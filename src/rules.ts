export type Severity = "low" | "medium" | "high" | "critical";

export interface Finding {
  rule: string;
  severity: Severity;
  kind: string;
  name: string;
  container?: string;
  message: string;
  fix: string;
}

type Obj = Record<string, any>;

const WORKLOADS = new Set(["Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "ReplicationController"]);
const DANGEROUS_CAPS = new Set(["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_RAW", "ALL"]);
const SENSITIVE_ENV = /(pass(word)?|secret|token|api[_-]?key|private[_-]?key|credential)/i;
const SENSITIVE_HOSTPATHS = ["/", "/etc", "/var/run/docker.sock", "/run/docker.sock", "/proc", "/sys", "/root", "/var/lib/kubelet", "/var/run/containerd"];

/** Extract the pod spec from any supported workload kind. */
export function podSpec(doc: Obj): Obj | undefined {
  switch (doc.kind) {
    case "Pod": return doc.spec;
    case "CronJob": return doc.spec?.jobTemplate?.spec?.template?.spec;
    default: return doc.spec?.template?.spec;
  }
}

function containersOf(spec: Obj): { c: Obj; init: boolean }[] {
  return [
    ...((spec.containers as Obj[] | undefined) ?? []).map((c) => ({ c, init: false })),
    ...((spec.initContainers as Obj[] | undefined) ?? []).map((c) => ({ c, init: true })),
  ];
}

export function imageIssue(image: string): "latest" | "untagged" | "ok" | "digest" {
  if (image.includes("@sha256:")) return "digest";
  const last = image.split("/").pop() ?? image;
  if (!last.includes(":")) return "untagged";
  return last.endsWith(":latest") ? "latest" : "ok";
}

export function auditDocument(doc: Obj): Finding[] {
  const out: Finding[] = [];
  const kind = String(doc?.kind ?? "");
  const name = String(doc?.metadata?.name ?? "(unnamed)");
  const add = (rule: string, severity: Severity, message: string, fix: string, container?: string) =>
    out.push({ rule, severity, kind, name, message, fix, ...(container ? { container } : {}) });

  if (kind === "Service" && (doc.spec?.type === "LoadBalancer" || doc.spec?.type === "NodePort")) {
    add("K8S020", "medium", `Service type ${doc.spec.type} exposes the workload outside the cluster`, "Use ClusterIP behind an Ingress with TLS and authentication, or restrict loadBalancerSourceRanges");
  }
  if (kind === "Ingress" && !(doc.spec?.tls?.length > 0)) {
    add("K8S021", "medium", "Ingress has no TLS section", "Add spec.tls with a certificate secret");
  }
  if (kind === "ClusterRoleBinding" && (doc.roleRef?.name === "cluster-admin")) {
    add("K8S022", "high", "Binding grants cluster-admin", "Grant a narrowly scoped Role instead");
  }
  if ((kind === "Role" || kind === "ClusterRole") && Array.isArray(doc.rules)) {
    for (const r of doc.rules as Obj[]) {
      if ((r.verbs ?? []).includes("*") && (r.resources ?? []).includes("*")) {
        add("K8S023", "critical", "RBAC rule allows all verbs on all resources", "List explicit resources and verbs");
      }
      if ((r.resources ?? []).includes("secrets") && ((r.verbs ?? []).some((v: string) => ["get", "list", "watch", "*"].includes(v)))) {
        add("K8S024", "medium", "RBAC rule can read Secrets", "Limit to named secrets with resourceNames or remove");
      }
    }
  }
  if (!WORKLOADS.has(kind)) return out;
  const spec = podSpec(doc);
  if (!spec) return out;

  if (spec.hostNetwork) add("K8S001", "high", "hostNetwork shares the node network namespace", "Remove hostNetwork");
  if (spec.hostPID) add("K8S002", "high", "hostPID exposes node processes", "Remove hostPID");
  if (spec.hostIPC) add("K8S003", "high", "hostIPC shares node IPC", "Remove hostIPC");
  for (const v of (spec.volumes as Obj[] | undefined) ?? []) {
    const p = v.hostPath?.path as string | undefined;
    if (p !== undefined) {
      const risky = SENSITIVE_HOSTPATHS.includes(p.replace(/\/+$/, "") || "/");
      add("K8S004", risky ? "critical" : "medium", `hostPath volume mounts ${p} from the node${risky ? " (container escape risk)" : ""}`, "Use emptyDir, a PVC or a ConfigMap/Secret volume");
    }
  }
  if (spec.serviceAccountName === undefined || spec.serviceAccountName === "default") {
    if (spec.automountServiceAccountToken !== false) {
      add("K8S005", "low", "uses the default service account and mounts its token", "Create a dedicated ServiceAccount or set automountServiceAccountToken: false");
    }
  }
  const podSc = spec.securityContext ?? {};
  for (const { c, init } of containersOf(spec)) {
    const cn = String(c.name ?? "(unnamed)") + (init ? " (init)" : "");
    const sc = c.securityContext ?? {};
    if (sc.privileged === true) add("K8S006", "critical", "privileged container has near-root access to the node", "Remove privileged; add only the specific capabilities needed", cn);
    if (sc.allowPrivilegeEscalation !== false && sc.privileged !== true) add("K8S007", "medium", "allowPrivilegeEscalation is not set to false", "Set securityContext.allowPrivilegeEscalation: false", cn);
    const nonRoot = sc.runAsNonRoot ?? podSc.runAsNonRoot;
    const uid = sc.runAsUser ?? podSc.runAsUser;
    if (uid === 0) add("K8S008", "high", "runs as UID 0", "Set runAsUser to a non-zero UID and runAsNonRoot: true", cn);
    else if (nonRoot !== true && uid === undefined) add("K8S008", "medium", "does not enforce a non-root user", "Set runAsNonRoot: true", cn);
    if (sc.readOnlyRootFilesystem !== true) add("K8S009", "low", "root filesystem is writable", "Set readOnlyRootFilesystem: true and mount emptyDir where writes are needed", cn);
    const caps = sc.capabilities ?? {};
    const added = ((caps.add as string[] | undefined) ?? []).filter((x) => DANGEROUS_CAPS.has(String(x).toUpperCase()));
    if (added.length > 0) add("K8S010", "high", `adds dangerous capabilities: ${added.join(", ")}`, "Drop ALL capabilities and add back only what is required", cn);
    else if (!((caps.drop as string[] | undefined) ?? []).map((x) => String(x).toUpperCase()).includes("ALL")) add("K8S011", "low", "does not drop all capabilities", "Add securityContext.capabilities.drop: [ALL]", cn);
    const seccomp = sc.seccompProfile ?? podSc.seccompProfile;
    if (!seccomp) add("K8S012", "low", "no seccompProfile set", "Set seccompProfile.type: RuntimeDefault", cn);
    const img = String(c.image ?? "");
    const issue = imageIssue(img);
    if (issue === "latest" || issue === "untagged") add("K8S013", "medium", `image '${img}' is ${issue === "latest" ? "tagged :latest" : "untagged (defaults to :latest)"}, so deployments are not reproducible`, "Pin a version tag or, better, an immutable digest (@sha256:...)", cn);
    else if (issue === "ok") add("K8S014", "low", `image '${img}' is pinned by tag only; tags are mutable`, "Pin by digest (@sha256:...)", cn);
    if (!c.resources?.limits?.memory || !c.resources?.limits?.cpu) add("K8S015", "medium", "missing CPU or memory limits (noisy neighbour / denial of service)", "Set resources.limits and resources.requests", cn);
    for (const e of (c.env as Obj[] | undefined) ?? []) {
      if (typeof e.value === "string" && e.value.length > 0 && SENSITIVE_ENV.test(String(e.name))) {
        add("K8S016", "high", `env var ${e.name} holds a literal value that looks like a secret`, "Reference a Secret with valueFrom.secretKeyRef", cn);
      }
    }
    if (!init && !c.livenessProbe && !c.readinessProbe) add("K8S017", "low", "no liveness or readiness probe", "Add probes so failures are detected and traffic is gated", cn);
    for (const p of (c.ports as Obj[] | undefined) ?? []) {
      if (p.hostPort) add("K8S018", "medium", `hostPort ${p.hostPort} binds to the node`, "Use a Service instead of hostPort", cn);
    }
  }
  return out;
}
