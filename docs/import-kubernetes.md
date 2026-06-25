# `threagile import kubernetes` — model from Kubernetes manifests

Generates a Threagile model fragment from Kubernetes manifests (a single file or
a multi-document YAML stream — e.g. `kubectl get ... -o yaml`, `helm template`,
or `kustomize build` output).

```sh
# everything in the cluster
kubectl get deploy,statefulset,daemonset,pod,job,cronjob,svc,ingress,secret,pvc -A -o yaml > manifests.yaml
threagile import kubernetes --manifests manifests.yaml --output model-fragment.yaml

# or pipe directly
helm template ./mychart | threagile import kubernetes --output model-fragment.yaml
```

The emitted YAML is in Threagile's authoring format and is **directly
analyzable**:

```sh
threagile analyze-model --model model-fragment.yaml --output out
```

## Mapping

| Kubernetes object | Threagile |
|-------------------|-----------|
| Deployment / StatefulSet / DaemonSet / ReplicaSet / Pod / Job / CronJob | Technical asset (Process, `container-platform`; **Datastore** if the container image is a known datastore — postgres, mysql, mongo, redis, elasticsearch, …) |
| Namespace (from `metadata.namespace`) | Trust boundary (`network-policy-namespace-isolation`) containing its workloads |
| Service `type: LoadBalancer` / `NodePort` | Marks the selected workloads internet-exposed + a communication link from an external client |
| Ingress | Marks the backing workloads internet-exposed + a communication link |
| Secret | Strictly-confidential data asset (tagged `credential`) |
| PersistentVolumeClaim | Datastore asset (`block-storage`) |

Hardening signals become tags: `securityContext.runAsNonRoot` → `run-as-non-root`;
a `privileged` container → `privileged-container`.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--manifests` | stdin | Path to the manifest YAML |
| `--output` | stdout | Write the fragment to a file |
| `--label` | `k8s` | Short label appended to generated asset IDs (e.g. `prod`) to keep multiple imports distinct |
| `--diff` | false | Print a summary of what would be generated without writing |

## Notes

- Review the generated fragment before merging: CIA ratings default to
  conservative values, and encryption defaults to `none` (manifests rarely
  declare at-rest encryption) — adjust to reflect reality.
- The importer is best-effort and skips objects it doesn't recognise.
