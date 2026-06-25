# `threagile import compose` — model from docker-compose

Generates a Threagile model fragment from a `docker-compose.yml`.

```sh
threagile import compose --compose docker-compose.yml --output model-fragment.yaml
threagile analyze-model --model model-fragment.yaml --output out
```

## Mapping

| docker-compose | Threagile |
|----------------|-----------|
| Service | Technical asset (Process; **Datastore** if the image is a known datastore — postgres, mysql, mongo, redis, elasticsearch, minio, …; `nginx`/`traefik` → reverse-proxy, `haproxy` → load-balancer). `build:` services are marked custom-developed. |
| `ports:` (host-published) | Marks the service internet-facing + a communication link from a synthetic internet client. (`expose:` is container-only and does **not** count.) |
| `depends_on` (list or map form) | Communication link service → dependency |
| `networks` (each network) | Trust boundary — `internal: true` networks become more-isolated (security-group) boundaries, others virtual-LAN. Each service joins its first network's boundary. |
| Secret-like environment variables (`*SECRET*`, `*PASSWORD*`, `*TOKEN*`, `*API_KEY*`, …) | A strictly-confidential **Application Secrets** data asset, processed by the services that carry them |

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--compose` | stdin | Path to the docker-compose file |
| `--output` | stdout | Write the fragment to a file |
| `--label` | `compose` | Short label appended to generated asset IDs |
| `--diff` | false | Print a summary without writing |

## Notes

- Review the fragment before merging: CIA ratings default conservatively and
  encryption defaults to `none` (compose rarely declares at-rest encryption).
- Secret-like env vars surfacing as a data asset is intentionally a *signal* —
  it makes "secrets baked into the compose file" visible to the analysis (and to
  `threagile paths`, which will show what an attacker reaching that service can
  read).
