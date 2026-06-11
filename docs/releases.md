# Release process

Releases are produced automatically by [GoReleaser](https://goreleaser.com) (config: `.goreleaser.yaml`)
when a tag matching `v*` (e.g. `v1.0.0`) is pushed to the repository.

The `.github/workflows/release.yml` workflow:

1. **security-gate** job: builds, vets, runs the full test suite with the race
   detector, runs `golangci-lint` (blocking), and runs `gosec` against the
   tagged commit. The release only proceeds if all of these pass.
2. **goreleaser** job (depends on `security-gate`): runs `goreleaser release --clean`,
   which:
   - builds `threagile` binaries for linux/darwin/windows on amd64/arm64,
   - packages each binary plus license, report templates, OpenAPI spec,
     JSON schema, and example/stub models into `.tar.gz` (`.zip` on Windows)
     archives,
   - builds and pushes multi-arch Docker images to
     `ghcr.io/threagile/threagile` tagged with the release version and `latest`
     (using `Dockerfile.goreleaser`),
   - creates a GitHub release with the archives, checksums, and an
     auto-generated changelog.

To cut a release:

```sh
git tag v1.0.0
git push origin v1.0.0
```

# 1.0.0 Not released yet

The code base changed quite significantly to be more modular, [cobra framework](https://github.com/spf13/cobra) started to be used and a lot of features was added.

- **BREAKING CHANGE** custom risk rules plugin subsystem is replaced with [custom risk rule scripts](./custom-risk-rules.md).
- [adoc reports](./asciidoctor-report.md).
- [includes](./includes.md) enable to split up huge yaml files into smaller one.
- [interactive mode](./mode-interactive.md) is added.
- [config.json](./config.md).
- minor bug fixes.

# 0.9.1

Upgrading dependencies.

# 0.9.0

The first release contain the idea of Threagile like on [this video](https://www.youtube.com/watch?v=LwyQ9W_vGlo).
