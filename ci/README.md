# CI workflows — activation step

`ci/github-workflows/` holds the CI and release pipelines. They are **not** in
`.github/workflows/` because the automation account that created this
repository has no `workflow` scope, and GitHub refuses any push that creates or
updates a workflow file without it. Nothing in the files themselves is pending.

To activate (once, by someone with `workflow` scope or the `kasil-astro` App
granted access to this repository):

```sh
mkdir -p .github/workflows
git mv ci/github-workflows/ci.yaml .github/workflows/ci.yaml
git mv ci/github-workflows/release.yaml .github/workflows/release.yaml
rm ci/README.md && rmdir ci/github-workflows ci
git commit -m "ci: activate the CI and release pipelines"
git push
```

What they do:

| Workflow | Trigger | Runs |
|---|---|---|
| `ci.yaml` | PR, push to `main` | `gofmt` check, `go vet`, `go test`, a linux/arm64 cross-build, `helm lint` and two renders (default + all features), and `egressctl lint` over any committed policy files |
| `release.yaml` | tag `v*` | multi-arch (amd64+arm64) images for `egressd` and `egressctl` to `ghcr.io/snbuback/kasil-egress/<binary>`, and the chart to `oci://ghcr.io/snbuback/charts` |

The first `v*` tag also makes the images public, because the packages inherit
the visibility of this public repository — which is what lets a cluster pull
them without an image pull secret.
