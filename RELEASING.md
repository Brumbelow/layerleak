# Releasing layerleak

## Release Rules

- The canonical install path is `go install github.com/brumbelow/layerleak@latest`.
- The current module path is `github.com/brumbelow/layerleak`, so release tags for this module must stay on `v1.x.y`.
- `v1.0.0` is already published. The next root-module release continues the `v1.x.y` sequence, for example `v1.1.0` for the next feature release or `v1.0.1` for a patch.
- Do not publish new `v2+` tags from this module path. Historical `v2.x` GitHub Releases are not valid module-major releases for `go install github.com/brumbelow/layerleak@latest` and are not selectable by the Go module proxy. A true v2 release requires changing the module path to `github.com/brumbelow/layerleak/v2`.

## Choosing the Next Tag

- Bump the minor version (`v1.N+1.0`) for additive, backward-compatible changes to the CLI, API surface, configuration schema, or persistence schema.
- Bump the patch version (`v1.N.M+1`) for bug fixes and documentation-only changes that do not change behavior.
- Do not reuse a tag that has already been pushed.

## Release Checklist

1. Start from `main` with CI green.
2. Verify local quality checks:

```bash
go test ./... -count=1
docker compose config
GOBIN=/tmp/layerleak-bin GOCACHE=/tmp/layerleak-gocache go install .
/tmp/layerleak-bin/layerleak --help
/tmp/layerleak-bin/layerleak scan --help
/tmp/layerleak-bin/layerleak --version
```

3. Create the next root-compatible tag, for example:

```bash
git tag v1.1.0
git push origin v1.1.0
```

4. After the tag is pushed, verify the published install path from a clean module cache:

```bash
GOBIN=/tmp/layerleak-release-check/bin \
GOCACHE=/tmp/layerleak-release-check/cache \
GOMODCACHE=/tmp/layerleak-release-check/mod \
go install github.com/brumbelow/layerleak@latest
/tmp/layerleak-release-check/bin/layerleak --help
/tmp/layerleak-release-check/bin/layerleak --version
```

5. `layerleak --version` for a module-installed binary should report the published tag via Go build info. Local checkout builds report the version Go embeds for the checkout, falling back to `dev` when no module version is available.

6. If install behavior changed, update `README.md` and `CONTRIBUTING.md` in the same release train.

## GitHub Releases

The Go module proxy resolves `@latest` by reading repository tags, not by reading the GitHub Releases "Latest" designation. Treat the GitHub Releases UI as documentation only. The authoritative install target for users is the highest semver-compatible tag on the root module, which must be a `v1.x.y` tag while the module path is `github.com/brumbelow/layerleak`.
