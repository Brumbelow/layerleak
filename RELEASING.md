# Releasing layerleak

## Release Rules

- The canonical install path is `go install github.com/brumbelow/layerleak@latest`.
- The current module path is `github.com/brumbelow/layerleak`, so release tags for this module must stay on `v1.x.y`.
- The next stable root-module release should be `v1.0.0`.
- Do not publish new `v2+` tags from this module path. A true v2 release requires a module path change to `github.com/brumbelow/layerleak/v2`.

## Release Checklist

1. Start from `main` with CI green.
2. Verify local quality checks:

```bash
go test ./...
GOBIN=/tmp/layerleak-bin GOCACHE=/tmp/layerleak-gocache go install .
/tmp/layerleak-bin/layerleak --help
```

3. Create the next root-compatible tag, for example:

```bash
git tag v1.0.0
git push origin v1.0.0
```

4. After the tag is pushed, verify the published install path from a clean environment:

```bash
go install github.com/brumbelow/layerleak@latest
layerleak --help
```

5. If install behavior changed, update `README.md` and `CONTRIBUTING.md` in the same release train.
