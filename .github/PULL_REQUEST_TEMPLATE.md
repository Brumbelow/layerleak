## Summary

Describe the user-visible behavior and why this is the smallest suitable change.

## Security and compatibility

- Secret/redaction impact:
- OCI/network/resource-bound impact:
- CLI/API/result/schema compatibility:
- Migration or deployment impact:

## Verification

- [ ] `git diff --check`
- [ ] `gofmt`, `go mod verify`, and `go mod tidy -diff`
- [ ] `go vet ./...`
- [ ] Normal and race tests
- [ ] PostgreSQL/migration tests when applicable
- [ ] amd64/arm64 container or Compose checks when applicable
- [ ] Documentation and OpenAPI updated when behavior changes
- [ ] Third-party notices updated when dependencies change

List the exact checks run and any check that could not run locally.
