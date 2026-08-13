# Third-party notices

Layerleak is distributed under the MIT License. The compiled CLI and container
also include code from the projects below, which retain their own copyright and
license terms.

| Module | Version | License |
| --- | --- | --- |
| `github.com/distribution/reference` | v0.6.0 | Apache-2.0 |
| `github.com/klauspost/compress` | v1.19.1 | Apache-2.0, BSD-3-Clause, and MIT components |
| `github.com/lib/pq` | v1.12.3 | MIT |
| `github.com/opencontainers/go-digest` | v1.0.0 | Apache-2.0 |
| `github.com/spf13/cobra` | v1.10.2 | Apache-2.0 |
| `github.com/spf13/pflag` | v1.0.9 | BSD-3-Clause |
| `golang.org/x/sys` | v0.47.0 | BSD-3-Clause |
| `golang.org/x/term` | v0.45.0 | BSD-3-Clause |

The corresponding license texts are present in each module's source archive.
Links to those versioned sources and the classified license for every linked
package are emitted as `dependency-licenses.csv` by the full verification
workflow and attached to each GitHub release. Per-platform SPDX SBOMs are also
attached and attested.

This inventory covers linked Go dependencies, not build-only tools or services
used to test Layerleak. The PostgreSQL image in `docker-compose.yml` and the
GitHub Actions used by the repository are separately distributed components
under their respective terms.
