package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// rootLongHelp is the description `layerleak --help` prints above the list of
// subcommands, which cobra builds from each command's Short text.
const rootLongHelp = `Layerleak scans OCI container images for likely secrets: image layers
(including files deleted by later layers), environment variables, labels,
history and configuration. It reads images from public or authenticated
registries, OCI image layouts, OCI archives and docker save archives, and
reports redacted findings as a summary, a stable JSON result or SARIF.

Run 'layerleak scan --help' for scan inputs, exit codes and the environment
variables that configure a scan.`

// scanLongHelp is the description of `layerleak scan --help`.
const scanLongHelp = `Scan an OCI image for likely secrets.

<image-ref> is a registry reference (alpine:3.20, ghcr.io/org/app@sha256:...)
or a local image source:

  oci:<dir>[:<tag>][@<digest>]                 OCI image layout directory
  oci-archive:<file.tar>[:<tag>][@<digest>]    tar archive of an OCI image layout
  docker-archive:<file.tar>[:<repo>[:<tag>]][@<digest>]   docker save archive

The path ends at the first colon (a Windows drive letter stays in the path).
A local source that holds one image needs no tag; one that holds several
needs a tag (an index.json ref.name such as 1.2 or docker.io/library/app:1.2,
or a docker save RepoTags name such as app:1.2) or a digest. --all-tags
enumerates the tags a local source holds. Registry credentials
(--username/--password-stdin, LAYERLEAK_REGISTRY_USERNAME) are refused for
local sources.

Every scan that produced a result writes one scan record under --output-dir,
LAYERLEAK_FINDINGS_DIR or ./findings (unless --no-artifacts). The scan is
also saved to PostgreSQL when LAYERLEAK_DATABASE_URL is set (unless --no-db).

Exit codes:
  0  complete scan with no actionable finding at or above --fail-on, or an
     accepted --allow-partial scan with none
  1  invalid input, operational failure (registry, network, authentication),
     persistence failure, or cancellation (LAYERLEAK_SCAN_TIMEOUT, SIGINT,
     SIGTERM)
  2  one or more actionable findings at or above --fail-on (default low;
     --fail-on none never exits 2); findings take precedence over code 3
  3  usable but incomplete coverage and --allow-partial was not given

Environment variables (flags override the matching variable):
  Registry and network:
    LAYERLEAK_REGISTRY_BASE_URL LAYERLEAK_REGISTRY_AUTH_URL
    LAYERLEAK_REGISTRY_USERNAME LAYERLEAK_REGISTRY_PASSWORD
    LAYERLEAK_DOCKER_CONFIG LAYERLEAK_ALLOWED_PRIVATE_REGISTRY_HOSTS
    LAYERLEAK_ALLOWED_PRIVATE_AUTH_HOSTS LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS
    LAYERLEAK_REGISTRY_MAX_REDIRECTS LAYERLEAK_HTTP_TIMEOUT
    LAYERLEAK_BLOB_TIMEOUT HTTPS_PROXY HTTP_PROXY NO_PROXY
  Scope and resource bounds:
    LAYERLEAK_SCAN_TIMEOUT LAYERLEAK_TAG_PAGE_SIZE
    LAYERLEAK_MAX_REPOSITORY_TAGS LAYERLEAK_MAX_REPOSITORY_TARGETS
    LAYERLEAK_MAX_FILE_BYTES LAYERLEAK_MAX_LAYER_BYTES
    LAYERLEAK_MAX_LAYER_ENTRIES LAYERLEAK_MAX_IMAGE_LAYERS
    LAYERLEAK_MAX_IMAGE_MANIFESTS LAYERLEAK_MAX_IMAGE_LAYER_BYTES
    LAYERLEAK_MAX_IMAGE_ARTIFACTS LAYERLEAK_MAX_RETAINED_BYTES
    LAYERLEAK_MAX_MANIFEST_BYTES LAYERLEAK_MAX_CONFIG_BYTES
    LAYERLEAK_MAX_TAG_RESPONSE_BYTES LAYERLEAK_MAX_AUTH_RESPONSE_BYTES
    LAYERLEAK_MAX_NESTED_ARCHIVE_BYTES LAYERLEAK_MAX_NESTED_ARCHIVE_ENTRIES
    LAYERLEAK_MAX_LAYER_CACHE_BYTES LAYERLEAK_MAX_FINDINGS_PER_SCAN
  Output and logging:
    LAYERLEAK_FINDINGS_DIR LAYERLEAK_LOG_LEVEL LAYERLEAK_LOG_FORMAT TERM CI
  PostgreSQL (not opened with --no-db):
    LAYERLEAK_DATABASE_URL LAYERLEAK_DATABASE_MAX_OPEN_CONNS
    LAYERLEAK_DATABASE_MAX_IDLE_CONNS LAYERLEAK_DATABASE_CONN_MAX_LIFETIME
    LAYERLEAK_DATABASE_CONN_MAX_IDLE_TIME LAYERLEAK_DATABASE_QUERY_TIMEOUT
    LAYERLEAK_DATABASE_WRITE_TIMEOUT LAYERLEAK_PERSIST_RAW_SECRETS
    LAYERLEAK_MAX_RAW_FINDING_BYTES`

// scanExample is the Examples section of `layerleak scan --help`: a registry
// image, a local input and a baselined CI run.
const scanExample = `  # Scan a registry image and keep the JSON result
  layerleak scan alpine:3.20 --format json --output result.json

  # Scan the app:1.2 image of a docker save archive; fail only on medium or high
  layerleak scan docker-archive:app.tar:app:1.2 --fail-on medium

  # Accept reviewed findings (layerleak baseline create) and emit SARIF
  layerleak scan ghcr.io/org/app:1.2 --baseline layerleak-baseline.json --format sarif --output layerleak.sarif`

// usageHintFlagError appends a pointer to the command's help to a flag
// parsing error, since usage is not printed on errors (SilenceUsage).
func usageHintFlagError(cmd *cobra.Command, err error) error {
	return fmt.Errorf("%w; run '%s --help' for usage", err, cmd.CommandPath())
}

// exactArgsWithHint is cobra.ExactArgs with the same help pointer.
func exactArgsWithHint(count int) cobra.PositionalArgs {
	check := cobra.ExactArgs(count)
	return func(cmd *cobra.Command, args []string) error {
		if err := check(cmd, args); err != nil {
			return fmt.Errorf("%w; run '%s --help' for usage", err, cmd.CommandPath())
		}
		return nil
	}
}
