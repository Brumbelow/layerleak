# Detector catalog

<!-- Generated from the detector catalog by
     go test ./internal/cli -run TestDetectorsDocMatchesCatalog -update-docs
     Do not edit by hand; the test fails when this file and the catalog disagree. -->

This is the list of identifiers a finding can carry in `detector_name`
(and SARIF `ruleId`), as printed by `layerleak detectors list` and returned by
`GET /api/v1/detectors`. `layerleak detectors list --format json` prints the same
rows as JSON.

**Confidence** is the tier a match carries before path and key context adjust
it: a value under a test or example path can be lowered, one assigned to a
secret-looking key can be raised, and placeholder values are suppressed
rather than reported (see [false-positives.md](false-positives.md)).
`--fail-on` compares against the adjusted tier. When several strategies or
branches emit the same identifier at different tiers the tiers are joined low
to high (`medium/high`).

**Strategy** names how the identifier is matched:

| Strategy | Meaning |
| --- | --- |
| `regex` | A value pattern matched anywhere in the content, behind a literal prefilter. |
| `path_regex` | A value pattern that only runs on files whose path names a known configuration or credential file. |
| `key_value` | A value pattern gated on the environment variable, label or key name the value is assigned to. |
| `contextual` | A vendor token found either by its prefixed form or by an assignment to a vendor-named key. |
| `url` | A URL whose userinfo carries a password, with host and scheme checks. |
| `pem` | PEM armour parsing for private key blocks. |
| `structured_file` | A reader for one credential file format (.aws/credentials, .git-credentials, .pgpass). |
| `shape` | A token shape checked by a structural validator such as an embedded identifier or checksum. |
| `path_only` | A file reported by its path alone when its content cannot be read (binary or oversize); the finding has no value. |
| `entropy` | A keyword-gated entropy heuristic over assigned values. |

## Detectors (161)

| Detector | Confidence | Strategy | Description |
| --- | --- | --- | --- |
| `age_secret_key` | high | `regex` | age (and SOPS) identity secret key in Bech32 form with the AGE-SECRET-KEY-1 prefix. |
| `airtable_personal_access_token` | high | `regex` | Airtable personal access token (pat prefix with a 64-hex suffix). |
| `algolia_admin_api_key` | high | `key_value`, `regex` | Algolia admin or write API key assigned to an Algolia-named key. |
| `alibaba_access_key_id` | high | `regex` | Alibaba Cloud AccessKey ID (LTAI prefix). |
| `anthropic_api_key` | high | `regex` | Anthropic API key (sk-ant- prefix). |
| `artifactory_api_key` | high | `regex` | JFrog Artifactory API key (AKCp prefix). |
| `artifactory_reference_token` | high | `regex` | JFrog Artifactory reference token (base64 of the reftkn:01 marker). |
| `asana_personal_access_token` | high | `regex` | Asana personal access token near the word asana. |
| `assigned_sensitive_value` | high | `key_value` | Long opaque value assigned to a client_secret, access_token, refresh_token or auth_token key. |
| `atlassian_api_token` | high | `regex` | Atlassian Cloud API token (ATATT3 prefix). |
| `aws_access_key_id` | high | `regex` | AWS access key id (AKIA, ASIA, ABIA or ACCA prefix). |
| `aws_secret_access_key` | high | `key_value`, `regex` | AWS secret access key assigned to a secret_access_key name (40 base64 characters). |
| `aws_session_token` | high | `key_value`, `regex` | AWS STS session token (IQoJ, FQoG or FwoG blob or an aws_session_token assignment). |
| `aws_shared_credentials_access_key_id` | medium/high | `structured_file` | aws_access_key_id entry in an .aws/credentials or .aws/config profile. |
| `aws_shared_credentials_secret_access_key` | high | `structured_file` | aws_secret_access_key entry in an .aws/credentials or .aws/config profile. |
| `aws_shared_credentials_session_token` | medium/high | `structured_file` | aws_session_token entry in an .aws/credentials or .aws/config profile. |
| `aws_sso_cache_token` | high | `path_regex` | Access, refresh, client secret or session token in an AWS CLI or SSO cache file under .aws/. |
| `azure_cli_token_cache` | high | `path_regex` | Access or refresh token or client secret in an Azure CLI token cache file under .azure/. |
| `azure_client_secret` | high | `key_value`, `regex` | Microsoft Entra (Azure AD) application client secret, by its Q~ shape or an azure_client_secret assignment. |
| `azure_devops_personal_access_token` | high | `key_value`, `regex` | Azure DevOps personal access token (84 characters containing AZDO) or an Azure DevOps PAT assignment. |
| `azure_shared_access_key` | high | `regex` | SharedAccessKey value in an Azure Service Bus, Event Hubs or IoT Hub connection string. |
| `azure_storage_account_key` | high | `regex` | AccountKey value in an Azure Storage connection string (86 base64 characters). |
| `azure_storage_sas_token` | high | `regex` | Azure Storage shared access signature (sv= and sig= query parameters). |
| `base64_pem_private_key` | high | `regex` | Base64-encoded PEM private key, as embedded in Kubernetes Secrets and kubeconfig files. |
| `basic_auth_url` | high | `url` | http(s), ftp or similar URL with a user:password userinfo on a routable host. |
| `bitbucket_app_password` | high | `regex` | Bitbucket app password (ATBB prefix). |
| `bundler_credentials` | high | `path_regex` | user:password credential in a Bundler .bundle/config BUNDLE_* entry. |
| `circleci_personal_api_token` | high | `regex` | CircleCI personal API token (CCIPAT_ prefix). |
| `circleci_project_api_token` | high | `regex` | CircleCI project API token (CCIPRJ_ prefix). |
| `cloudflare_api_token` | high | `key_value`, `regex` | Cloudflare API token (cfut_ or cfat_ prefix) or a token assigned to a Cloudflare API key name. |
| `composer_auth_password` | high | `path_regex` | Password in a Composer auth.json file. |
| `connection_url_credentials` | high | `url` | Database, message-queue or cache connection URL with a user:password userinfo. |
| `crates_io_token` | high | `regex` | crates.io API token (cio prefix). |
| `databricks_token` | high | `regex` | Databricks personal access token (dapi prefix). |
| `datadog_api_key` | high | `key_value` | Datadog API key (32 hex characters) assigned to a Datadog API key name. |
| `datadog_application_key` | high | `key_value` | Datadog application key (40 hex characters) assigned to a Datadog application key name. |
| `digitalocean_personal_access_token` | high | `regex` | DigitalOcean personal access, OAuth or refresh token (dop_v1_, doo_v1_ or dor_v1_ prefix). |
| `discord_bot_token` | high | `shape` | Discord bot token (base64 snowflake id, timestamp and HMAC segments). |
| `discord_webhook` | high | `regex` | Discord webhook URL with its id and token path segments. |
| `docker_auth_blob` | high | `path_regex`, `regex` | Base64 user:password auth entry in a Docker config.json auths map. |
| `docker_config_identity_token` | high | `path_regex` | identitytoken entry in a Docker config.json auths map. |
| `docker_config_json_blob` | high | `regex` | Base64-encoded Docker config.json, as stored in a Kubernetes .dockerconfigjson Secret. |
| `docker_config_registry_token` | high | `path_regex` | registrytoken entry in a Docker config.json auths map. |
| `docker_hub_organization_access_token` | high | `regex` | Docker Hub organization access token (dckr_oat_ prefix). |
| `docker_hub_personal_access_token` | high | `regex` | Docker Hub personal access token (dckr_pat_ prefix). |
| `doppler_token` | high | `regex` | Doppler service, personal, service-account or CLI token (dp.st., dp.pt., dp.sa. or dp.ct. prefix). |
| `dropbox_access_token` | high | `regex` | Dropbox short-lived access token (sl. prefix). |
| `duffel_api_token` | high | `regex` | Duffel API access token (duffel_test_ or duffel_live_ prefix). |
| `facebook_access_token` | medium | `regex` | Facebook Graph API access token (EAA prefix) with a plausible structure. |
| `facebook_app_secret` | high | `key_value`, `regex` | Facebook app secret (32 hex characters) assigned to a Facebook app secret name. |
| `flutterwave_secret_key` | high | `regex` | Flutterwave secret key (FLWSECK- or FLWSECK_TEST- prefix). |
| `fly_api_token` | high | `regex` | Fly.io API token (fo1_ prefix) or macaroon (fm1a_, fm1r_ or fm2_ prefix). |
| `framework_secret_key` | high | `regex` | Web framework signing secret assigned to SECRET_KEY, DJANGO_SECRET_KEY, FLASK_SECRET_KEY, JWT_SECRET_KEY or app.secret_key. |
| `git_credentials_password` | high | `structured_file` | Password in a URL stored in a Git .git-credentials file. |
| `github_token` | high | `regex` | GitHub personal access, OAuth, user-to-server, server-to-server, refresh or fine-grained token (ghp_, gho_, ghu_, ghs_, ghr_ or github_pat_ prefix). |
| `gitlab_agent_token` | high | `regex` | GitLab agent for Kubernetes token (glagent- prefix). |
| `gitlab_ci_job_token` | high | `regex` | GitLab CI job token (glcbt- prefix). |
| `gitlab_deploy_token` | high | `regex` | GitLab deploy token (gldt- prefix). |
| `gitlab_feature_flag_client_token` | high | `regex` | GitLab feature flags client token (glffct- prefix). |
| `gitlab_feed_token` | high | `regex` | GitLab feed token (glft- prefix). |
| `gitlab_incoming_mail_token` | high | `regex` | GitLab incoming mail token (glimt- prefix). |
| `gitlab_oauth_application_secret` | high | `regex` | GitLab OAuth application secret (gloas- prefix). |
| `gitlab_personal_access_token` | high | `regex` | GitLab personal access token (glpat- prefix). |
| `gitlab_pipeline_trigger_token` | high | `regex` | GitLab pipeline trigger token (glptt- prefix). |
| `gitlab_private_token_header` | high | `regex` | PRIVATE-TOKEN HTTP header carrying a GitLab token. |
| `gitlab_runner_registration_token` | high | `regex` | GitLab runner registration token (glrtr- or GR1348941 prefix). |
| `gitlab_runner_token` | high | `regex` | GitLab runner authentication token (glrt- prefix). |
| `gitlab_scim_token` | high | `regex` | GitLab SCIM token (glsoat- prefix). |
| `google_api_key` | high | `regex` | Google Cloud API key (AIza prefix). |
| `google_oauth_access_token` | high | `regex` | Google OAuth 2.0 access token (ya29. prefix). |
| `google_oauth_client_secret` | high | `regex` | Google OAuth 2.0 client secret (GOCSPX- prefix). |
| `google_oauth_refresh_token` | high | `regex` | Google OAuth 2.0 refresh token (1//0 prefix), as cached by gcloud and client libraries. |
| `grafana_cloud_api_token` | high | `regex` | Grafana Cloud access policy token (glc_ prefix). |
| `grafana_service_account_token` | high | `regex` | Grafana service account token (glsa_ prefix). |
| `heroku_api_key` | high | `contextual` | Heroku API key (HRKU- prefix) or a UUID assigned to a Heroku API key name. |
| `htpasswd_password_hash` | high | `path_regex` | Password hash in an Apache htpasswd file. |
| `http_api_key_header` | high | `regex` | X-Api-Key HTTP header carrying a key. |
| `http_basic_authorization_header` | high | `regex` | Authorization: Basic HTTP header carrying base64 credentials. |
| `http_bearer_authorization_header` | high | `regex` | Authorization: Bearer HTTP header carrying a token. |
| `huggingface_token` | high | `regex` | Hugging Face user or organization access token (hf_ or api_org_ prefix). |
| `json_web_token` | medium | `regex` | JSON Web Token with a decodable header and payload. |
| `kafka_sasl_jaas_password` | high | `regex` | password option of a Kafka SASL JAAS LoginModule configuration. |
| `keyword_entropy` | low | `entropy` | High-entropy value next to a secret keyword, with no vendor-specific shape. |
| `kubeconfig_client_key_data` | high | `path_regex` | client-key-data entry (a base64 PEM private key) in a kubeconfig file. |
| `kubeconfig_password` | high | `path_regex` | password entry of a user in a kubeconfig file. |
| `kubeconfig_token` | high | `path_regex` | token entry of a user in a kubeconfig file. |
| `laravel_app_key` | high | `regex` | Laravel APP_KEY (base64: prefix). |
| `linear_api_key` | high | `regex` | Linear API key (lin_api_ prefix). |
| `mailchimp_api_key` | high | `regex` | Mailchimp API key (32 hex characters with a -usN data-centre suffix). |
| `mailgun_api_key` | high | `key_value`, `regex` | Mailgun API key (key- prefix) or a Mailgun key assigned to a Mailgun-named key. |
| `mapbox_secret_token` | high | `regex` | Mapbox secret access token (sk.eyJ prefix). |
| `maven_settings_password` | high | `path_regex` | <password> element in a Maven settings.xml server entry. |
| `mysql_client_password` | high | `path_regex` | password option in a MySQL or MariaDB client configuration file (.my.cnf, my.cnf, .mylogin.cnf). |
| `netlify_personal_access_token` | high | `regex` | Netlify personal access token (nfp_ prefix). |
| `netrc_password` | medium | `path_regex` | password token in a .netrc file. |
| `new_relic_insights_key` | high | `regex` | New Relic Insights insert or query key (NRII- or NRIQ- prefix). |
| `new_relic_license_key` | high | `regex` | New Relic license key (NRAL suffix). |
| `new_relic_user_api_key` | high | `regex` | New Relic user API key (NRAK- prefix). |
| `nightfall_api_key` | high | `regex` | Nightfall API key (NF- prefix). |
| `notion_integration_token` | high | `regex` | Notion internal integration token (secret_ or ntn_ prefix). |
| `npm_token` | high | `regex` | npm granular or classic access token (npm_ prefix). |
| `npmrc_auth_token` | high | `path_regex` | _authToken entry in an .npmrc file. |
| `npmrc_basic_auth` | high | `path_regex` | _auth entry (base64 user:password) in an .npmrc file. |
| `npmrc_password` | high | `path_regex` | _password entry in an .npmrc registry scope. |
| `nuget_api_key` | high | `regex` | NuGet.org API key (oy2 prefix). |
| `okta_api_token` | high | `regex` | Okta API token following the SSWS authorization scheme. |
| `openai_api_key` | high | `regex` | OpenAI API key (sk- prefix in the project, service account, admin or legacy form). |
| `openrouter_api_key` | high | `regex` | OpenRouter API key (sk-or-v1- prefix). |
| `password_hash` | medium | `regex` | Unix crypt password hash (MD5, APR1, SHA-256, SHA-512, bcrypt or yescrypt) outside a password file. |
| `pem_private_key` | medium/high | `pem` | PEM-armoured private key block, including PGP private key armour. |
| `pgpass_password` | high | `structured_file` | Password field of a libpq .pgpass entry. |
| `php_define_password` | high | `regex` | PHP define() constant whose name says password, secret, api key or token. |
| `planetscale_oauth_token` | high | `regex` | PlanetScale OAuth token (pscale_oauth_ prefix). |
| `planetscale_password` | high | `regex` | PlanetScale database password (pscale_pw_ prefix). |
| `planetscale_service_token` | high | `regex` | PlanetScale service token (pscale_tkn_ prefix). |
| `postman_api_key` | high | `regex` | Postman API key (PMAK- prefix). |
| `prefect_api_key` | high | `regex` | Prefect Cloud API key (pnu_ prefix). |
| `pulumi_access_token` | high | `regex` | Pulumi Cloud access token (pul- prefix). |
| `pypi_api_token` | high | `regex` | PyPI API token (pypi- prefix). |
| `pypirc_password` | medium | `path_regex` | password entry in a .pypirc file. |
| `rails_master_key` | high | `path_regex` | Rails config/master.key or credentials key file content (32 hex characters). |
| `rails_secret_key_base` | high | `regex` | Rails secret_key_base assignment (64 to 128 hex characters). |
| `render_api_key` | high | `regex` | Render API key (rnd_ prefix). |
| `rubygems_api_key` | high | `regex` | RubyGems.org API key (rubygems_ prefix). |
| `sendgrid_api_key` | high | `regex` | SendGrid API key (SG. prefix with two dot-separated segments). |
| `sensitive_file_credential_store` | medium | `path_only` | Unreadable credential store file by path (.netrc, .pgpass, .git-credentials, .aws/credentials, .docker/config.json). |
| `sensitive_file_gpg_keyring` | medium | `path_only` | Unreadable GnuPG secret keyring by path (secring.gpg or private-keys-v1.d/*.key). |
| `sensitive_file_keystore` | low/medium | `path_only` | Unreadable PKCS#12 bundle (.p12, .pfx) or Java keystore (.jks, .keystore) by path. |
| `sensitive_file_password_database` | medium | `path_only` | Unreadable KeePass database (.kdbx) by path. |
| `sensitive_file_private_key` | medium | `path_only` | Unreadable SSH private key file by path (id_rsa, id_ed25519 and variants). |
| `sentry_dsn` | medium | `regex` | Sentry DSN with a public key on an ingest host (an identifier, not a credential). |
| `sentry_organization_token` | high | `regex` | Sentry organization auth token (sntrys_ prefix). |
| `sentry_user_token` | high | `regex` | Sentry user auth token (sntryu_ prefix). |
| `shadow_password_hash` | high | `path_regex` | Password hash in /etc/shadow, /etc/gshadow, /etc/passwd or master.passwd. |
| `shopify_access_token` | high | `regex` | Shopify Admin API access token (shpat_ prefix). |
| `shopify_partner_key` | high | `regex` | Shopify Partners API key (shppa_ prefix). |
| `shopify_shared_secret` | high | `regex` | Shopify app shared secret (shpss_ prefix). |
| `slack_token` | high | `regex` | Slack bot, user, app-level, refresh or configuration token (xox*- or xapp- prefix). |
| `slack_webhook` | high | `regex` | Slack incoming webhook URL (hooks.slack.com/services/...). |
| `snyk_api_token` | high | `contextual` | Snyk API token: a UUID assigned to a Snyk token name. |
| `sonarcloud_token` | high | `regex` | SonarCloud token (sqco_ prefix). |
| `sonarqube_token` | high | `regex` | SonarQube user, project or global analysis token (squ_, sqp_ or sqa_ prefix). |
| `square_application_secret` | high | `regex` | Square application secret (sq0csp- prefix). |
| `square_oauth_token` | high | `regex` | Square OAuth access token (sq0atp- prefix). |
| `stripe_api_key` | high | `regex` | Stripe secret or restricted API key (sk_live_, sk_test_, rk_live_ or rk_test_ prefix). |
| `stripe_webhook_secret` | high | `regex` | Stripe webhook signing secret (whsec_ prefix). |
| `supabase_personal_access_token` | high | `regex` | Supabase personal access token (sbp_ prefix). |
| `supabase_service_role_key` | high | `regex` | Supabase service_role JWT (a JWT whose payload claims the service_role). |
| `tailscale_key` | high | `regex` | Tailscale auth, API or OAuth key (tskey- prefix). |
| `telegram_bot_token` | high | `shape` | Telegram bot token (numeric bot id, a colon and a 35-character secret). |
| `terraform_cloud_token` | high | `path_regex`, `regex` | Terraform Cloud or Enterprise API token (.atlasv1. marker) or a credentials.tfrc.json / .terraformrc token entry. |
| `twilio_account_sid` | medium | `regex` | Twilio account SID (AC prefix; an identifier, not a credential). |
| `twilio_api_key` | high | `regex` | Twilio API key SID (SK prefix). |
| `twilio_auth_token` | high | `regex` | Twilio auth token (32 hex characters) assigned to a Twilio auth token name. |
| `twitch_api_token` | high | `key_value`, `regex` | Twitch client secret or OAuth token (30 alphanumerics) assigned to a Twitch-named key. |
| `vault_token` | high | `regex` | HashiCorp Vault service, batch or recovery token (hvs., hvb. or hvr. prefix). |
| `vault_token_file` | high | `path_regex` | Token stored in a .vault-token file, including the legacy s. form. |
| `vercel_access_token` | medium | `key_value` | Vercel access token assigned to a Vercel or Zeit token name. |
| `wordpress_auth_salt` | high | `regex` | WordPress authentication key or salt constant in wp-config.php. |
| `xml_password_attribute` | high | `path_regex` | password or passwd attribute in an XML configuration file. |
| `xml_password_element` | high | `path_regex` | <password> or <passphrase> element in an XML configuration file. |
