#!/bin/sh
# Single source of the semgrep invocation: the pre-commit hook and both CI
# pipelines run this file, so they apply the same rules. Plain sh, because the
# semgrep container image has neither make nor bash.
set -eu
cd "$(dirname "$0")/.."

exec semgrep scan \
	--metrics=off \
	--error \
	--config p/golang \
	--config p/default \
	--config p/gosec \
	--config p/owasp-top-ten \
	--config p/github-actions \
	--config p/javascript \
	--exclude '*_templ.go' \
	--exclude 'internal/database/*.sql.go' \
	.
