#!/bin/sh
# The templ generator and runtime must be the same version: a runtime upgrade
# can drop helpers that an older generator still emits. The generator is
# therefore taken from go.mod, and every pinned copy has to match it.
set -eu
cd "$(dirname "$0")/.."

version=$(go list -m -f '{{.Version}}' github.com/a-h/templ)

stale=$(grep -nE 'templ@v[0-9]|TEMPL_VERSION:' Dockerfile .gitlab-ci.yml .github/workflows/ci.yml | grep -vF "$version" || true)
if [ -n "$stale" ]; then
	echo "templ CLI pinned to a version other than go.mod ($version):" >&2
	echo "$stale" >&2
	exit 1
fi

go run "github.com/a-h/templ/cmd/templ@$version" generate -log-level error
go build ./...
