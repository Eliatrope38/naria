// Package naria embeds the migrations and static files into the binary.
package naria

import "embed"

//go:embed migrations/*.sql
var Migrations embed.FS

//go:embed web/static
var StaticFiles embed.FS
