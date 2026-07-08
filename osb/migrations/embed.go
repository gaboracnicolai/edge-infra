// Package osbmigrations embeds the OSB SQL migrations so the migrate runner
// (cmd/migrate) can apply them to the shared database alongside the
// control-plane set. The files remain plain SQL on disk — the Python worker and
// the integration harness apply them independently.
package osbmigrations

import "embed"

//go:embed *.sql
var FS embed.FS
