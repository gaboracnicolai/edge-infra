// Package migrations embeds the control-plane SQL migrations (0001–NNNN) so the
// migrate runner (cmd/migrate) can apply them to the shared database without
// shipping loose .sql files alongside the binary. The files remain plain SQL on
// disk — the integration harness and CI apply them by path independently.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
