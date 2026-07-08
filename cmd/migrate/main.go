// Command migrate applies the control-plane and OSB SQL migrations to the shared
// database, idempotently. It runs as a Helm pre-install/pre-upgrade hook Job in
// Kubernetes, and standalone anywhere else — `DATABASE_URL=... migrate` — so the
// non-Kubernetes self-host path has the same one-command story (no K8s assumed).
package main

import (
	"context"
	"log"
	"os"

	"github.com/edge-infra/control-plane/internal/migrate"
	cpmig "github.com/edge-infra/control-plane/migrations"
	osbmig "github.com/edge-infra/control-plane/osb/migrations"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("migrate: DATABASE_URL is required")
	}
	// Control-plane schema first, then OSB. Both target the ONE shared database;
	// the OSB set references only its own tables, and the shared gateways/routes
	// the OSB translator writes to are created by the control-plane set.
	n, err := migrate.Apply(context.Background(), dsn, []migrate.Set{
		{Name: "cp", FS: cpmig.FS},
		{Name: "osb", FS: osbmig.FS},
	})
	if err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Printf("migrate: applied %d new migration(s); schema up to date", n)
}
