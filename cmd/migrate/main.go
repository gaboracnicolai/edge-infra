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
	sets := []migrate.Set{
		{Name: "cp", FS: cpmig.FS},
		{Name: "osb", FS: osbmig.FS},
	}

	// `migrate baseline` adopts the runner on a DB that already has the schema but
	// no tracking (a pre-runner / manually-migrated deploy): it records the
	// already-applied files without running them. The probe — latest CP (0007
	// client_ca_secret_name) + latest OSB (0003 dead_letter) — proves the DB is at
	// the current schema before recording.
	if len(os.Args) > 1 && os.Args[1] == "baseline" {
		const probe = "to_regclass('public.dead_letter') IS NOT NULL AND " +
			"EXISTS (SELECT 1 FROM information_schema.columns " +
			"WHERE table_name = 'routes' AND column_name = 'client_ca_secret_name')"
		n, err := migrate.Baseline(context.Background(), dsn, sets, probe)
		if err != nil {
			log.Fatalf("migrate baseline: %v", err)
		}
		log.Printf("migrate baseline: recorded %d already-applied migration(s); no SQL run", n)
		return
	}

	n, err := migrate.Apply(context.Background(), dsn, sets)
	if err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Printf("migrate: applied %d new migration(s); schema up to date", n)
}
