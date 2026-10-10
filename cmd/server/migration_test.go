package main

// The organisations migration on a database that holds data from before it: sites,
// submissions and API tokens are kept, and the former administrator becomes the
// administrator of the initial organisation. Skipped without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	naria "gitlab.com/detag_inno/naria"
)

const beforeOrganisations = "20261010000001"

func TestMigrationOrganisationsGardeLesDonnees(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL absent")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connexion: %v", err)
	}
	defer admin.Close()
	const name = "naria_migration_test"
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("création de la base: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name) })

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("DSN: %v", err)
	}
	u.Path = "/" + name
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatalf("ouverture: %v", err)
	}
	defer db.Close()

	goose.SetBaseFS(naria.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(db, "migrations", mustVersion(t, beforeOrganisations)); err != nil {
		t.Fatalf("migrations antérieures: %v", err)
	}

	// Legacy data: an administrator and a member, a site and a form of the member, a
	// submission, and an API token created by the administrator on the member's site.
	legacy := []string{
		`INSERT INTO users (id, email, name, role, password_hash, created_at) VALUES
		 ('00000000-0000-0000-0000-00000000000a', 'admin@x.test', 'Admin', 'admin', 'h', now() - interval '2 days'),
		 ('00000000-0000-0000-0000-00000000000b', 'membre@x.test', 'Membre', 'member', 'h', now() - interval '1 day')`,
		`INSERT INTO sites (id, owner_id, name) VALUES ('00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-00000000000b', 'Site')`,
		`INSERT INTO forms (id, site_id, name, access_key) VALUES ('00000000-0000-0000-0000-0000000000f1', '00000000-0000-0000-0000-0000000000c1', 'Contact', 'cle')`,
		`INSERT INTO submissions (id, form_id, payload) VALUES ('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000f1', 'chiffre')`,
		`INSERT INTO api_tokens (site_id, user_id, name, token_hash) VALUES ('00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-00000000000a', 'Jeton', 'empreinte')`,
	}
	for _, q := range legacy {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("données antérieures: %v", err)
		}
	}

	if err := goose.Up(db, "migrations"); err != nil {
		t.Fatalf("migration organisations: %v", err)
	}

	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	if n := count(`SELECT count(*) FROM sites WHERE name = 'Site'`); n != 1 {
		t.Errorf("site perdu : %d", n)
	}
	if n := count(`SELECT count(*) FROM submissions WHERE payload = 'chiffre'`); n != 1 {
		t.Errorf("soumission perdue : %d", n)
	}
	if n := count(`SELECT count(*) FROM api_tokens WHERE token_hash = 'empreinte'`); n != 1 {
		t.Errorf("jeton perdu : %d", n)
	}
	if n := count(`SELECT count(*) FROM organisations`); n != 1 {
		t.Errorf("organisations : %d (1 attendue)", n)
	}
	var role string
	var orgs sql.NullString
	if err := db.QueryRow(`SELECT role, org_id::text FROM users WHERE email = 'admin@x.test'`).Scan(&role, &orgs); err != nil {
		t.Fatal(err)
	}
	if role != "admin_orga" || !orgs.Valid {
		t.Errorf("ancien administrateur : rôle %q, organisation %v (admin_orga attendu)", role, orgs)
	}
	if n := count(`SELECT count(*) FROM users WHERE email = 'membre@x.test' AND role = 'user'`); n != 1 {
		t.Errorf("le membre n'est pas devenu utilisateur")
	}
	if n := count(`SELECT count(*) FROM users WHERE role = 'admin'`); n != 0 {
		t.Errorf("administrateur de plateforme créé par la migration : %d", n)
	}
}

func mustVersion(t *testing.T, v string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		t.Fatalf("version %q: %v", v, err)
	}
	return n
}
