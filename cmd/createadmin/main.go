// createadmin creates an account (admin by default) to bootstrap a new instance.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/term"

	"gitlab.com/detag_inno/naria/internal/auth"
	"gitlab.com/detag_inno/naria/internal/config"
	"gitlab.com/detag_inno/naria/internal/database"
)

func main() {
	email := flag.String("email", "", "email du compte")
	name := flag.String("name", "", "nom affiché")
	password := flag.String("password", "", "mot de passe")
	role := flag.String("role", auth.RoleAdmin, "rôle: admin (administrateur de plateforme) ; les administrateurs d'organisation se créent depuis /organisations")
	dsn := flag.String("dsn", "", "DATABASE_URL (sinon variable d'env)")
	flag.Parse()

	// A password passed as a flag is visible in `ps` and the shell history.
	pass := *password
	if pass == "" {
		pass = readPasswordStdin()
	}

	if *email == "" || *name == "" || pass == "" {
		log.Fatal("flags -email et -name sont requis ; le mot de passe est lu sur stdin si -password est absent")
	}
	if minLen := config.PasswordMinLength(); len(pass) < minLen {
		log.Fatalf("le mot de passe doit faire au moins %d caractères", minLen)
	}
	// An organisation's administrator needs an organisation, which this command does not set.
	if *role != auth.RoleAdmin {
		log.Fatal("le rôle doit être 'admin' : les autres comptes se créent depuis l'interface")
	}
	connStr := *dsn
	if connStr == "" {
		connStr = mustEnv("DATABASE_URL")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		log.Fatalf("connexion db: %v", err)
	}
	defer pool.Close()
	q := database.New(pool)

	hash, err := auth.HashPassword(pass)
	if err != nil {
		log.Fatalf("hash: %v", err)
	}

	u, err := q.CreateUser(ctx, database.CreateUserParams{
		Email:        auth.NormalizeEmail(*email),
		Name:         *name,
		Role:         *role,
		PasswordHash: hash,
	})
	if err != nil {
		log.Fatalf("création utilisateur: %v", err)
	}
	log.Printf("compte %q créé (%s), rôle=%s", u.Email, u.ID, u.Role)
}

// readPasswordStdin reads the password from stdin, keeping it out of argv. The input is
// hidden on a terminal; on a pipe, a line read lets the command be scripted.
func readPasswordStdin() string {
	fmt.Fprint(os.Stderr, "Mot de passe : ")
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr) // ReadPassword does not echo the newline
		if err != nil {
			return ""
		}
		return strings.TrimRight(string(b), "\r\n")
	}
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		return ""
	}
	fmt.Fprintln(os.Stderr)
	return strings.TrimRight(sc.Text(), "\r\n")
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("variable d'environnement %s requise", key)
	}
	return v
}
