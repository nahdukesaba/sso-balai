package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"

	"github.com/nahdukesaba/sso-balai/internal/config"
)

const migrationTable = "sso_schema_migrations"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: go run ./cmd/migrate [up|down|version]")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to open database connection: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{
		MigrationsTable: migrationTable,
	})
	if err != nil {
		log.Fatalf("failed to initialize migration driver: %v", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres",
		driver,
	)
	if err != nil {
		log.Fatalf("failed to initialize migrations: %v", err)
	}

	switch os.Args[1] {
	case "up":
		runUp(m)

	case "down":
		runDown(m)

	case "version":
		showVersion(m)

	default:
		log.Fatalf("unknown command %q; use up, down, or version", os.Args[1])
	}
}

func runUp(m *migrate.Migrate) {
	err := m.Up()

	if errors.Is(err, migrate.ErrNoChange) {
		log.Println("migration: no changes")
		return
	}

	if err != nil {
		log.Fatalf("migration up failed: %v", err)
	}

	log.Println("migration up completed")
}

func runDown(m *migrate.Migrate) {
	err := m.Steps(-1)

	if errors.Is(err, migrate.ErrNoChange) {
		log.Println("migration: no changes")
		return
	}

	if err != nil {
		log.Fatalf("migration down failed: %v", err)
	}

	log.Println("migration down completed")
}

func showVersion(m *migrate.Migrate) {
	version, dirty, err := m.Version()

	if errors.Is(err, migrate.ErrNilVersion) {
		fmt.Println("version: none")
		fmt.Println("dirty: false")
		return
	}

	if err != nil {
		log.Fatalf("failed to read migration version: %v", err)
	}

	fmt.Printf("version: %d\n", version)
	fmt.Printf("dirty: %t\n", dirty)
}
