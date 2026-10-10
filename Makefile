.PHONY: generate sqlc build run dev tidy db-up db-down up down logs createadmin test test-secu

# Génère le code templ (templates) + sqlc (requêtes)
generate:
	templ generate
	sqlc generate

sqlc:
	sqlc generate

build: generate
	go build -o bin/server ./cmd/server
	go build -o bin/createadmin ./cmd/createadmin

# Lance le serveur en local (nécessite DATABASE_URL ou un .env exporté)
run: generate
	go run ./cmd/server

tidy:
	go mod tidy

# Démarre uniquement Postgres en local (pour `make run`)
db-up:
	docker compose up -d db

db-down:
	docker compose stop db

# Stack complète en conteneurs
up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f app

# Crée un compte (administrateur par défaut). Ex :
#   make createadmin EMAIL=vous@exemple.fr NAME="David" PASS="secret"
createadmin:
	go run ./cmd/createadmin -email "$(EMAIL)" -name "$(NAME)" -password "$(PASS)" -role $(or $(ROLE),admin)

# Tests. Les tests d'intégration (cloisonnement, point d'entrée public) sont ignorés sans TEST_DATABASE_URL.
test: generate
	go test ./...

# Tests d'intégration contre un Postgres jetable (nécessite Docker).
test-secu: generate
	@docker rm -f naria-test-db >/dev/null 2>&1 || true
	@docker run -d --rm --name naria-test-db \
		-e POSTGRES_USER=test -e POSTGRES_PASSWORD=test -e POSTGRES_DB=test \
		-p 127.0.0.1:55432:5432 postgres:17-alpine >/dev/null
	@echo "attente de Postgres…"; \
		for i in $$(seq 1 30); do docker exec naria-test-db pg_isready -U test >/dev/null 2>&1 && break; sleep 1; done
	@TEST_DATABASE_URL="postgres://test:test@127.0.0.1:55432/test?sslmode=disable" go test ./cmd/server/ -v; \
		status=$$?; docker rm -f naria-test-db >/dev/null 2>&1; exit $$status
