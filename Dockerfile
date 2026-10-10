# build
FROM golang:1.26.6-alpine AS build
RUN apk add --no-cache git
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

ARG VERSION=dev

COPY . .
# Génère le code templ puis compile deux binaires statiques.
RUN go install github.com/a-h/templ/cmd/templ@v0.3.1020 && templ generate
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X gitlab.com/detag_inno/naria/internal/version.Version=$VERSION" \
    -o /out/server ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/createadmin ./cmd/createadmin

# runtime
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 app
COPY --from=build /out/server /usr/local/bin/server
COPY --from=build /out/createadmin /usr/local/bin/createadmin
USER app
EXPOSE 8080
# Pas d'ENTRYPOINT figé : la commande par défaut lance le serveur, mais on peut
# exécuter d'autres binaires (ex: createadmin) via `docker compose run app createadmin ...`.
CMD ["server"]
