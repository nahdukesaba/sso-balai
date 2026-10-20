# SSO Balai

Centralized authentication service for BP3KP Sumatera II applications.

## Tech Stack

- Go
- Fiber
- PostgreSQL (database only; no Supabase Auth)
- Git / GitHub

## Development

Run the API:

```bash
go run ./cmd/api
```

Health check:

```http
GET /health
```
