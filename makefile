.SILENT: run, migrate, migrate-test

run:
	go run cmd/auth/main.go --config=./config/local.yaml

migrate:
	go run ./cmd/migrator/main.go --storage-path=./storage/auth.db --migrations-path=./migrations

migrate-test:
	go run ./cmd/migrator/main.go --storage-path=./storage/auth.db --migrations-path=./tests/migrations --migrations-table=migrations_test
test:
	go test -v ./tests/auth_register_login_test.go