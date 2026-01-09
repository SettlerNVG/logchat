.PHONY: proto build-server build-client run-server run-client test lint clean docker-up docker-down migrate-up migrate-down dev restart reset

# Quick development start
dev:
	@echo "Starting development environment..."
	@docker-compose -f docker/docker-compose.yml up -d
	@echo "Building client..."
	@cd client && go build -o ../bin/logchat ./cmd
	@echo "Ready! Run: ./bin/logchat"

# Restart with clean sessions
restart:
	@./scripts/dev-restart.sh

# Full reset (rebuild server too)
reset:
	@echo "🔄 Full reset..."
	@docker-compose -f docker/docker-compose.yml down
	@docker-compose -f docker/docker-compose.yml up -d --build
	@sleep 3
	@./scripts/dev-restart.sh

# Proto generation
proto:
	@echo "Generating proto files..."
	@cd proto && buf generate

proto-lint:
	@cd proto && buf lint

# Build
build-server:
	@echo "Building server..."
	@cd server && go build -o ../bin/logmessager-server ./cmd

build-client:
	@echo "Building client..."
	@cd client && go build -o ../bin/logchat ./cmd

build: build-server build-client

# Run
run-server:
	@cd server && go run ./cmd

run-client:
	@cd client && go run ./cmd

# Test
test:
	@cd server && go test -v ./...
	@cd client && go test -v ./...

test-coverage:
	@cd server && go test -coverprofile=coverage.out ./...
	@cd client && go test -coverprofile=coverage.out ./...

# Lint
lint:
	@cd server && golangci-lint run
	@cd client && golangci-lint run

# Docker
docker-up:
	@docker-compose -f docker/docker-compose.yml up -d

docker-down:
	@docker-compose -f docker/docker-compose.yml down

docker-logs:
	@docker-compose -f docker/docker-compose.yml logs -f

docker-build:
	@docker-compose -f docker/docker-compose.yml build

# Database migrations
migrate-up:
	@cd server && go run ./cmd migrate up

migrate-down:
	@cd server && go run ./cmd migrate down

migrate-create:
	@read -p "Migration name: " name; \
	migrate create -ext sql -dir server/migrations -seq $$name

# Clean
clean:
	@rm -rf bin/
	@cd server && go clean
	@cd client && go clean

# Development setup
setup:
	@echo "Installing dependencies..."
	@go install github.com/bufbuild/buf/cmd/buf@latest
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	@echo "Setup complete!"

# Help
help:
	@echo "Available targets:"
	@echo "  dev            - Quick start: docker + build client"
	@echo "  restart        - Clean sessions + rebuild client"
	@echo "  reset          - Full reset: rebuild server + clean + rebuild client"
	@echo "  proto          - Generate Go code from proto files"
	@echo "  build          - Build server and client"
	@echo "  run-server     - Run the central server"
	@echo "  run-client     - Run the client"
	@echo "  test           - Run tests"
	@echo "  lint           - Run linter"
	@echo "  docker-up      - Start Docker containers"
	@echo "  docker-down    - Stop Docker containers"
	@echo "  migrate-up     - Run database migrations"
	@echo "  migrate-down   - Rollback database migrations"
	@echo "  setup          - Install development dependencies"
