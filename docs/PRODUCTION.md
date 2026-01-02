# Production Deployment Guide

## Prerequisites

- Docker & Docker Compose
- Domain name (for TLS)
- Server with at least 1GB RAM

## Quick Start

### 1. Clone and Configure

```bash
git clone https://github.com/yourusername/logmessager
cd logmessager

# Copy and edit production config
cp docker/.env.prod.example docker/.env.prod
```

### 2. Generate Secrets

```bash
# Generate JWT secret
openssl rand -base64 32

# Generate database password
openssl rand -base64 24
```

Edit `docker/.env.prod`:

```env
DB_PASSWORD=<generated-password>
JWT_SECRET=<generated-secret>
TLS_ENABLED=true
```

### 3. Generate TLS Certificates

For development/testing:
```bash
chmod +x scripts/generate-certs.sh
./scripts/generate-certs.sh docker/certs your-domain.com
```

For production, use Let's Encrypt:
```bash
# Install certbot
sudo apt install certbot

# Get certificates
sudo certbot certonly --standalone -d your-domain.com

# Copy to docker/certs
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem docker/certs/server.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem docker/certs/server.key
```

### 4. Deploy

```bash
# Start services
docker-compose -f docker/docker-compose.prod.yml --env-file docker/.env.prod up -d

# Check logs
docker-compose -f docker/docker-compose.prod.yml logs -f server
```

## Security Checklist

### Server

- [ ] Strong JWT_SECRET (32+ bytes, random)
- [ ] Strong DB_PASSWORD (24+ bytes, random)
- [ ] TLS enabled
- [ ] Firewall configured (only port 50051 open)
- [ ] Regular security updates

### Database

- [ ] Not exposed to internet (internal network only)
- [ ] Regular backups
- [ ] Strong password

### Monitoring

- [ ] Log aggregation (ELK, Loki, etc.)
- [ ] Metrics collection (Prometheus)
- [ ] Alerting configured

## Architecture

```
Internet
    │
    ▼
┌─────────────────┐
│   Firewall      │  Port 50051 only
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  LogMessager    │  gRPC Server
│    Server       │  (TLS)
└────────┬────────┘
         │ Internal Network
         ▼
┌─────────────────┐
│   PostgreSQL    │  Not exposed
└─────────────────┘
```

## Scaling

### Horizontal Scaling

For high availability, deploy multiple server instances behind a load balancer:

```yaml
# docker-compose.scale.yml
services:
  server:
    deploy:
      replicas: 3
```

Use a gRPC-aware load balancer (Envoy, nginx with grpc_pass).

### Database Scaling

For high load:
1. Use connection pooling (PgBouncer)
2. Read replicas for read-heavy workloads
3. Consider managed PostgreSQL (AWS RDS, Cloud SQL)

## Backup & Recovery

### Database Backup

```bash
# Backup
docker exec logmessager-db-prod pg_dump -U logmessager logmessager > backup.sql

# Restore
docker exec -i logmessager-db-prod psql -U logmessager logmessager < backup.sql
```

### Automated Backups

Add to crontab:
```bash
0 2 * * * /path/to/backup-script.sh
```

## Updating

### Rolling Update

```bash
# Pull latest
git pull

# Rebuild and restart
docker-compose -f docker/docker-compose.prod.yml build
docker-compose -f docker/docker-compose.prod.yml up -d
```

### Database Migrations

Migrations run automatically on startup. For manual control:

```bash
# Check current version
docker run --rm -v $(pwd)/server/migrations:/migrations \
  migrate/migrate -path=/migrations \
  -database "postgres://..." version

# Migrate up
docker run --rm -v $(pwd)/server/migrations:/migrations \
  migrate/migrate -path=/migrations \
  -database "postgres://..." up

# Rollback
docker run --rm -v $(pwd)/server/migrations:/migrations \
  migrate/migrate -path=/migrations \
  -database "postgres://..." down 1
```

## Troubleshooting

### Server won't start

```bash
# Check logs
docker-compose -f docker/docker-compose.prod.yml logs server

# Common issues:
# - Database not ready: wait for postgres healthcheck
# - Wrong DATABASE_URL: check connection string
# - Port already in use: change GRPC_PORT
```

### Connection refused

```bash
# Check if server is running
docker ps

# Check if port is open
nc -zv your-domain.com 50051

# Check firewall
sudo ufw status
```

### High memory usage

```bash
# Check container stats
docker stats

# Adjust limits in docker-compose.prod.yml
deploy:
  resources:
    limits:
      memory: 256M
```

## Client Distribution

### Homebrew (macOS)

Create a tap repository and formula:

```ruby
# Formula/logmessager.rb
class Logmessager < Formula
  desc "Secure terminal messenger"
  homepage "https://github.com/yourusername/logmessager"
  url "https://github.com/yourusername/logmessager/releases/download/v1.0.0/logmessager-darwin-arm64"
  sha256 "..."
  
  def install
    bin.install "logmessager-darwin-arm64" => "logmessager"
  end
end
```

### Direct Download

```bash
# Linux
curl -L https://github.com/yourusername/logmessager/releases/latest/download/logmessager-linux-amd64 -o logmessager
chmod +x logmessager
sudo mv logmessager /usr/local/bin/

# macOS
curl -L https://github.com/yourusername/logmessager/releases/latest/download/logmessager-darwin-arm64 -o logmessager
chmod +x logmessager
sudo mv logmessager /usr/local/bin/
```
