#!/bin/bash
# Dev restart script - cleans sessions and rebuilds

set -e

echo "🔄 Restarting development environment..."

# Clean sessions in DB
echo "🧹 Cleaning sessions..."
docker exec logmessager-db psql -U logmessager -d logmessager -c "UPDATE sessions SET status = 'ended' WHERE status = 'active';" 2>/dev/null || true
docker exec logmessager-db psql -U logmessager -d logmessager -c "UPDATE chat_requests SET status = 'expired' WHERE status = 'pending';" 2>/dev/null || true

# Rebuild client
echo "🔨 Building client..."
cd "$(dirname "$0")/../client"
go build -o ../bin/logchat ./cmd

echo "✅ Done! Run: ./bin/logchat"
