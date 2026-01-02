#!/bin/bash
# Build release binaries for multiple platforms

set -e

VERSION="${1:-dev}"
BUILD_DIR="./bin/release"
LDFLAGS="-s -w -X main.Version=$VERSION -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "Building LogChat $VERSION"

mkdir -p "$BUILD_DIR"

# Platforms to build
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

# Build client
echo "Building client..."
for platform in "${PLATFORMS[@]}"; do
    GOOS="${platform%/*}"
    GOARCH="${platform#*/}"
    
    output="$BUILD_DIR/logchat-$GOOS-$GOARCH"
    if [ "$GOOS" = "windows" ]; then
        output="$output.exe"
    fi
    
    echo "  $GOOS/$GOARCH -> $output"
    
    (cd client && CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
        go build -ldflags="$LDFLAGS" -o "../$output" ./cmd)
done

# Build server (Linux only for Docker)
echo "Building server..."
for platform in "linux/amd64" "linux/arm64"; do
    GOOS="${platform%/*}"
    GOARCH="${platform#*/}"
    
    output="$BUILD_DIR/logchat-server-$GOOS-$GOARCH"
    
    echo "  $GOOS/$GOARCH -> $output"
    
    (cd server && CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
        go build -ldflags="$LDFLAGS" -o "../$output" ./cmd)
done

# Create checksums
echo "Creating checksums..."
(cd "$BUILD_DIR" && sha256sum * > checksums.txt)

echo "Build complete! Binaries in $BUILD_DIR"
ls -la "$BUILD_DIR"
