#!/bin/bash
# Generate self-signed certificates for development/testing
# For production, use proper certificates from Let's Encrypt or similar

set -e

CERT_DIR="${1:-./docker/certs}"
DOMAIN="${2:-localhost}"
DAYS="${3:-365}"

mkdir -p "$CERT_DIR"

echo "Generating certificates for domain: $DOMAIN"

# Generate CA key and certificate
openssl genrsa -out "$CERT_DIR/ca.key" 4096
openssl req -new -x509 -days "$DAYS" -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/C=US/ST=State/L=City/O=LogMessager/CN=LogMessager CA"

# Generate server key
openssl genrsa -out "$CERT_DIR/server.key" 2048

# Generate server CSR
openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=US/ST=State/L=City/O=LogMessager/CN=$DOMAIN"

# Create extensions file for SAN
cat > "$CERT_DIR/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# Sign server certificate
openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.crt" \
    -days "$DAYS" -extfile "$CERT_DIR/server.ext"

# Cleanup
rm "$CERT_DIR/server.csr" "$CERT_DIR/server.ext"

# Set permissions
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo "Certificates generated in $CERT_DIR"
echo "  CA Certificate: $CERT_DIR/ca.crt"
echo "  Server Certificate: $CERT_DIR/server.crt"
echo "  Server Key: $CERT_DIR/server.key"
