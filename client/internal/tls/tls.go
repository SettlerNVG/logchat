package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// LoadClientCredentials загружает TLS credentials для gRPC клиента
func LoadClientCredentials(caFile, serverName string) (credentials.TransportCredentials, error) {
	// Если CA файл не указан, используем системный trust store
	var certPool *x509.CertPool
	
	if caFile != "" {
		// Загружаем CA сертификат (для self-signed сертификатов)
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		certPool = x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to add CA certificate to pool")
		}
	} else {
		// Используем системный trust store (для Let's Encrypt и других публичных CA)
		var err error
		certPool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system cert pool: %w", err)
		}
	}

	// Настройки TLS
	config := &tls.Config{
		RootCAs:    certPool,
		ServerName: serverName, // Для проверки CN в сертификате
		MinVersion: tls.VersionTLS13,
	}

	return credentials.NewTLS(config), nil
}
