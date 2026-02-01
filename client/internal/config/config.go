package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig
	P2P       P2PConfig
	STUN      STUNConfig
	Log       LogConfig
	DataDir   string
}

type STUNConfig struct {
	Servers []string
	Enabled bool
}

type ServerConfig struct {
	Address    string
	TLS        TLSConfig
}

type TLSConfig struct {
	Enabled    bool
	CAFile     string
	ServerName string
}

type P2PConfig struct {
	PortRangeStart int
	PortRangeEnd   int
}

type LogConfig struct {
	Level  string
	Format string
}

func Load() (*Config, error) {
	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.AddConfigPath(".")

	// Also check home directory
	home, _ := os.UserHomeDir()
	if home != "" {
		viper.AddConfigPath(filepath.Join(home, ".logchat"))
	}

	viper.AutomaticEnv()

	// Set defaults - ready to use out of the box
	// For development: use localhost without TLS
	// For production: override CENTRAL_SERVER_ADDRESS via env or config file
	viper.SetDefault("CENTRAL_SERVER_ADDRESS", "localhost:50051")
	viper.SetDefault("TLS_ENABLED", false) // Auto-detect based on server address
	viper.SetDefault("TLS_CA_FILE", "")    // Use system CA pool if empty
	viper.SetDefault("TLS_SERVER_NAME", "") // Auto-detect from server address
	viper.SetDefault("P2P_PORT_RANGE_START", 50000)
	viper.SetDefault("P2P_PORT_RANGE_END", 50999)
	viper.SetDefault("STUN_ENABLED", true)
	viper.SetDefault("STUN_SERVERS", "stun.l.google.com:19302,stun.stunprotocol.org:3478,stun.nextcloud.com:443")
	viper.SetDefault("LOG_LEVEL", "info")
	viper.SetDefault("LOG_FORMAT", "console")

	// Data directory for keys and config
	dataDir := filepath.Join(home, ".logchat")
	viper.SetDefault("DATA_DIR", dataDir)

	_ = viper.ReadInConfig()

	serverAddr := viper.GetString("CENTRAL_SERVER_ADDRESS")
	tlsEnabled := viper.GetBool("TLS_ENABLED")
	tlsServerName := viper.GetString("TLS_SERVER_NAME")
	
	// Auto-enable TLS for non-localhost addresses
	if !tlsEnabled && !isLocalhost(serverAddr) {
		tlsEnabled = true
	}
	
	// Auto-detect server name from address if not specified
	if tlsServerName == "" {
		tlsServerName = extractHostname(serverAddr)
	}

	return &Config{
		Server: ServerConfig{
			Address: serverAddr,
			TLS: TLSConfig{
				Enabled:    tlsEnabled,
				CAFile:     viper.GetString("TLS_CA_FILE"),
				ServerName: tlsServerName,
			},
		},
		P2P: P2PConfig{
			PortRangeStart: viper.GetInt("P2P_PORT_RANGE_START"),
			PortRangeEnd:   viper.GetInt("P2P_PORT_RANGE_END"),
		},
		STUN: STUNConfig{
			Enabled: viper.GetBool("STUN_ENABLED"),
			Servers: parseSTUNServers(viper.GetString("STUN_SERVERS")),
		},
		Log: LogConfig{
			Level:  viper.GetString("LOG_LEVEL"),
			Format: viper.GetString("LOG_FORMAT"),
		},
		DataDir: viper.GetString("DATA_DIR"),
	}, nil
}

// parseSTUNServers parses comma-separated STUN server list
func parseSTUNServers(serversStr string) []string {
	if serversStr == "" {
		return []string{"stun.l.google.com:19302"}
	}
	
	var servers []string
	for _, s := range strings.Split(serversStr, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			// Remove stun: prefix if present
			s = strings.TrimPrefix(s, "stun:")
			servers = append(servers, s)
		}
	}
	
	if len(servers) == 0 {
		return []string{"stun.l.google.com:19302"}
	}
	
	return servers
}

// EnsureDataDir creates data directory if it doesn't exist
func (c *Config) EnsureDataDir() error {
	return os.MkdirAll(c.DataDir, 0700)
}

// KeysPath returns path to keys file
func (c *Config) KeysPath() string {
	return filepath.Join(c.DataDir, "keys.json")
}

// CredentialsPath returns path to credentials file
func (c *Config) CredentialsPath() string {
	return filepath.Join(c.DataDir, "credentials.json")
}

// isLocalhost checks if address is localhost
func isLocalhost(addr string) bool {
	return strings.HasPrefix(addr, "localhost:") ||
		strings.HasPrefix(addr, "127.0.0.1:") ||
		strings.HasPrefix(addr, "[::1]:")
}

// extractHostname extracts hostname from address (removes port)
func extractHostname(addr string) string {
	// Handle IPv6 addresses like [::1]:50051
	if strings.HasPrefix(addr, "[") {
		if idx := strings.Index(addr, "]"); idx != -1 {
			return addr[1:idx]
		}
	}
	
	// Handle regular addresses like localhost:50051
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	
	return addr
}
