package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig
	P2P       P2PConfig
	Log       LogConfig
	DataDir   string
}

type ServerConfig struct {
	Address string
	TLS     bool
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

	// Set defaults
	viper.SetDefault("CENTRAL_SERVER_ADDRESS", "localhost:50051")
	viper.SetDefault("CENTRAL_SERVER_TLS", false)
	viper.SetDefault("P2P_PORT_RANGE_START", 50000)
	viper.SetDefault("P2P_PORT_RANGE_END", 50999)
	viper.SetDefault("LOG_LEVEL", "info")
	viper.SetDefault("LOG_FORMAT", "console")

	// Data directory for keys and config
	dataDir := filepath.Join(home, ".logchat")
	viper.SetDefault("DATA_DIR", dataDir)

	_ = viper.ReadInConfig()

	return &Config{
		Server: ServerConfig{
			Address: viper.GetString("CENTRAL_SERVER_ADDRESS"),
			TLS:     viper.GetBool("CENTRAL_SERVER_TLS"),
		},
		P2P: P2PConfig{
			PortRangeStart: viper.GetInt("P2P_PORT_RANGE_START"),
			PortRangeEnd:   viper.GetInt("P2P_PORT_RANGE_END"),
		},
		Log: LogConfig{
			Level:  viper.GetString("LOG_LEVEL"),
			Format: viper.GetString("LOG_FORMAT"),
		},
		DataDir: viper.GetString("DATA_DIR"),
	}, nil
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
