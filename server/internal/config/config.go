package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	TLS      TLSConfig
	Log      LogConfig
}

type ServerConfig struct {
	Host     string
	GRPCPort int
	Env      string
}

type DatabaseConfig struct {
	URL                string
	MaxConnections     int
	MaxIdleConnections int
}

type JWTConfig struct {
	Secret               string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
}

type TLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

type LogConfig struct {
	Level  string
	Format string
}

func Load() (*Config, error) {
	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.AddConfigPath(".")
	viper.AddConfigPath("..")

	// Environment variables override
	viper.AutomaticEnv()

	// Set defaults
	viper.SetDefault("SERVER_HOST", "0.0.0.0")
	viper.SetDefault("SERVER_GRPC_PORT", 50051)
	viper.SetDefault("SERVER_ENV", "development")
	viper.SetDefault("DATABASE_MAX_CONNECTIONS", 25)
	viper.SetDefault("DATABASE_MAX_IDLE_CONNECTIONS", 5)
	viper.SetDefault("JWT_ACCESS_TOKEN_DURATION", "24h")
	viper.SetDefault("JWT_REFRESH_TOKEN_DURATION", "168h")
	viper.SetDefault("TLS_ENABLED", false)
	viper.SetDefault("LOG_LEVEL", "debug")
	viper.SetDefault("LOG_FORMAT", "console")

	// Try to read config file (optional)
	_ = viper.ReadInConfig()

	accessDuration, err := time.ParseDuration(viper.GetString("JWT_ACCESS_TOKEN_DURATION"))
	if err != nil {
		accessDuration = 15 * time.Minute
	}

	refreshDuration, err := time.ParseDuration(viper.GetString("JWT_REFRESH_TOKEN_DURATION"))
	if err != nil {
		refreshDuration = 168 * time.Hour
	}

	return &Config{
		Server: ServerConfig{
			Host:     viper.GetString("SERVER_HOST"),
			GRPCPort: viper.GetInt("SERVER_GRPC_PORT"),
			Env:      viper.GetString("SERVER_ENV"),
		},
		Database: DatabaseConfig{
			URL:                viper.GetString("DATABASE_URL"),
			MaxConnections:     viper.GetInt("DATABASE_MAX_CONNECTIONS"),
			MaxIdleConnections: viper.GetInt("DATABASE_MAX_IDLE_CONNECTIONS"),
		},
		JWT: JWTConfig{
			Secret:               viper.GetString("JWT_SECRET"),
			AccessTokenDuration:  accessDuration,
			RefreshTokenDuration: refreshDuration,
		},
		TLS: TLSConfig{
			Enabled:  viper.GetBool("TLS_ENABLED"),
			CertFile: viper.GetString("TLS_CERT_FILE"),
			KeyFile:  viper.GetString("TLS_KEY_FILE"),
		},
		Log: LogConfig{
			Level:  viper.GetString("LOG_LEVEL"),
			Format: viper.GetString("LOG_FORMAT"),
		},
	}, nil
}
