package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/logmessager/server/internal/auth"
	"github.com/logmessager/server/internal/config"
	grpcserver "github.com/logmessager/server/internal/grpc"
	"github.com/logmessager/server/internal/repository"
	"github.com/logmessager/server/internal/service"
)

func main() {
	// Load config
	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
	}

	// Setup logging
	setupLogging(cfg.Log)

	log.Info().
		Str("env", cfg.Server.Env).
		Int("port", cfg.Server.GRPCPort).
		Msg("Starting LogMessager server")

	// Connect to database
	ctx := context.Background()
	db, err := repository.NewDB(ctx, cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer db.Close()

	log.Info().Msg("Connected to database")

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	contactRepo := repository.NewContactRepository(db)

	// Initialize JWT manager
	jwtManager := auth.NewJWTManager(
		cfg.JWT.Secret,
		cfg.JWT.AccessTokenDuration,
		cfg.JWT.RefreshTokenDuration,
	)

	// Initialize services
	authService := service.NewAuthService(userRepo, tokenRepo, jwtManager)
	userService := service.NewUserService(userRepo)
	sessionService := service.NewSessionService(sessionRepo, userRepo)

	// Initialize gRPC interceptor
	authInterceptor := grpcserver.NewAuthInterceptor(authService)

	// Create gRPC server
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(authInterceptor.Unary()),
		grpc.StreamInterceptor(authInterceptor.Stream()),
	)

	// Register services
	grpcserver.RegisterAuthServer(grpcServer, authService)
	grpcserver.RegisterUserServer(grpcServer, userService, userRepo, contactRepo)
	grpcserver.RegisterSessionServer(grpcServer, sessionService)

	// Enable reflection for development
	if cfg.Server.Env == "development" {
		reflection.Register(grpcServer)
		log.Info().Msg("gRPC reflection enabled")
	}

	// Start listening
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.GRPCPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", addr).Msg("Failed to listen")
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		log.Info().Msg("Shutting down server...")
		grpcServer.GracefulStop()
	}()

	log.Info().Str("addr", addr).Msg("gRPC server listening")

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatal().Err(err).Msg("Failed to serve")
	}
}

func setupLogging(cfg config.LogConfig) {
	// Set log level
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Set output format
	if cfg.Format == "console" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
}
