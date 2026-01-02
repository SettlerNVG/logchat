package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/logmessager/client/internal/client"
	"github.com/logmessager/client/internal/config"
	"github.com/logmessager/client/internal/tui"
)

func main() {
	// Load config
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Setup logging
	setupLogging(cfg.Log)

	// Create client
	c, err := client.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create client")
	}
	defer c.Close()

	// Create TUI app
	app := tui.NewApp(c)

	// Run TUI
	p := tea.NewProgram(app, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal().Err(err).Msg("Failed to run TUI")
	}
}

func setupLogging(cfg config.LogConfig) {
	// Set log level
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// For TUI, we need to log to file instead of stderr
	// to avoid interfering with the terminal UI
	logFile, err := os.OpenFile("/tmp/logchat.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Fallback to discard
		log.Logger = zerolog.Nop()
		return
	}

	if cfg.Format == "console" {
		log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: logFile}).With().Timestamp().Logger()
	} else {
		log.Logger = zerolog.New(logFile).With().Timestamp().Logger()
	}
}
