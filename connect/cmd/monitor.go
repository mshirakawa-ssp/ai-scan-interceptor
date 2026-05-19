package cmd

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ai-scan-connect/config"
	"ai-scan-connect/enroll"
	"ai-scan-connect/monitor"
)

// Monitor runs the integrity check loop in the foreground.
func Monitor(args []string) error {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	configPath := fs.String("config", "", "config.json path")
	intervalStr := fs.String("interval", "60s", "check interval (e.g. 30s, 1m)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	interval, err := time.ParseDuration(*intervalStr)
	if err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	paths := enroll.DefaultPaths()

	logger := log.New(os.Stderr, "[monitor] ", log.LstdFlags)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	return monitor.Run(ctx, cfg, paths, interval, logger)
}
