package cmd

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ai-scan-connect/config"
	"ai-scan-connect/enroll"
	"ai-scan-connect/proxy"
)

// Forward runs the local mTLS forwarding proxy in the foreground.
func Forward(args []string) error {
	fs := flag.NewFlagSet("forward", flag.ContinueOnError)
	configPath := fs.String("config", "", "config.json path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	paths := enroll.DefaultPaths()

	f, err := proxy.NewFromConfig(cfg, paths.CertPath, paths.KeyPath)
	if err != nil {
		return err
	}
	logger := log.New(os.Stderr, "[forward] ", log.LstdFlags)
	f.Logger = logger

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "forward: shutdown signal received")
		cancel()
	}()

	return f.ListenAndServe(ctx)
}
