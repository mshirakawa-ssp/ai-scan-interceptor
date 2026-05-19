package cmd

import (
	"flag"
	"fmt"

	"ai-scan-connect/config"
	"ai-scan-connect/enroll"
)

// Enroll runs only the enrollment step.
func Enroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	configPath := fs.String("config", "", "config.json path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	paths := enroll.DefaultPaths()
	if _, err := enroll.EnsureKey(paths.KeyPath); err != nil {
		return err
	}
	if err := enroll.Enroll(cfg, paths, nil); err != nil {
		return err
	}
	fmt.Printf("enroll: cert saved at %s\n", paths.CertPath)
	return nil
}
