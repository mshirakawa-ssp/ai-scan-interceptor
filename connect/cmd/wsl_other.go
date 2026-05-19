//go:build !windows

package cmd

import "ai-scan-connect/config"

// installInWSLDistros is a no-op on non-Windows builds.
func installInWSLDistros(_ *config.Config) {}
