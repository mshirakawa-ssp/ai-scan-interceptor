//go:build windows

package cmd

import (
	"fmt"
	"os"

	"ai-scan-connect/certstore"
	"ai-scan-connect/config"
	"ai-scan-connect/envvars"
)

// installInWSLDistros enumerates installed WSL distros and runs the in-distro
// install script for each supported one. Best-effort: per-distro failures are
// logged as warnings rather than aborting the whole `install` run.
func installInWSLDistros(cfg *config.Config) {
	distros, err := certstore.EnumerateDistros()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wsl: enumerate skipped: %v\n", err)
		return
	}
	if len(distros) == 0 {
		return
	}
	fmt.Printf("wsl: found %d distro(s): %v\n", len(distros), distros)
	for _, d := range distros {
		if err := certstore.InstallInDistro(
			d,
			[]byte(cfg.OrgCAPEM),
			cfg.LocalListen,
			envvars.MarkerStartLine,
			envvars.MarkerEndLine,
		); err != nil {
			fmt.Fprintf(os.Stderr, "wsl[%s]: %v\n", d, err)
			continue
		}
		fmt.Printf("wsl[%s]: install OK\n", d)
	}
}
