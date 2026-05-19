package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"ai-scan-connect/certstore"
	"ai-scan-connect/envvars"
)

// Uninstall removes the managed config artifacts:
//   - rc managed block from all rc files
//   - org CA from OS trust store
//
// It does NOT delete /var/lib/ai-scan-connect (keys/certs) — that's a
// destructive operation reserved for an explicit `--purge` flag.
func Uninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "also delete keys, certs, and config")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mgr := envvars.New()
	touched, err := mgr.Remove()
	if err != nil && !errors.Is(err, envvars.ErrNotImplemented) {
		fmt.Fprintf(os.Stderr, "envvars: %v\n", err)
	}
	for _, p := range touched {
		fmt.Printf("envvars: stripped managed block from %s\n", p)
	}

	inst := certstore.New()
	if err := inst.Uninstall(); err != nil && !errors.Is(err, certstore.ErrNotImplemented) {
		fmt.Fprintf(os.Stderr, "certstore: %v\n", err)
	}

	if *purge {
		fmt.Fprintln(os.Stderr, "uninstall: --purge requested but not yet implemented")
	}
	fmt.Println("uninstall: done")
	return nil
}
