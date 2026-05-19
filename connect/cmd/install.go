package cmd

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"ai-scan-connect/certstore"
	"ai-scan-connect/config"
	"ai-scan-connect/envvars"
	"ai-scan-connect/enroll"
)

// Install performs the full first-time setup:
//  1. load config
//  2. install org CA into OS trust store + canonical bundle path
//  3. write managed env-var block into rc files
//  4. ensure RSA keypair
//  5. enroll (CSR -> server -> save cert)
func Install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	configPath := fs.String("config", "", "config.json path (default: OS standard)")
	skipEnroll := fs.Bool("skip-enroll", false, "skip the enroll step (useful for dev)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "warning: install typically requires root for system CA install")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	// 2) CA install
	inst := certstore.New()
	if dst, err := inst.Install([]byte(cfg.OrgCAPEM)); err != nil {
		// Linux returns nil error if no system anchor dir; only Win/Mac stubs error here.
		fmt.Fprintf(os.Stderr, "certstore: %v (continuing with env-var-only mode)\n", err)
	} else if dst != "" {
		fmt.Printf("certstore: installed system CA at %s\n", dst)
	}
	caPath := config.DefaultCAInstallPath()
	fmt.Printf("certstore: canonical CA bundle at %s\n", caPath)

	// 2b) Windows-only: also install into each WSL distro (no-op elsewhere).
	installInWSLDistros(cfg)

	// 3) env vars
	mgr := envvars.New()
	v := envvars.Vars{
		HTTPSProxy:       "http://" + cfg.LocalListen,
		HTTPProxy:        "http://" + cfg.LocalListen,
		NodeExtraCACerts: caPath,
		RequestsCABundle: caPath,
		SSLCertFile:      caPath,
	}
	touched, err := mgr.Apply(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envvars: %v\n", err)
	}
	for _, p := range touched {
		fmt.Printf("envvars: applied managed block to %s\n", p)
	}

	// 4) keypair + 5) enroll
	paths := enroll.DefaultPaths()
	if _, err := enroll.EnsureKey(paths.KeyPath); err != nil {
		return fmt.Errorf("ensure key: %w", err)
	}
	fmt.Printf("enroll: keypair at %s\n", paths.KeyPath)

	if *skipEnroll {
		fmt.Println("enroll: skipped (--skip-enroll)")
		return nil
	}
	if cfg.EnrollmentToken == "" {
		fmt.Println("enroll: no enrollment_token in config; skipping (run `enroll` later)")
		return nil
	}
	if err := enroll.Enroll(cfg, paths, nil); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	fmt.Printf("enroll: client cert saved at %s\n", paths.CertPath)
	return nil
}
