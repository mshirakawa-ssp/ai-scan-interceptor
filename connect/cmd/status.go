package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"ai-scan-connect/config"
	"ai-scan-connect/enroll"
	"ai-scan-connect/monitor"
)

// Status prints a one-shot diagnostic snapshot.
func Status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	configPath := fs.String("config", "", "config.json path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "status: cannot load config: %v\n", err)
		return err
	}
	paths := enroll.DefaultPaths()

	fmt.Printf("config:        %s\n", configFilePath(*configPath))
	fmt.Printf("interceptor:   %s\n", cfg.InterceptorURL)
	fmt.Printf("enroll URL:    %s\n", cfg.EnrollURL)
	fmt.Printf("local listen:  %s\n", cfg.LocalListen)
	fmt.Printf("fail_close:    %v\n", cfg.FailClose)
	fmt.Printf("CA bundle:     %s\n", config.DefaultCAInstallPath())
	fmt.Printf("state dir:     %s\n", paths.StateDir)

	if cert, err := enroll.LoadCert(paths.CertPath); err != nil {
		fmt.Printf("client cert:   MISSING (%v)\n", err)
	} else {
		fmt.Printf("client cert:   CN=%s NotAfter=%s\n",
			cert.Subject.CommonName, cert.NotAfter.Format(time.RFC3339))
		if enroll.ShouldRenew(cert, time.Now()) {
			fmt.Println("               (past 50% lifetime — renewal due)")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := monitor.CheckAndRecover(ctx, cfg, paths)
	fmt.Printf("rc drift:      %d files\n", len(r.RCDrift))
	for _, p := range r.RCDrift {
		fmt.Printf("               drift: %s\n", p)
	}
	fmt.Printf("upstream TCP:  %v\n", r.UpstreamReachable)

	return nil
}

func configFilePath(p string) string {
	if p != "" {
		return p
	}
	return config.DefaultConfigPath()
}
