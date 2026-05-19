package main

import (
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ai-scan-interceptor/detection"
	"ai-scan-interceptor/icap"
	"ai-scan-interceptor/notification"
	"ai-scan-interceptor/policy"
	"ai-scan-interceptor/siem"
	"ai-scan-interceptor/storage"
)

func main() {
	addr := getEnv("ICAP_ADDR", ":1344")
	logDir := getEnv("LOG_DIR", "./logs")
	configDir := getEnv("CONFIG_DIR", "/config")

	log.Printf("[main] starting AI-Scan-Interceptor")
	log.Printf("[main] log dir: %s", logDir)
	log.Printf("[main] config dir: %s", configDir)

	logger, err := storage.NewLogger(logDir)
	if err != nil {
		log.Fatalf("[main] logger init: %v", err)
	}
	defer logger.Close()

	// --- Policy config ---
	config, err := policy.Load(configDir + "/policy.json")
	if err != nil {
		log.Fatalf("[main] policy load: %v", err)
	}
	config.StartReloader()
	log.Printf("[main] policy loaded: mode=%s", config.Get().GlobalMode)

	// --- Notifier (Slack webhook + Email) ---
	// notification.json takes precedence; env vars serve as fallback.
	notifStore := notification.LoadConfigStore(configDir + "/notification.json")
	notifier := notification.NewDynamicNotifier(notifStore, notification.EmailConfig{
		Host:     getEnv("SMTP_HOST", ""),
		Port:     getEnv("SMTP_PORT", "587"),
		User:     getEnv("SMTP_USER", ""),
		Password: getEnv("SMTP_PASS", ""),
		From:     getEnv("SMTP_FROM", ""),
		To:       getEnvSlice("ALERT_EMAIL_TO", nil),
	}, getEnv("WEBHOOK_URL", ""))
	detector := detection.NewDetector()

	// --- Unified rules store (builtin + custom via rules.json) ---
	rulesPath := configDir + "/rules.json"
	if err := detection.SeedRulesFile(rulesPath); err != nil {
		log.Printf("[main] rules seed warning: %v", err)
	}
	entries, err := detection.LoadRulesFile(rulesPath)
	if err != nil {
		log.Printf("[main] rules load warning: %v, using built-in defaults", err)
		entries = detection.DefaultEntries()
	}
	detection.SetActiveRules(detection.EntriesToAlertRules(entries))
	detection.StartRulesReloader(rulesPath)
	log.Printf("[main] loaded %d rules", len(detection.ActiveRules()))

	// --- SIEM exporter (optional) ---
	siemExporter := siem.New(
		getEnv("SIEM_TYPE", ""),
		getEnv("SIEM_URL", ""),
		getEnv("SIEM_TOKEN", ""),
		getEnv("SIEM_INDEX", "ai-scan"),
	)
	defer siemExporter.Close()

	handler := &icap.PromptHandler{
		Detector: detector,
		Logger:   logger,
		Notifier: notifier,
		Policy:   config,
		SIEM:     siemExporter,
	}
	respHandler := &icap.ResponseHandler{
		Logger: logger,
	}
	server := &icap.Server{
		Addr:           addr,
		Handler:        handler,
		RESPMODHandler: respHandler,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("[main] server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("[main] received %s, shutting down", sig)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvSlice(key string, fallback []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
