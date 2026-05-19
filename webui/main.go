package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	// Sub-command: unlock-user <username>
	// Usage: docker exec <container> /app/webui unlock-user admin
	if len(os.Args) == 3 && os.Args[1] == "unlock-user" {
		runUnlockUser(os.Args[2])
		return
	}

	// Sub-command: set-password <username> <new-password>
	// Usage: docker exec <container> /app/webui set-password admin <newpass>
	if len(os.Args) == 4 && os.Args[1] == "set-password" {
		runSetPassword(os.Args[2], os.Args[3])
		return
	}

	logDir := os.Getenv("LOG_DIR")
	if logDir == "" {
		logDir = "/logs"
	}

	if err := validateLogDir(logDir); err != nil {
		log.Fatalf("[webui] invalid LOG_DIR: %v", err)
	}

	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "/config"
	}

	var err error
	if err = validateConfigDir(configDir); err != nil {
		log.Fatalf("[webui] invalid CONFIG_DIR: %v", err)
	}

	usersPath := configDir + "/users.json"
	userStore, err := newUserStore(usersPath)
	if err != nil {
		log.Fatalf("[webui] user store: %v", err)
	}

	logSettingsPath := configDir + "/settings.json"
	logSettings, err := newLogSettingsStore(logSettingsPath)
	if err != nil {
		log.Fatalf("[webui] log settings: %v", err)
	}

	notifSettingsPath := configDir + "/notification.json"
	notifSettings, err := newNotificationSettingsStore(notifSettingsPath)
	if err != nil {
		log.Fatalf("[webui] notification settings: %v", err)
	}

	// Organization CA: auto-generate on first start, load otherwise.
	orgName := os.Getenv("ORG_NAME")
	orgCA, err := newOrgCA(configDir, orgName)
	if err != nil {
		log.Fatalf("[webui] org CA: %v", err)
	}
	log.Printf("[webui] org CA loaded: subject=%q not_after=%s",
		orgCA.Subject(), orgCA.NotAfter().Format("2006-01-02"))

	enrollTokens, err := newEnrollTokenStore(configDir + "/enroll-tokens.json")
	if err != nil {
		log.Fatalf("[webui] enroll tokens: %v", err)
	}

	devices, err := newDeviceStore(configDir + "/devices.json")
	if err != nil {
		log.Fatalf("[webui] device store: %v", err)
	}

	// CRL: revoked client cert serials. tls-proxy polls this file every 30s.
	crl, err := newCRLStore(configDir + "/revoked-serials.json")
	if err != nil {
		log.Fatalf("[webui] CRL store: %v", err)
	}
	devices.SetCRL(crl)

	RunLogCleanup(logDir, logSettings)

	mux := http.NewServeMux()
	registerHandlers(mux, logDir, configDir, userStore, logSettings, notifSettings, orgCA, enrollTokens, devices, crl)

	addr := ":8080"
	log.Printf("[webui] starting on %s, reading logs from %s", addr, logDir)
	// Wrap the entire mux with security headers so every response is covered.
	if err := http.ListenAndServe(addr, WithSecurityHeaders(mux)); err != nil {
		log.Fatalf("[webui] server error: %v", err)
	}
}

// runSetPassword is the break-glass CLI: resets a user's password.
// Run via: docker exec ai-scan-interceptor-webui-1 /app/webui set-password <username> <newpass>
func runSetPassword(username, password string) {
	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "/config"
	}
	store, err := newUserStore(configDir + "/users.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading users: %v\n", err)
		os.Exit(1)
	}
	var userID string
	for _, u := range store.users {
		if u.Username == username {
			userID = u.ID
			break
		}
	}
	if userID == "" {
		fmt.Fprintf(os.Stderr, "error: user %q not found\n", username)
		os.Exit(1)
	}
	if err := store.UpdatePassword(userID, password); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK: password updated for user %q\n", username)
}

// runUnlockUser is the break-glass CLI: clears lockout for the named user.
// Run via: docker exec ai-scan-interceptor-webui-1 /app/webui unlock-user <username>
func runUnlockUser(username string) {
	configDir := os.Getenv("CONFIG_DIR")
	if configDir == "" {
		configDir = "/config"
	}
	store, err := newUserStore(configDir + "/users.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading users: %v\n", err)
		os.Exit(1)
	}
	if err := store.UnlockUserByName(username); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK: account lockout cleared for user %q\n", username)
	fmt.Println("Note: IP rate limits reset automatically on container restart,")
	fmt.Println("      or via: DELETE /api/auth/rate-limits (requires admin session)")
}
