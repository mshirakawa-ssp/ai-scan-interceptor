// Package main is the entrypoint for ai-scan-connect.
//
// AI-Scan-Connect is a lightweight endpoint agent that:
//   - installs the org CA into the OS trust store
//   - writes proxy/CA env vars into shell rc files (idempotently, via marker block)
//   - runs a local mTLS forwarding proxy on 127.0.0.1
//   - performs initial enrollment (CSR -> /enroll -> client cert) and renewal
//   - periodically checks integrity and recovers drift
package main

import (
	"fmt"
	"os"

	"ai-scan-connect/cmd"
)

const version = "0.1.0-skeleton"

func usage() {
	fmt.Fprintf(os.Stderr, `ai-scan-connect %s

Usage:
  ai-scan-connect <subcommand> [flags]

Subcommands:
  install     Initial setup: CA install, env var, key gen, enroll
  forward     Run the local forwarding proxy (foreground)
  monitor     Periodic integrity check (60s)
  enroll      Enroll only (CSR -> server -> save cert)
  uninstall   Remove managed config (rc marker block, certs, etc.)
  status      Show current diagnostic state
  version     Print version

`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]

	var err error
	switch sub {
	case "install":
		err = cmd.Install(args)
	case "forward":
		err = cmd.Forward(args)
	case "monitor":
		err = cmd.Monitor(args)
	case "enroll":
		err = cmd.Enroll(args)
	case "uninstall":
		err = cmd.Uninstall(args)
	case "status":
		err = cmd.Status(args)
	case "version", "-v", "--version":
		fmt.Println("ai-scan-connect", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", sub)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
