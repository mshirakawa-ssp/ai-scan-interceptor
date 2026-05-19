// Package siem provides async log forwarding to SIEM platforms.
// Supported backends: Splunk HEC, Elasticsearch Bulk API.
// Configure via environment variables:
//
//	SIEM_TYPE  — "splunk" or "elasticsearch" (empty = disabled)
//	SIEM_URL   — e.g. https://splunk:8088/services/collector/event
//	SIEM_TOKEN — Splunk HEC token or ES API key
//	SIEM_INDEX — Splunk index or ES index name (default: "ai-scan")
package siem

import (
	"log"

	"ai-scan-interceptor/storage"
)

// Exporter forwards log entries to an external SIEM platform.
type Exporter interface {
	// Send enqueues an entry for async delivery. Never blocks.
	Send(entry storage.LogEntry)
	// Close drains the queue and releases resources.
	Close()
}

// nopExporter discards all entries (used when SIEM is not configured).
type nopExporter struct{}

func (n *nopExporter) Send(_ storage.LogEntry) {}
func (n *nopExporter) Close()                  {}

// New returns an Exporter for the given backend type.
// Returns a no-op exporter when siemType is empty.
func New(siemType, url, token, index string) Exporter {
	if siemType == "" {
		return &nopExporter{}
	}
	if index == "" {
		index = "ai-scan"
	}
	switch siemType {
	case "splunk":
		e := newSplunk(url, token, index)
		log.Printf("[siem] Splunk HEC exporter → %s (index=%s)", url, index)
		return e
	case "elasticsearch":
		e := newElasticsearch(url, token, index)
		log.Printf("[siem] Elasticsearch exporter → %s (index=%s)", url, index)
		return e
	default:
		log.Printf("[siem] unknown SIEM_TYPE=%q — disabling", siemType)
		return &nopExporter{}
	}
}
