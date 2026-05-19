package siem

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"ai-scan-interceptor/storage"
)

var testEntry = storage.LogEntry{
	Timestamp: time.Date(2026, 4, 24, 10, 0, 0, 0, time.UTC),
	Service:   "Claude-API",
	Host:      "api.anthropic.com",
	Path:      "/v1/messages",
	Prompt:    "hello",
	Triggered: true,
	Severity:  "high",
	ClientIP:  "192.168.1.1",
	UserID:    "alice",
}

func TestNopExporter(t *testing.T) {
	e := New("", "", "", "")
	e.Send(testEntry) // must not panic
	e.Close()
}

func TestSplunkExporter(t *testing.T) {
	var received map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Splunk test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := newSplunk(srv.URL, "test-token", "ai-scan")
	e.Send(testEntry)
	e.Close()

	if received == nil {
		t.Fatal("Splunk server received no request")
	}
	if received["sourcetype"] != "ai_scan_interceptor" {
		t.Errorf("sourcetype=%v", received["sourcetype"])
	}
	if received["index"] != "ai-scan" {
		t.Errorf("index=%v", received["index"])
	}
}

func TestElasticsearchExporter(t *testing.T) {
	var received storage.LogEntry
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	e := newElasticsearch(srv.URL, "", "ai-scan")
	e.Send(testEntry)
	e.Close()

	if received.Service != "Claude-API" {
		t.Errorf("service=%q want Claude-API", received.Service)
	}
	if received.UserID != "alice" {
		t.Errorf("user_id=%q want alice", received.UserID)
	}
}

func TestAsyncQueueDrop(t *testing.T) {
	blocked := make(chan struct{})
	// sender blocks until test releases it — fills the queue immediately.
	// Use atomic for calls because multiple workers increment concurrently.
	var calls atomic.Int64
	e := newAsync("test", func(_ storage.LogEntry) error {
		<-blocked
		calls.Add(1)
		return nil
	})

	// Fill beyond queue capacity
	for i := 0; i < queueCap+100; i++ {
		e.Send(testEntry)
	}
	close(blocked) // release workers
	e.Close()

	got := int(calls.Load())
	// Workers may have dequeued up to workerCount items before the queue filled.
	// So calls <= queueCap + workerCount (overflow items were dropped).
	maxCalls := queueCap + workerCount
	if got > maxCalls {
		t.Errorf("expected at most %d calls (queueCap=%d + workers=%d), got %d",
			maxCalls, queueCap, workerCount, got)
	}
	// Confirm at least some drops occurred (we sent 100 over capacity)
	if got == queueCap+100 {
		t.Error("expected some drops but none occurred")
	}
}
