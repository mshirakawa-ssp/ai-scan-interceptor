package siem

import (
	"log"

	"ai-scan-interceptor/storage"
)

const (
	queueCap    = 1000
	workerCount = 2
)

// asyncExporter wraps a backend sender with a buffered channel for non-blocking delivery.
type asyncExporter struct {
	queue  chan storage.LogEntry
	done   chan struct{}
	sender func(storage.LogEntry) error
	name   string
}

func newAsync(name string, sender func(storage.LogEntry) error) *asyncExporter {
	e := &asyncExporter{
		queue:  make(chan storage.LogEntry, queueCap),
		done:   make(chan struct{}),
		sender: sender,
		name:   name,
	}
	for i := 0; i < workerCount; i++ {
		go e.worker()
	}
	return e
}

func (e *asyncExporter) Send(entry storage.LogEntry) {
	select {
	case e.queue <- entry:
	default:
		log.Printf("[siem/%s] queue full — dropping entry for service=%s", e.name, entry.Service)
	}
}

func (e *asyncExporter) Close() {
	close(e.queue)
	// wait for all workers to drain
	for i := 0; i < workerCount; i++ {
		<-e.done
	}
}

func (e *asyncExporter) worker() {
	defer func() { e.done <- struct{}{} }()
	for entry := range e.queue {
		if err := e.sender(entry); err != nil {
			log.Printf("[siem/%s] send error: %v", e.name, err)
		}
	}
}
