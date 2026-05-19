package siem

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ai-scan-interceptor/storage"
)

type splunkExporter struct {
	*asyncExporter
}

func newSplunk(url, token, index string) Exporter {
	client := &http.Client{Timeout: 10 * time.Second}
	send := func(entry storage.LogEntry) error {
		payload := map[string]any{
			"time":  entry.Timestamp.Unix(),
			"index": index,
			"sourcetype": "ai_scan_interceptor",
			"event": entry,
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Splunk "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("splunk HEC %d", resp.StatusCode)
		}
		return nil
	}
	return &splunkExporter{newAsync("splunk", send)}
}
