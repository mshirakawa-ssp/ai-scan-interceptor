package siem

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"ai-scan-interceptor/storage"
)

type esExporter struct {
	*asyncExporter
}

func newElasticsearch(url, token, index string) Exporter {
	client := &http.Client{Timeout: 10 * time.Second}
	// ES Bulk API: POST /<index>/_bulk with newline-delimited JSON
	bulkURL := url + "/" + index + "/_doc"
	send := func(entry storage.LogEntry) error {
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		req, err := http.NewRequest(http.MethodPost, bulkURL, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "ApiKey "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("elasticsearch %d", resp.StatusCode)
		}
		return nil
	}
	return &esExporter{newAsync("elasticsearch", send)}
}
