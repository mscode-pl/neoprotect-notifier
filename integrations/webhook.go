package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"neoprotect-notifier/neoprotect"
)

type WebhookIntegration struct {
	url     string
	headers map[string]string
	timeout time.Duration
	client  *http.Client
}

type WebhookConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Timeout int               `json:"timeout"`
}

func (w *WebhookIntegration) Name() string {
	return "webhook"
}

func (w *WebhookIntegration) Initialize(rawConfig map[string]interface{}) error {
	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook config: %w", err)
	}

	var config WebhookConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return fmt.Errorf("failed to unmarshal webhook config: %w", err)
	}

	if config.URL == "" {
		return fmt.Errorf("webhook URL is required")
	}

	timeout := 10
	if config.Timeout > 0 {
		timeout = config.Timeout
	}

	w.url = config.URL
	w.headers = config.Headers
	w.timeout = time.Duration(timeout) * time.Second
	w.client = &http.Client{
		Timeout: w.timeout,
	}

	return nil
}

func (w *WebhookIntegration) NotifyNewAttack(ctx context.Context, attack *neoprotect.Attack) (string, error) {
	attackID := attack.ID
	if attackID == "" {
		attackID = "unknown"
	}

	targetIP := attack.DstAddressString
	if targetIP == "" {
		targetIP = "unknown"
	}

	payload := map[string]interface{}{
		"event":           "new_attack",
		"attack_id":       attackID,
		"target_ip":       targetIP,
		"started_at":      attack.StartedAt,
		"signatures":      attack.GetSignatureNames(),
		"peak_bps":        attack.GetPeakBPS(),
		"peak_pps":        attack.GetPeakPPS(),
		"notification_ts": time.Now(),
	}

	return "", w.sendWebhook(ctx, payload)
}

func (w *WebhookIntegration) NotifyAttackUpdate(ctx context.Context, attack *neoprotect.Attack, previous *neoprotect.Attack, messageID string) error {
	diff := attack.CalculateDiff(previous)

	attackID := attack.ID
	if attackID == "" {
		attackID = "unknown"
	}

	targetIP := attack.DstAddressString
	if targetIP == "" {
		targetIP = "unknown"
	}

	payload := map[string]interface{}{
		"event":              "attack_update",
		"attack_id":          attackID,
		"target_ip":          targetIP,
		"started_at":         attack.StartedAt,
		"current_signatures": attack.GetSignatureNames(),
		"peak_bps":           attack.GetPeakBPS(),
		"peak_pps":           attack.GetPeakPPS(),
		"notification_ts":    time.Now(),
	}

	if diff != nil {
		payload["changes"] = diff
	}

	return w.sendWebhook(ctx, payload)
}

func (w *WebhookIntegration) NotifyAttackEnded(ctx context.Context, attack *neoprotect.Attack, messageID string) error {
	attackID := attack.ID
	if attackID == "" {
		attackID = "unknown"
	}

	targetIP := attack.DstAddressString
	if targetIP == "" {
		targetIP = "unknown"
	}

	payload := map[string]interface{}{
		"event":           "attack_ended",
		"attack_id":       attackID,
		"target_ip":       targetIP,
		"started_at":      attack.StartedAt,
		"ended_at":        attack.EndedAt,
		"duration":        attack.Duration().String(),
		"signatures":      attack.GetSignatureNames(),
		"peak_bps":        attack.GetPeakBPS(),
		"peak_pps":        attack.GetPeakPPS(),
		"notification_ts": time.Now(),
	}

	return w.sendWebhook(ctx, payload)
}

func (w *WebhookIntegration) sendWebhook(ctx context.Context, payload map[string]interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	if _, hasContentType := w.headers["Content-Type"]; !hasContentType {
		req.Header.Set("Content-Type", "application/json")
	}

	for key, value := range w.headers {
		req.Header.Set(key, value)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("Failed to close response body")
		}
	}(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook request failed with status code %d", resp.StatusCode)
	}

	return nil
}
