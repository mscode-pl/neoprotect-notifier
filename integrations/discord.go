package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"neoprotect-notifier/neoprotect"
)

type DiscordIntegration struct {
	webhookURL string
	username   string
	avatarURL  string
	client     *http.Client
}

type DiscordConfig struct {
	WebhookURL string `json:"webhookUrl"`
	Username   string `json:"username"`
	AvatarURL  string `json:"avatarUrl"`
	Timeout    int    `json:"timeout"`
}

type DiscordMessage struct {
	Username  string         `json:"username,omitempty"`
	AvatarURL string         `json:"avatar_url,omitempty"`
	Content   string         `json:"content,omitempty"`
	Embeds    []DiscordEmbed `json:"embeds,omitempty"`
}

type DiscordEmbed struct {
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description,omitempty"`
	URL         string         `json:"url,omitempty"`
	Color       int            `json:"color,omitempty"`
	Fields      []DiscordField `json:"fields,omitempty"`
	Thumbnail   *DiscordImage  `json:"thumbnail,omitempty"`
	Image       *DiscordImage  `json:"image,omitempty"`
	Footer      *DiscordFooter `json:"footer,omitempty"`
	Timestamp   string         `json:"timestamp,omitempty"`
	Author      *DiscordAuthor `json:"author,omitempty"`
}

type DiscordField struct {
	Name   string `json:"name,omitempty"`
	Value  string `json:"value,omitempty"`
	Inline bool   `json:"inline,omitempty"`
}

type DiscordImage struct {
	URL string `json:"url,omitempty"`
}

type DiscordFooter struct {
	Text    string `json:"text,omitempty"`
	IconURL string `json:"icon_url,omitempty"`
}

type DiscordAuthor struct {
	Name    string `json:"name,omitempty"`
	URL     string `json:"url,omitempty"`
	IconURL string `json:"icon_url,omitempty"`
}

type DiscordResponse struct {
	ID        string `json:"id"`
	Type      int    `json:"type"`
	Content   string `json:"content"`
	ChannelID string `json:"channel_id"`
	Author    struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Avatar   string `json:"avatar"`
		Bot      bool   `json:"bot"`
	} `json:"author"`
	Timestamp string `json:"timestamp"`
}

func (d *DiscordIntegration) Name() string {
	return "discord"
}

func (d *DiscordIntegration) Initialize(rawConfig map[string]interface{}) error {
	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal Discord config: %w", err)
	}

	var config DiscordConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return fmt.Errorf("failed to unmarshal Discord config: %w", err)
	}

	d.webhookURL = config.WebhookURL
	if d.webhookURL == "" || (!strings.HasPrefix(d.webhookURL, "http://") && !strings.HasPrefix(d.webhookURL, "https://")) {
		return fmt.Errorf("invalid discord webhook URL: must be a valid HTTP/HTTPS URL")
	}

	log.Printf("Discord integration initializing with webhook URL: %s", d.webhookURL)

	if config.Username == "" {
		config.Username = "NeoProtect Monitor"
	}

	timeout := 10
	if config.Timeout > 0 {
		timeout = config.Timeout
	}

	d.username = config.Username
	d.avatarURL = config.AvatarURL
	d.client = &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	log.Printf("Discord integration initialized successfully")
	return nil
}

func (d *DiscordIntegration) NotifyNewAttack(ctx context.Context, attack *neoprotect.Attack) (string, error) {
	embed := d.createAttackEmbed(attack, nil, DiscordColorRed, "`🔥` New DDoS Attack Detected")

	message := &DiscordMessage{
		Username:  d.username,
		AvatarURL: d.avatarURL,
		Embeds:    []DiscordEmbed{embed},
	}

	messageID, err := d.sendDiscordMessage(ctx, message)
	if err != nil {
		return "", err
	}

	return messageID, nil
}

func (d *DiscordIntegration) NotifyAttackUpdate(ctx context.Context, attack *neoprotect.Attack, previous *neoprotect.Attack, messageID string) error {
	embed := d.createAttackEmbed(attack, previous, DiscordColorYellow, "`📶` DDoS Attack Updated")

	message := &DiscordMessage{
		Username:  d.username,
		AvatarURL: d.avatarURL,
		Embeds:    []DiscordEmbed{embed},
	}

	if messageID != "" {
		return d.updateDiscordMessage(ctx, messageID, message)
	}

	_, err := d.sendDiscordMessage(ctx, message)
	return err
}

func (d *DiscordIntegration) NotifyAttackEnded(ctx context.Context, attack *neoprotect.Attack, messageID string) error {
	if messageID == "" {
		log.Printf("No message ID available for attack %s, cannot update Discord webhook", attack.ID)
		return nil
	}

	embed := d.createAttackEmbed(attack, nil, DiscordColorGreen, "`🚀` DDoS Attack Ended")

	message := &DiscordMessage{
		Username:  d.username,
		AvatarURL: d.avatarURL,
		Embeds:    []DiscordEmbed{embed},
	}

	log.Printf("Updating Discord webhook message %s for ended attack %s", messageID, attack.ID)
	return d.updateDiscordMessage(ctx, messageID, message)
}

func (d *DiscordIntegration) createAttackEmbed(attack *neoprotect.Attack, previous *neoprotect.Attack, color int, title string) DiscordEmbed {
	var description strings.Builder

	if attack.StartedAt != nil {
		description.WriteString("### Attack Timeline\n")
		description.WriteString(fmt.Sprintf("**`🕒`** Started: %s\n", formatTimeToLocal(attack.StartedAt)))

		if attack.EndedAt != nil {
			description.WriteString(fmt.Sprintf("**`🛑`** Ended: %s\n", formatTimeToLocal(attack.EndedAt)))
			description.WriteString(fmt.Sprintf("**`⏱️`** Duration: %s\n", formatDurationReadable(attack.Duration())))
		} else {
			description.WriteString("**`⚠️`** Status: Active\n")
			description.WriteString(fmt.Sprintf("**`⏱️`** Duration: %s\n", formatDurationReadable(attack.Duration())))
		}
	}

	description.WriteString("### Attack Details\n")
	targetIP := attack.DstAddressString
	if targetIP == "" {
		targetIP = "unknown"
	}
	description.WriteString(fmt.Sprintf("**`🎯`** Target IP: `%s`\n", targetIP))

	attackID := attack.ID
	if attackID == "" {
		attackID = "unknown"
	}
	description.WriteString(fmt.Sprintf("**`🔍`** Attack ID: `%s`\n", attackID))

	panelLink := fmt.Sprintf("https://panel.neoprotect.net/network/ips/%s?tab=attacks", targetIP)
	description.WriteString(fmt.Sprintf("**`🔗`** [View in NeoProtect Panel](%s)\n", panelLink))

	fields := []DiscordField{
		{
			Name: "**`📊`** Traffic Statistics",
			Value: fmt.Sprintf("**Peak Bandwidth:** %s\n**Peak Packet Rate:** %s",
				formatBPS(attack.GetPeakBPS()),
				formatPPS(attack.GetPeakPPS())),
			Inline: false,
		},
		{
			Name:   "**`🔎`** Attack Signatures",
			Value:  d.formatSignatures(attack),
			Inline: false,
		},
	}

	if previous != nil {
		diff := attack.CalculateDiff(previous)
		if len(diff) > 0 {
			var changesBuilder strings.Builder

			if bpsChange, ok := diff["bpsPeakChange"].(int64); ok {
				var changeSymbol string
				if bpsChange > 0 {
					changeSymbol = "`📈`"
				} else {
					changeSymbol = "`📉`"
				}
				changesBuilder.WriteString(fmt.Sprintf("%s **Bandwidth:** %s → %s (%+d%%)\n",
					changeSymbol,
					formatBPS(previous.GetPeakBPS()),
					formatBPS(attack.GetPeakBPS()),
					calculatePercentageChange(previous.GetPeakBPS(), attack.GetPeakBPS())))
			}

			if ppsChange, ok := diff["ppsPeakChange"].(int64); ok {
				var changeSymbol string
				if ppsChange > 0 {
					changeSymbol = "`📈`"
				} else {
					changeSymbol = "`📉`"
				}
				changesBuilder.WriteString(fmt.Sprintf("%s **Packet Rate:** %s → %s (%+d%%)\n",
					changeSymbol,
					formatPPS(previous.GetPeakPPS()),
					formatPPS(attack.GetPeakPPS()),
					calculatePercentageChange(previous.GetPeakPPS(), attack.GetPeakPPS())))
			}

			if newSigs, ok := diff["newSignatures"].([]string); ok && len(newSigs) > 0 {
				changesBuilder.WriteString("**`⚠️`** New Attack Signatures:\n")
				for _, sig := range newSigs {
					changesBuilder.WriteString(fmt.Sprintf("• `%s`\n", sig))
				}
			}

			if changesBuilder.Len() > 0 {
				fields = append(fields, DiscordField{
					Name:   "**`📝`** Changes Detected",
					Value:  changesBuilder.String(),
					Inline: false,
				})
			}
		}
	}

	timestamp := time.Now().Format(time.RFC3339)
	if attack.StartedAt != nil {
		timestamp = attack.StartedAt.Format(time.RFC3339)
	}

	footer := &DiscordFooter{
		Text:    "NeoProtect Monitor Bot",
		IconURL: "https://cms.mscode.pl/uploads/icon_blue_84fa10dde8.png",
	}

	embed := DiscordEmbed{
		Title:       title,
		Description: description.String(),
		Color:       color,
		Fields:      fields,
		Footer:      footer,
		Timestamp:   timestamp,
		URL:         panelLink,
	}

	return embed
}

func (d *DiscordIntegration) formatSignatures(attack *neoprotect.Attack) string {
	names := attack.GetSignatureNames()
	if len(names) == 0 {
		return "No signatures detected"
	}

	var result strings.Builder
	for _, name := range names {
		result.WriteString(fmt.Sprintf("• `%s`\n", name))
	}

	return result.String()
}

func (d *DiscordIntegration) sendDiscordMessage(ctx context.Context, message *DiscordMessage) (string, error) {
	if d.client == nil {
		d.client = &http.Client{
			Timeout: 10 * time.Second,
		}
		log.Printf("Warning: Discord integration HTTP client was nil, created a default one")
	}

	webhookURL := d.webhookURL
	if !strings.Contains(webhookURL, "?") {
		webhookURL += "?wait=true"
	} else {
		webhookURL += "&wait=true"
	}

	jsonMessage, err := json.Marshal(message)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Discord message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewBuffer(jsonMessage))
	if err != nil {
		return "", fmt.Errorf("failed to create Discord request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send Discord request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("discord request failed with status code %d and could not read response body: %v",
				resp.StatusCode, err)
		}
		return "", fmt.Errorf("discord request failed with status code %d: %s", resp.StatusCode, string(body))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Warning: Could not read Discord response body: %v", err)
		return "", nil
	}

	if len(bodyBytes) == 0 {
		log.Printf("Warning: Discord response body is empty")
		return "", nil
	}

	var response DiscordResponse
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		log.Printf("Warning: Could not unmarshal Discord response: %v, body: %s", err, string(bodyBytes))
		return "", nil
	}

	if response.ID == "" {
		log.Printf("Warning: Discord response does not contain message ID, full response: %s", string(bodyBytes))
		return "", nil
	}

	log.Printf("Discord message sent successfully, message ID: %s", response.ID)
	return response.ID, nil
}

func (d *DiscordIntegration) updateDiscordMessage(ctx context.Context, messageID string, message *DiscordMessage) error {
	if d.client == nil {
		d.client = &http.Client{
			Timeout: 10 * time.Second,
		}
		log.Printf("Warning: Discord integration HTTP client was nil, created a default one")
	}

	updateURL := fmt.Sprintf("%s/messages/%s", d.webhookURL, messageID)

	jsonMessage, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal Discord message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, updateURL, bytes.NewBuffer(jsonMessage))
	if err != nil {
		return fmt.Errorf("failed to create Discord update request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send Discord update request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("discord update request failed with status code %d and could not read response body: %v",
				resp.StatusCode, err)
		}
		return fmt.Errorf("discord update request failed with status code %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Discord message updated successfully")
	return nil
}
