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
	Timeout    int    `json:"timeout"` // in seconds
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

// DiscordField represents a field in a Discord embed
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

func (d *DiscordIntegration) Name() string {
	return "discord"
}

// Initialize sets up the Discord integration
func (d *DiscordIntegration) Initialize(rawConfig map[string]interface{}) error {
	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal Discord config: %w", err)
	}

	var config DiscordConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return fmt.Errorf("failed to unmarshal Discord config: %w", err)
	}

	// Validate webhook URL
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

// NotifyNewAttack sends a Discord notification for a new attack
func (d *DiscordIntegration) NotifyNewAttack(ctx context.Context, attack *neoprotect.Attack) (string, error) {
	embed := d.createAttackEmbed(attack, nil, DiscordColorRed, "New DDoS Attack Detected")

	message := &DiscordMessage{
		Username:  d.username,
		AvatarURL: d.avatarURL,
		Embeds:    []DiscordEmbed{embed},
	}

	return "", d.sendDiscordMessage(ctx, message)
}

// NotifyAttackUpdate sends a Discord notification for an attack update
func (d *DiscordIntegration) NotifyAttackUpdate(ctx context.Context, attack *neoprotect.Attack, previous *neoprotect.Attack, messageID string) error {
	embed := d.createAttackEmbed(attack, previous, DiscordColorYellow, "DDoS Attack Updated")

	message := &DiscordMessage{
		Username:  d.username,
		AvatarURL: d.avatarURL,
		Embeds:    []DiscordEmbed{embed},
	}

	return d.sendDiscordMessage(ctx, message)
}

// NotifyAttackEnded sends a Discord notification for an attack that has ended
func (d *DiscordIntegration) NotifyAttackEnded(ctx context.Context, attack *neoprotect.Attack, messageID string) error {
	embed := d.createAttackEmbed(attack, nil, DiscordColorGreen, "DDoS Attack Ended")

	message := &DiscordMessage{
		Username:  d.username,
		AvatarURL: d.avatarURL,
		Embeds:    []DiscordEmbed{embed},
	}

	return d.sendDiscordMessage(ctx, message)
}

// createAttackEmbed creates a Discord embed for an attack notification
func (d *DiscordIntegration) createAttackEmbed(attack *neoprotect.Attack, previous *neoprotect.Attack, color int, title string) DiscordEmbed {
	var description strings.Builder

	// Create a more visually appealing description
	if attack.StartedAt != nil {
		description.WriteString("## Attack Timeline\n")
		description.WriteString(fmt.Sprintf("**🕒 Started:** %s\n", attack.StartedAt.Format(time.RFC3339)))

		if attack.EndedAt != nil {
			description.WriteString(fmt.Sprintf("**🛑 Ended:** %s\n", attack.EndedAt.Format(time.RFC3339)))
			description.WriteString(fmt.Sprintf("**⏱️ Duration:** %s\n", attack.Duration().String()))
		} else {
			description.WriteString("**⚠️ Status:** Active\n")
			description.WriteString(fmt.Sprintf("**⏱️ Duration so far:** %s\n", attack.Duration().String()))
		}
	}

	// Add IP target and attack ID information
	description.WriteString("## Attack Details\n")
	description.WriteString(fmt.Sprintf("**🎯 Target IP:** `%s`\n", attack.DstAddressString))
	description.WriteString(fmt.Sprintf("**🔍 Attack ID:** `%s`\n", attack.ID))

	fields := []DiscordField{
		{
			Name: "📊 Traffic Statistics",
			Value: fmt.Sprintf("**Peak Bandwidth:** %s\n**Peak Packet Rate:** %s",
				formatBPS(attack.GetPeakBPS()),
				formatPPS(attack.GetPeakPPS())),
			Inline: false,
		},
		{
			Name:   "🔎 Attack Signatures",
			Value:  d.formatSignatures(attack),
			Inline: false,
		},
	}

	// Add diff information if available
	if previous != nil {
		diff := attack.CalculateDiff(previous)
		if len(diff) > 0 {
			var changesBuilder strings.Builder

			// BPS changes
			if bpsChange, ok := diff["bpsPeakChange"].(int64); ok {
				var changeSymbol string
				if bpsChange > 0 {
					changeSymbol = "📈"
				} else {
					changeSymbol = "📉"
				}
				changesBuilder.WriteString(fmt.Sprintf("%s **Bandwidth:** %s → %s (%+d%%)\n",
					changeSymbol,
					formatBPS(previous.GetPeakBPS()),
					formatBPS(attack.GetPeakBPS()),
					calculatePercentageChange(previous.GetPeakBPS(), attack.GetPeakBPS())))
			}

			// PPS changes
			if ppsChange, ok := diff["ppsPeakChange"].(int64); ok {
				var changeSymbol string
				if ppsChange > 0 {
					changeSymbol = "📈"
				} else {
					changeSymbol = "📉"
				}
				changesBuilder.WriteString(fmt.Sprintf("%s **Packet Rate:** %s → %s (%+d%%)\n",
					changeSymbol,
					formatPPS(previous.GetPeakPPS()),
					formatPPS(attack.GetPeakPPS()),
					calculatePercentageChange(previous.GetPeakPPS(), attack.GetPeakPPS())))
			}

			// New signatures
			if newSigs, ok := diff["newSignatures"].([]string); ok && len(newSigs) > 0 {
				changesBuilder.WriteString("**⚠️ New Attack Signatures:**\n")
				for _, sig := range newSigs {
					changesBuilder.WriteString(fmt.Sprintf("• %s\n", sig))
				}
			}

			// Add the change field if we have content
			if changesBuilder.Len() > 0 {
				fields = append(fields, DiscordField{
					Name:   "📝 Changes Detected",
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
	}

	return embed
}

// formatSignatures formats the attack signatures into a string
func (d *DiscordIntegration) formatSignatures(attack *neoprotect.Attack) string {
	names := attack.GetSignatureNames()
	if len(names) == 0 {
		return "No signatures detected"
	}

	var result strings.Builder
	for _, name := range names {
		result.WriteString(fmt.Sprintf("• %s\n", name))
	}

	return result.String()
}

// sendDiscordMessage sends a message to Discord
func (d *DiscordIntegration) sendDiscordMessage(ctx context.Context, message *DiscordMessage) error {
	if d.client == nil {
		d.client = &http.Client{
			Timeout: 10 * time.Second, // Default timeout
		}
		log.Printf("Warning: Discord integration HTTP client was nil, created a default one")
	}

	jsonMessage, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal Discord message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL, bytes.NewBuffer(jsonMessage))
	if err != nil {
		return fmt.Errorf("failed to create Discord request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send Discord request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("discord request failed with status code %d and could not read response body: %v",
				resp.StatusCode, err)
		}
		return fmt.Errorf("discord request failed with status code %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Discord message sent successfully")
	return nil
}
