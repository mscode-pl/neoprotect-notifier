package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"neoprotect-notifier/neoprotect"
)

type DiscordBotIntegration struct {
	token        string
	clientID     string
	guildID      string
	channelID    string
	webhookURL   string
	username     string
	avatarURL    string
	client       *http.Client
	attackCache  map[string]string // Attack ID -> Message ID
	messageMutex sync.RWMutex
}

type DiscordBotConfig struct {
	Token      string `json:"token"`
	ClientID   string `json:"clientId"`
	GuildID    string `json:"guildId"`
	ChannelID  string `json:"channelId"`
	WebhookURL string `json:"webhookUrl"`
	Username   string `json:"username"`
	AvatarURL  string `json:"avatarUrl"`
	Timeout    int    `json:"timeout"` // in seconds
}

type DiscordAPIResponse struct {
	ID        string    `json:"id"`
	ChannelID string    `json:"channel_id"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

func (d *DiscordBotIntegration) Name() string {
	return "discord_bot"
}

// Initialize sets up the Discord bot integration
func (d *DiscordBotIntegration) Initialize(rawConfig map[string]interface{}) error {
	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal Discord bot config: %w", err)
	}

	var config DiscordBotConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return fmt.Errorf("failed to unmarshal Discord bot config: %w", err)
	}

	if config.Token == "" && config.WebhookURL == "" {
		return fmt.Errorf("either token or webhookURL must be provided")
	}

	if config.Username == "" {
		config.Username = "NeoProtect Attack Monitor"
	}

	timeout := 10
	if config.Timeout > 0 {
		timeout = config.Timeout
	}

	d.token = config.Token
	d.clientID = config.ClientID
	d.guildID = config.GuildID
	d.channelID = config.ChannelID
	d.client = &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}
	d.attackCache = make(map[string]string)

	// Register bot commands
	if d.token != "" && d.clientID != "" {
		if err := d.registerCommands(); err != nil {
			log.Printf("Warning: Failed to register Discord bot commands: %v", err)
		}
	}

	log.Printf("Discord bot integration initialized successfully")
	return nil
}

// NotifyNewAttack sends a Discord notification for a new attack
func (d *DiscordBotIntegration) NotifyNewAttack(ctx context.Context, attack *neoprotect.Attack) (string, error) {
	content := ":rotating_light: **New DDoS Attack Detected!** :rotating_light:"

	embed := d.createAttackEmbed(attack, nil, DiscordColorRed, "New DDoS Attack Detected")

	message := &DiscordMessage{
		Username:  d.username,
		AvatarURL: d.avatarURL,
		Content:   content,
		Embeds:    []DiscordEmbed{embed},
	}

	messageID, err := d.sendMessage(ctx, message)
	if err != nil {
		return "", err
	}

	if messageID != "" {
		d.messageMutex.Lock()
		d.attackCache[attack.ID] = messageID
		d.messageMutex.Unlock()
	}

	return messageID, nil
}

// NotifyAttackUpdate updates a Discord notification for an attack update
func (d *DiscordBotIntegration) NotifyAttackUpdate(ctx context.Context, attack *neoprotect.Attack, previous *neoprotect.Attack, messageID string) error {
	content := ":chart_with_upwards_trend: **DDoS Attack Update** :chart_with_downwards_trend:"

	embed := d.createAttackEmbed(attack, previous, DiscordColorYellow, "DDoS Attack Updated")

	message := &DiscordMessage{
		Username:  d.username,
		AvatarURL: d.avatarURL,
		Content:   content,
		Embeds:    []DiscordEmbed{embed},
	}

	if messageID == "" {
		d.messageMutex.RLock()
		cachedID, exists := d.attackCache[attack.ID]
		d.messageMutex.RUnlock()

		if exists {
			messageID = cachedID
		}
	}

	if messageID != "" {
		return d.updateMessage(ctx, messageID, message)
	}

	newMessageID, err := d.sendMessage(ctx, message)
	if err != nil {
		return err
	}

	if newMessageID != "" {
		d.messageMutex.Lock()
		d.attackCache[attack.ID] = newMessageID
		d.messageMutex.Unlock()
	}

	return nil
}

// NotifyAttackEnded sends a Discord notification for an attack that has ended
func (d *DiscordBotIntegration) NotifyAttackEnded(ctx context.Context, attack *neoprotect.Attack, messageID string) error {
	content := ":white_check_mark: **DDoS Attack Ended** :shield:"

	embed := d.createAttackEmbed(attack, nil, DiscordColorGreen, "DDoS Attack Ended")

	message := &DiscordMessage{
		Username:  d.username,
		AvatarURL: d.avatarURL,
		Content:   content,
		Embeds:    []DiscordEmbed{embed},
	}

	if messageID == "" {
		d.messageMutex.RLock()
		cachedID, exists := d.attackCache[attack.ID]
		d.messageMutex.RUnlock()

		if exists {
			messageID = cachedID
		}
	}

	if messageID != "" {
		err := d.updateMessage(ctx, messageID, message)

		if err == nil {
			d.messageMutex.Lock()
			delete(d.attackCache, attack.ID)
			d.messageMutex.Unlock()
		}

		return err
	}

	_, err := d.sendMessage(ctx, message)
	return err
}

// updateMessage updates an existing Discord message
func (d *DiscordBotIntegration) updateMessage(ctx context.Context, messageID string, message *DiscordMessage) error {
	if d.token != "" && d.channelID != "" {
		url := fmt.Sprintf("https://discord.com/api/v10/channels/%s/messages/%s", d.channelID, messageID)

		jsonMessage, err := json.Marshal(message)
		if err != nil {
			return fmt.Errorf("failed to marshal Discord message: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewBuffer(jsonMessage))
		if err != nil {
			return fmt.Errorf("failed to create Discord API request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bot %s", d.token))

		resp, err := d.client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send Discord API request: %w", err)
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				log.Printf("Error closing response body: %v", err)
			}
		}()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(resp.Body)

			// If message not found, it might be deleted - fallback to sending a new message
			if resp.StatusCode == 404 {
				log.Printf("Message %s not found, sending a new one", messageID)
				_, err := d.sendAPIMessage(ctx, message)
				return err
			}

			return fmt.Errorf("discord API request failed with status code %d: %s", resp.StatusCode, string(body))
		}

		return nil
	}

	return fmt.Errorf("no valid Discord sending method configured")
}

// registerCommands registers slash commands for the Discord bot
func (d *DiscordBotIntegration) registerCommands() error {
	if d.token == "" || d.clientID == "" {
		return fmt.Errorf("bot token and client ID are required to register commands")
	}

	commands := []map[string]interface{}{
		{
			"name":        "neo-stats",
			"description": "Get detailed statistics about DDoS attacks",
			"options": []map[string]interface{}{
				{
					"name":        "ip",
					"description": "IP address to get stats for (optional)",
					"type":        3,
					"required":    false,
				},
			},
		},
		{
			"name":        "neo-history",
			"description": "Get attack history",
			"options": []map[string]interface{}{
				{
					"name":        "limit",
					"description": "Number of attacks to show (default: 5)",
					"type":        4,
					"required":    false,
				},
			},
		},
	}

	var url string
	if d.guildID != "" {
		url = fmt.Sprintf("https://discord.com/api/v10/applications/%s/guilds/%s/commands", d.clientID, d.guildID)
	} else {
		url = fmt.Sprintf("https://discord.com/api/v10/applications/%s/commands", d.clientID)
	}

	jsonCommands, err := json.Marshal(commands)
	if err != nil {
		return fmt.Errorf("failed to marshal commands: %w", err)
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(jsonCommands))
	if err != nil {
		return fmt.Errorf("failed to create command registration request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bot %s", d.token))

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to register commands: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("command registration failed with status code %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Successfully registered Discord bot commands")
	return nil
}

// createAttackEmbed creates a Discord embed for an attack notification
func (d *DiscordBotIntegration) createAttackEmbed(attack *neoprotect.Attack, previous *neoprotect.Attack, color int, title string) DiscordEmbed {
	var description string
	if attack.StartedAt != nil {
		description = fmt.Sprintf("**Started:** %s", attack.StartedAt.Format(time.RFC3339))

		if attack.EndedAt != nil {
			description += fmt.Sprintf("\n**Ended:** %s\n**Duration:** %s",
				attack.EndedAt.Format(time.RFC3339),
				attack.Duration().String())
		}
	}

	fields := []DiscordField{
		{
			Name:   "Target IP",
			Value:  attack.DstAddressString,
			Inline: true,
		},
		{
			Name:   "Attack ID",
			Value:  attack.ID,
			Inline: true,
		},
		{
			Name:   "Peak Traffic",
			Value:  fmt.Sprintf("%d bps / %d pps", attack.GetPeakBPS(), attack.GetPeakPPS()),
			Inline: true,
		},
		{
			Name:   "Attack Signatures",
			Value:  d.formatSignatures(attack),
			Inline: false,
		},
	}

	if previous != nil {
		diff := attack.CalculateDiff(previous)
		if len(diff) > 0 {
			diffText := "```\n"
			for key, value := range diff {
				diffText += fmt.Sprintf("%s: %v\n", key, value)
			}
			diffText += "```"

			fields = append(fields, DiscordField{
				Name:   "Changes Detected",
				Value:  diffText,
				Inline: false,
			})
		}
	}

	if d.token != "" {
		fields = append(fields, DiscordField{
			Name: "Commands",
			Value: "Use `/neo-stats` to get detailed stats\n" +
				"Use `/neo-history` to view attack history",
			Inline: false,
		})
	}

	timestamp := time.Now().Format(time.RFC3339)
	if attack.StartedAt != nil {
		timestamp = attack.StartedAt.Format(time.RFC3339)
	}

	footer := &DiscordFooter{
		Text:    "NeoProtect Attack Monitor",
		IconURL: "https://neoprotect.net/favicon.ico",
	}

	embed := DiscordEmbed{
		Title:       title,
		Description: description,
		Color:       color,
		Fields:      fields,
		Footer:      footer,
		Timestamp:   timestamp,
	}

	return embed
}

// formatSignatures formats the attack signatures into a string
func (d *DiscordBotIntegration) formatSignatures(attack *neoprotect.Attack) string {
	names := attack.GetSignatureNames()
	if len(names) == 0 {
		return "Unknown"
	}

	result := ""
	for _, name := range names {
		result += "• " + name + "\n"
	}

	return result
}

// sendMessage sends a message to Discord via direct API call
func (d *DiscordBotIntegration) sendMessage(ctx context.Context, message *DiscordMessage) (string, error) {
	if d.token != "" && d.channelID != "" {
		return d.sendAPIMessage(ctx, message)
	}

	return "", fmt.Errorf("no valid Discord sending method configured")
}

// sendAPIMessage sends a message via Discord API (requires bot token)
func (d *DiscordBotIntegration) sendAPIMessage(ctx context.Context, message *DiscordMessage) (string, error) {
	url := fmt.Sprintf("https://discord.com/api/v10/channels/%s/messages", d.channelID)

	jsonMessage, err := json.Marshal(message)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Discord message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonMessage))
	if err != nil {
		return "", fmt.Errorf("failed to create Discord API request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bot %s", d.token))

	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send Discord API request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("discord API request failed with status code %d: %s", resp.StatusCode, string(body))
	}

	var apiResponse DiscordAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return "", fmt.Errorf("failed to decode Discord API response: %w", err)
	}

	return apiResponse.ID, nil
}
