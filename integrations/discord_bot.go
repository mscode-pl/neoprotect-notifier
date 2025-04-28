package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"neoprotect-notifier/neoprotect"
)

type DiscordBotIntegration struct {
	token         string
	clientID      string
	guildID       string
	channelID     string
	username      string
	avatarURL     string
	attackCache   map[string]string
	messageMutex  sync.RWMutex
	neoprotectAPI *neoprotect.Client
	dg            *discordgo.Session
}

type DiscordBotConfig struct {
	Token     string `json:"token"`
	ClientID  string `json:"clientId"`
	GuildID   string `json:"guildId"`
	ChannelID string `json:"channelId"`
	Username  string `json:"username"`
	AvatarURL string `json:"avatarUrl"`
}

func (d *DiscordBotIntegration) Name() string {
	return "discord_bot"
}

func (d *DiscordBotIntegration) Initialize(rawConfig map[string]interface{}) error {
	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal Discord bot config: %w", err)
	}

	var config DiscordBotConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return fmt.Errorf("failed to unmarshal Discord bot config: %w", err)
	}

	if config.Token == "" {
		return fmt.Errorf("bot token must be provided")
	}

	if config.ChannelID == "" {
		return fmt.Errorf("channel ID must be provided")
	}

	d.token = config.Token
	d.clientID = config.ClientID
	d.guildID = config.GuildID
	d.channelID = config.ChannelID
	d.username = config.Username
	d.attackCache = make(map[string]string)

	dg, err := discordgo.New("Bot " + config.Token)
	if err != nil {
		return fmt.Errorf("error creating Discord session: %w", err)
	}

	dg.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsGuilds

	dg.AddHandler(d.handleReady)
	dg.AddHandler(d.handleInteractionCreate)

	err = dg.Open()
	if err != nil {
		return fmt.Errorf("error opening connection to Discord: %w", err)
	}

	d.dg = dg

	err = d.registerCommands()
	if err != nil {
		log.Printf("Warning: Failed to register slash commands: %v", err)
	} else {
		log.Printf("Discord bot commands registered successfully")
	}

	_, err = d.dg.ChannelMessageSend(d.channelID, "🤖 **NeoProtect Monitor Bot is online!**")
	if err != nil {
		log.Printf("Warning: Failed to send welcome message: %v", err)
	}

	log.Printf("Discord bot integration initialized successfully")
	return nil
}

func (d *DiscordBotIntegration) handleReady(s *discordgo.Session, r *discordgo.Ready) {
	log.Println("Discord bot is now ready!")

	err := s.UpdateGameStatus(0, "Monitoring DDoS attacks")
	if err != nil {
		log.Printf("Error setting bot presence: %v", err)
	}
}

func (d *DiscordBotIntegration) registerCommands() error {
	commands := []*discordgo.ApplicationCommand{
		{
			Name:        "attack",
			Description: "Get information about a specific attack",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "id",
					Description: "Attack ID (optional, shows current attack if not provided)",
					Required:    false,
				},
			},
		},
		{
			Name:        "stats",
			Description: "Get detailed statistics about DDoS attacks",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "ip",
					Description: "IP address to get stats for (optional)",
					Required:    false,
				},
			},
		},
		{
			Name:        "history",
			Description: "Get attack history",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionInteger,
					Name:        "limit",
					Description: "Number of attacks to show (default: 5)",
					Required:    false,
				},
			},
		},
	}

	if d.guildID != "" {
		for _, v := range commands {
			_, err := d.dg.ApplicationCommandCreate(d.dg.State.User.ID, d.guildID, v)
			if err != nil {
				return fmt.Errorf("cannot create '%v' command: %v", v.Name, err)
			}
		}
	} else {
		for _, v := range commands {
			_, err := d.dg.ApplicationCommandCreate(d.dg.State.User.ID, "", v)
			if err != nil {
				return fmt.Errorf("cannot create '%v' command: %v", v.Name, err)
			}
		}
	}

	return nil
}

func (d *DiscordBotIntegration) handleInteractionCreate(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.Type != discordgo.InteractionApplicationCommand {
		return
	}

	log.Printf("Received command: %s", i.ApplicationCommandData().Name)

	switch i.ApplicationCommandData().Name {
	case "attack":
		d.handleAttackCommand(s, i)
	case "stats":
		d.handleStatsCommand(s, i)
	case "history":
		d.handleHistoryCommand(s, i)
	default:
		err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "Unknown command. Available commands: `/attack`, `/stats`, `/history`",
			},
		})
		if err != nil {
			log.Printf("Error responding to interaction: %v", err)
		}
	}
}

func (d *DiscordBotIntegration) handleAttackCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if d.neoprotectAPI == nil {
		err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "⚠️ NeoProtect API client is not configured for this bot.",
			},
		})
		if err != nil {
			log.Printf("Error responding to interaction: %v", err)
		}
		return
	}

	options := i.ApplicationCommandData().Options

	var attackID string
	for _, opt := range options {
		if opt.Name == "id" {
			attackID = opt.StringValue()
			break
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var attack *neoprotect.Attack
	var err error

	if attackID == "" {
		ipAddresses, err := d.neoprotectAPI.GetIPAddresses(ctx)
		if err != nil {
			respondWithError(s, i, fmt.Sprintf("❌ Failed to fetch IP addresses: %v", err))
			return
		}

		for _, ip := range ipAddresses {
			attack, err = d.neoprotectAPI.GetActiveAttack(ctx, ip.IPv4)
			if err == nil && attack != nil {
				break
			}
		}

		if attack == nil {
			respondWithMessage(s, i, "✅ No active attacks found.")
			return
		}
	} else {
		respondWithMessage(s, i, "❌ Looking up attacks by ID is not currently supported. Please use `/history` to view recent attacks.")
		return
	}

	embed := d.createDiscordgoEmbed(attack, nil, 0x3498DB, "DDoS Attack Details")

	err = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})
	if err != nil {
		log.Printf("Error responding to interaction with embed: %v", err)
	}
}

func (d *DiscordBotIntegration) handleStatsCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if d.neoprotectAPI == nil {
		log.Printf("Error: NeoProtect API client is nil in handleStatsCommand")
		respondWithMessage(s, i, "⚠️ NeoProtect API client is not available. Please check your configuration.")
		return
	}

	options := i.ApplicationCommandData().Options

	var targetIP string
	for _, opt := range options {
		if opt.Name == "ip" {
			targetIP = opt.StringValue()
			break
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if targetIP == "" {
		ipAddresses, err := d.neoprotectAPI.GetIPAddresses(ctx)
		if err != nil {
			respondWithError(s, i, fmt.Sprintf("❌ Failed to fetch IP addresses: %v", err))
			return
		}

		var description strings.Builder

		for _, ip := range ipAddresses {
			attack, err := d.neoprotectAPI.GetActiveAttack(ctx, ip.IPv4)
			status := "✅ No active attack"
			if err == nil && attack != nil && attack.StartedAt != nil {
				status = fmt.Sprintf("🚨 Under attack since %s", attack.StartedAt.Format(time.RFC3339))
			}

			description.WriteString(fmt.Sprintf("**IP:** `%s`\n**Status:** %s\n\n", ip.IPv4, status))
		}

		embed := &discordgo.MessageEmbed{
			Title:       "NeoProtect Protection Status",
			Description: description.String(),
			Color:       0x3498DB,
			Footer: &discordgo.MessageEmbedFooter{
				Text:    "Use /stats ip:<ip-address> for detailed statistics",
				IconURL: "https://cms.mscode.pl/uploads/icon_blue_84fa10dde8.png",
			},
			Timestamp: time.Now().Format(time.RFC3339),
		}

		err = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Embeds: []*discordgo.MessageEmbed{embed},
			},
		})
		if err != nil {
			log.Printf("Error responding to interaction with embed: %v", err)
		}
		return
	} else {
		ipPattern := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
		if !ipPattern.MatchString(targetIP) {
			respondWithMessage(s, i, "❌ Invalid IP address format. Please use dotted decimal notation (e.g., 192.168.1.1).")
			return
		}

		attack, err := d.neoprotectAPI.GetActiveAttack(ctx, targetIP)
		notFoundError := false
		if err != nil {
			if errors.Is(err, neoprotect.ErrNoActiveAttack) {
				notFoundError = true
			} else {
				respondWithError(s, i, fmt.Sprintf("❌ Failed to check attack status: %v", err))
				return
			}
		}

		attacks, err := d.neoprotectAPI.GetAttacks(ctx, targetIP)
		if err != nil {
			respondWithError(s, i, fmt.Sprintf("❌ Failed to fetch attack history: %v", err))
			return
		}

		var description strings.Builder
		description.WriteString(fmt.Sprintf("## Statistics for IP: `%s`\n\n", targetIP))

		if attack != nil && !notFoundError {
			description.WriteString("**🚨 Current Status:** Under Attack\n")
			description.WriteString(fmt.Sprintf("**Attack Start:** %s\n", attack.StartedAt.Format(time.RFC3339)))
			description.WriteString(fmt.Sprintf("**Duration:** %s\n", attack.Duration().String()))
			description.WriteString(fmt.Sprintf("**Peak Bandwidth:** %s\n", formatBPS(attack.GetPeakBPS())))
			description.WriteString(fmt.Sprintf("**Peak Packet Rate:** %s\n", formatPPS(attack.GetPeakPPS())))
		} else {
			description.WriteString("**✅ Current Status:** No Active Attack\n")
		}

		description.WriteString(fmt.Sprintf("\n## Attack History\n\n"))
		description.WriteString(fmt.Sprintf("**Total Attacks:** %d\n", len(attacks)))

		var totalDuration time.Duration
		var peakBPS int64
		var peakPPS int64

		for _, a := range attacks {
			if a.EndedAt != nil {
				totalDuration += a.Duration()
			}

			if a.GetPeakBPS() > peakBPS {
				peakBPS = a.GetPeakBPS()
			}

			if a.GetPeakPPS() > peakPPS {
				peakPPS = a.GetPeakPPS()
			}
		}

		description.WriteString(fmt.Sprintf("**Total Attack Time:** %s\n", totalDuration.String()))
		description.WriteString(fmt.Sprintf("**All-Time Peak Bandwidth:** %s\n", formatBPS(peakBPS)))
		description.WriteString(fmt.Sprintf("**All-Time Peak Packet Rate:** %s\n", formatPPS(peakPPS)))

		embed := &discordgo.MessageEmbed{
			Title:       "NeoProtect IP Statistics",
			Description: description.String(),
			Color:       0x3498DB,
			Footer: &discordgo.MessageEmbedFooter{
				Text:    "Use /history for detailed attack history",
				IconURL: "https://cms.mscode.pl/uploads/icon_blue_84fa10dde8.png",
			},
			Timestamp: time.Now().Format(time.RFC3339),
		}

		err = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Embeds: []*discordgo.MessageEmbed{embed},
			},
		})
		if err != nil {
			log.Printf("Error responding to interaction with embed: %v", err)
		}
	}
}

func (d *DiscordBotIntegration) handleHistoryCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if d.neoprotectAPI == nil {
		respondWithMessage(s, i, "⚠️ NeoProtect API client is not configured for this bot.")
		return
	}

	options := i.ApplicationCommandData().Options

	limit := 5
	for _, opt := range options {
		if opt.Name == "limit" {
			limit = int(opt.IntValue())
			if limit < 1 {
				limit = 1
			} else if limit > 20 {
				limit = 20
			}
			break
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ipAddresses, err := d.neoprotectAPI.GetIPAddresses(ctx)
	if err != nil {
		respondWithError(s, i, fmt.Sprintf("❌ Failed to fetch IP addresses: %v", err))
		return
	}

	var allAttacks []*neoprotect.Attack
	for _, ip := range ipAddresses {
		attacks, err := d.neoprotectAPI.GetAttacks(ctx, ip.IPv4)
		if err != nil {
			log.Printf("Warning: Failed to fetch attacks for IP %s: %v", ip.IPv4, err)
			continue
		}

		allAttacks = append(allAttacks, attacks...)
	}

	for i := 0; i < len(allAttacks); i++ {
		for j := i + 1; j < len(allAttacks); j++ {
			if allAttacks[i].StartedAt != nil && allAttacks[j].StartedAt != nil &&
				allAttacks[i].StartedAt.Before(*allAttacks[j].StartedAt) {
				allAttacks[i], allAttacks[j] = allAttacks[j], allAttacks[i]
			}
		}
	}

	if len(allAttacks) > limit {
		allAttacks = allAttacks[:limit]
	}

	var description strings.Builder
	description.WriteString(fmt.Sprintf("## Recent Attack History\n\n"))

	if len(allAttacks) == 0 {
		description.WriteString("No attack history found.")
	} else {
		for i, attack := range allAttacks {
			status := "✅ Ended"
			duration := "N/A"

			if attack.StartedAt != nil {
				if attack.EndedAt != nil {
					duration = attack.Duration().String()
				} else {
					status = "🚨 Active"
					duration = fmt.Sprintf("%s (ongoing)", attack.Duration().String())
				}

				description.WriteString(fmt.Sprintf("### %d. Attack on %s\n", i+1, attack.DstAddressString))
				description.WriteString(fmt.Sprintf("**ID:** `%s`\n", attack.ID))
				description.WriteString(fmt.Sprintf("**Started:** %s\n", attack.StartedAt.Format(time.RFC3339)))
				description.WriteString(fmt.Sprintf("**Status:** %s\n", status))
				description.WriteString(fmt.Sprintf("**Duration:** %s\n", duration))
				description.WriteString(fmt.Sprintf("**Peak:** %s / %s\n",
					formatBPS(attack.GetPeakBPS()),
					formatPPS(attack.GetPeakPPS())))

				signatures := attack.GetSignatureNames()
				if len(signatures) > 0 {
					description.WriteString("**Signatures:** ")
					for j, sig := range signatures {
						if j > 0 {
							description.WriteString(", ")
						}
						description.WriteString(sig)
					}
					description.WriteString("\n")
				}

				description.WriteString("\n")
			}
		}
	}

	embed := &discordgo.MessageEmbed{
		Title:       "NeoProtect Attack History",
		Description: description.String(),
		Color:       0x3498DB,
		Footer: &discordgo.MessageEmbedFooter{
			Text:    fmt.Sprintf("Showing %d of %d attacks", len(allAttacks), len(allAttacks)),
			IconURL: "https://cms.mscode.pl/uploads/icon_blue_84fa10dde8.png",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	err = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})
	if err != nil {
		log.Printf("Error responding to interaction with embed: %v", err)
	}
}

func respondWithMessage(s *discordgo.Session, i *discordgo.InteractionCreate, message string) {
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: message,
		},
	})
	if err != nil {
		log.Printf("Error responding to interaction with message: %v", err)
	}
}

func respondWithError(s *discordgo.Session, i *discordgo.InteractionCreate, errorMsg string) {
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: errorMsg,
		},
	})
	if err != nil {
		log.Printf("Error responding to interaction with error message: %v", err)
	}
}

func (d *DiscordBotIntegration) NotifyNewAttack(ctx context.Context, attack *neoprotect.Attack) (string, error) {
	if d.dg == nil {
		return "", fmt.Errorf("discord session not initialized")
	}

	content := ":rotating_light: **New DDoS Attack Detected!** :rotating_light:"
	embed := d.createDiscordgoEmbed(attack, nil, 0xFF0000, "New DDoS Attack Detected")

	msg, err := d.dg.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
		Content: content,
		Embeds:  []*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		return "", fmt.Errorf("failed to send Discord message: %w", err)
	}

	if msg.ID != "" {
		d.messageMutex.Lock()
		d.attackCache[attack.ID] = msg.ID
		d.messageMutex.Unlock()
	}

	return msg.ID, nil
}

func (d *DiscordBotIntegration) NotifyAttackUpdate(ctx context.Context, attack *neoprotect.Attack, previous *neoprotect.Attack, messageID string) error {
	if d.dg == nil {
		return fmt.Errorf("discord session not initialized")
	}

	content := ":chart_with_upwards_trend: **DDoS Attack Update** :chart_with_downwards_trend:"
	embed := d.createDiscordgoEmbed(attack, previous, 0xFFFF00, "DDoS Attack Updated")

	if messageID == "" {
		d.messageMutex.RLock()
		cachedID, exists := d.attackCache[attack.ID]
		d.messageMutex.RUnlock()

		if exists {
			messageID = cachedID
		}
	}

	if messageID != "" {
		embeds := []*discordgo.MessageEmbed{embed}
		_, err := d.dg.ChannelMessageEditComplex(&discordgo.MessageEdit{
			Channel: d.channelID,
			ID:      messageID,
			Content: &content,
			Embeds:  &embeds,
		})
		if err != nil {
			if strings.Contains(err.Error(), "Unknown Message") {
				msg, err := d.dg.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
					Content: content,
					Embeds:  []*discordgo.MessageEmbed{embed},
				})
				if err != nil {
					return fmt.Errorf("failed to send new Discord message: %w", err)
				}

				d.messageMutex.Lock()
				d.attackCache[attack.ID] = msg.ID
				d.messageMutex.Unlock()
				return nil
			}
			return fmt.Errorf("failed to edit Discord message: %w", err)
		}
		return nil
	}

	msg, err := d.dg.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
		Content: content,
		Embeds:  []*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		return fmt.Errorf("failed to send Discord message: %w", err)
	}

	if msg.ID != "" {
		d.messageMutex.Lock()
		d.attackCache[attack.ID] = msg.ID
		d.messageMutex.Unlock()
	}

	return nil
}

func (d *DiscordBotIntegration) NotifyAttackEnded(ctx context.Context, attack *neoprotect.Attack, messageID string) error {
	if d.dg == nil {
		return fmt.Errorf("discord session not initialized")
	}

	content := ":white_check_mark: **DDoS Attack Ended** :shield:"
	embed := d.createDiscordgoEmbed(attack, nil, 0x00FF00, "DDoS Attack Ended")

	if messageID == "" {
		d.messageMutex.RLock()
		cachedID, exists := d.attackCache[attack.ID]
		d.messageMutex.RUnlock()

		if exists {
			messageID = cachedID
		}
	}

	if messageID != "" {
		embeds := []*discordgo.MessageEmbed{embed}
		_, err := d.dg.ChannelMessageEditComplex(&discordgo.MessageEdit{
			Channel: d.channelID,
			ID:      messageID,
			Content: &content,
			Embeds:  &embeds,
		})
		if err != nil {
			if strings.Contains(err.Error(), "Unknown Message") {
				_, err := d.dg.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
					Content: content,
					Embeds:  []*discordgo.MessageEmbed{embed},
				})
				if err != nil {
					return fmt.Errorf("failed to send new Discord message: %w", err)
				}
				return nil
			}
			return fmt.Errorf("failed to edit Discord message: %w", err)
		}

		d.messageMutex.Lock()
		delete(d.attackCache, attack.ID)
		d.messageMutex.Unlock()
		return nil
	}

	_, err := d.dg.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
		Content: content,
		Embeds:  []*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		return fmt.Errorf("failed to send Discord message: %w", err)
	}

	return nil
}

func (d *DiscordBotIntegration) createDiscordgoEmbed(attack *neoprotect.Attack, previous *neoprotect.Attack, color int, title string) *discordgo.MessageEmbed {
	var description strings.Builder

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

	description.WriteString("\n## Attack Details\n")
	description.WriteString(fmt.Sprintf("**🎯 Target IP:** `%s`\n", attack.DstAddressString))
	description.WriteString(fmt.Sprintf("**🔍 Attack ID:** `%s`\n", attack.ID))

	fields := []*discordgo.MessageEmbedField{
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

	if previous != nil {
		diff := attack.CalculateDiff(previous)
		if len(diff) > 0 {
			var changesBuilder strings.Builder

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

			if newSigs, ok := diff["newSignatures"].([]string); ok && len(newSigs) > 0 {
				changesBuilder.WriteString("**⚠️ New Attack Signatures:**\n")
				for _, sig := range newSigs {
					changesBuilder.WriteString(fmt.Sprintf("• %s\n", sig))
				}
			}

			if changesBuilder.Len() > 0 {
				fields = append(fields, &discordgo.MessageEmbedField{
					Name:   "📝 Changes Detected",
					Value:  changesBuilder.String(),
					Inline: false,
				})
			}
		}
	}

	embed := &discordgo.MessageEmbed{
		Title:       title,
		Description: description.String(),
		Color:       color,
		Fields:      fields,
		Footer: &discordgo.MessageEmbedFooter{
			Text:    "NeoProtect Monitor Bot",
			IconURL: "https://cms.mscode.pl/uploads/icon_blue_84fa10dde8.png",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	return embed
}

func (d *DiscordBotIntegration) formatSignatures(attack *neoprotect.Attack) string {
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

func (d *DiscordBotIntegration) Shutdown() {
	if d.dg != nil {
		log.Println("Shutting down Discord bot...")

		if d.clientID != "" {
			var commands []*discordgo.ApplicationCommand
			var err error

			if d.guildID != "" {
				commands, err = d.dg.ApplicationCommands(d.clientID, d.guildID)
			} else {
				commands, err = d.dg.ApplicationCommands(d.clientID, "")
			}

			if err != nil {
				log.Printf("Error getting application commands: %v", err)
			} else {
				for _, cmd := range commands {
					if d.guildID != "" {
						err := d.dg.ApplicationCommandDelete(d.clientID, d.guildID, cmd.ID)
						if err != nil {
							log.Printf("Error deleting guild command %s: %v", cmd.Name, err)
						}
					} else {
						err := d.dg.ApplicationCommandDelete(d.clientID, "", cmd.ID)
						if err != nil {
							log.Printf("Error deleting global command %s: %v", cmd.Name, err)
						}
					}
				}
			}
		}

		err := d.dg.Close()
		if err != nil {
			log.Printf("Error closing Discord session: %v", err)
		}

		d.dg = nil
		log.Println("Discord bot integration shutdown complete")
	}
}

func SetNeoprotectClient(d *DiscordBotIntegration, client *neoprotect.Client) {
	d.neoprotectAPI = client
}
