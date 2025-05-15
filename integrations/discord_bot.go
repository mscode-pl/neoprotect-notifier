package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
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
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	if err != nil {
		log.Printf("Error acknowledging interaction: %v", err)
		return
	}

	if d.neoprotectAPI == nil {
		_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Content: "⚠️ NeoProtect API client is not configured for this bot.",
		})
		if err != nil {
			return
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
	var fetchErr error

	if attackID == "" {
		ipAddresses, err := d.neoprotectAPI.GetIPAddresses(ctx)
		if err != nil {
			_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ Failed to fetch IP addresses: %v", err),
			})
			if err != nil {
				return
			}
			return
		}

		for _, ip := range ipAddresses {
			attack, fetchErr = d.neoprotectAPI.GetActiveAttack(ctx, ip.IPv4)
			if fetchErr == nil && attack != nil {
				break
			}
		}

		if attack == nil {
			_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
				Content: "✅ No active attacks found.",
			})
			if err != nil {
				return
			}
			return
		}
	} else {
		_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Content: "❌ Looking up attacks by ID is not currently supported. Please use `/history` to view recent attacks.",
		})
		if err != nil {
			return
		}
		return
	}

	embed := d.createDiscordgoEmbed(attack, nil, 0x3498DB, "DDoS Attack Details")

	_, err = s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
		Embeds: []*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		log.Printf("Error sending followup message: %v", err)
	}
}

func (d *DiscordBotIntegration) handleHistoryCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	if err != nil {
		log.Printf("Error acknowledging interaction: %v", err)
		return
	}

	if d.neoprotectAPI == nil {
		_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Content: "⚠️ NeoProtect API client is not configured for this bot.",
		})
		if err != nil {
			return
		}
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ipAddresses, err := d.neoprotectAPI.GetIPAddresses(ctx)
	if err != nil {
		_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Failed to fetch IP addresses: %v", err),
		})
		if err != nil {
			return
		}
		return
	}

	var allAttacks []*neoprotect.Attack
	for _, ip := range ipAddresses {
		if ip == nil || ip.IPv4 == "" {
			continue
		}

		// Only get max 5 pages of attacks per IP to avoid timeouts
		maxPages := 5
		for page := 0; page < maxPages; page++ {
			attacks, err := d.neoprotectAPI.GetAttacks(ctx, ip.IPv4, page)
			if err != nil {
				log.Printf("Warning: Failed to fetch attacks for IP %s, page %d: %v", ip.IPv4, page, err)
				break
			}

			if len(attacks) == 0 {
				break
			}

			allAttacks = append(allAttacks, attacks...)

			// If we have enough attacks for our limit, stop fetching more
			if len(allAttacks) >= limit*3 {
				break
			}
		}

		// If we have a good number of attacks, stop checking more IPs
		if len(allAttacks) >= limit*2 {
			break
		}
	}

	// Sort attacks by start time (most recent first)
	sort.Slice(allAttacks, func(i, j int) bool {
		if allAttacks[i].StartedAt == nil {
			return false
		}
		if allAttacks[j].StartedAt == nil {
			return true
		}
		return allAttacks[i].StartedAt.After(*allAttacks[j].StartedAt)
	})

	if len(allAttacks) > limit {
		allAttacks = allAttacks[:limit]
	}

	var description strings.Builder
	description.WriteString(fmt.Sprintf("## Recent Attack History\n\n"))

	if len(allAttacks) == 0 {
		description.WriteString("No attack history found.")
	} else {
		for i, attack := range allAttacks {
			if attack == nil || attack.StartedAt == nil {
				continue
			}

			status := "✅ Ended"
			duration := "N/A"
			panelLink := fmt.Sprintf("https://panel.neoprotect.net/network/ips/%s?tab=attacks", attack.DstAddressString)

			if attack.EndedAt != nil {
				duration = attack.Duration().String()
			} else {
				status = "`🚨` Active"
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
			description.WriteString(fmt.Sprintf("**Panel:** [View Details](%s)\n", panelLink))

			signatures := attack.GetSignatureNames()
			if len(signatures) > 0 {
				description.WriteString("**Signatures:** ")
				for j, sig := range signatures {
					if j > 0 {
						description.WriteString(", ")
					}
					description.WriteString(fmt.Sprintf("`%s`", sig))
				}
				description.WriteString("\n")
			}

			description.WriteString("\n")
		}
	}

	embed := &discordgo.MessageEmbed{
		Title:       "NeoProtect Attack History",
		Description: description.String(),
		Color:       0x3498DB,
		Footer: &discordgo.MessageEmbedFooter{
			Text:    fmt.Sprintf("Showing %d most recent attacks", len(allAttacks)),
			IconURL: "https://cms.mscode.pl/uploads/icon_blue_84fa10dde8.png",
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}

	_, err = s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
		Embeds: []*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		log.Printf("Error sending followup message: %v", err)
	}
}

func (d *DiscordBotIntegration) handleStatsCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	if err != nil {
		log.Printf("Error acknowledging interaction: %v", err)
		return
	}

	if d.neoprotectAPI == nil {
		log.Printf("Error: NeoProtect API client is nil in handleStatsCommand")
		_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Content: "⚠️ NeoProtect API client is not available. Please check your configuration.",
		})
		if err != nil {
			return
		}
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second) // Increase timeout
	defer cancel()

	ipAddresses, err := d.neoprotectAPI.GetIPAddresses(ctx)
	if err != nil {
		_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Failed to fetch IP addresses: %v", err),
		})
		if err != nil {
			return
		}
		return
	}

	if targetIP == "" {
		var description strings.Builder

		for _, ip := range ipAddresses {
			if ip == nil || ip.IPv4 == "" {
				continue
			}

			var status string
			panelLink := fmt.Sprintf("https://panel.neoprotect.net/network/ips/%s?tab=attacks", ip.IPv4)

			attack, err := d.neoprotectAPI.GetActiveAttack(ctx, ip.IPv4)
			if err != nil {
				if errors.Is(err, neoprotect.ErrNoActiveAttack) {
					status = "✅ No active attack"
				} else {
					status = fmt.Sprintf("❓ Error checking status: %v", err)
				}
			} else if attack != nil && attack.StartedAt != nil {
				status = fmt.Sprintf("`🚨` Under attack since %s", attack.StartedAt.Format(time.RFC3339))
			} else {
				status = "✅ No active attack"
			}

			description.WriteString(fmt.Sprintf("**IP:** `%s` | **Status:** %s | [View in Panel](%s)\n\n", ip.IPv4, status, panelLink))
		}

		if description.Len() == 0 {
			description.WriteString("No IP addresses found in your account.")
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

		_, err = s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
		if err != nil {
			log.Printf("Error sending followup message: %v", err)
		}

		return
	} else {
		ipPattern := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
		if !ipPattern.MatchString(targetIP) {
			_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
				Content: "❌ Invalid IP address format. Please use dotted decimal notation (e.g., 192.168.1.1).",
			})
			if err != nil {
				return
			}
			return
		}

		ipExists := false
		for _, ip := range ipAddresses {
			if ip != nil && ip.IPv4 == targetIP {
				ipExists = true
				break
			}
		}

		if !ipExists {
			_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ IP address `%s` was not found in your NeoProtect account.", targetIP),
			})
			if err != nil {
				log.Printf("Error sending IP not found message: %v", err)
			}
			return
		}

		var attack *neoprotect.Attack
		notFoundError := false

		attack, err = d.neoprotectAPI.GetActiveAttack(ctx, targetIP)
		if err != nil {
			if errors.Is(err, neoprotect.ErrNoActiveAttack) {
				notFoundError = true
				log.Printf("No active attack for IP %s", targetIP)
			} else if strings.Contains(err.Error(), "status code 404") {
				_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
					Content: fmt.Sprintf("❌ IP address `%s` was not found in the NeoProtect system.", targetIP),
				})
				if err != nil {
					log.Printf("Error sending IP not found message: %v", err)
				}
				return
			} else {
				_, err := s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
					Content: fmt.Sprintf("❌ Failed to check attack status: %v", err),
				})
				if err != nil {
					return
				}
				return
			}
		}

		var attacks []*neoprotect.Attack
		maxPages := 20

		for page := 0; page < maxPages; page++ {
			pageAttacks, err := d.neoprotectAPI.GetAttacks(ctx, targetIP, page)
			if err != nil {
				if strings.Contains(err.Error(), "status code 404") {
					log.Printf("Error: IP %s not found when fetching attack history", targetIP)
					break
				} else {
					log.Printf("Error fetching attack history for IP %s, page %d: %v", targetIP, page, err)
					break
				}
			}

			if len(pageAttacks) == 0 {
				break
			}

			attacks = append(attacks, pageAttacks...)

			if len(attacks) >= 100 {
				log.Printf("Collected 100 attack records for IP %s, stopping pagination", targetIP)
				break
			}
		}

		panelLink := fmt.Sprintf("https://panel.neoprotect.net/network/ips/%s?tab=attacks", targetIP)

		var description strings.Builder
		description.WriteString(fmt.Sprintf("## Statistics for IP: `%s`\n\n", targetIP))
		description.WriteString(fmt.Sprintf("**`🔗`** [View in NeoProtect Panel](%s)\n\n", panelLink))

		if attack != nil && !notFoundError && attack.StartedAt != nil {
			description.WriteString("**`🚨`** Current Status: Under Attack\n")
			description.WriteString(fmt.Sprintf("**Attack Start:** %s\n", attack.StartedAt.Format(time.RFC3339)))
			description.WriteString(fmt.Sprintf("**Duration:** %s\n", attack.Duration().String()))
			description.WriteString(fmt.Sprintf("**Peak Bandwidth:** %s\n", formatBPS(attack.GetPeakBPS())))
			description.WriteString(fmt.Sprintf("**Peak Packet Rate:** %s\n", formatPPS(attack.GetPeakPPS())))
		} else {
			description.WriteString("**`✅`** Current Status: No Active Attack\n")
		}

		attackCount := len(attacks)
		totalMessage := fmt.Sprintf("%d (showing latest %d)", attackCount, attackCount)
		if attackCount >= 100 {
			totalMessage = fmt.Sprintf("%d+ (showing latest %d, see panel for full history)", attackCount, attackCount)
		}

		description.WriteString(fmt.Sprintf("\n## Attack History\n\n"))
		description.WriteString(fmt.Sprintf("**Total Attacks:** %s\n", totalMessage))

		var totalDuration time.Duration
		var peakBPS int64
		var peakPPS int64

		for _, a := range attacks {
			if a == nil {
				continue
			}

			if a.StartedAt != nil && a.EndedAt != nil {
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
			URL:         panelLink,
			Footer: &discordgo.MessageEmbedFooter{
				Text:    "Use /history for detailed attack history",
				IconURL: "https://cms.mscode.pl/uploads/icon_blue_84fa10dde8.png",
			},
			Timestamp: time.Now().Format(time.RFC3339),
		}

		_, err = s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
		if err != nil {
			log.Printf("Error sending followup message: %v", err)
		}
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

	embed := d.createDiscordgoEmbed(attack, nil, 0xFF0000, "`🔥` New DDoS Attack Detected")
	embeds := []*discordgo.MessageEmbed{embed}

	msg, err := d.dg.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
		Embeds: embeds,
	})
	if err != nil {
		return "", fmt.Errorf("failed to send Discord message: %w", err)
	}

	if msg.ID != "" {
		d.messageMutex.Lock()
		d.attackCache[attack.ID] = msg.ID
		d.messageMutex.Unlock()

		go func() {
			time.Sleep(5 * time.Second)

			embed.Timestamp = time.Now().Format(time.RFC3339)
			updatedEmbeds := []*discordgo.MessageEmbed{embed}

			_, err := d.dg.ChannelMessageEditComplex(&discordgo.MessageEdit{
				Channel: d.channelID,
				ID:      msg.ID,
				Embeds:  &updatedEmbeds,
			})

			if err != nil {
				log.Printf("Error updating attack notification after delay: %v", err)
			} else {
				log.Printf("Successfully updated attack notification after 5s delay")
			}
		}()
	}

	return msg.ID, nil
}

func (d *DiscordBotIntegration) NotifyAttackUpdate(ctx context.Context, attack *neoprotect.Attack, previous *neoprotect.Attack, messageID string) error {
	if d.dg == nil {
		return fmt.Errorf("discord session not initialized")
	}

	embed := d.createDiscordgoEmbed(attack, previous, 0xFFFF00, "DDoS Attack Updated")
	embeds := []*discordgo.MessageEmbed{embed}

	if messageID == "" {
		d.messageMutex.RLock()
		cachedID, exists := d.attackCache[attack.ID]
		d.messageMutex.RUnlock()

		if exists {
			messageID = cachedID
		}
	}

	if messageID != "" {
		_, err := d.dg.ChannelMessageEditComplex(&discordgo.MessageEdit{
			Channel: d.channelID,
			ID:      messageID,
			Embeds:  &embeds,
		})
		if err != nil {
			if strings.Contains(err.Error(), "Unknown Message") {
				newEmbeds := []*discordgo.MessageEmbed{embed}
				msg, err := d.dg.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
					Embeds: newEmbeds,
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

	newEmbeds := []*discordgo.MessageEmbed{embed}
	msg, err := d.dg.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
		Embeds: newEmbeds,
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

	embed := d.createDiscordgoEmbed(attack, nil, 0x00FF00, "DDoS Attack Ended")
	embeds := []*discordgo.MessageEmbed{embed}

	if messageID == "" {
		d.messageMutex.RLock()
		cachedID, exists := d.attackCache[attack.ID]
		d.messageMutex.RUnlock()

		if exists {
			messageID = cachedID
		}
	}

	if messageID != "" {
		_, err := d.dg.ChannelMessageEditComplex(&discordgo.MessageEdit{
			Channel: d.channelID,
			ID:      messageID,
			Embeds:  &embeds,
		})
		if err != nil {
			if strings.Contains(err.Error(), "Unknown Message") {
				newEmbeds := []*discordgo.MessageEmbed{embed}
				_, err := d.dg.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
					Embeds: newEmbeds,
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

	newEmbeds := []*discordgo.MessageEmbed{embed}
	_, err := d.dg.ChannelMessageSendComplex(d.channelID, &discordgo.MessageSend{
		Embeds: newEmbeds,
	})
	if err != nil {
		return fmt.Errorf("failed to send Discord message: %w", err)
	}

	return nil
}

func (d *DiscordBotIntegration) createDiscordgoEmbed(attack *neoprotect.Attack, previous *neoprotect.Attack, color int, title string) *discordgo.MessageEmbed {
	var description strings.Builder

	if attack.StartedAt != nil {
		description.WriteString("### Attack Timeline\n")
		description.WriteString(fmt.Sprintf("**`🕒`** Started: %s\n", attack.StartedAt.Format(time.RFC3339)))

		if attack.EndedAt != nil {
			description.WriteString(fmt.Sprintf("**`🛑`** Ended: %s\n", attack.EndedAt.Format(time.RFC3339)))
			description.WriteString(fmt.Sprintf("**`⏱️`** Duration: %s\n", attack.Duration().String()))
		} else {
			description.WriteString("**`⚠️`** Status: Active\n")
			description.WriteString(fmt.Sprintf("**`⏱️`** Duration so far: %s\n", attack.Duration().String()))
		}
	}

	description.WriteString("### Attack Details\n")
	description.WriteString(fmt.Sprintf("**`🎯`** Target IP: `%s`\n", attack.DstAddressString))
	description.WriteString(fmt.Sprintf("**`🔍`** Attack ID: `%s`\n", attack.ID))

	panelLink := fmt.Sprintf("https://panel.neoprotect.net/network/ips/%s?tab=attacks", attack.DstAddressString)
	description.WriteString(fmt.Sprintf("**`🔗`** [View in NeoProtect Panel](%s)\n", panelLink))

	fields := []*discordgo.MessageEmbedField{
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
				fields = append(fields, &discordgo.MessageEmbedField{
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

	embed := &discordgo.MessageEmbed{
		Title:       title,
		Description: description.String(),
		Color:       color,
		Fields:      fields,
		URL:         panelLink,
		Footer: &discordgo.MessageEmbedFooter{
			Text:    "NeoProtect Monitor Bot",
			IconURL: "https://cms.mscode.pl/uploads/icon_blue_84fa10dde8.png",
		},
		Timestamp: timestamp,
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
		result.WriteString(fmt.Sprintf("• `%s`\n", name))
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
