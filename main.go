package main

import (
	"context"
	"errors"
	"flag"
	_ "fmt"
	"log"
	"os"
	"os/signal"
	_ "path/filepath"
	"sync"
	"syscall"
	"time"

	"neoprotect-notifier/config"
	"neoprotect-notifier/integrations"
	"neoprotect-notifier/neoprotect"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting NeoProtect Attack Notifier")

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := neoprotect.NewClient(cfg.APIKey, cfg.APIEndpoint)
	if err != nil {
		log.Fatalf("Failed to create NeoProtect client: %v", err)
	}

	integrationManager, err := integrations.NewManager("./integrations", cfg.EnabledIntegrations)
	if err != nil {
		log.Fatalf("Failed to initialize integration manager: %v", err)
	}

	if err := integrationManager.InitializeIntegrations(cfg); err != nil {
		log.Fatalf("Failed to initialize integrations: %v", err)
	}

	log.Println("Setting NeoProtect API client on integrations...")
	integrationManager.SetAPIClient(client)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorAttacks(ctx, client, integrationManager, cfg.PollInterval, cfg)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Received termination signal, shutting down...")
	integrationManager.Shutdown()
	cancel()

	wg.Wait()
	log.Println("Shutdown complete")
}

func monitorAttacks(ctx context.Context, client *neoprotect.Client, manager *integrations.Manager, pollInterval time.Duration, cfg *config.Config) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	knownAttacks := make(map[string]*neoprotect.Attack)
	messageTracker := integrations.NewMessageTracker()

	var ipsToMonitor []string
	if cfg.MonitorMode == "specific" {
		ipsToMonitor = cfg.SpecificIPs
	}

	log.Println("Performing initial attack status fetch (active attacks only)")
	fetchAndProcessActiveAttacks(ctx, client, manager, cfg.MonitorMode, ipsToMonitor, knownAttacks, messageTracker)

	for {
		select {
		case <-ctx.Done():
			log.Println("Attack monitoring stopped")
			return
		case <-ticker.C:
			fetchAndProcessActiveAttacks(ctx, client, manager, cfg.MonitorMode, ipsToMonitor, knownAttacks, messageTracker)
		}
	}
}

func fetchAndProcessActiveAttacks(ctx context.Context, client *neoprotect.Client, manager *integrations.Manager, monitorMode string, ipsToMonitor []string, knownAttacks map[string]*neoprotect.Attack, messageTracker *integrations.MessageTracker) {
	var attacks []*neoprotect.Attack
	var err error

	if monitorMode == "all" {
		attacks, err = client.GetAllAttacksAllPages(ctx, true)
		if err != nil {
			log.Printf("Error fetching active attacks: %v", err)
			return
		}
	} else if monitorMode == "specific" {
		var allAttacks []*neoprotect.Attack
		for _, ip := range ipsToMonitor {
			ipAttack, err := client.GetActiveAttack(ctx, ip)
			if err != nil {
				if !errors.Is(err, neoprotect.ErrNoActiveAttack) {
					log.Printf("Error fetching active attack for IP %s: %v", ip, err)
				}
				continue
			}

			if ipAttack != nil {
				allAttacks = append(allAttacks, ipAttack)
			}
		}
		attacks = allAttacks
	} else {
		log.Printf("Invalid monitor mode: %s", monitorMode)
		return
	}

	processActiveAttacks(ctx, client, manager, attacks, knownAttacks, messageTracker)
	checkForEndedAttacks(ctx, manager, attacks, knownAttacks, messageTracker)
	cleanupEndedAttacks(knownAttacks)
}

func processActiveAttacks(ctx context.Context, client *neoprotect.Client, manager *integrations.Manager, attacks []*neoprotect.Attack, knownAttacks map[string]*neoprotect.Attack, messageTracker *integrations.MessageTracker) {
	seenAttacks := make(map[string]bool)

	for _, attack := range attacks {
		seenAttacks[attack.ID] = true

		existingAttack, exists := knownAttacks[attack.ID]

		if !exists {
			log.Printf("New attack detected for IP %s: %s", attack.DstAddressString, attack.ID)
			knownAttacks[attack.ID] = attack

			messageID, err := manager.NotifyNewAttack(ctx, attack)
			if err != nil {
				log.Printf("Error notifying integrations about new attack: %v", err)
			} else if messageID != "" {
				messageTracker.TrackMessage(attack.ID, messageID)
			}
		} else if !attack.Equal(existingAttack) {
			log.Printf("Attack updated for IP %s: %s", attack.DstAddressString, attack.ID)

			previousState := *existingAttack
			knownAttacks[attack.ID] = attack

			messageID := messageTracker.GetMessageID(attack.ID)
			err := manager.NotifyAttackUpdate(ctx, attack, &previousState, messageID)
			if err != nil {
				log.Printf("Error notifying integrations about attack update: %v", err)
			}
		}
	}
}

func checkForEndedAttacks(ctx context.Context, manager *integrations.Manager, activeAttacks []*neoprotect.Attack, knownAttacks map[string]*neoprotect.Attack, messageTracker *integrations.MessageTracker) {
	activeAttackIDs := make(map[string]bool)
	for _, attack := range activeAttacks {
		activeAttackIDs[attack.ID] = true
	}

	for id, attack := range knownAttacks {
		if !activeAttackIDs[id] && attack.EndedAt == nil {
			log.Printf("Attack implicitly ended for IP %s: %s", attack.DstAddressString, attack.ID)

			now := time.Now()
			attack.EndedAt = &now

			messageID := messageTracker.GetMessageID(attack.ID)
			err := manager.NotifyAttackEnded(ctx, attack, messageID)
			if err != nil {
				log.Printf("Error notifying integrations about implicitly ended attack: %v", err)
			}

			knownAttacks[id] = attack
		}
	}
}

func cleanupEndedAttacks(knownAttacks map[string]*neoprotect.Attack) {
	for id, attack := range knownAttacks {
		if attack.EndedAt != nil && time.Since(*attack.EndedAt) > 24*time.Hour {
			log.Printf("Removing ended attack from tracking: %s", id)
			delete(knownAttacks, id)
		}
	}
}
