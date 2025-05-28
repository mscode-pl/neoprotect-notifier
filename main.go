package main

import (
	"context"
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

	log.Println("Performing initial attack status fetch (active attacks only)")
	fetchAndProcessActiveAttacks(ctx, client, manager, cfg.MonitorMode, cfg.SpecificIPs, knownAttacks, messageTracker, cfg)

	for {
		select {
		case <-ctx.Done():
			log.Println("Attack monitoring stopped")
			return
		case <-ticker.C:
			fetchAndProcessActiveAttacks(ctx, client, manager, cfg.MonitorMode, cfg.SpecificIPs, knownAttacks, messageTracker, cfg)
		}
	}
}

func fetchAndProcessActiveAttacks(ctx context.Context, client *neoprotect.Client, manager *integrations.Manager, monitorMode string, ipsToMonitor []string, knownAttacks map[string]*neoprotect.Attack, messageTracker *integrations.MessageTracker, cfg *config.Config) {
	attacks, err := client.GetAllAttacksAllPages(ctx, true)
	if err != nil {
		log.Printf("Error fetching active attacks: %v", err)
		return
	}

	if monitorMode == "specific" {
		var filteredAttacks []*neoprotect.Attack
		for _, attack := range attacks {
			for _, ip := range ipsToMonitor {
				if attack.DstAddressString == ip {
					if !cfg.IsBlacklisted(ip) {
						filteredAttacks = append(filteredAttacks, attack)
					}
					break
				}
			}
		}
		attacks = filteredAttacks
	} else if monitorMode == "all" {
		var filteredAttacks []*neoprotect.Attack
		for _, attack := range attacks {
			if !cfg.IsBlacklisted(attack.DstAddressString) {
				filteredAttacks = append(filteredAttacks, attack)
			}
		}
		attacks = filteredAttacks
	} else {
		log.Printf("Invalid monitor mode: %s", monitorMode)
		return
	}

	var validAttacks []*neoprotect.Attack
	for _, attack := range attacks {
		if !isValidAttack(attack) {
			log.Printf("Skipping invalid attack: ID=%s, IP=%s", attack.ID, attack.DstAddressString)
			continue
		}
		validAttacks = append(validAttacks, attack)
	}

	processActiveAttacks(ctx, client, manager, validAttacks, knownAttacks, messageTracker)
	checkForEndedAttacks(ctx, manager, validAttacks, knownAttacks, messageTracker)
	cleanupEndedAttacks(knownAttacks)
}

func isValidAttack(attack *neoprotect.Attack) bool {
	if attack == nil {
		return false
	}
	if attack.ID == "" {
		return false
	}
	if attack.DstAddressString == "" {
		return false
	}
	return true
}

func processActiveAttacks(ctx context.Context, client *neoprotect.Client, manager *integrations.Manager, attacks []*neoprotect.Attack, knownAttacks map[string]*neoprotect.Attack, messageTracker *integrations.MessageTracker) {
	seenAttacks := make(map[string]bool)

	for _, attack := range attacks {
		seenAttacks[attack.ID] = true

		existingAttack, exists := knownAttacks[attack.ID]

		if !exists {
			knownAttacks[attack.ID] = attack

			err := manager.NotifyNewAttack(ctx, attack, messageTracker)
			if err != nil {
				log.Printf("Error notifying integrations about new attack: %v", err)
			}
		} else if !attack.Equal(existingAttack) {
			previousState := *existingAttack
			knownAttacks[attack.ID] = attack

			err := manager.NotifyAttackUpdate(ctx, attack, &previousState, messageTracker)
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
			now := time.Now()
			attack.EndedAt = &now

			err := manager.NotifyAttackEnded(ctx, attack, messageTracker)
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
			delete(knownAttacks, id)
		}
	}
}
