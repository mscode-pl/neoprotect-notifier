package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"plugin"
	"strings"
	"sync"

	"neoprotect-notifier/config"
	"neoprotect-notifier/neoprotect"
)

type Integration interface {
	Name() string
	Initialize(cfg map[string]interface{}) error
	NotifyNewAttack(ctx context.Context, attack *neoprotect.Attack) (string, error)
	NotifyAttackUpdate(ctx context.Context, attack *neoprotect.Attack, previous *neoprotect.Attack, messageID string) error
	NotifyAttackEnded(ctx context.Context, attack *neoprotect.Attack, messageID string) error
}

type MessageTracker struct {
	mu         sync.RWMutex
	messageIDs map[string]map[string]string
}

func NewMessageTracker() *MessageTracker {
	return &MessageTracker{
		messageIDs: make(map[string]map[string]string),
	}
}

func (m *MessageTracker) TrackMessage(attackID, integrationName, messageID string) {
	if messageID == "" || attackID == "" || integrationName == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.messageIDs[attackID] == nil {
		m.messageIDs[attackID] = make(map[string]string)
	}
	m.messageIDs[attackID][integrationName] = messageID
}

func (m *MessageTracker) GetMessageID(attackID, integrationName string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if attackMessages, exists := m.messageIDs[attackID]; exists {
		return attackMessages[integrationName]
	}
	return ""
}

func (m *MessageTracker) RemoveMessage(attackID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.messageIDs, attackID)
}

type Manager struct {
	integrations map[string]Integration
	directory    string
	config       *config.Config
	mu           sync.RWMutex
}

func (m *Manager) InitializeIntegrations(cfg *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, integration := range m.integrations {
		var rawConfig map[string]interface{}

		if name == "console" {
			if configData, ok := cfg.IntegrationConfigs[name]; ok {
				if err := json.Unmarshal(configData, &rawConfig); err != nil {
					return fmt.Errorf("failed to unmarshal config for %s: %w", name, err)
				}
			} else {
				rawConfig = make(map[string]interface{})
				log.Printf("Using default configuration for console integration")
			}
		} else {
			configData, ok := cfg.IntegrationConfigs[name]
			if !ok {
				return fmt.Errorf("no configuration found for %s integration", name)
			}

			if err := json.Unmarshal(configData, &rawConfig); err != nil {
				return fmt.Errorf("failed to unmarshal config for %s: %w", name, err)
			}
		}

		if err := integration.Initialize(rawConfig); err != nil {
			return fmt.Errorf("failed to initialize %s integration: %w", name, err)
		}
	}

	return nil
}

// NewManager creates a new integration manager
func NewManager(directory string, enabledIntegrations []string) (*Manager, error) {
	manager := &Manager{
		integrations: make(map[string]Integration),
		directory:    directory,
	}

	if err := os.MkdirAll(directory, 0755); err != nil {
		return nil, fmt.Errorf("failed to create integrations directory: %w", err)
	}

	err := manager.loadBuiltInIntegrations(enabledIntegrations)
	if err != nil {
		return nil, fmt.Errorf("failed to load built-in integrations: %w", err)
	}

	err = manager.loadPluginIntegrations(directory, enabledIntegrations)
	if err != nil {
		log.Printf("Warning: failed to load plugin integrations: %v", err)
	}

	if len(manager.integrations) == 0 {
		return nil, errors.New("no integrations were loaded")
	}

	log.Printf("Loaded %d integration(s): %s", len(manager.integrations), manager.listIntegrationNames())
	return manager, nil
}

func (m *Manager) SetConfig(cfg *config.Config) {
	m.config = cfg
}

func (m *Manager) listIntegrationNames() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.integrations))
	for name := range m.integrations {
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

func (m *Manager) loadBuiltInIntegrations(enabledIntegrations []string) error {
	builtIns := map[string]Integration{
		"webhook":     &WebhookIntegration{},
		"console":     &ConsoleIntegration{},
		"discord":     &DiscordIntegration{},
		"discord_bot": &DiscordBotIntegration{},
	}

	for name, integration := range builtIns {
		if isEnabled(name, enabledIntegrations) {
			m.integrations[name] = integration
			log.Printf("Registered built-in integration: %s", name)
		}
	}

	return nil
}

// Loads integrations from plugin files in the specified directory
func (m *Manager) loadPluginIntegrations(directory string, enabledIntegrations []string) error {
	files, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("failed to read integrations directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".so") {
			continue
		}

		pluginPath := filepath.Join(directory, file.Name())
		name := strings.TrimSuffix(file.Name(), ".so")

		if !isEnabled(name, enabledIntegrations) {
			log.Printf("Skipping disabled plugin integration: %s", name)
			continue
		}

		p, err := plugin.Open(pluginPath)
		if err != nil {
			log.Printf("Error loading plugin %s: %v", pluginPath, err)
			continue
		}

		sym, err := p.Lookup("Integration")
		if err != nil {
			log.Printf("Error looking up Integration symbol in %s: %v", pluginPath, err)
			continue
		}

		integration, ok := sym.(Integration)
		if !ok {
			log.Printf("Symbol in %s does not implement Integration interface", pluginPath)
			continue
		}

		m.mu.Lock()
		m.integrations[name] = integration
		m.mu.Unlock()

		log.Printf("Registered plugin integration: %s", name)
	}

	return nil
}

// NotifyNewAttack notifies all integrations about a new attack
func (m *Manager) NotifyNewAttack(ctx context.Context, attack *neoprotect.Attack, messageTracker *MessageTracker) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	wg := sync.WaitGroup{}

	type notifyResult struct {
		IntegrationName string
		MessageID       string
		Error           error
	}

	results := make(chan notifyResult, len(m.integrations))

	for name, integration := range m.integrations {
		wg.Add(1)
		go func(name string, integration Integration) {
			defer wg.Done()

			msgID, err := integration.NotifyNewAttack(ctx, attack)
			results <- notifyResult{
				IntegrationName: name,
				MessageID:       msgID,
				Error:           err,
			}
		}(name, integration)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if result.Error != nil {
			log.Printf("Error notifying integration %s about new attack: %v", result.IntegrationName, result.Error)
			lastErr = result.Error
		}

		if result.MessageID != "" && messageTracker != nil {
			messageTracker.TrackMessage(attack.ID, result.IntegrationName, result.MessageID)
		}
	}

	return lastErr
}

// NotifyAttackUpdate Notifies all integrations about an attack update
func (m *Manager) NotifyAttackUpdate(ctx context.Context, attack *neoprotect.Attack, previous *neoprotect.Attack, messageTracker *MessageTracker) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	wg := sync.WaitGroup{}

	for name, integration := range m.integrations {
		wg.Add(1)
		go func(name string, integration Integration) {
			defer wg.Done()

			var messageID string
			if messageTracker != nil {
				messageID = messageTracker.GetMessageID(attack.ID, name)
			}

			if err := integration.NotifyAttackUpdate(ctx, attack, previous, messageID); err != nil {
				log.Printf("Error notifying integration %s about attack update: %v", name, err)
				lastErr = err
			}
		}(name, integration)
	}

	wg.Wait()
	return lastErr
}

// NotifyAttackEnded Notifies all integrations about an attack that has ended
func (m *Manager) NotifyAttackEnded(ctx context.Context, attack *neoprotect.Attack, messageTracker *MessageTracker) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	wg := sync.WaitGroup{}

	for name, integration := range m.integrations {
		wg.Add(1)
		go func(name string, integration Integration) {
			defer wg.Done()

			var messageID string
			if messageTracker != nil {
				messageID = messageTracker.GetMessageID(attack.ID, name)
			}

			if err := integration.NotifyAttackEnded(ctx, attack, messageID); err != nil {
				log.Printf("Error notifying integration %s about attack end: %v", name, err)
				lastErr = err
			}
		}(name, integration)
	}

	wg.Wait()
	return lastErr
}

func isEnabled(name string, enabledIntegrations []string) bool {
	for _, enabled := range enabledIntegrations {
		if enabled == name {
			return true
		}
	}
	return false
}

func (m *Manager) Shutdown() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for name, integration := range m.integrations {
		if discordBot, ok := integration.(*DiscordBotIntegration); ok {
			log.Printf("Shutting down Discord bot integration: %s", name)
			discordBot.Shutdown()
		}
	}
}

func (m *Manager) SetAPIClient(client *neoprotect.Client) {
	if client == nil {
		log.Println("Error: Cannot set nil NeoProtect client on integrations")
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	discordBotCount := 0
	for name, integration := range m.integrations {
		if discordBot, ok := integration.(*DiscordBotIntegration); ok {
			discordBotCount++
			log.Printf("Setting API client for %s integration", name)
			discordBot.neoprotectAPI = client
		}
	}

	if discordBotCount == 0 {
		log.Println("Warning: No Discord bot integrations found to set API client on")
	} else {
		log.Printf("Set API client on %d Discord bot integration(s)", discordBotCount)
	}
}
