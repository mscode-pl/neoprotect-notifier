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
	messageIDs map[string]string // attack ID -> message ID
}

func NewMessageTracker() *MessageTracker {
	return &MessageTracker{
		messageIDs: make(map[string]string),
	}
}

func (m *MessageTracker) TrackMessage(attackID, messageID string) {
	if messageID == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.messageIDs[attackID] = messageID
}

func (m *MessageTracker) GetMessageID(attackID string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.messageIDs[attackID]
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

		if configData, ok := cfg.IntegrationConfigs[name]; ok {
			if err := json.Unmarshal(configData, &rawConfig); err != nil {
				return fmt.Errorf("failed to unmarshal config for %s: %w", name, err)
			}

			if err := integration.Initialize(rawConfig); err != nil {
				return fmt.Errorf("failed to initialize %s integration: %w", name, err)
			}
		} else {
			log.Printf("Warning: No configuration found for %s integration", name)
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

	// Load built-in integrations
	err := manager.loadBuiltInIntegrations(enabledIntegrations)
	if err != nil {
		return nil, fmt.Errorf("failed to load built-in integrations: %w", err)
	}

	// Load plugin integrations
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
		// More integrations soon…
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
func (m *Manager) NotifyNewAttack(ctx context.Context, attack *neoprotect.Attack) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	var messageID string
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

	// Close results channel after all goroutines finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	for result := range results {
		if result.Error != nil {
			log.Printf("Error notifying integration %s about new attack: %v", result.IntegrationName, result.Error)
			lastErr = result.Error
		}

		// Prefer Discord Bot message ID if available, otherwise use Discord
		if result.MessageID != "" {
			if result.IntegrationName == "discord_bot" || messageID == "" {
				messageID = result.MessageID
			}
		}
	}

	return messageID, lastErr
}

// NotifyAttackUpdate Notifies all integrations about an attack update
func (m *Manager) NotifyAttackUpdate(ctx context.Context, attack *neoprotect.Attack, previous *neoprotect.Attack, messageID string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	wg := sync.WaitGroup{}

	for name, integration := range m.integrations {
		wg.Add(1)
		go func(name string, integration Integration) {
			defer wg.Done()

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
func (m *Manager) NotifyAttackEnded(ctx context.Context, attack *neoprotect.Attack, messageID string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var lastErr error
	wg := sync.WaitGroup{}

	for name, integration := range m.integrations {
		wg.Add(1)
		go func(name string, integration Integration) {
			defer wg.Done()

			if err := integration.NotifyAttackEnded(ctx, attack, messageID); err != nil {
				log.Printf("Error notifying integration %s about attack end: %v", name, err)
				lastErr = err
			}
		}(name, integration)
	}

	wg.Wait()
	return lastErr
}

// isEnabled checks if an integration is in the enabled list
func isEnabled(name string, enabledIntegrations []string) bool {
	for _, enabled := range enabledIntegrations {
		if enabled == name {
			return true
		}
	}
	return false
}
