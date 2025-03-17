package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	APIKey      string `json:"apiKey"`
	APIEndpoint string `json:"apiEndpoint"`

	PollInterval        time.Duration `json:"-"`
	PollIntervalSeconds int           `json:"pollIntervalSeconds"`

	MonitorMode string   `json:"monitorMode"`
	SpecificIPs []string `json:"specificIPs"`

	EnabledIntegrations []string `json:"enabledIntegrations"`

	IntegrationConfigs map[string]json.RawMessage `json:"integrationConfigs"`
}

// LoadConfig loads and parses the configuration file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	err = json.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	cfg.PollInterval = time.Duration(cfg.PollIntervalSeconds) * time.Second

	return &cfg, nil
}

// validateConfig validates the configuration and sets default values
func validateConfig(cfg *Config) error {
	if cfg.APIKey == "" {
		return fmt.Errorf("apiKey must be provided")
	}

	if cfg.APIEndpoint == "" {
		cfg.APIEndpoint = "https://api.neoprotect.net/v2"
	}

	if cfg.PollIntervalSeconds <= 0 {
		cfg.PollIntervalSeconds = 60
	}

	// Validate monitor mode
	if cfg.MonitorMode == "" {
		cfg.MonitorMode = "all"
	} else if cfg.MonitorMode != "all" && cfg.MonitorMode != "specific" {
		return fmt.Errorf("monitorMode must be either 'all' or 'specific'")
	}

	if cfg.MonitorMode == "specific" && len(cfg.SpecificIPs) == 0 {
		return fmt.Errorf("at least one IP address must be provided in specificIPs when monitorMode is 'specific'")
	}

	if cfg.IntegrationConfigs == nil {
		cfg.IntegrationConfigs = make(map[string]json.RawMessage)
	}

	return nil
}

// GetIntegrationConfig retrieves the configuration for a specific integration
func (c *Config) GetIntegrationConfig(name string, target interface{}) error {
	config, ok := c.IntegrationConfigs[name]
	if !ok {
		return fmt.Errorf("no configuration found for integration: %s", name)
	}

	return json.Unmarshal(config, target)
}
