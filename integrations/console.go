package integrations

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"neoprotect-notifier/neoprotect"
)

type ConsoleIntegration struct {
	logPrefix    string
	formatJSON   bool
	colorEnabled bool
}

type ConsoleConfig struct {
	LogPrefix    string `json:"logPrefix"`
	FormatJSON   bool   `json:"formatJson"`
	ColorEnabled bool   `json:"colorEnabled"`
}

func (c *ConsoleIntegration) Name() string {
	return "console"
}

// Initialize sets up the console integration
func (c *ConsoleIntegration) Initialize(rawConfig map[string]interface{}) error {
	configBytes, err := json.Marshal(rawConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal console config: %w", err)
	}

	var config ConsoleConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return fmt.Errorf("failed to unmarshal console config: %w", err)
	}

	if config.LogPrefix == "" {
		config.LogPrefix = "NEOPROTECT"
	}

	c.logPrefix = config.LogPrefix
	c.formatJSON = config.FormatJSON
	c.colorEnabled = config.ColorEnabled

	return nil
}

// NotifyNewAttack logs a new attack notification to the console
func (c *ConsoleIntegration) NotifyNewAttack(ctx context.Context, attack *neoprotect.Attack) (string, error) {
	message := c.formatAttack("NEW ATTACK", attack, nil, c.colorRed())
	log.Println(message)
	return "", nil // Console integration doesn't track message IDs
}

// NotifyAttackUpdate logs an attack update notification to the console
func (c *ConsoleIntegration) NotifyAttackUpdate(ctx context.Context, attack *neoprotect.Attack, previous *neoprotect.Attack, messageID string) error {
	message := c.formatAttack("ATTACK UPDATE", attack, previous, c.colorYellow())
	log.Println(message)
	return nil
}

// NotifyAttackEnded logs an attack ended notification to the console
func (c *ConsoleIntegration) NotifyAttackEnded(ctx context.Context, attack *neoprotect.Attack, messageID string) error {
	message := c.formatAttack("ATTACK ENDED", attack, nil, c.colorGreen())
	log.Println(message)
	return nil
}

// formatAttack formats an attack notification as a string
func (c *ConsoleIntegration) formatAttack(eventType string, attack *neoprotect.Attack, previous *neoprotect.Attack, colorCode string) string {
	if c.formatJSON {
		return c.formatJSONOutput(eventType, attack, previous)
	}

	var timeInfo string
	if attack.StartedAt != nil {
		timeInfo = fmt.Sprintf("started at %s", attack.StartedAt.Format(time.RFC3339))
		if attack.EndedAt != nil {
			timeInfo += fmt.Sprintf(", ended at %s (duration: %s)",
				attack.EndedAt.Format(time.RFC3339),
				attack.Duration().String())
		}
	}

	var diffInfo string
	if previous != nil {
		diff := attack.CalculateDiff(previous)
		if diffBytes, err := json.Marshal(diff); err == nil {
			diffInfo = fmt.Sprintf(" Changes: %s", string(diffBytes))
		}
	}

	return fmt.Sprintf("%s[%s] %s: Attack %s on %s, %s, %d signatures (%s), peak: %d bps, %d pps%s%s",
		colorCode,
		c.logPrefix,
		eventType,
		attack.ID[:8],
		attack.DstAddressString,
		timeInfo,
		len(attack.Signatures),
		c.joinSignatureNames(attack),
		attack.GetPeakBPS(),
		attack.GetPeakPPS(),
		diffInfo,
		c.colorReset(),
	)
}

// formatJSONOutput formats an attack notification as JSON
func (c *ConsoleIntegration) formatJSONOutput(eventType string, attack *neoprotect.Attack, previous *neoprotect.Attack) string {
	output := map[string]interface{}{
		"prefix":     c.logPrefix,
		"event":      eventType,
		"attack_id":  attack.ID,
		"target_ip":  attack.DstAddressString,
		"started_at": attack.StartedAt,
		"ended_at":   attack.EndedAt,
		"signatures": attack.GetSignatureNames(),
		"peak_bps":   attack.GetPeakBPS(),
		"peak_pps":   attack.GetPeakPPS(),
		"timestamp":  time.Now(),
	}

	if previous != nil {
		output["changes"] = attack.CalculateDiff(previous)
	}

	if attack.EndedAt != nil {
		output["duration"] = attack.Duration().String()
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting JSON: %v", err)
	}

	return fmt.Sprintf("%s%s%s", c.colorCode(eventType), string(jsonBytes), c.colorReset())
}

// joinSignatureNames joins the attack signature names into a comma-separated string
func (c *ConsoleIntegration) joinSignatureNames(attack *neoprotect.Attack) string {
	names := attack.GetSignatureNames()
	if len(names) == 0 {
		return "unknown"
	}

	result := names[0]
	for i := 1; i < len(names); i++ {
		result += ", " + names[i]
	}

	return result
}

// colorCode returns the appropriate color code for an event type
func (c *ConsoleIntegration) colorCode(eventType string) string {
	if !c.colorEnabled {
		return ""
	}

	switch eventType {
	case "NEW ATTACK":
		return ColorRed
	case "ATTACK UPDATE":
		return ColorYellow
	case "ATTACK ENDED":
		return ColorGreen
	default:
		return ColorBlue
	}
}

// colorRed returns the red color code if colors are enabled
func (c *ConsoleIntegration) colorRed() string {
	if c.colorEnabled {
		return ColorRed
	}
	return ""
}

// colorYellow returns the yellow color code if colors are enabled
func (c *ConsoleIntegration) colorYellow() string {
	if c.colorEnabled {
		return ColorYellow
	}
	return ""
}

// colorGreen returns the green color code if colors are enabled
func (c *ConsoleIntegration) colorGreen() string {
	if c.colorEnabled {
		return ColorGreen
	}
	return ""
}

// colorReset returns the color reset code if colors are enabled
func (c *ConsoleIntegration) colorReset() string {
	if c.colorEnabled {
		return ColorReset
	}
	return ""
}
