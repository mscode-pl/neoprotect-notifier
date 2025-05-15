package neoprotect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	ErrNoActiveAttack = errors.New("no active attack found")
	ErrRequestFailed  = errors.New("API request failed")
	ErrIPNotFound     = errors.New("IP address not found")
)

type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

func NewClient(apiKey, baseURL string) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("API key is required")
	}

	if baseURL == "" {
		baseURL = "https://api.neoprotect.net/v2"
	}

	return &Client{
		apiKey:  apiKey,
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// GetAttacks fetches all attacks for a specific IP address with pagination
func (c *Client) GetAttacks(ctx context.Context, ip string, page int) ([]*Attack, error) {
	endpoint := fmt.Sprintf("%s/ips/%s/attacks", c.baseURL, ip)

	if page > 0 {
		endpoint += fmt.Sprintf("?page=%d", page)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: %s (status code %d): %s",
			ErrRequestFailed, endpoint, resp.StatusCode, string(body))
	}

	var attacks []*Attack
	if err := json.NewDecoder(resp.Body).Decode(&attacks); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return attacks, nil
}

// GetAllAttacksForIP fetches all attacks for a specific IP across all pages
func (c *Client) GetAllAttacksForIP(ctx context.Context, ip string) ([]*Attack, error) {
	var allAttacks []*Attack
	page := 0

	for {
		attacks, err := c.GetAttacks(ctx, ip, page)
		if err != nil {
			return nil, err
		}

		if len(attacks) == 0 {
			break
		}

		allAttacks = append(allAttacks, attacks...)
		page++

		if page > 100 {
			log.Printf("Warning: Reached maximum page limit (100) when fetching attacks for IP %s", ip)
			break
		}
	}

	return allAttacks, nil
}

// GetActiveAttack fetches the currently active attack for a specific IP address
func (c *Client) GetActiveAttack(ctx context.Context, ip string) (*Attack, error) {
	endpoint := fmt.Sprintf("%s/ips/%s/attack", c.baseURL, ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNoActiveAttack
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: %s (status code %d): %s",
			ErrRequestFailed, endpoint, resp.StatusCode, string(body))
	}

	var attack Attack
	if err := json.NewDecoder(resp.Body).Decode(&attack); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &attack, nil
}

// GetAttackStats fetches detailed statistics for a specific attack
func (c *Client) GetAttackStats(ctx context.Context, attackID string) (*AttackStats, error) {
	endpoint := fmt.Sprintf("%s/ips/attacks/%s/stats", c.baseURL, attackID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: %s (status code %d): %s",
			ErrRequestFailed, endpoint, resp.StatusCode, string(body))
	}

	var stats AttackStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &stats, nil
}

// GetAttackSample fetches a sample file URL for a specific attack
func (c *Client) GetAttackSample(ctx context.Context, attackID string) (string, error) {
	endpoint := fmt.Sprintf("%s/ips/attacks/%s/sample", c.baseURL, attackID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%w: %s (status code %d): %s",
			ErrRequestFailed, endpoint, resp.StatusCode, string(body))
	}

	var sampleURL string
	if err := json.NewDecoder(resp.Body).Decode(&sampleURL); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return sampleURL, nil
}

// GetAllAttacks fetches all attacks with pagination support
func (c *Client) GetAllAttacks(ctx context.Context, activeOnly bool, page int) ([]*Attack, error) {
	endpoint := fmt.Sprintf("%s/ips/attacks", c.baseURL)

	var queryParams []string
	if activeOnly {
		queryParams = append(queryParams, "showActive=true")
	}
	if page > 0 {
		queryParams = append(queryParams, fmt.Sprintf("page=%d", page))
	}

	if len(queryParams) > 0 {
		endpoint += "?" + strings.Join(queryParams, "&")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: %s (status code %d): %s",
			ErrRequestFailed, endpoint, resp.StatusCode, string(body))
	}

	var attacks []*Attack
	if err := json.NewDecoder(resp.Body).Decode(&attacks); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return attacks, nil
}

// GetAllAttacksAllPages fetches all attacks across all pages
func (c *Client) GetAllAttacksAllPages(ctx context.Context, activeOnly bool) ([]*Attack, error) {
	var allAttacks []*Attack
	page := 0

	for {
		attacks, err := c.GetAllAttacks(ctx, activeOnly, page)
		if err != nil {
			return nil, err
		}

		if len(attacks) == 0 {
			break
		}

		allAttacks = append(allAttacks, attacks...)
		page++

		if page > 100 {
			log.Printf("Warning: Reached maximum page limit (100) when fetching all attacks")
			break
		}
	}

	return allAttacks, nil
}

// GetIPAddresses fetches all IP addresses assigned to the account
func (c *Client) GetIPAddresses(ctx context.Context) ([]*IPAddressModel, error) {
	endpoint := fmt.Sprintf("%s/ips", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: %s (status code %d): %s",
			ErrRequestFailed, endpoint, resp.StatusCode, string(body))
	}

	var addresses []*IPAddressModel
	if err := json.NewDecoder(resp.Body).Decode(&addresses); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return addresses, nil
}
