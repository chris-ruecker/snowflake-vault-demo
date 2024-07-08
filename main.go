package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	vault "github.com/hashicorp/vault/api"
)

type VaultConfig struct {
	Address       string
	Role          string
	Path          string
	SnowflakeRole string
}

type SnowflakeCredentials struct {
	User     string `json:"username"`
	Password string `json:"password"`
	Account  string `json:"account"`
}

func main() {
	// Load Vault configuration
	vaultConfig := VaultConfig{
		Address:       os.Getenv("VAULT_ADDR"),
		Role:          os.Getenv("VAULT_ROLE"),
		Path:          os.Getenv("VAULT_PATH"),
		SnowflakeRole: os.Getenv("VAULT_SNOWFLAKE_ROLE"),
	}

	// Authenticate to Vault using Kubernetes service account
	vaultClient, err := vault.NewClient(&vault.Config{
		Address: vaultConfig.Address,
	})
	if err != nil {
		log.Fatalf("failed to create Vault client: %v", err)
	}

	token, err := loginWithKubernetes(vaultClient, vaultConfig)
	if err != nil {
		log.Fatalf("failed to login to Vault: %v", err)
	}
	vaultClient.SetToken(token)

	// Read Snowflake credentials from Vault
	snowflakeCredentials, err := readSnowflakeCredentials(vaultClient, vaultConfig.SnowflakeRole)
	if err != nil {
		log.Fatalf("failed to read Snowflake credentials from Vault: %v", err)
	}

	// Output the credentials
	fmt.Printf("Snowflake User: %s\n", snowflakeCredentials.User)
	fmt.Printf("Snowflake Password: %s\n", snowflakeCredentials.Password)
	fmt.Printf("Snowflake Account: %s\n", snowflakeCredentials.Account)
}

func loginWithKubernetes(vaultClient *vault.Client, config VaultConfig) (string, error) {
	// Read the JWT from the Kubernetes service account
	jwt, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", fmt.Errorf("failed to read service account token: %w", err)
	}

	// Prepare login request
	loginData := map[string]interface{}{
		"role": config.Role,
		"jwt":  string(jwt),
	}

	// Perform login
	path := fmt.Sprintf("auth/%s/login", config.Path)
	resp, err := vaultClient.Logical().Write(path, loginData)
	if err != nil {
		return "", fmt.Errorf("failed to login to Vault: %w", err)
	}

	return resp.Auth.ClientToken, nil
}

func readSnowflakeCredentials(vaultClient *vault.Client, role string) (*SnowflakeCredentials, error) {
	path := fmt.Sprintf("database/creds/%s", role)
	secret, err := vaultClient.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from Vault: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no secret data found at path: %s", path)
	}

	data, err := json.Marshal(secret.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secret data: %w", err)
	}

	var credentials SnowflakeCredentials
	if err := json.Unmarshal(data, &credentials); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret data: %w", err)
	}

	return &credentials, nil
}
