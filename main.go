package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	vault "github.com/hashicorp/vault/api"
	_ "github.com/snowflakedb/gosnowflake"
)

type VaultConfig struct {
	Address           string
	Role              string
	Path              string
	SecretsEnginePath string
	SnowflakeRole     string
}

type SnowflakeCredentials struct {
	User     string `json:"username"`
	Password string `json:"password"`
}

func main() {
	// Load Vault configuration
	vaultConfig := VaultConfig{
		Address:           os.Getenv("VAULT_ADDR"),
		Role:              os.Getenv("VAULT_ROLE"),
		Path:              os.Getenv("VAULT_PATH"),
		SecretsEnginePath: os.Getenv("VAULT_SECRETS_ENGINE_PATH"),
		SnowflakeRole:     os.Getenv("VAULT_SNOWFLAKE_ROLE"),
	}

	snowflakeAccount := os.Getenv("SNOWFLAKE_ACCOUNT")
	snowflakeWarehouse := os.Getenv("SNOWFLAKE_WAREHOUSE")

	if snowflakeAccount == "" {
		log.Fatalf("SNOWFLAKE_ACCOUNT environment variable not set")
	}

	if snowflakeWarehouse == "" {
		log.Fatalf("SNOWFLAKE_WAREHOUSE environment variable not set")
	}

	// Authenticate to Vault using Kubernetes service account
	vaultClient, err := vault.NewClient(&vault.Config{
		Address: vaultConfig.Address,
	})

	if err != nil {
		log.Fatalf("failed to create Vault client: %v", err)
	}

	tokenSecret, err := loginWithKubernetes(vaultClient, vaultConfig)
	if err != nil {
		log.Fatalf("failed to login to Vault: %v", err)
	}

	vaultClient.SetToken(tokenSecret.Auth.ClientToken)

	for {

		if err := verifyToken(vaultClient); err != nil {
			log.Printf("Vault token is invalid: %v", err)
			tokenSecret, err = loginWithKubernetes(vaultClient, vaultConfig)
			if err != nil {
				log.Fatalf("failed to login to Vault: %v", err)
			}
			vaultClient.SetToken(tokenSecret.Auth.ClientToken)
		}

		fmt.Printf("Vault token is valid for %s", tokenSecret.Auth.LeaseDuration)

		// Read Snowflake credentials from Vault
		snowflakeCredentials, err := readSnowflakeCredentials(vaultClient, vaultConfig.SnowflakeRole, vaultConfig.SecretsEnginePath)
		if err != nil {
			log.Fatalf("failed to read Snowflake credentials from Vault: %v", err)
		}

		// Output the credentials
		fmt.Printf("Snowflake User: %s\n", snowflakeCredentials.User)
		fmt.Printf("Snowflake Password: %s\n", snowflakeCredentials.Password)
		fmt.Printf("Snowflake Account: %s\n", snowflakeAccount)

		// Connect to Snowflake
		dsn := fmt.Sprintf("%s:%s@%s?warehouse=%s", snowflakeCredentials.User, snowflakeCredentials.Password, snowflakeAccount, snowflakeWarehouse)
		db, err := sql.Open("snowflake", dsn)
		if err != nil {
			log.Fatalf("failed to connect to Snowflake: %v", err)
		}

		// Query Snowflake
		rows, err := db.Query("SELECT C_NAME FROM SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.CUSTOMER LIMIT 1")
		if err != nil {
			log.Fatalf("failed to query Snowflake: %v", err)
		}

		// Print results
		for rows.Next() {
			var c_name string
			if err := rows.Scan(&c_name); err != nil {
				log.Fatalf("failed to scan row: %v", err)
			}
			fmt.Printf("Customer Name: %s\n", c_name)
		}

		db.Close()
		rows.Close()
		time.Sleep(10 * time.Second)
	}
}

func loginWithKubernetes(vaultClient *vault.Client, config VaultConfig) (*vault.Secret, error) {
	// Read the JWT from the Kubernetes service account
	jwt, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {

		return nil, fmt.Errorf("failed to read service account token: %w", err)
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
		return nil, fmt.Errorf("failed to login to Vault: %w", err)
	}

	return resp, nil
}

func verifyToken(vaultClient *vault.Client) error {
	sec, err := vaultClient.Auth().Token().LookupSelf()
	fmt.Println(sec.Renewable)
	return err
}

func readSnowflakeCredentials(vaultClient *vault.Client, role string, enginepath string) (*SnowflakeCredentials, error) {
	path := fmt.Sprintf("%s/creds/%s", enginepath, role)
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
