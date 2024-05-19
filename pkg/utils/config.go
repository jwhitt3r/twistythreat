// Package utils provides utility functions to Load environment variables
// to safely interact with external services
package utils

import (
	"github.com/joho/godotenv"
	"log"
	"os"
)

// LoadEnv loads environment variables from a .env file
func LoadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

// GetEnv retrieves the value of the environment variable named by the key.
// It returns the value, which will be empty if the variable is not present.
func GetEnv(key string) string {
	return os.Getenv(key)
}
