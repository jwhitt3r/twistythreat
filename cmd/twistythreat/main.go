package main

import (
	"fmt"
	"sync"
	"github.com/jwhitt3r/twistythreat/pkg/domains"
	"github.com/jwhitt3r/twistythreat/pkg/utils"
    "github.com/joho/godotenv"
)

func main() {

    // Load environment variables from .env file
    utils.LoadEnv()

    // Retrieve the API key from environment variables
    apiKey := utils.GetEnv("VIRUSTOTAL_API_KEY")
    if apiKey == "" {
        log.Fatalf("VIRUSTOTAL_API_KEY not set in .env file")
    }

    // Pass the API key to the relevant functions or packages
    domain.SetAPIKey(apiKey)


	domains, err := domain.LoadDomains("dnstwist_output.json")
	if err != nil {
		fmt.Println("Error loading domains:", err)
		return
	}

	var wg sync.WaitGroup
	results := make(chan string, len(domains) * 3)

	for _, domain := range domains {
		wg.Add(1)
		go domain.PerformWhoIsLookUp(d.Domain, &wg, results)
		wg.Add(1)
		go domain.CheckDNSRecords(d.Domain, &wg, results)
		wg.Add(1)
		go domain.CheckThreatIntelligence(d.Domain, &wg, results)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		fmt.Println(results)
	}
}