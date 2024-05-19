package main

import (
	"fmt"
	"bufio"
	"log"
	"sync"
	"os"
	"github.com/jwhitt3r/twistythreat/pkg/domain"
	"github.com/jwhitt3r/twistythreat/pkg/utils"
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


	domains, err := domain.LoadDomains("sample_output.json")
	if err != nil {
		fmt.Println("Error loading domains:", err)
		return
	}

    var wg sync.WaitGroup
    results := make(chan domain.DomainStatus, len(domains)*3)

    for _, d := range domains {
        wg.Add(1)
        go domain.CheckThreatIntelligence(d.Domain, &wg, results)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

   // Create files to save the categorized results
   registeredFile, err := os.Create("registered.txt")
   if err != nil {
	   log.Fatalf("Error creating registered file: %v", err)
   }
   defer registeredFile.Close()
   registeredWriter := bufio.NewWriter(registeredFile)
   defer registeredWriter.Flush()

   unregisteredFile, err := os.Create("unregistered.txt")
   if err != nil {
	   log.Fatalf("Error creating unregistered file: %v", err)
   }
   defer unregisteredFile.Close()
   unregisteredWriter := bufio.NewWriter(unregisteredFile)
   defer unregisteredWriter.Flush()

   suspiciousFile, err := os.Create("suspicious.txt")
   if err != nil {
	   log.Fatalf("Error creating suspicious file: %v", err)
   }
   defer suspiciousFile.Close()
   suspiciousWriter := bufio.NewWriter(suspiciousFile)
   defer suspiciousWriter.Flush()

   condensedSuspiciousFile, err := os.Create("condensed_suspicious.txt")
   if err != nil {
	   log.Fatalf("Error creating condensed suspicious file: %v", err)
   }
   defer condensedSuspiciousFile.Close()
   condensedSuspiciousWriter := bufio.NewWriter(condensedSuspiciousFile)
   defer condensedSuspiciousWriter.Flush()

   // Process and categorize the results
   for result := range results {
	   fmt.Println(result.Domain, result.Status) // Optional: also print to console
	   var writer *bufio.Writer
	   switch result.Status {
	   case "registered":
		   writer = registeredWriter
	   case "unregistered":
		   writer = unregisteredWriter
	   case "suspicious":
		   writer = suspiciousWriter
		   condensedSuspiciousWriter.WriteString(fmt.Sprintf("Domain: %s\nVirusTotal Link: https://www.virustotal.com/gui/domain/%s\nDetermination: %s\n\n", result.Domain, result.Domain, result.Status))
	   }

	   _, err := writer.WriteString(fmt.Sprintf("Domain: %s\nStatus: %s\nData:\n%s\n\n", result.Domain, result.Status, result.WhoisData))
	   if err != nil {
		   log.Fatalf("Error writing to file: %v", err)
	   }
   }

   fmt.Println("Results categorized and saved to files.")
}