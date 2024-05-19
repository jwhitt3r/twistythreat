// Package main is the entry point for the twistythreat application.
// It loads configuration, retrieves domain information from a file,
// performs threat intelligence checks using VirusTotal, and categorizes
// domains based on their status. The application then sends the results
// to an HTTP endpoint.
//
// Example usage:
//
//  1. Create a .env file with your environment variables:
//     VIRUSTOTAL_API_KEY=your_api_key_here
//     HTTP_ENDPOINT=https://www.example.com
//
//  2. Create a domains.txt file with the list of domains to analyze, one per line:
//     example1.com
//     example2.org
//
// 3. Create a Dockerfile to set up the environment and build the Go application.
// 4. Create a docker-compose.yml file to define the services and configurations.
//
// Dockerfile:
//
//	# Use an official Python runtime as a parent image
//	FROM python:3.12-alpine
//
//	# Install Go and other dependencies
//	RUN apk add --no-cache go git build-base
//
//	# Install dnstwist
//	RUN pip install dnstwist
//
//	# Set the working directory inside the container
//	WORKDIR /app
//
//	# Clone the GitHub repository
//	RUN git clone https://github.com/your-username/your-repo.git .
//
//	# Set up the Go environment and install dependencies
//	RUN go mod download
//
//	# Build the Go application
//	RUN go build -o twistythreat cmd/twistythreat/main.go
//
//	# Run the application
//	CMD ["./twistythreat"]
//
// docker-compose.yml:
//
//	services:
//	  twistythreat:
//	    build: .
//	    env_file:
//	      - .env
//	    volumes:
//	      - ./output:/app/output
//	    command: ["./twistythreat"]
//
// To build and run the application using Docker Compose:
//
//  1. Build and run the Docker container:
//     docker-compose up --build
//
//  2. The application will read the domains from domains.txt, perform the analysis,
//     categorize the results, save them to files, and send the condensed suspicious
//     results to the specified HTTP endpoint.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"

	"github.com/jwhitt3r/twistythreat/pkg/domain"
	"github.com/jwhitt3r/twistythreat/pkg/utils"
)

// runDnstwist runs dnstwist for the given domain and captures the output in memory.
func runDnstwist(d string) ([]domain.Domain, error) {
	cmd := exec.Command("dnstwist", "-f", "json", d)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error running dnstwist for domain %s: %v", d, err)
	}

	var dnstwistOutput []domain.Domain
	err = json.Unmarshal(output, &dnstwistOutput)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling dnstwist output for domain %s: %v", d, err)
	}

	return dnstwistOutput, nil
}

// sendFileToHTTPEndpoint reads the content of the given file and sends it to the specified HTTP endpoint.
func sendFileToHTTPEndpoint(filename string, url string) error {
	fileContent, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file %s: %v", filename, err)
	}

	resp, err := http.Post(url, "text/plain", bytes.NewBuffer(fileContent))
	if err != nil {
		return fmt.Errorf("error sending HTTP POST request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

// main is the entry point for the twistthreat application.
// It loads configuration, retrieves domain information from a JSON file,
// performs threat intelligence checks using VirusTotal, and categorizes
// domains based on their status.
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

	file, err := os.Open("domains.txt")
	if err != nil {
		log.Fatalf("Error opening domains file: %v", err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading domains file: %v", err)
	}

	var wg sync.WaitGroup
	results := make(chan domain.DomainStatus, len(domains))

	for _, d := range domains {
		// Run dnstwist for each domain and capture the output
		dnstwistOutput, err := runDnstwist(d)
		if err != nil {
			log.Printf("Error running dnstwist for domain %s: %v", d, err)
			continue
		}

		// Perform threat intelligence checks on each dnstwist result
		for _, domainEntry := range dnstwistOutput {
			wg.Add(1)
			go domain.CheckThreatIntelligence(domainEntry.Domain, &wg, results)
		}
	}

	// Close the results channel once all routines have returned
	go func() {
		wg.Wait()
		close(results)
	}()

	// Create files to save the categorised results
	registeredFile, err := os.Create("output/registered.txt")
	if err != nil {
		log.Fatalf("Error creating registered file: %v", err)
	}
	defer registeredFile.Close()
	registeredWriter := bufio.NewWriter(registeredFile)
	defer registeredWriter.Flush()

	unregisteredFile, err := os.Create("output/unregistered.txt")
	if err != nil {
		log.Fatalf("Error creating unregistered file: %v", err)
	}
	defer unregisteredFile.Close()
	unregisteredWriter := bufio.NewWriter(unregisteredFile)
	defer unregisteredWriter.Flush()

	suspiciousFile, err := os.Create("output/suspicious.txt")
	if err != nil {
		log.Fatalf("Error creating suspicious file: %v", err)
	}
	defer suspiciousFile.Close()
	suspiciousWriter := bufio.NewWriter(suspiciousFile)
	defer suspiciousWriter.Flush()

	condensedSuspiciousFile, err := os.Create("output/condensed_suspicious.txt")
	if err != nil {
		log.Fatalf("Error creating condensed suspicious file: %v", err)
	}
	defer condensedSuspiciousFile.Close()
	condensedSuspiciousWriter := bufio.NewWriter(condensedSuspiciousFile)
	defer condensedSuspiciousWriter.Flush()

	// Process the results  write content to Writers and associating files
	for result := range results {
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

		// Write the data to the associating file based on the domains results
		_, err := writer.WriteString(fmt.Sprintf("Domain: %s\nStatus: %s\nData:\n%s\n\n", result.Domain, result.Status, result.AnalysisData))
		if err != nil {
			log.Fatalf("Error writing to file: %v", err)
		}
	}

	// Flush the writers
	if err := registeredWriter.Flush(); err != nil {
		log.Fatalf("Error flushing registeredWriter: %v", err)
	}
	if err := unregisteredWriter.Flush(); err != nil {
		log.Fatalf("Error flushing unregisteredWriter: %v", err)
	}
	if err := suspiciousWriter.Flush(); err != nil {
		log.Fatalf("Error flushing suspiciousWriter: %v", err)
	}
	if err := condensedSuspiciousWriter.Flush(); err != nil {
		log.Fatalf("Error flushing condensedSuspiciousWriter: %v", err)
	}

	// Send the condensed suspicious file to the HTTP endpoint set in the .env
	httpEndpoint := utils.GetEnv("HTTP_ENDPOINT")
	if err := sendFileToHTTPEndpoint("condensed_suspicious.txt", httpEndpoint); err != nil {
		log.Fatalf("Error sending condensed suspicious file to HTTP endpoint: %v", err)
	}

	fmt.Println("Results categorised and saved to files.")
}
