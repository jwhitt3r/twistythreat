// Package domain implements utility for checking domains generated
// by DNSTwist against virustotal.

// pkg/domain/threat_intelligence.go
// provides functionality to check each domain against VirusTotal
// and determines if they are registered, suspicious, or unregistered.
// If the body of the VirusTotal description contains malicious or phishing
// it is determined as suspicious.
package domain

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Set the VIRUSTOTAL_API_KEY
var apiKey string

// SetAPIKey sets the API key for threat intelligence checks
func SetAPIKey(key string) {
	apiKey = key
}

// CheckThreatIntelligence performs a VirusTotal lookup for a domain. The result of the check
// is categorised as either registered, suspicious, unregistered based on the VirusTotal data
// received. The results are then sent to the channel results.
// Example usage:
//
//	var wg sync.WaitGroup
//	results := make(chan domain.DomainStatus, 1)
//	domain.CheckThreatIntelligence("example.com", &wg, results)
//	wg.Wait()
//	close(results)
//
//	for result := range results {
//	    fmt.Println(result.Domain, result.Status)
//	}
//
// Parameters:
// - domain: The domain name to be analyzed.
// - wg: A wait group to synchronize the go routines.
// - results: A channel to send the results of the analysis.
func CheckThreatIntelligence(domain string, wg *sync.WaitGroup, results chan<- DomainStatus) {
	defer wg.Done()
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("x-apikey", apiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		results <- DomainStatus{Domain: domain, Status: "error", AnalysisData: fmt.Sprintf("Error checking threat intelligence: %v", err)}
		return
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	bodyStr := string(body)

	// Check for indicators to determine if the domain is suspicious or unregistered, if nothing of those are met,
	//all domains will be categorised as registered
	status := "registered"
	if strings.Contains(strings.ToLower(bodyStr), "malicious") || strings.Contains(strings.ToLower(bodyStr), "phishing") {
		status = "suspicious"
	} else if strings.Contains(strings.ToLower(bodyStr), "not found") || strings.Contains(strings.ToLower(bodyStr), "no match") {
		status = "unregistered"
	}

	results <- DomainStatus{Domain: domain, Status: status, AnalysisData: bodyStr}
}
