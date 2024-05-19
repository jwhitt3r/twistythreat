// pkg/domain/threat_intelligence.go
package domain

import (
    "fmt"
    "io/ioutil"
    "net/http"
    "sync"
	"strings"
)

var apiKey string

// SetAPIKey sets the API key for threat intelligence checks
func SetAPIKey(key string) {
    apiKey = key
}

func CheckThreatIntelligence(domain string, wg *sync.WaitGroup, results chan<- DomainStatus) {
    defer wg.Done()
    url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain)

    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Add("x-apikey", apiKey)

    res, err := http.DefaultClient.Do(req)
    if err != nil {
        results <- DomainStatus{Domain: domain, Status: "error", WhoisData: fmt.Sprintf("Error checking threat intelligence: %v", err)}
        return
    }
    defer res.Body.Close()

    body, _ := ioutil.ReadAll(res.Body)
    bodyStr := string(body)

    // Check for suspicious indicators in the response
    status := "registered"
    if strings.Contains(strings.ToLower(bodyStr), "malicious") || strings.Contains(strings.ToLower(bodyStr), "phishing") {
        status = "suspicious"
    } else if strings.Contains(strings.ToLower(bodyStr), "not found") || strings.Contains(strings.ToLower(bodyStr), "no match") {
        status = "unregistered"
    }

    results <- DomainStatus{Domain: domain, Status: status, WhoisData: bodyStr}
}
