package domain

import (
    "fmt"
    "sync"
	"strings"
    "github.com/domainr/whois"
)



// PerformWhoisLookup performs a Whois lookup for the given domain and sends the result to the results channel.
func PerformWhoisLookup(domain string, wg *sync.WaitGroup, results chan<- DomainStatus) {
    defer wg.Done()

    // Create a Whois request
	req, err := whois.NewRequest(domain)
    if err != nil {
        results <- DomainStatus{Domain: domain, Status: "error", WhoisData: fmt.Sprintf("Error creating Whois request: %v", err)}
        return
    }

    // Fetch the Whois data
    res, err := whois.DefaultClient.Fetch(req)
    if err != nil {
        results <- DomainStatus{Domain: domain, Status: "unregistered", WhoisData: fmt.Sprintf("Error fetching Whois data: %v", err)}
        return
    }

    // Clean the result by removing the notice and terms of use
    cleanedResult := cleanWhoisResult(res.String())

     // Determine the status based on the Whois data
	 status := categorizeDomain(cleanedResult)

	 // Output the result
	 results <- DomainStatus{Domain: domain, Status: status, WhoisData: cleanedResult}
 
}


// categorizeDomain categorizes the domain based on the Whois data.
func categorizeDomain(whoisData string) string {
    if strings.Contains(strings.ToLower(whoisData), "no match for") || strings.Contains(strings.ToLower(whoisData), "not found") {
        return "unregistered"
    }
    if strings.Contains(strings.ToLower(whoisData), "fraud") || strings.Contains(strings.ToLower(whoisData), "phishing") {
        return "suspicious"
    }
    return "registered"
}

// cleanWhoisResult removes the notice and terms of use from the Whois result.
func cleanWhoisResult(whoisData string) string {
    // Identify common patterns to remove (these can vary depending on the Whois server)
    termsOfUseMarkers := []string{
        "terms of use",
        "terms and conditions",
        "notice",
		"notice:",
        "by submitting a query",
        "the registry database contains only",
        "for more information on whois status codes",
        "notice: the expiration date displayed in this record",
		"For more information on Whois status codes, please visit https://icann.org/epp",
        "NOTICE: The expiration date displayed in this record",
        "Terms of Use",
        "terms and conditions",
        "By submitting a query",
        "The Registry database contains only",
	}

    lowerData := strings.ToLower(whoisData)
    for _, marker := range termsOfUseMarkers {
        if idx := strings.Index(lowerData, marker); idx != -1 {
            return whoisData[:idx]
        }
    }
    return whoisData
}