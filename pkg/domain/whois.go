package domain

import (
    "context"
    "fmt"
    "sync"

    "github.com/domainr/whois"
)

func PerformWhoisLookup(domain string, wg *sync.WaitGroup, results chan<- string) {
    defer wg.Done()
    req, err := whois.NewRequest(domain)
    if err != nil {
        results <- fmt.Sprintf("Error creating Whois request for %s: %v", domain, err)
        return
    }
    res, err := whois.DefaultClient.Fetch(context.Background(), req)
    if err != nil {
        results <- fmt.Sprintf("Error fetching Whois data for %s: %v", domain, err)
        return
    }
    results <- fmt.Sprintf("Whois Data for %s: %s", domain, string(res.Body))
}