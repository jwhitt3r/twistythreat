// pkg/domain/dns.go
package domain

import (
    "fmt"
    "sync"

    "github.com/miekg/dns"
)

func CheckDNSRecords(domain string, wg *sync.WaitGroup, results chan<- DomainStatus) {
    defer wg.Done()

    var msg dns.Msg
    msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
    in, err := dns.Exchange(&msg, "8.8.8.8:53")
    if err != nil {
        results <- DomainStatus{Domain: domain, Status: "error", WhoisData: fmt.Sprintf("Error checking DNS records: %v", err)}
        return
    }

    for _, ans := range in.Answer {
        if a, ok := ans.(*dns.A); ok {
            results <- DomainStatus{Domain: domain, Status: "registered", WhoisData: fmt.Sprintf("A record for %s: %s", domain, a.A)}
            return
        }
    }
    results <- DomainStatus{Domain: domain, Status: "unregistered", WhoisData: "No A records found"}
}
