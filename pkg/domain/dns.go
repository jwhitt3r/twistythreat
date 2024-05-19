package domain

import (
    "fmt"
    "sync"

    "github.com/miekg/dns"
)

func CheckDNSRecords(domain string, wg *sync.WaitGroup, results chan<- string) {
    defer wg.Done()
    var msg dns.Msg
    msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
    in, err := dns.Exchange(&msg, "8.8.8.8:53")
    if err != nil {
        results <- fmt.Sprintf("Error checking DNS records for %s: %v", domain, err)
        return
    }
    for _, ans := range in.Answer {
        if a, ok := ans.(*dns.A); ok {
            results <- fmt.Sprintf("A record for %s: %s", domain, a.A)
        }
    }
}