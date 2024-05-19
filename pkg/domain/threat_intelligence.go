package domain

import (
    "fmt"
    "io/ioutil"
    "net/http"
    "sync"
)

var apiKey string
func SetAPIKey(key string){
	apiKey = key
}

func CheckThreatIntelligence(domain string, wg *sync.WaitGroup, results chan<- string) {
    defer wg.Done()
	
    url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain)

    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Add("x-apikey", apiKey)

    res, err := http.DefaultClient.Do(req)
    if err != nil {
        results <- fmt.Sprintf("Error checking threat intelligence for %s: %v", domain, err)
        return
    }
    defer res.Body.Close()

    body, _ := ioutil.ReadAll(res.Body)
    results <- fmt.Sprintf("Threat Intelligence Data for %s: %s", domain, string(body))
}