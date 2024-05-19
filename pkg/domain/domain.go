// Package domain implements utility for checking domains generated
// by DNSTwist against virustotal.

// pkg/domain/domain.go
// provides the Domain shape provided by DNSTwist
// the DomainStatus post filtered from VirusTotal
// and a utility function for loading the domains
// from DNSTwists JSON file.
package domain

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// Domain defines the shape of the DNSTwist record
type Domain struct {
	// Defines the fuzzer that was used to determine the twisted FQDN
	Fuzzer string `json:"fuzzer"`
	// The FQDN that was generated
	Domain string `json:"domain"`
	// Associated A records that are attached to the FQDN
	DNS_A []string `json:"dns_a,omitempty"`
	// Associated AAAA records that are attached to the FQDN
	DNS_AAAA []string `json:"dns_aaaa,omitempty"`
}

// DomainStatus represents the status of a domain after analysis. It includes
// the domain name, its determined status (e.g., registered, unregistered, suspicious),
// and the threat intelligence data associated with it.
type DomainStatus struct {
	// FQDN that is being analysed
	Domain string
	// Status is determined on the post analysis of the VirusTotal check.
	// Its value can either:
	// - "registered": The domain is currently registered.
	// - "unregistered": The domain is not registered.
	// - "suspicious": The domain has been flagged by threat intelligence services
	Status string
	// AnalysisData contains the data retrieved from VirusTotal or any other
	// threat intelligence services used for the domain analysis.
	AnalysisData string
}

// Load the DNSTwist data from a JSON file and unmarshal it into an array of domains
func LoadDomains(filename string) ([]Domain, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	byteValue, _ := ioutil.ReadAll(file)
	var domains []Domain
	json.Unmarshal(byteValue, &domains)

	return domains, nil
}
