package domain

import (
    "encoding/json"
    "io/ioutil"
    "os"
)

type Domain struct {
    Fuzzer  string   `json:"fuzzer"`
    Domain  string   `json:"domain"`
    DNS_A   []string `json:"dns_a,omitempty"`
    DNS_AAAA []string `json:"dns_aaaa,omitempty"`
}

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
