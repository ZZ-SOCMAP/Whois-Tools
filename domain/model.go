package domain

import "sync"

type WhoisInfo struct {
	Domain         string   `json:"domain"`
	Server         string   `json:"server"`
	Created        string   `json:"created"`
	Updated        string   `json:"updated"`
	Expiry         string   `json:"expiry"`
	Status         []string `json:"status"`
	Dnssec         bool     `json:"dnssec"`
	NameServer     []string `json:"name_server"`
	Administrative Contact  `json:"administrative"`
	Registrar      Contact  `json:"registrar"`
	Registrant     Contact  `json:"registrant"`
}

type Contact struct {
	Organization string `json:"organization"`
	Name         string `json:"name"`
	Address      string `json:"address"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
}

var whoispool = sync.Pool{New: func() interface{} { return new(WhoisInfo) }}

func NewWhoisInfo() *WhoisInfo {
	return whoispool.Get().(*WhoisInfo)
}

func PutWhoisInfo(data *WhoisInfo) {
	data.Domain = ""
	data.Server = ""
	data.Created = ""
	data.Updated = ""
	data.Expiry = ""
	data.Status = []string{}
	data.Dnssec = false
	data.NameServer = []string{}
	data.Administrative = Contact{}
	data.Registrar = Contact{}
	data.Registrant = Contact{}
	whoispool.Put(data)
}
