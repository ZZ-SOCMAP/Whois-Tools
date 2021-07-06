package ip

import "sync"

// WhoisInfo struct with information on IP address range.
type WhoisInfo struct {
	Inetnum  string   `json:"inetnum"`
	Netname  string   `json:"netname"`
	Describe []string `json:"describe"`
	Country  string   `json:"country"`
	Status   string   `json:"status"`
	Created  string   `json:"created"`
	Updated  string   `json:"updated"`
	Source   string   `json:"source"`
	Server   string   `json:"server"`
}

var whoispool = sync.Pool{New: func() interface{} { return new(WhoisInfo) }}

func NewWhoisInfo(source, server string) *WhoisInfo {
	data := whoispool.Get().(*WhoisInfo)
	data.Source = source
	data.Server = server
	return data
}

func PutWhoisInfo(data *WhoisInfo) {
	data.Inetnum = ""
	data.Netname = ""
	data.Describe = []string{}
	data.Country = ""
	data.Status = ""
	data.Created = ""
	data.Updated = ""
	data.Source = ""
	data.Server = ""
	whoispool.Put(data)
}
