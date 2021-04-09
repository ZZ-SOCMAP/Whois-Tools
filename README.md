# whois

whois query and parse tools, support `domain` and `ipv4` and `ipv6`.

# install

```shell
go get github.com/yanmengfei/whois
```

# example

```go
package main

import (
	"fmt"
	"github.com/yanmengfei/whois"
	"github.com/yanmengfei/whois/domain"
	"github.com/yanmengfei/whois/ip"
)

func main() {
	// query ip whois
	var ipKey = "114.114.114.114"
	if ipWhois, err := ip.Query(&whois.QueryOptions{Key: ipKey}); err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("=== Query ip whois for", ipKey)
		fmt.Println("Inetnum:", ipWhois.Inetnum)
		fmt.Println("Server:", ipWhois.Server)
		fmt.Println("Source:", ipWhois.Source)
		fmt.Println("Country:", ipWhois.Country)
		fmt.Println("Created:", ipWhois.Created)
		fmt.Println("Updated:", ipWhois.Updated)
	}

	// query domain whois
	var domainKey = "itmeng.top"
	if domainWhois, err := domain.Query(&whois.QueryOptions{Key: domainKey}); err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("=== Query domain whois for", domainKey)
		fmt.Println("Server:", domainWhois.Server)
		fmt.Println("Created:", domainWhois.Created)
		fmt.Println("Updated:", domainWhois.Updated)
		fmt.Println("Expiry:", domainWhois.Expiry)
		fmt.Println("Status:", domainWhois.Status)
		fmt.Println("Dnssec:", domainWhois.Dnssec)
		fmt.Println("NameServer:", domainWhois.NameServer)
		fmt.Println("Administrative:", domainWhois.Administrative)
		fmt.Println("Registrant:", domainWhois.Registrant)
		fmt.Println("Registrar:", domainWhois.Registrar)
	}

}
```