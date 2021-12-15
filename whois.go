package whois

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

const (
	IanaWhoisServer  = "whois.iana.org"
	DefaultWhoisPort = "43"
)

type QueryOptions struct {
	Key    string
	Server string
}

// ConnectWhoisServer get document from whois server
func ConnectWhoisServer(options *QueryOptions) (document string, err error) {
	if options.Server == "whois.arin.net" {
		options.Key = "n + " + options.Key // 域名: 加拿大、北美地区
	}
	connect, err := net.DialTimeout("tcp", net.JoinHostPort(options.Server, DefaultWhoisPort), time.Second*100)
	if err != nil {
		return document, fmt.Errorf("core: connect to core server failed: %v", err)
	}
	_ = connect.SetWriteDeadline(time.Now().Add(time.Second * 100))
	if _, err = connect.Write([]byte(options.Key + "\r\n")); err != nil {
		return document, fmt.Errorf("core: send to core server failed: %v", err)
	}
	_ = connect.SetReadDeadline(time.Now().Add(time.Second * 100))
	buffer, err := ioutil.ReadAll(connect)
	if err != nil {
		return document, fmt.Errorf("core: read from core server failed: %v", err)
	}
	_ = connect.Close()
	return string(buffer[:]), err
}

// GetRefer get whois server from document
func GetRefer(document string) (refer string) {
	tokens := []string{"whois: ", "Registrar WHOIS Server: ", "refer: "}
	for i := 0; i < 2; i++ {
		start := strings.Index(document, tokens[i])
		if start != -1 {
			start += len(tokens[i])
			refer = strings.TrimSpace(document[start : start+strings.Index(document[start:], "\n")])
		}
	}
	return refer
}
