package domain

import (
	"errors"
	"github.com/likexian/gokit/assert"
	"github.com/likexian/gokit/xslice"
	"github.com/yanmengfei/whois"
	"regexp"
	"sort"
	"strings"
)

// Query 在线查询whois信息
func Query(options *whois.QueryOptions) (*WhoisInfo, error) {
	if options.Server == "" || options.Server == whois.IanaWhoisServer {
		options.Server = whois.IanaWhoisServer
		var block, err = whois.ConnectWhoisServer(options)
		if err != nil {
			return nil, err
		}
		if options.Server = whois.GetRefer(block); options.Server == "" {
			return nil, errors.New("invalid domain address: " + options.Key)
		}
	}
	var document, err = whois.ConnectWhoisServer(options)
	if err != nil {
		return nil, err
	}
	return Parser(document)
}

// Parser 解析主逻辑
func Parser(document string) (*WhoisInfo, error) {
	name, extension := searchDomain(document)
	if name == "" {
		return nil, errors.New("invalid domain whois document")
	}
	var data WhoisInfo
	whoisText, _ := prepare(document, extension)
	whoisLines := strings.Split(whoisText, "\n")
	for i := 0; i < len(whoisLines); i++ {
		line := strings.TrimSpace(whoisLines[i])
		if len(line) < 5 || !strings.Contains(line, ":") {
			continue
		}
		fChar := line[:1]
		if assert.IsContains([]string{"-", "*", "%", ">", ";"}, fChar) {
			continue
		}
		if line[len(line)-1:] == ":" {
			i += 1
			for ; i < len(whoisLines); i++ {
				thisLine := strings.TrimSpace(whoisLines[i])
				if strings.Contains(thisLine, ":") {
					break
				}
				line += thisLine + ","
			}
			line = strings.Trim(line, ",")
			i -= 1
		}

		lines := strings.SplitN(line, ":", 2)
		name := strings.TrimSpace(lines[0])
		value := strings.TrimSpace(lines[1])
		value = strings.TrimSpace(strings.Trim(value, ":"))

		if value == "" {
			continue
		}

		keyName := searchKeyName(name)
		switch keyName {

		case "domain_status":
			data.Status = append(data.Status, strings.Split(value, ",")...)
		case "domain_dnssec":
			if !data.Dnssec {
				data.Dnssec = isDNSSecEnabled(value)
			}
		case "whois_server":
			if data.Server == "" {
				data.Server = value
			}
		case "name_servers":
			data.NameServer = append(data.NameServer, strings.Split(value, ",")...)
		case "created_date":
			if data.Created == "" {
				data.Created = value
			}
		case "updated_date":
			if data.Updated == "" {
				data.Updated = value
			}
		case "expired_date":
			if data.Expiry == "" {
				data.Expiry = value
			}
		default:
			name = clearKeyName(name)
			if !strings.Contains(name, " ") {
				name += " name"
			}
			ns := strings.SplitN(name, " ", 2)
			name = strings.TrimSpace("registrant " + ns[1])
			if ns[0] == "registrar" || ns[0] == "registration" {
				parseContact(&data.Registrar, name, value)
			} else if ns[0] == "registrant" || ns[0] == "holder" {
				parseContact(&data.Registrant, name, value)
			} else if ns[0] == "admin" || ns[0] == "administrative" {
				parseContact(&data.Administrative, name, value)
			}
		}
	}
	data.NameServer = fixNameServers(data.NameServer)
	data.Status = fixDomainStatus(data.Status)
	data.NameServer = xslice.Unique(data.NameServer).([]string)
	data.Status = xslice.Unique(data.Status).([]string)
	return &data, nil
}

// parseContact do parse contact info
func parseContact(contact *Contact, name, value string) {
	switch searchKeyName(name) {
	case "registrant_name":
		contact.Name = value
	case "registrant_organization":
		contact.Organization = value
	case "registrant_street":
		if contact.Address == "" {
			contact.Address = value
		} else {
			contact.Address += ", " + value
		}
	case "registrant_phone":
		contact.Phone = value
	case "registrant_email":
		contact.Email = strings.ToLower(value)
	}
}

// isDNSSecEnabled returns if domain dnssec is enabled
func isDNSSecEnabled(data string) bool {
	switch strings.ToLower(data) {
	case "yes", "active", "signed", "signeddelegation":
		return true
	default:
		return false
	}
}

// clearKeyName returns cleared key name
func clearKeyName(key string) string {
	if strings.Contains(key, "(") {
		key = strings.Split(key, "(")[0]
	}
	key = strings.Replace(key, "-", " ", -1)
	key = strings.Replace(key, "_", " ", -1)
	key = strings.Replace(key, "/", " ", -1)
	key = strings.Replace(key, "\\", " ", -1)
	key = strings.Replace(key, "'", " ", -1)
	key = strings.Replace(key, ".", " ", -1)
	key = strings.TrimPrefix(key, "Registry ")
	key = strings.TrimPrefix(key, "Sponsoring ")
	key = strings.TrimSpace(key)
	key = strings.ToLower(key)
	return key
}

// searchDomain find domain from whois info
func searchDomain(text string) (string, string) {
	r := regexp.MustCompile(`(?i)\[?domain:?(\s*_?name)?]?[\s.]*:?\s*([^\s]+)\.([^.\s]{2,})`)
	m := r.FindStringSubmatch(text)
	if len(m) > 0 {
		return strings.ToLower(strings.TrimSpace(m[2])), strings.ToLower(strings.TrimSpace(m[3]))
	}

	r = regexp.MustCompile(`(?i)\[?domain:?(\s*_?name)?]?\s*:?\s*([^.\s]{2,})\n`)
	m = r.FindStringSubmatch(text)
	if len(m) > 0 {
		return strings.ToLower(strings.TrimSpace(m[2])), ""
	}

	return "", ""
}

// searchKeyName returns the mapper value by key
func searchKeyName(key string) string {
	key = clearKeyName(key)
	if v, ok := keyRule[key]; ok {
		return v
	}
	return ""
}

// fixDomainStatus returns fixed domain status
func fixDomainStatus(status []string) []string {
	for k, v := range status {
		names := strings.Split(strings.TrimSpace(v), " ")
		status[k] = strings.ToLower(names[0])
	}
	return status
}

// fixNameServers returns fixed name servers
func fixNameServers(servers []string) []string {
	for k, v := range servers {
		names := strings.Split(strings.TrimSpace(v), " ")
		servers[k] = strings.ToLower(strings.Trim(names[0], "."))
	}
	return servers
}

// Keys returns all keys of map by sort
func keys(m map[string]string) []string {
	var r []string
	for k := range m {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
