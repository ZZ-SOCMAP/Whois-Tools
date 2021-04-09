package ip

import (
	"bufio"
	"errors"
	"github.com/yanmengfei/whois"
	"regexp"
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
			return nil, errors.New("invalid IP address: " + options.Key)
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
	var rx, _ = regexp.Compile(sourcePattern)
	var s = rx.FindAllStringSubmatch(document, -1)
	if len(s) >= 1 {
		var source = s[0][1]
		var data = WhoisInfo{Source: source, Server: serverRule[source]}
		var parser = parserRule[source]
		var sc = bufio.NewScanner(strings.NewReader(document))
		for sc.Scan() {
			parser(sc.Text(), &data)
		}
		return &data, nil
	}
	return nil, errors.New("invalid ip whois document")
}

// parseAPNIC 解析apnic
func parseAPNIC(line string, result *WhoisInfo) {
	var value string
	if strings.HasPrefix(line, "inetnum") {
		value = parseLine(line, 8)
		if value != "" {
			result.Inetnum = value
		}
	} else if strings.HasPrefix(line, "netname") {
		result.Netname = parseLine(line, 8)
	} else if strings.HasPrefix(line, "descr") {
		value = parseLine(line, 6)
		if value != "" {
			result.Describe = append(result.Describe, value)
		}
	} else if strings.HasPrefix(line, "country") {
		value = parseLine(line, 8)
		if result.Country == "" && value != "" {
			result.Country = value
		}
	} else if strings.HasPrefix(line, "status") {
		value = parseLine(line, 7)
		if result.Status == "" && value != "" {
			result.Status = value
		}
	} else if strings.HasPrefix(line, "created") {
		value = parseLine(line, 8)
		if result.Created == "" && value != "" {
			result.Created = value
		}
	} else if strings.HasPrefix(line, "last-modified") {
		value = parseLine(line, 14)
		if result.Updated == "" && value != "" {
			result.Updated = value
		}
	}
}

// parseRIPE 解析ripe
func parseRIPE(line string, result *WhoisInfo) {
	var value string
	if strings.HasPrefix(line, "inetnum") {
		value = parseLine(line, 8)
		if value != "" {
			result.Inetnum = value
		}
	} else if strings.HasPrefix(line, "netname") {
		result.Netname = parseLine(line, 8)
	} else if strings.HasPrefix(line, "descr") {
		value = parseLine(line, 6)
		if value != "" {
			result.Describe = append(result.Describe, value)
		}
	} else if strings.HasPrefix(line, "country") {
		value = parseLine(line, 8)
		if result.Country == "" && value != "" {
			result.Country = value
		}
	} else if strings.HasPrefix(line, "status") {
		value = parseLine(line, 7)
		if result.Status == "" && value != "" {
			result.Status = value
		}
	} else if strings.HasPrefix(line, "created") {
		value = parseLine(line, 8)
		if result.Created == "" && value != "" {
			result.Created = value
		}
	} else if strings.HasPrefix(line, "last-modified") {
		value = parseLine(line, 14)
		if result.Updated == "" && value != "" {
			result.Updated = value
		}
	}

}

// parseLACNIC 解析lacnic
func parseLACNIC(line string, result *WhoisInfo) {
	var value string
	if strings.HasPrefix(line, "inetnum") {
		value = parseLine(line, 8)
		if value != "" {
			result.Inetnum = value
		}
	} else if strings.HasPrefix(line, "owner") {
		value = parseLine(line, 6)
		if value != "" {
			result.Describe = append(result.Describe, value)
		}
	} else if strings.HasPrefix(line, "country") {
		value = parseLine(line, 8)
		if result.Country == "" && value != "" {
			result.Country = value
		}
	} else if strings.HasPrefix(line, "created") {
		value = parseLine(line, 8)
		if result.Created == "" && value != "" {
			result.Created = value
		}
	} else if strings.HasPrefix(line, "changed") {
		value = parseLine(line, 8)
		if result.Updated == "" && value != "" {
			result.Updated = value
		}
	}
}

// parseARIN 解析arin
func parseARIN(line string, result *WhoisInfo) {
	var value string
	if strings.HasPrefix(line, "route") {
		value = parseLine(line, 6)
		if value != "" {
			result.Inetnum = value
		}
	} else if strings.HasPrefix(line, "descr") {
		value = parseLine(line, 6)
		if value != "" {
			result.Describe = append(result.Describe, value)
		}
	} else if strings.HasPrefix(line, "country") {
		value = parseLine(line, 8)
		if result.Country == "" && value != "" {
			result.Country = value
		}
	} else if strings.HasPrefix(line, "status") {
		value = parseLine(line, 7)
		if result.Status == "" && value != "" {
			result.Status = value
		}
	} else if strings.HasPrefix(line, "created") {
		value = parseLine(line, 8)
		if result.Created == "" && value != "" {
			result.Created = value
		}
	} else if strings.HasPrefix(line, "last-modified") {
		value = parseLine(line, 14)
		if result.Updated == "" && value != "" {
			result.Updated = value
		}
	}
}

// parseAFRINIC 解析afrinic
func parseAFRINIC(line string, result *WhoisInfo) {
	var value string
	if strings.HasPrefix(line, "inetnum") {
		value = parseLine(line, 8)
		if value != "" {
			result.Inetnum = value
		}
	} else if strings.HasPrefix(line, "netname") {
		result.Netname = parseLine(line, 8)
	} else if strings.HasPrefix(line, "descr") {
		value = parseLine(line, 6)
		if value != "" {
			result.Describe = append(result.Describe, value)
		}
	} else if strings.HasPrefix(line, "country") {
		value = parseLine(line, 8)
		if result.Country == "" && value != "" {
			result.Country = value
		}
	} else if strings.HasPrefix(line, "created") {
		value = parseLine(line, 8)
		if result.Created == "" && value != "" {
			result.Created = value
		}
	}
}

// parseLine 从行信息截取value
func parseLine(line string, index int) string {
	if len(line) < index {
		return ""
	}
	return strings.TrimSpace(line[index:])
}
