package ip

// sourcePattern 匹配whois来源
const sourcePattern = `(?i)source:\W+(APNIC|AFRINIC|ARIN|RIPE|LACNIC)`

// parserRule 来源解析器map
var parserRule = map[string]func(line string, whois *WhoisInfo){
	"ARIN":    parseARIN,
	"RIPE":    parseRIPE,
	"APNIC":   parseAPNIC,
	"LACNIC":  parseLACNIC,
	"AFRINIC": parseAFRINIC,
}

// serverMap 来源服务器map
var serverRule = map[string]string{
	"ARIN":    "whois.arin.net",
	"RIPE":    "whois.ripe.net",
	"APNIC":   "whois.apnic.net",
	"LACNIC":  "whois.lacnic.net",
	"AFRINIC": "whois.afrinic.net",
}
