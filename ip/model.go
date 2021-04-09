package ip

// WhoisInfo struct with information on IP address range.
type WhoisInfo struct {
	Inetnum  string
	Netname  string
	Describe []string
	Country  string
	Status   string
	Created  string
	Updated  string
	Source   string
	Server   string
}
