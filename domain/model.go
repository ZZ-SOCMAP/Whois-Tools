package domain

type WhoisInfo struct {
	Domain     string
	Server     string
	Created    string
	Updated    string
	Expiry     string
	Status     []string
	Dnssec     bool
	NameServer []string
	Administrative Contact
	Registrar      Contact
	Registrant     Contact
}

type Contact struct {
	Organization string
	Name         string
	Address      string
	Email        string
	Phone        string
}
