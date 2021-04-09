package domain

import (
	"github.com/yanmengfei/whois"
	"testing"
)

var document = `Domain Name: itmeng.top
Registry Domain ID: D20181008G10001G_77894760-top
Registrar WHOIS Server: whois.hichina.com/
Registrar URL: http://www.net.cn
Updated Date:
Creation Date: 2018-10-08T04:13:36Z
Registry Expiry Date: 2023-10-08T04:13:36Z
Registrar: Alibaba Cloud Computing Ltd. d/b/a HiChina (www.net.cn)
Registrar IANA ID: 1599
Registrar Abuse Contact Email: DomainAbuse@service.aliyun.com
Registrar Abuse Contact Phone: +86.95187
Domain Status: ok https://icann.org/epp#OK
Registry Registrant ID: REDACTED FOR PRIVACY
Registrant Name: REDACTED FOR PRIVACY
Registrant Organization: yan meng fei
Registrant Street:  REDACTED FOR PRIVACY
Registrant City: REDACTED FOR PRIVACY
Registrant State/Province: he nan
Registrant Postal Code: REDACTED FOR PRIVACY
Registrant Country: CN
Registrant Phone: REDACTED FOR PRIVACY
Registrant Phone Ext: REDACTED FOR PRIVACY
Registrant Fax: REDACTED FOR PRIVACY
Registrant Fax Ext: REDACTED FOR PRIVACY
Registrant Email: Please query the RDDS service of the Registrar of Record  identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Registry Admin ID: REDACTED FOR PRIVACY
Admin Name: REDACTED FOR PRIVACY
Admin Organization: REDACTED FOR PRIVACY
Admin Street:  REDACTED FOR PRIVACY
Admin City: REDACTED FOR PRIVACY
Admin State/Province: REDACTED FOR PRIVACY
Admin Postal Code: REDACTED FOR PRIVACY
Admin Country: REDACTED FOR PRIVACY
Admin Phone: REDACTED FOR PRIVACY
Admin Phone Ext: REDACTED FOR PRIVACY
Admin Fax: REDACTED FOR PRIVACY
Admin Fax Ext: REDACTED FOR PRIVACY
Admin Email: Please query the RDDS service of the Registrar of Record  identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Registry Tech ID: REDACTED FOR PRIVACY
Tech Name: REDACTED FOR PRIVACY
Tech Organization: REDACTED FOR PRIVACY
Tech Street:  REDACTED FOR PRIVACY
Tech City: REDACTED FOR PRIVACY
Tech State/Province: REDACTED FOR PRIVACY
Tech Postal Code: REDACTED FOR PRIVACY
Tech Country: REDACTED FOR PRIVACY
Tech Phone: REDACTED FOR PRIVACY
Tech Phone Ext: REDACTED FOR PRIVACY
Tech Fax: REDACTED FOR PRIVACY
Tech Fax Ext: REDACTED FOR PRIVACY
Tech Email: Please query the RDDS service of the Registrar of Record  identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.
Name Server: dns11.hichina.com
Name Server: dns12.hichina.com
DNSSEC: unsigned
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of WHOIS database: 2021-04-09T06:47:49Z <<<
`

func TestParser(t *testing.T) {
	if data, err := Parser(document); err == nil {
		t.Log("Domain:", data.Domain)
		t.Log("Server:", data.Server)
		t.Log("Created:", data.Created)
		t.Log("Updated:", data.Updated)
		t.Log("Expiry:", data.Expiry)
		t.Log("Status:", data.Status)
		t.Log("Dnssec:", data.Dnssec)
		t.Log("NameServer:", data.NameServer)
		t.Log("Administrative:", data.Administrative)
		t.Log("Registrant:", data.Registrant)
		t.Log("Registrar:", data.Registrar)
	} else {
		t.Error(err.Error())
	}
}

func TestQuery(t *testing.T) {
	if data, err := Query(&whois.QueryOptions{Key: "itmeng.top"}); err == nil {
		t.Log("Domain:", data.Domain)
		t.Log("Server:", data.Server)
		t.Log("Created:", data.Created)
		t.Log("Updated:", data.Updated)
		t.Log("Expiry:", data.Expiry)
		t.Log("Status:", data.Status)
		t.Log("Dnssec:", data.Dnssec)
		t.Log("NameServer:", data.NameServer)
		t.Log("Administrative:", data.Administrative)
		t.Log("Registrant:", data.Registrant)
		t.Log("Registrar:", data.Registrar)
	} else {
		t.Error(err.Error())
	}
}
