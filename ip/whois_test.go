package ip

import (
	"github.com/yanmengfei/whois"
	"testing"
)

var docs = []string{`% [whois.apnic.net]
% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html

% Information related to '39.96.0.0 - 39.108.255.255'

% Abuse contact for '39.96.0.0 - 39.108.255.255' is 'ipas@cnnic.cn'

inetnum:        39.96.0.0 - 39.108.255.255
netname:        ALISOFT
descr:          Aliyun Computing Co., LTD
descr:          5F, Builing D, the West Lake International Plaza of S&T
descr:          No.391 Wen'er Road, Hangzhou, Zhejiang, China, 310099
country:        CN
admin-c:        ZM1015-AP
tech-c:         ZM877-AP
tech-c:         ZM876-AP
tech-c:         ZM875-AP
mnt-by:         MAINT-CNNIC-AP
mnt-irt:        IRT-CNNIC-CN
status:         ALLOCATED PORTABLE
last-modified:  2015-02-10T00:05:56Z
source:         APNIC`,
	`inetnum:        105.237.168.192 - 105.237.168.255
netname:        MTNBS-CUST-105-237-168-192-26
descr:          MTN Business SA Pool Region 7300
country:        ZA
admin-c:        MBIP-AFRINIC
tech-c:         MBIP-AFRINIC
status:         ASSIGNED PA
mnt-by:         MTNBUSINESS-MNT
changed:        ***@mtnbusiness.co.za 20130615
remarks:        report abuse to abuse@mtnbusiness.co.za
source:         AFRINIC`,
	`route:          8.18.161.0/24
origin:         AS16676
descr:          209 W. Jackson Blvd.
                Suite 200
                Chicago IL 60606
                United States
admin-c:        EP352-ARIN
tech-c:         EP352-ARIN
tech-c:         SYSTE577-ARIN
mnt-by:         MNT-BARCHA
created:        2021-02-24T15:29:54Z
last-modified:  2021-02-24T15:29:54Z
source:         ARIN`,
	`inetnum:        194.206.161.47 - 194.206.161.47
netname:        FR-RPN-HOLDING
descr:          RPN Holding
descr:          ZI nord BP 7132
descr:          01007
descr:          Bourg en Bresse
country:        FR
admin-c:        DUMY-RIPE
tech-c:         DUMY-RIPE
status:         ASSIGNED PA
mnt-by:         OLEANE-NOC
created:        1970-01-01T00:00:00Z
last-modified:  2001-09-21T22:08:01Z
source:         RIPE
remarks:        ****************************
remarks:        * THIS OBJECT IS MODIFIED
remarks:        * Please note that all data that is generally regarded as personal
remarks:        * data has been removed from this object.
remarks:        * To view the original object, please query the RIPE Database at:
remarks:        * http://www.ripe.net/whois
remarks:        ****************************`,
}

var sources = []string{"APNIC", "AFRINIC", "ARIN", "RIPE"}

// TestParser 测试各个RIR机构whois解析
func TestParser(t *testing.T) {
	for i := 0; i < len(docs); i++ {
		if data, err := Parser(docs[i]); err == nil {
			t.Log("Inetnum:", data.Inetnum)
			t.Log("Server:", data.Server)
			t.Log("Source:", data.Source)
			t.Log("Country:", data.Country)
			t.Log("Created:", data.Created)
			t.Log("Updated:", data.Updated)
			t.Log("========================")
		} else {
			t.Errorf("parser error(%s): %s", sources[i], err.Error())
		}
	}
}

// TestQuery 测试各个RIR机构whois在线查询
func TestQuery(t *testing.T) {
	var ips = []string{"39.96.0.1", "105.237.168.193", "8.18.161.1", "194.206.161.48"}
	for i := 0; i < len(ips); i++ {
		if data, err := Query(&whois.QueryOptions{Key: ips[i]}); err == nil {
			t.Log("Inetnum:", data.Inetnum)
			t.Log("Server:", data.Server)
			t.Log("Source:", data.Source)
			t.Log("Country:", data.Country)
			t.Log("Created:", data.Created)
			t.Log("Updated:", data.Updated)
		} else {
			// 由于whois各大服务器均在国外, 可能会由于网络原因测试失败(connect to core server failed)
			t.Errorf("query error(%s): %s", sources[i], err.Error())
		}
		t.Log("========================")
	}
}
