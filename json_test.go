package dnsmsg

import (
	"encoding/json"
	"testing"
)

// TestDomainNameMarshalJSON tests that a domain name is exported as its
// presentation-format string.
func TestDomainNameMarshalJSON(t *testing.T) {
    tests := []struct {
        name string
        want string
    }{
        {
            name: ".",
            want: `"."`,
        },
        {
            name: "example.com",
            want: `"example.com."`,
        },
        {
            name: "a.b.c",
            want: `"a.b.c."`,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            d := testDomainName(t, tt.name)
            got, err := json.Marshal(d)
            if err != nil {
                t.Errorf("json.Marshal() error = %v", err)
                return
            }
            if string(got) != tt.want {
                t.Errorf("json.Marshal() = %q, want %q", string(got), tt.want)
            }
        })
    }
}

// TestRecordMarshalJSON tests that resource records are exported as JSON
// objects that keep the presentation-format strings of their fields.
func TestRecordMarshalJSON(t *testing.T) {
    tests := []struct {
        name  string
        rdata RDATA
        want  string
    }{
        {
            name:  "A record",
            rdata: NewRecordA([4]byte{192, 134, 1, 21}),
            want:  `{"address":"192.134.1.21"}`,
        },
        {
            name:  "NS record",
            rdata: NewRecordNS(testDomainName(t, "ns1.example.com")),
            want:  `{"nsname":"ns1.example.com."}`,
        },
        {
            name:  "SOA record",
            rdata: NewRecordSOA(testDomainName(t, "a.root-sns.net"), testDomainName(t, "a.root-sns.net"), 20240817, 0, 0, 0, 0),
            want:  `{"expire":0,"minimum":0,"mname":"a.root-sns.net.","refresh":0,"retry":0,"rname":"a.root-sns.net.","serial":20240817}`,
        },
        {
            name:  "MX record",
            rdata: NewRecordMX(3600, testDomainName(t, "mail.example.com")),
            want:  `{"Exchange":"mail.example.com.","Preference":3600}`,
        },
        {
            name:  "AAAA record",
            rdata: NewRecordAAAA([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
            want:  `{"address":"::1"}`,
        },
        {
            name:  "DS record",
            rdata: NewRecordDS(1000, 5, 1, []byte{0x00, 0x01}),
            want:  `{"Algorithm":5,"Digest":"0001","DigestType":1,"KeyTag":1000}`,
        },
        {
            name:  "OPT record",
            rdata: NewRecordOPT(0, 0x8000, EDNSOptionDNSSEC{}, EDNSOptionNSID{ID: "ednsx"}, NewEDNSOptionEDE(6, "bogus"), EDNSOptionRaw{OptionCode: 8, OptionData: []byte{0x00, 0x00, 0x01, 0x18, 0x01, 0xc6, 0x33, 0x64}}),
            want:  `{"Flags":32768,"Options":[{"Code":1},{"Code":3,"ID":"ednsx"},{"Code":15,"ErrorCode":6,"ExtraText":"bogus"},{"Code":8,"OptionData":"0000011801c63364"}],"Version":0}`,
        },
        {
            name:  "RRSIG record",
            rdata: NewRecordRRSIG(1, 1, 1, 3600, 1457745740, 1457659200, 9526, testDomainName(t, "example.com"), []byte("key")),
            want:  `{"Algorithm":1,"Expiration":1457745740,"Inception":1457659200,"KeyTag":9526,"Labels":1,"OrigTTL":3600,"Signature":"a2V5","SignersName":"example.com.","TypeCovered":"A"}`,
        },
        {
            name:  "DNSKEY record",
            rdata: NewRecordDNSKEY(256, 3, 1, []byte{0x01, 0x02}),
            want:  `{"Algorithm":1,"Flags":256,"Protocol":3,"PublicKey":"AQI"}`,
        },
        {
            name:  "unknown type record",
            rdata: RecordRaw{rtype: 100, Data: []byte{0x66, 0x66}},
            want:  `{"Data":"ZmY","rtype":"TYPE100"}`,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := json.Marshal(tt.rdata)
            if err != nil {
                t.Errorf("json.Marshal() error = %v", err)
                return
            }
            if string(got) != tt.want {
                t.Errorf("json.Marshal() = %q, want %q", string(got), tt.want)
            }
        })
    }
}

// TestResourceRecordMarshalJSON tests that a resource record is exported as
// a JSON object with its name, class, type, TTL, and RDATA.
func TestResourceRecordMarshalJSON(t *testing.T) {
    tests := []struct {
        name string
        rr   ResourceRecord
        want string
    }{
        {
            name: "A record",
            rr: ResourceRecord{
                Name:  testDomainName(t, "example.com"),
                Class: CLASS_IN,
                Type:  TYPE_A,
                TTL:   300,
                RData: NewRecordA([4]byte{192, 134, 1, 21}),
            },
            want: `{"Class":"IN","Name":"example.com.","RData":{"address":"192.134.1.21"},"TTL":300,"Type":"A"}`,
        },
        {
            name: "unknown type record",
            rr: ResourceRecord{
                Name:  testDomainName(t, "example.com"),
                Class: CLASS_IN,
                Type:  100,
                TTL:   0,
                RData: RecordRaw{rtype: 100, Data: []byte{0x66, 0x66}},
            },
            want: `{"Class":"IN","Name":"example.com.","RData":{"Data":"ZmY","rtype":"TYPE100"},"TTL":0,"Type":"TYPE100"}`,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := json.Marshal(tt.rr)
            if err != nil {
                t.Errorf("json.Marshal() error = %v", err)
                return
            }
            if string(got) != tt.want {
                t.Errorf("json.Marshal() = %q, want %q", string(got), tt.want)
            }
        })
    }
}

// TestMessageMarshalJSON tests that a message is exported as a JSON object
// with its header fields and all four question/answer/authority/additional
// sections.  The count fields are exported as stored, not derived from the
// section lengths, and a section that is not present is exported as null.
func TestMessageMarshalJSON(t *testing.T) {
    tests := []struct {
        name string
        msg  Message
        want string
    }{
        {
            name: "empty message",
            msg: Message{
                ID:      1,
                QR:      1,
                OPCODE:  0,
                AA:      0,
                TC:      0,
                RD:      0,
                RA:      0,
                Z:       0,
                AD:      0,
                CD:      0,
                RCODE:   0,
                QDCOUNT: 0,
                ANCOUNT: 0,
                NSCOUNT: 0,
                ARCOUNT: 0,
            },
            want: `{"AA":0,"AD":0,"ANCOUNT":0,"ARCOUNT":0,"AdditionalSection":null,"AnswerSection":null,"AuthoritySection":null,"CD":0,"ID":1,"NSCOUNT":0,"OPCODE":0,"QDCOUNT":0,"QR":1,"QuestionSection":null,"RA":0,"RCODE":0,"RD":0,"TC":0,"Z":0}`,
        },
        {
            name: "query with an answer",
            msg: Message{
                ID:      1,
                QR:      1,
                QDCOUNT: 1,
                ANCOUNT: 1,
                QuestionSection: []QuestionSectionEntry{
                    QuestionSectionEntry{
                        QName: testDomainName(t, "example.com"),
                        Class: CLASS_IN,
                        Type:  TYPE_A,
                    },
                },
                AnswerSection: []ResourceRecord{
                    ResourceRecord{
                        Name:  testDomainName(t, "example.com"),
                        Class: CLASS_IN,
                        Type:  TYPE_A,
                        TTL:   300,
                        RData: NewRecordA([4]byte{192, 134, 1, 21}),
                    },
                },
            },
            want: `{"AA":0,"AD":0,"ANCOUNT":1,"ARCOUNT":0,"AdditionalSection":null,"AnswerSection":[{"Class":"IN","Name":"example.com.","RData":{"address":"192.134.1.21"},"TTL":300,"Type":"A"}],"AuthoritySection":null,"CD":0,"ID":1,"NSCOUNT":0,"OPCODE":0,"QDCOUNT":1,"QR":1,"QuestionSection":[{"Class":"IN","QName":"example.com.","Type":"A"}],"RA":0,"RCODE":0,"RD":0,"TC":0,"Z":0}`,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := json.Marshal(tt.msg)
            if err != nil {
                t.Errorf("json.Marshal() error = %v", err)
                return
            }
            if string(got) != tt.want {
                t.Errorf("json.Marshal() = %q, want %q", string(got), tt.want)
            }
        })
    }
}
